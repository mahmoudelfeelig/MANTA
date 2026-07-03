from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .cache_utils import load_feature_windows_cached
from .features import (
    FEATURE_COLUMNS,
    build_android_feature_windows,
    build_android_sliding_feature_windows,
)
from .io_utils import read_csv_resilient


AUDIT_FEATURES = [
    "flow_count",
    "byte_rate",
    "packet_rate",
    "mean_packet_size",
    "outbound_ratio",
    "destination_diversity",
    "destination_concentration",
    "destination_transition_rate",
    "novelty_score",
    "dns_flow_ratio",
    "web_flow_ratio",
    "private_destination_ratio",
    "flow_count_deviation",
    "byte_rate_deviation",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit near-duplicate Android feature windows with conflicting labels")
    parser.add_argument("--input", required=True, help="Flow CSV used for training/evaluation")
    parser.add_argument("--output", required=True, help="Output JSON audit report")
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0)
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
    parser.add_argument("--top-groups", type=int, default=30)
    parser.add_argument("--round-digits", type=int, default=2)
    return parser.parse_args()


def _load_windows(
    input_path: str | Path,
    *,
    window_mode: str,
    max_adaptive_windows: int,
    label_strategy: str,
    multi_horizon_training: bool,
) -> pd.DataFrame:
    if window_mode == "bucket":
        build_windows_fn = build_android_feature_windows
        cache_name = "android_feature_windows"
    elif window_mode == "sliding":
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=False,
            label_strategy=label_strategy,
            emit_all_horizons=multi_horizon_training,
        )
        cache_name = "android_sliding_feature_windows"
    else:
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=True,
            max_windows=max_adaptive_windows,
            label_strategy=label_strategy,
            emit_all_horizons=multi_horizon_training,
        )
        cache_name = "android_adaptive_feature_windows"
        if max_adaptive_windows > 0:
            cache_name = f"{cache_name}_max{max_adaptive_windows}"
    if label_strategy != "window":
        cache_name = f"{cache_name}_{label_strategy}"
    if multi_horizon_training:
        cache_name = f"{cache_name}_multihorizon"
    return load_feature_windows_cached(
        input_path,
        build_windows_fn=build_windows_fn,
        read_frame_fn=read_csv_resilient,
        cache_name=cache_name,
    )


def build_label_audit(
    input_path: str | Path,
    *,
    window_mode: str = "adaptive",
    max_adaptive_windows: int = 0,
    label_strategy: str = "window",
    multi_horizon_training: bool = False,
    top_groups: int = 30,
    round_digits: int = 2,
) -> dict[str, object]:
    windows = _load_windows(
        input_path,
        window_mode=window_mode,
        max_adaptive_windows=max_adaptive_windows,
        label_strategy=label_strategy,
        multi_horizon_training=multi_horizon_training,
    ).copy()
    if "label" not in windows.columns:
        raise ValueError("Windows must include a label column")
    windows["label"] = pd.to_numeric(windows["label"], errors="coerce").fillna(0).astype(int)
    for column in ("dataset_source", "app_family", "app_id", "session_id"):
        if column not in windows.columns:
            windows[column] = "unknown"
        windows[column] = windows[column].astype(str).fillna("unknown")

    audit_features = [column for column in AUDIT_FEATURES if column in windows.columns]
    missing_contract_features = [column for column in FEATURE_COLUMNS if column not in windows.columns]
    rounded = windows[["dataset_source", "app_family"]].copy()
    for column in audit_features:
        rounded[column] = pd.to_numeric(windows[column], errors="coerce").fillna(0.0).round(round_digits)
    group_keys = ["dataset_source", "app_family", *audit_features]
    grouped = windows.assign(__fingerprint=rounded[group_keys].astype(str).agg("|".join, axis=1)).groupby("__fingerprint", sort=False)
    conflicts = grouped.agg(
        rows=("label", "size"),
        positives=("label", "sum"),
        datasets=("dataset_source", lambda values: sorted(set(values.astype(str)))[:5]),
        families=("app_family", lambda values: sorted(set(values.astype(str)))[:5]),
        apps=("app_id", lambda values: sorted(set(values.astype(str)))[:8]),
        sessions=("session_id", lambda values: sorted(set(values.astype(str)))[:8]),
    ).reset_index()
    conflicts["negatives"] = conflicts["rows"] - conflicts["positives"]
    conflicts["positive_rate"] = conflicts["positives"] / conflicts["rows"].clip(lower=1)
    conflicts = conflicts[(conflicts["positives"] > 0) & (conflicts["negatives"] > 0)].copy()
    conflicts = conflicts.sort_values(["rows", "positives"], ascending=False, kind="mergesort")

    family_conflicts = []
    if not conflicts.empty:
        exploded = conflicts.explode("families")
        family_conflicts = (
            exploded.groupby("families", dropna=False)
            .agg(conflict_groups=("__fingerprint", "size"), conflict_rows=("rows", "sum"))
            .sort_values("conflict_rows", ascending=False)
            .reset_index()
            .rename(columns={"families": "app_family"})
            .to_dict(orient="records")
        )

    return {
        "rows": int(len(windows)),
        "positives": int((windows["label"] == 1).sum()),
        "negatives": int((windows["label"] == 0).sum()),
        "round_digits": int(round_digits),
        "audit_features": audit_features,
        "missing_contract_features": missing_contract_features,
        "conflicting_fingerprint_groups": int(len(conflicts)),
        "conflicting_rows": int(conflicts["rows"].sum()) if not conflicts.empty else 0,
        "conflicting_row_share": float(conflicts["rows"].sum() / max(1, len(windows))) if not conflicts.empty else 0.0,
        "family_conflicts": family_conflicts,
        "top_conflicts": conflicts.head(top_groups).to_dict(orient="records"),
    }


def main() -> None:
    args = parse_args()
    report = build_label_audit(
        args.input,
        window_mode=args.window_mode,
        max_adaptive_windows=args.max_adaptive_windows,
        label_strategy=args.label_strategy,
        multi_horizon_training=args.multi_horizon_training,
        top_groups=args.top_groups,
        round_digits=args.round_digits,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
