from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .cache_utils import load_feature_windows_cached
from .features import build_android_feature_windows, build_android_sliding_feature_windows
from .io_utils import read_csv_resilient
from .splits import split_for_strategy


SPLIT_STRATEGIES = [
    "source_aware_auto",
    "source_env_session",
    "source_env_family_time",
    "source_family",
    "family_time",
    "app_family_time",
    "temporal_holdout",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit dataset balance and domain splits for Android model windows")
    parser.add_argument("--input", required=True, help="Flow CSV used for training/evaluation")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0)
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
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


def _counts(frame: pd.DataFrame, column: str) -> list[dict[str, object]]:
    if column not in frame.columns:
        return []
    grouped = frame.groupby(column, dropna=False)
    rows = []
    for value, group in grouped:
        labels = pd.to_numeric(group["label"], errors="coerce").fillna(0).astype(int)
        rows.append(
            {
                "group": str(value),
                "rows": int(len(group)),
                "positives": int((labels == 1).sum()),
                "negatives": int((labels == 0).sum()),
                "positive_rate": float((labels == 1).mean()) if len(group) else 0.0,
            }
        )
    rows.sort(key=lambda row: int(row["rows"]), reverse=True)
    return rows


def build_split_balance_audit(
    input_path: str | Path,
    *,
    random_seed: int = 42,
    test_ratio: float = 0.3,
    window_mode: str = "adaptive",
    max_adaptive_windows: int = 0,
    label_strategy: str = "window",
    multi_horizon_training: bool = False,
) -> dict[str, object]:
    windows = _load_windows(
        input_path,
        window_mode=window_mode,
        max_adaptive_windows=max_adaptive_windows,
        label_strategy=label_strategy,
        multi_horizon_training=multi_horizon_training,
    ).copy()
    windows["label"] = pd.to_numeric(windows["label"], errors="coerce").fillna(0).astype(int)
    audits = []
    for strategy in SPLIT_STRATEGIES:
        try:
            split = split_for_strategy(
                windows,
                strategy=strategy,
                label_column="label",
                test_size=test_ratio,
                random_seed=random_seed,
            )
        except ValueError as exc:
            audits.append({"strategy": strategy, "available": False, "reason": str(exc)})
            continue
        train = windows.iloc[split.train_idx]
        test = windows.iloc[split.test_idx]
        audits.append(
            {
                "strategy": strategy,
                "available": True,
                "selected_strategy": split.strategy,
                "summary": split.summary,
                "train_sources": _counts(train, "dataset_source"),
                "test_sources": _counts(test, "dataset_source"),
                "train_families": _counts(train, "app_family"),
                "test_families": _counts(test, "app_family"),
            }
        )
    return {
        "rows": int(len(windows)),
        "positives": int((windows["label"] == 1).sum()),
        "negatives": int((windows["label"] == 0).sum()),
        "dataset_sources": _counts(windows, "dataset_source"),
        "app_families": _counts(windows, "app_family"),
        "splits": audits,
    }


def main() -> None:
    args = parse_args()
    report = build_split_balance_audit(
        args.input,
        random_seed=args.random_seed,
        test_ratio=args.test_ratio,
        window_mode=args.window_mode,
        max_adaptive_windows=args.max_adaptive_windows,
        label_strategy=args.label_strategy,
        multi_horizon_training=args.multi_horizon_training,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
