from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .cache_utils import _sample_by_source
from .metrics import binary_classification_metrics
from .privacy_views import PRIVACY_FEATURE_SETS, build_window_privacy_views_from_windows
from .splits import source_aware_train_test_split
from .window_builders import add_window_protocol_args, adaptive_cache_name, load_android_windows_for_protocol


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate privacy-utility trade-offs across MANTA privacy views")
    parser.add_argument("--input", required=True, help="Flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument(
        "--contamination",
        type=float,
        default=None,
        help="Deprecated compatibility flag retained for older experiment-suite commands; ignored by the current supervised privacy ablation.",
    )
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--seeds", type=int, default=3, help="Number of seeded grouped-split evaluations per view")
    parser.add_argument("--max-rows", type=int, default=250000)
    add_window_protocol_args(parser)
    return parser.parse_args()


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.0, 1.0, 101):
        pred = (scores >= threshold).astype(int)
        current_f1 = float(f1_score(y_true, pred, zero_division=0))
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = float(threshold)
    return best_threshold


def _evaluate_view(
    frame: pd.DataFrame,
    view_name: str,
    random_seed: int,
    max_rows: int,
) -> dict[str, float | int | None]:
    if "label" not in frame.columns:
        raise SystemExit("Privacy ablation requires labels.")
    if len(frame) > max_rows > 0:
        labels = pd.to_numeric(frame["label"], errors="coerce").fillna(0).astype(int)
        positives = frame[labels == 1]
        negatives = frame[labels == 0]
        negatives = _sample_by_source(negatives, max(0, max_rows - len(positives)), random_seed)
        frame = pd.concat([positives, negatives], ignore_index=True, sort=False)
    feature_columns = [column for column in PRIVACY_FEATURE_SETS[view_name] if column in frame.columns]
    if not feature_columns:
        raise SystemExit(f"Privacy view '{view_name}' has no usable feature columns. Delete stale privacy caches or rerun with the patched cache validation.")
    labels = frame["label"].fillna(0).astype(int).to_numpy()
    split = source_aware_train_test_split(frame, label_column="label", test_size=0.3, random_seed=random_seed)
    train_idx, test_idx = split.train_idx, split.test_idx
    train_df = frame.iloc[train_idx]
    test_df = frame.iloc[test_idx]
    y_train = labels[train_idx]
    y_test = labels[test_idx]
    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=random_seed)),
        ]
    )
    model.fit(train_df[feature_columns].fillna(0.0), y_train)
    scores = model.predict_proba(test_df[feature_columns].fillna(0.0))[:, 1]
    threshold = _best_threshold(y_true=y_test, scores=scores)
    metrics = binary_classification_metrics(y_test, scores, threshold)
    return {
        "rows_train": int(len(train_df)),
        "rows_test": int(len(test_df)),
        "split_strategy": split.strategy,
        **metrics,
    }


def _aggregate_runs(runs: list[dict[str, float | int | None]]) -> dict[str, object]:
    summary: dict[str, object] = {"runs": runs}
    numeric_keys = {
        key
        for run in runs
        for key, value in run.items()
        if isinstance(value, (int, float)) and key not in {"rows_train", "rows_test"}
    }
    if runs:
        summary["rows_train"] = int(np.mean([int(run["rows_train"]) for run in runs]))
        summary["rows_test"] = int(np.mean([int(run["rows_test"]) for run in runs]))
        summary["split_strategy"] = runs[0].get("split_strategy")
    for key in sorted(numeric_keys):
        values = np.asarray([float(run[key]) for run in runs if isinstance(run.get(key), (int, float))], dtype=float)
        if values.size == 0:
            summary[key] = None
            continue
        summary[key] = float(values.mean())
        if values.size > 1:
            summary[f"{key}_std"] = float(values.std(ddof=0))
    return summary


def main() -> None:
    args = parse_args()
    windows = load_android_windows_for_protocol(args.input, args, cache_prefix="privacy")
    views = build_window_privacy_views_from_windows(windows)

    results: dict[str, dict[str, float | int | None]] = {}
    for view_name, frame in views.items():
        runs = [
            _evaluate_view(
                frame=frame,
                view_name=view_name,
                random_seed=args.random_seed + (seed_offset * 17),
                max_rows=args.max_rows,
            )
            for seed_offset in range(max(1, args.seeds))
        ]
        results[view_name] = _aggregate_runs(runs)

    baseline_f1 = float(results["off"]["f1"])
    baseline_pr_auc = float(results["off"]["pr_auc"])
    baseline_roc_auc = float(results["off"]["roc_auc"]) if isinstance(results["off"].get("roc_auc"), (int, float)) else None
    deltas: dict[str, dict[str, float | None]] = {}
    for name, metrics in results.items():
        f1_value = metrics.get("f1")
        pr_auc_value = metrics.get("pr_auc")
        roc_auc_value = metrics.get("roc_auc")
        delta = (float(f1_value) - baseline_f1) if isinstance(f1_value, (int, float)) else None
        deltas[name] = {
            "f1_delta_vs_off": delta,
            "f1_delta_vs_full": delta,
            "pr_auc_relative_drop_vs_off": (
                0.0 if not isinstance(pr_auc_value, (int, float)) else max(0.0, 1.0 - (float(pr_auc_value) / max(1e-9, baseline_pr_auc)))
            ),
            "roc_auc_relative_drop_vs_off": (
                None
                if baseline_roc_auc is None or not isinstance(roc_auc_value, (int, float))
                else max(0.0, 1.0 - (float(roc_auc_value) / max(1e-9, baseline_roc_auc)))
            ),
        }

    payload = {
        "rows": int(len(next(iter(views.values())))),
        "window_protocol": {
            "window_mode": args.window_mode,
            "window_seconds": int(args.window_seconds),
            "label_strategy": args.label_strategy,
            "max_adaptive_windows": int(args.max_adaptive_windows),
            "max_flow_rows": int(args.max_flow_rows),
            "multi_horizon_training": bool(args.multi_horizon_training),
            "cache_name": adaptive_cache_name(args, "privacy"),
        },
        "compatibility": {
            "ignored_contamination": args.contamination,
        },
        "seeds": int(max(1, args.seeds)),
        "feature_sets": {name: {"features": features} for name, features in PRIVACY_FEATURE_SETS.items()},
        "results": results,
        "deltas": deltas,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
