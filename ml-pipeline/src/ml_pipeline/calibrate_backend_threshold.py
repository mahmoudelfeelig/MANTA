from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from .compare_android_deployable_models import _load_backend_remote_modeling, _sample_balanced, _score_remote_model
from .metrics import binary_classification_metrics, threshold_sweep_metrics
from .splits import source_aware_train_test_split
from .window_builders import add_window_protocol_args, adaptive_cache_name, load_android_windows_for_protocol


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calibrate backend remote model threshold on Android-style validation windows")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--remote-model", required=True, help="Backend model JSON to calibrate")
    parser.add_argument("--output-model", required=True, help="Output calibrated backend model JSON")
    parser.add_argument("--output-report", required=True, help="Output calibration report JSON")
    parser.add_argument("--max-eval-rows", type=int, default=5000, help="Balanced validation rows; 0 means full holdout")
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--target-precision", type=float, default=0.85)
    parser.add_argument("--target-recall", type=float, default=0.90)
    parser.add_argument("--target-max-fpr", type=float, default=0.18)
    parser.add_argument("--cache-prefix", default="android")
    add_window_protocol_args(parser)
    return parser.parse_args()


def _select_threshold(sweep, target_precision: float, target_recall: float, target_max_fpr: float) -> tuple[float, dict[str, Any]]:
    candidates = sweep[
        (sweep["precision"] >= target_precision)
        & (sweep["recall"] >= target_recall)
        & (sweep["false_positive_rate"] <= target_max_fpr)
    ]
    reason = "met_precision_recall_fpr_targets"
    if candidates.empty:
        candidates = sweep[
            (sweep["recall"] >= target_recall)
            & (sweep["false_positive_rate"] <= target_max_fpr)
        ]
        reason = "met_recall_fpr_targets"
    if candidates.empty:
        candidates = sweep[sweep["false_positive_rate"] <= target_max_fpr]
        reason = "met_fpr_target_only"
    if candidates.empty:
        candidates = sweep
        reason = "fallback_max_f1"
    selected = candidates.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0]
    best_f1 = sweep.sort_values(["f1", "precision", "recall"], ascending=False).iloc[0]
    return float(selected["threshold"]), {
        "policy": "android_validation_precision_recall_fpr_budget",
        "target_precision": float(target_precision),
        "target_recall": float(target_recall),
        "target_max_fpr": float(target_max_fpr),
        "selected_reason": reason,
        "selected": {key: float(selected[key]) for key in ["threshold", "precision", "recall", "f1", "false_positive_rate"]},
        "best_f1": {key: float(best_f1[key]) for key in ["threshold", "precision", "recall", "f1", "false_positive_rate"]},
    }


def main() -> None:
    args = parse_args()
    windows = load_android_windows_for_protocol(args.input, args, cache_prefix=args.cache_prefix)
    if "label" not in windows.columns or windows["label"].fillna(0).astype(int).nunique() < 2:
        raise SystemExit("Backend threshold calibration requires labeled windows with both classes.")

    split = source_aware_train_test_split(
        windows,
        label_column="label",
        test_size=float(args.test_ratio),
        random_seed=int(args.random_seed),
    )
    holdout = windows.iloc[split.test_idx].reset_index(drop=True)
    validation = _sample_balanced(holdout, int(args.max_eval_rows), int(args.random_seed))
    labels = validation["label"].fillna(0).astype(int).to_numpy()

    model_path = Path(args.remote_model)
    model = json.loads(model_path.read_text(encoding="utf-8"))
    remote_module = _load_backend_remote_modeling()
    scores = _score_remote_model(remote_module, model, validation)
    sweep = threshold_sweep_metrics(labels, scores, steps=1001)
    threshold, policy = _select_threshold(
        sweep,
        target_precision=float(args.target_precision),
        target_recall=float(args.target_recall),
        target_max_fpr=float(args.target_max_fpr),
    )
    metrics = binary_classification_metrics(labels, scores, threshold)

    calibrated = dict(model)
    calibrated["recommended_threshold"] = threshold
    calibrated["threshold_policy"] = policy
    calibrated["calibrated_on"] = {
        "protocol": "android_adaptive_validation_holdout",
        "split_strategy": split.strategy,
        "validation_rows": int(len(validation)),
        "label_counts": {str(key): int(value) for key, value in validation["label"].fillna(0).astype(int).value_counts().to_dict().items()},
        "cache_name": adaptive_cache_name(args, args.cache_prefix),
    }

    output_model = Path(args.output_model)
    output_report = Path(args.output_report)
    output_model.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_model.write_text(json.dumps(calibrated, indent=2), encoding="utf-8")
    output_report.write_text(
        json.dumps(
            {
                "input": str(Path(args.input).expanduser().resolve()),
                "remote_model": str(model_path),
                "output_model": str(output_model),
                "window_protocol": calibrated["calibrated_on"],
                "threshold": threshold,
                "threshold_policy": policy,
                "metrics": metrics,
                "score_summary": {
                    "min": float(np.min(scores)),
                    "max": float(np.max(scores)),
                    "mean": float(np.mean(scores)),
                    "p50": float(np.quantile(scores, 0.50)),
                    "p90": float(np.quantile(scores, 0.90)),
                    "p99": float(np.quantile(scores, 0.99)),
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Calibrated backend model written to {output_model}")
    print(f"Calibration report written to {output_report}")
    print(f"threshold={threshold:.4f} precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} fpr={metrics['false_positive_rate']:.4f}")


if __name__ == "__main__":
    main()
