from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)

from .calibration import calibrate_thresholds
from .cache_utils import load_feature_windows_cached
from .explain import compute_feature_contributions
from .features import build_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import operational_binary_metrics, threshold_sweep_metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate baseline anomaly model")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--artifacts", required=True, help="Directory containing baseline_model.joblib")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threshold on normalized anomaly score")
    parser.add_argument(
        "--auto-threshold",
        action="store_true",
        help="Select threshold by maximizing F1 on labeled data (falls back to --threshold when labels are unavailable)",
    )
    parser.add_argument("--explanations-output", default="", help="Optional CSV path for top-feature explanations")
    parser.add_argument("--policy-output", default="", help="Optional JSON path for calibrated adaptive policy")
    parser.add_argument("--window-scores-output", default="", help="Optional CSV path with per-window scores/predictions")
    parser.add_argument("--threshold-sweep-output", default="", help="Optional CSV path with threshold sweep metrics")
    parser.add_argument("--roc-output", default="", help="Optional CSV path for ROC curve points")
    parser.add_argument("--pr-output", default="", help="Optional CSV path for precision-recall curve points")
    parser.add_argument("--confusion-output", default="", help="Optional JSON path for confusion matrix")
    return parser.parse_args()


def normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
    min_v = np.min(raw_scores)
    max_v = np.max(raw_scores)
    if np.isclose(min_v, max_v):
        return np.zeros_like(raw_scores)
    return (raw_scores - min_v) / (max_v - min_v)


def _select_best_threshold(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, pd.DataFrame]:
    sweep = threshold_sweep_metrics(y_true, scores, steps=101)
    best = sweep.sort_values(["f1", "precision", "recall"], ascending=False).iloc[0]
    return float(best["threshold"]), sweep


def main() -> None:
    args = parse_args()
    model = joblib.load(Path(args.artifacts) / "baseline_model.joblib")

    windows = load_feature_windows_cached(
        args.input,
        build_windows_fn=build_feature_windows,
        read_frame_fn=read_csv_resilient,
    )
    X = feature_matrix(windows)

    decision = -model.decision_function(X)
    scores = normalize_scores(decision)
    windows["anomaly_score"] = scores
    selected_threshold = args.threshold
    threshold_source = "fixed"
    sweep_df: pd.DataFrame | None = None

    report = {
        "rows": int(len(windows)),
        "threshold": selected_threshold,
        "threshold_source": threshold_source,
        "score_min": float(scores.min()) if len(scores) else 0.0,
        "score_max": float(scores.max()) if len(scores) else 0.0,
    }

    if "label" in windows.columns:
        y_true = windows["label"].fillna(0).astype(int).values
        if args.auto_threshold:
            selected_threshold, sweep_df = _select_best_threshold(y_true=y_true, scores=scores)
            threshold_source = "auto_f1"
            report["threshold"] = selected_threshold
            report["threshold_source"] = threshold_source
        else:
            _, sweep_df = _select_best_threshold(y_true=y_true, scores=scores)

        predictions = (scores >= selected_threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
        report.update(operational_binary_metrics(y_true, scores, selected_threshold))
        report["confusion_matrix"] = {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    else:
        predictions = (scores >= selected_threshold).astype(int)
        report["positive_predictions"] = int(predictions.sum())

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.explanations_output:
        explanations = compute_feature_contributions(windows)
        explanations_path = Path(args.explanations_output)
        explanations_path.parent.mkdir(parents=True, exist_ok=True)
        explanations.to_csv(explanations_path, index=False)

    if args.policy_output:
        policy = calibrate_thresholds(windows_df=windows, score_column="anomaly_score", app_column="app_id")
        policy_path = Path(args.policy_output)
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")

    if args.window_scores_output:
        windows_output = Path(args.window_scores_output)
        windows_output.parent.mkdir(parents=True, exist_ok=True)
        export_windows = windows.copy()
        export_windows["prediction"] = predictions
        export_windows.to_csv(windows_output, index=False)

    if args.threshold_sweep_output and sweep_df is not None:
        sweep_output = Path(args.threshold_sweep_output)
        sweep_output.parent.mkdir(parents=True, exist_ok=True)
        sweep_df.to_csv(sweep_output, index=False)

    if "label" in windows.columns and args.roc_output:
        y_true = windows["label"].fillna(0).astype(int).values
        fpr, tpr, roc_thresholds = roc_curve(y_true, scores)
        roc_df = pd.DataFrame({"fpr": fpr, "tpr": tpr, "threshold": roc_thresholds})
        roc_output = Path(args.roc_output)
        roc_output.parent.mkdir(parents=True, exist_ok=True)
        roc_df.to_csv(roc_output, index=False)

    if "label" in windows.columns and args.pr_output:
        y_true = windows["label"].fillna(0).astype(int).values
        precision, recall, pr_thresholds = precision_recall_curve(y_true, scores)
        pr_thresholds_padded = np.append(pr_thresholds, np.nan)
        pr_df = pd.DataFrame({"precision": precision, "recall": recall, "threshold": pr_thresholds_padded})
        pr_output = Path(args.pr_output)
        pr_output.parent.mkdir(parents=True, exist_ok=True)
        pr_df.to_csv(pr_output, index=False)

    if args.confusion_output and "confusion_matrix" in report:
        confusion_output = Path(args.confusion_output)
        confusion_output.parent.mkdir(parents=True, exist_ok=True)
        confusion_output.write_text(json.dumps(report["confusion_matrix"], indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
