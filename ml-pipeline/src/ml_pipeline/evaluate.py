from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

from .features import build_feature_windows, feature_matrix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate baseline anomaly model")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--artifacts", required=True, help="Directory containing baseline_model.joblib")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threshold on normalized anomaly score")
    return parser.parse_args()


def normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
    min_v = np.min(raw_scores)
    max_v = np.max(raw_scores)
    if np.isclose(min_v, max_v):
        return np.zeros_like(raw_scores)
    return (raw_scores - min_v) / (max_v - min_v)


def main() -> None:
    args = parse_args()
    model = joblib.load(Path(args.artifacts) / "baseline_model.joblib")

    df = pd.read_csv(args.input)
    windows = build_feature_windows(df)
    X = feature_matrix(windows)

    decision = -model.decision_function(X)
    scores = normalize_scores(decision)
    predictions = (scores >= args.threshold).astype(int)

    report = {
        "rows": int(len(windows)),
        "threshold": args.threshold,
        "score_min": float(scores.min()) if len(scores) else 0.0,
        "score_max": float(scores.max()) if len(scores) else 0.0,
        "positive_predictions": int(predictions.sum()),
    }

    if "label" in windows.columns:
        y_true = windows["label"].fillna(0).astype(int).values
        report.update(
            {
                "precision": float(precision_score(y_true, predictions, zero_division=0)),
                "recall": float(recall_score(y_true, predictions, zero_division=0)),
                "f1": float(f1_score(y_true, predictions, zero_division=0)),
                "roc_auc": float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) > 1 else None,
                "pr_auc": float(average_precision_score(y_true, scores)),
            }
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
