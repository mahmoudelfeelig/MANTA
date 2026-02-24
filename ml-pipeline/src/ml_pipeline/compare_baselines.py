from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

from .evaluate import normalize_scores
from .features import build_feature_windows, feature_matrix
from .ids_baseline import score_ids_baseline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare ML baseline with IDS-style rule baseline")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--artifacts", required=True, help="Directory with baseline_model.joblib")
    parser.add_argument("--output", required=True, help="Output JSON comparison path")
    parser.add_argument("--model-threshold", type=float, default=0.5)
    parser.add_argument("--ids-threshold", type=float, default=0.55)
    parser.add_argument("--windows-output", default="", help="Optional CSV path for per-window comparison")
    return parser.parse_args()


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray) -> dict:
    report: dict[str, float | None] = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, scores)),
    }
    report["roc_auc"] = float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) > 1 else None
    return report


def main() -> None:
    args = parse_args()
    model = joblib.load(Path(args.artifacts) / "baseline_model.joblib")

    df = pd.read_csv(args.input)
    windows = build_feature_windows(df)
    X = feature_matrix(windows)

    ml_scores = normalize_scores(-model.decision_function(X))
    ml_pred = (ml_scores >= args.model_threshold).astype(int)

    ids_scores = score_ids_baseline(windows)
    ids_pred = (ids_scores >= args.ids_threshold).astype(int)

    report: dict[str, dict | int] = {
        "rows": int(len(windows)),
        "model": {
            "threshold": args.model_threshold,
            "positive_predictions": int(ml_pred.sum()),
            "score_min": float(ml_scores.min()) if len(ml_scores) else 0.0,
            "score_max": float(ml_scores.max()) if len(ml_scores) else 0.0,
        },
        "ids_baseline": {
            "threshold": args.ids_threshold,
            "positive_predictions": int(ids_pred.sum()),
            "score_min": float(ids_scores.min()) if len(ids_scores) else 0.0,
            "score_max": float(ids_scores.max()) if len(ids_scores) else 0.0,
        },
    }

    if "label" in windows.columns:
        y_true = windows["label"].fillna(0).astype(int).to_numpy()
        model_metrics = _metrics(y_true=y_true, y_pred=ml_pred, scores=ml_scores)
        ids_metrics = _metrics(y_true=y_true, y_pred=ids_pred, scores=ids_scores)
        report["model"].update(model_metrics)  # type: ignore[arg-type]
        report["ids_baseline"].update(ids_metrics)  # type: ignore[arg-type]

        model_f1 = float(model_metrics["f1"])
        ids_f1 = float(ids_metrics["f1"])
        report["head_to_head"] = {
            "better_f1": "model" if model_f1 >= ids_f1 else "ids_baseline",
            "f1_delta_model_minus_ids": model_f1 - ids_f1,
        }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.windows_output:
        windows_output = Path(args.windows_output)
        windows_output.parent.mkdir(parents=True, exist_ok=True)
        enriched = windows.copy()
        enriched["model_score"] = ml_scores
        enriched["model_prediction"] = ml_pred
        enriched["ids_score"] = ids_scores
        enriched["ids_prediction"] = ids_pred
        enriched.to_csv(windows_output, index=False)


if __name__ == "__main__":
    main()
