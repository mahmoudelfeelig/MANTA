from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

from .features import build_feature_windows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a lightweight IDS-style rule baseline")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    parser.add_argument("--threshold", type=float, default=0.55, help="Anomaly threshold for rule score")
    parser.add_argument("--windows-output", default="", help="Optional CSV path with per-window scores")
    return parser.parse_args()


def _clip01(values: np.ndarray) -> np.ndarray:
    return np.clip(values, 0.0, 1.0)


def score_ids_baseline(windows: pd.DataFrame) -> np.ndarray:
    novelty = _clip01(windows["novelty_score"].to_numpy(dtype=float))
    burstiness = _clip01(windows["burstiness"].to_numpy(dtype=float) / 500.0)
    outbound = _clip01((windows["outbound_ratio"].to_numpy(dtype=float) - 0.7) / 0.3)
    frequency = _clip01(windows["connection_frequency_delta"].to_numpy(dtype=float) / 20.0)

    bytes_out = windows["total_bytes_out"].to_numpy(dtype=float)
    bytes_in = windows["total_bytes_in"].to_numpy(dtype=float)
    exfil_ratio = _clip01(((bytes_out / (bytes_in + 1.0)) - 2.0) / 6.0)

    score = (
        0.32 * novelty +
        0.22 * burstiness +
        0.20 * exfil_ratio +
        0.14 * outbound +
        0.12 * frequency
    )
    return _clip01(score)


def _classification_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray) -> dict:
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
    df = pd.read_csv(args.input)
    windows = build_feature_windows(df)
    scores = score_ids_baseline(windows)
    predictions = (scores >= args.threshold).astype(int)

    report: dict[str, float | int | None] = {
        "rows": int(len(windows)),
        "threshold": args.threshold,
        "positive_predictions": int(predictions.sum()),
        "score_min": float(scores.min()) if len(scores) else 0.0,
        "score_max": float(scores.max()) if len(scores) else 0.0,
    }

    if "label" in windows.columns:
        y_true = windows["label"].fillna(0).astype(int).to_numpy()
        report.update(_classification_metrics(y_true=y_true, y_pred=predictions, scores=scores))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.windows_output:
        windows_output = Path(args.windows_output)
        windows_output.parent.mkdir(parents=True, exist_ok=True)
        enriched = windows.copy()
        enriched["ids_score"] = scores
        enriched["ids_prediction"] = predictions
        enriched.to_csv(windows_output, index=False)


if __name__ == "__main__":
    main()
