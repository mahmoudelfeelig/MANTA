from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def expected_calibration_error(y_true: np.ndarray, scores: np.ndarray, *, bins: int = 10) -> float:
    if len(y_true) == 0:
        return 0.0
    y = np.asarray(y_true, dtype=float)
    s = np.asarray(scores, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = float(len(y))
    error = 0.0
    for lower, upper in zip(edges[:-1], edges[1:], strict=False):
        if upper >= 1.0:
            mask = (s >= lower) & (s <= upper)
        else:
            mask = (s >= lower) & (s < upper)
        if not np.any(mask):
            continue
        accuracy = float(np.mean(y[mask]))
        confidence = float(np.mean(s[mask]))
        error += (float(mask.sum()) / total) * abs(accuracy - confidence)
    return float(error)


def binary_classification_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float | int | None]:
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    pred = (s >= threshold).astype(int)
    report: dict[str, float | int | None] = {
        "threshold": float(threshold),
        "positive_predictions": int(pred.sum()),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, s)),
        "roc_auc": float(roc_auc_score(y, s)) if len(np.unique(y)) > 1 else None,
        "brier_score": float(brier_score_loss(y, np.clip(s, 0.0, 1.0))),
        "ece": float(expected_calibration_error(y, np.clip(s, 0.0, 1.0))),
    }
    return report


def per_group_binary_metrics(
    y_true: np.ndarray,
    scores: np.ndarray,
    groups: pd.Series,
    threshold: float,
    *,
    min_rows: int = 24,
) -> dict[str, dict[str, float | int | None]]:
    payload: dict[str, dict[str, float | int | None]] = {}
    grouped = pd.DataFrame(
        {
            "group": groups.astype(str).fillna("unknown"),
            "label": np.asarray(y_true, dtype=int),
            "score": np.asarray(scores, dtype=float),
        }
    )
    for group_name, group in grouped.groupby("group", dropna=False, sort=True):
        if len(group) < min_rows or group["label"].nunique() < 2:
            continue
        payload[str(group_name)] = {
            "rows": int(len(group)),
            **binary_classification_metrics(
                group["label"].to_numpy(dtype=int),
                group["score"].to_numpy(dtype=float),
                threshold,
            ),
        }
    return payload
