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
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    report: dict[str, float | int | None] = {
        "threshold": float(threshold),
        "positive_predictions": int(pred.sum()),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "pr_auc": float(average_precision_score(y, s)),
        "roc_auc": float(roc_auc_score(y, s)) if len(np.unique(y)) > 1 else None,
        "brier_score": float(brier_score_loss(y, np.clip(s, 0.0, 1.0))),
        "ece": float(expected_calibration_error(y, np.clip(s, 0.0, 1.0))),
    }
    return report


def threshold_binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float | int]:
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    pred = (s >= threshold).astype(int)
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    return {
        "threshold": float(threshold),
        "positive_predictions": int(pred.sum()),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
    }


def threshold_sweep_metrics(y_true: np.ndarray, scores: np.ndarray, *, steps: int = 201) -> pd.DataFrame:
    rows: list[dict[str, float | int | None]] = []
    for threshold in np.linspace(0.0, 1.0, steps):
        rows.append(threshold_binary_metrics(y_true, scores, float(threshold)))
    return pd.DataFrame(rows)


def select_threshold_by_f1(y_true: np.ndarray, scores: np.ndarray) -> float:
    sweep = threshold_sweep_metrics(y_true, scores)
    if sweep.empty:
        return 0.5
    return float(sweep.sort_values(["f1", "precision", "recall"], ascending=False).iloc[0]["threshold"])


def precision_at_alert_budgets(y_true: np.ndarray, scores: np.ndarray, budgets: tuple[int, ...] = (1, 3, 5, 10)) -> dict[str, float | int]:
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    order = np.argsort(-s)
    payload: dict[str, float | int] = {}
    for budget in budgets:
        k = min(int(budget), len(y))
        if k <= 0:
            payload[f"precision_at_{budget}"] = 0.0
            payload[f"true_positives_at_{budget}"] = 0
            continue
        selected = y[order[:k]]
        payload[f"precision_at_{budget}"] = float(selected.mean())
        payload[f"true_positives_at_{budget}"] = int(selected.sum())
    return payload


def recall_at_fpr(y_true: np.ndarray, scores: np.ndarray, fpr_targets: tuple[float, ...] = (0.01, 0.05, 0.10)) -> dict[str, float | None]:
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    negatives = max(1, int((y == 0).sum()))
    positives = max(1, int((y == 1).sum()))
    if len(y) == 0:
        return {f"recall_at_fpr_{target:g}": 0.0 for target in fpr_targets}
    order = np.argsort(-s)
    sorted_y = y[order]
    true_positives = np.cumsum(sorted_y == 1)
    false_positives = np.cumsum(sorted_y == 0)
    recalls = true_positives / positives
    fprs = false_positives / negatives
    payload: dict[str, float | None] = {}
    for target in fpr_targets:
        eligible = recalls[fprs <= target]
        payload[f"recall_at_fpr_{target:g}"] = float(eligible.max()) if len(eligible) else 0.0
    return payload


def calibration_bins(y_true: np.ndarray, scores: np.ndarray, *, bins: int = 10) -> list[dict[str, float | int]]:
    y = np.asarray(y_true, dtype=float)
    s = np.clip(np.asarray(scores, dtype=float), 0.0, 1.0)
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows: list[dict[str, float | int]] = []
    for lower, upper in zip(edges[:-1], edges[1:], strict=False):
        mask = ((s >= lower) & (s <= upper)) if upper >= 1.0 else ((s >= lower) & (s < upper))
        if not np.any(mask):
            rows.append({"lower": float(lower), "upper": float(upper), "rows": 0, "mean_score": 0.0, "positive_rate": 0.0})
            continue
        rows.append(
            {
                "lower": float(lower),
                "upper": float(upper),
                "rows": int(mask.sum()),
                "mean_score": float(s[mask].mean()),
                "positive_rate": float(y[mask].mean()),
            }
        )
    return rows


def operational_binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    return {
        **binary_classification_metrics(y_true, scores, threshold),
        **precision_at_alert_budgets(y_true, scores),
        **recall_at_fpr(y_true, scores),
        "calibration_bins": calibration_bins(y_true, scores),
    }


def per_group_binary_metrics(
    y_true: np.ndarray,
    scores: np.ndarray,
    groups: pd.Series,
    threshold: float,
    *,
    min_rows: int = 24,
    max_groups: int = 50,
) -> dict[str, dict[str, float | int | None]]:
    payload: dict[str, dict[str, float | int | None]] = {}
    group_values = groups.astype(str).fillna("unknown").replace({"": "unknown", "nan": "unknown", "None": "unknown"})
    y_all = np.asarray(y_true, dtype=int)
    scores_all = np.asarray(scores, dtype=float)
    counts = group_values.value_counts(dropna=False)
    for group_name, rows in counts.head(max_groups).items():
        if int(rows) < min_rows:
            continue
        mask = group_values.to_numpy(dtype=str) == str(group_name)
        y = y_all[mask]
        if len(np.unique(y)) < 2:
            continue
        pred = (scores_all[mask] >= threshold).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        payload[str(group_name)] = {
            "rows": int(mask.sum()),
            "positives": int((y == 1).sum()),
            "threshold": float(threshold),
            "positive_predictions": int(pred.sum()),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "false_positive_rate": float(fp / max(1, fp + tn)),
        }
    return payload
