from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS, build_feature_windows, feature_matrix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train Android-ready logistic model and export JSON")
    parser.add_argument("--input", required=True, help="Flow CSV with labels")
    parser.add_argument("--output-model", required=True, help="Output JSON model path")
    parser.add_argument("--output-report", required=True, help="Output evaluation report JSON")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    return parser.parse_args()


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    best = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.0, 1.0, 101):
        pred = (scores >= threshold).astype(int)
        current = float(f1_score(y_true, pred, zero_division=0))
        if current > best_f1:
            best_f1 = current
            best = float(threshold)
    return best


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    windows = build_feature_windows(df)
    if "label" not in windows.columns:
        raise SystemExit("Input must include label or is_anomaly column for supervised Android model training")

    sorted_windows = windows.sort_values("window_bucket", kind="mergesort").reset_index(drop=True)
    split_index = max(1, int(len(sorted_windows) * (1.0 - args.test_ratio)))
    train_df = sorted_windows.iloc[:split_index].copy()
    test_df = sorted_windows.iloc[split_index:].copy()
    if test_df.empty:
        raise SystemExit("Not enough rows to build a non-empty test split")

    all_labels = sorted_windows["label"].fillna(0).astype(int)
    if all_labels.nunique() < 2:
        raise SystemExit("Input does not contain at least two classes after window aggregation")

    # Prefer time-aware split, but recover when it collapses to a single class in training.
    if train_df["label"].fillna(0).astype(int).nunique() < 2:
        class_counts = all_labels.value_counts()
        can_stratify = bool(not class_counts.empty and class_counts.min() >= 2)
        stratify_labels = all_labels if can_stratify else None
        train_df, test_df = train_test_split(
            sorted_windows,
            test_size=args.test_ratio,
            random_state=args.random_seed,
            stratify=stratify_labels,
        )
        train_df = train_df.reset_index(drop=True)
        test_df = test_df.reset_index(drop=True)

    # Guarantee that training sees both classes when they exist globally.
    train_labels = train_df["label"].fillna(0).astype(int)
    all_classes = set(all_labels.unique().tolist())
    train_classes = set(train_labels.unique().tolist())
    missing_train_classes = list(all_classes - train_classes)
    if missing_train_classes:
        for missing_class in missing_train_classes:
            candidates = test_df[test_df["label"].fillna(0).astype(int) == missing_class]
            if not candidates.empty:
                moved = candidates.iloc[[0]]
                test_df = test_df.drop(index=moved.index).reset_index(drop=True)
                train_df = pd.concat([train_df, moved], ignore_index=True)

    if test_df.empty:
        raise SystemExit("Test split is empty after class-balance adjustment")

    if train_df["label"].fillna(0).astype(int).nunique() < 2:
        raise SystemExit("Training split has fewer than two classes; cannot train logistic model")

    X_train = feature_matrix(train_df)
    y_train = train_df["label"].fillna(0).astype(int).to_numpy()
    X_test = feature_matrix(test_df)
    y_test = test_df["label"].fillna(0).astype(int).to_numpy()

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=800, class_weight="balanced", random_state=args.random_seed)),
        ]
    )
    pipeline.fit(X_train, y_train)

    scores = pipeline.predict_proba(X_test)[:, 1]
    threshold = _best_threshold(y_true=y_test, scores=scores)
    pred = (scores >= threshold).astype(int)

    scaler: StandardScaler = pipeline.named_steps["scaler"]
    clf: LogisticRegression = pipeline.named_steps["clf"]
    model_payload = {
        "model_type": "logistic_regression",
        "version": 1,
        "feature_order": FEATURE_COLUMNS,
        "means": scaler.mean_.astype(float).tolist(),
        "scales": np.where(scaler.scale_ == 0, 1.0, scaler.scale_).astype(float).tolist(),
        "weights": clf.coef_[0].astype(float).tolist(),
        "bias": float(clf.intercept_[0]),
        "recommended_threshold": threshold,
    }

    report_payload = {
        "rows_train": int(len(train_df)),
        "rows_test": int(len(test_df)),
        "threshold": threshold,
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_test, scores)),
        "roc_auc": float(roc_auc_score(y_test, scores)) if len(np.unique(y_test)) > 1 else None,
    }

    model_path = Path(args.output_model)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text(json.dumps(model_payload, indent=2), encoding="utf-8")

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
