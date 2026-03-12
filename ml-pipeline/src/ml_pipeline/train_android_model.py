from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .cache_utils import load_feature_windows_cached
from .dataset_metadata import compute_source_balance_weights, hard_example_weight
from .features import FEATURE_COLUMNS, build_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import binary_classification_metrics, per_group_binary_metrics
from .progress import PhaseProgress
from .splits import source_aware_train_test_split


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
    progress = PhaseProgress("Android linear training")
    progress.update(5, "Loading flow CSV")
    progress.update(18, "Building feature windows")
    windows = load_feature_windows_cached(
        args.input,
        build_windows_fn=build_feature_windows,
        read_frame_fn=read_csv_resilient,
    )
    if "label" not in windows.columns:
        raise SystemExit("Input must include label or is_anomaly column for supervised Android model training")

    progress.update(30, "Preparing source-aware holdout split")
    if windows["label"].fillna(0).astype(int).nunique() < 2:
        raise SystemExit("Input does not contain at least two classes after window aggregation")
    split = source_aware_train_test_split(
        windows,
        label_column="label",
        test_size=args.test_ratio,
        random_seed=args.random_seed,
    )
    train_df = windows.iloc[split.train_idx].reset_index(drop=True)
    test_df = windows.iloc[split.test_idx].reset_index(drop=True)

    X_train = feature_matrix(train_df)
    y_train = train_df["label"].fillna(0).astype(int).to_numpy()
    X_test = feature_matrix(test_df)
    y_test = test_df["label"].fillna(0).astype(int).to_numpy()
    source_weights = compute_source_balance_weights(train_df["dataset_source"])
    sample_weights = np.asarray(
        [
            hard_example_weight(
                label=int(label),
                dataset_source=str(source),
                app_family=str(family),
            )
            * float(source_weights.get(str(source), 1.0))
            for label, source, family in zip(
                y_train,
                train_df["dataset_source"],
                train_df["app_family"],
                strict=False,
            )
        ],
        dtype=float,
    )

    progress.update(52, "Fitting logistic regression")
    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=800, class_weight="balanced", random_state=args.random_seed)),
        ]
    )
    fit_start = time.perf_counter()
    pipeline.fit(X_train, y_train, clf__sample_weight=sample_weights)
    training_seconds = float(time.perf_counter() - fit_start)

    progress.update(78, "Evaluating model")
    scores = pipeline.predict_proba(X_test)[:, 1]
    threshold = _best_threshold(y_true=y_test, scores=scores)
    metrics = binary_classification_metrics(y_test, scores, threshold)

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
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "training_seconds": training_seconds,
        **metrics,
        "per_source_metrics": per_group_binary_metrics(y_test, scores, test_df["dataset_source"], threshold, min_rows=24),
    }

    model_path = Path(args.output_model)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    progress.update(92, "Writing model artifact")
    model_path.write_text(json.dumps(model_payload, indent=2), encoding="utf-8")

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
