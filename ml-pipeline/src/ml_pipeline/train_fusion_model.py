from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS, build_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import operational_binary_metrics, select_threshold_by_f1
from .splits import source_aware_train_test_split


DEFAULT_SCORE_COLUMNS = [
    "logistic_score",
    "gbdt_score",
    "statistical_score",
    "multivariate_score",
    "sequence_score",
    "destination_context_score",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train learned fusion over model/context score columns")
    parser.add_argument("--input", required=True, help="Scored window CSV or canonical flow CSV")
    parser.add_argument("--output-model", required=True)
    parser.add_argument("--output-report", required=True)
    parser.add_argument("--score-columns", nargs="*", default=DEFAULT_SCORE_COLUMNS)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _load_scored_windows(path: Path, score_columns: list[str]) -> pd.DataFrame:
    frame = read_csv_resilient(path)
    if all(column in frame.columns for column in score_columns) and "label" in frame.columns:
        return frame
    windows = build_feature_windows(frame)
    if "label" not in windows.columns:
        raise ValueError("Fusion training requires labels and score columns, or a labeled canonical flow CSV.")
    features = feature_matrix(windows)
    baseline = features.rank(pct=True).mean(axis=1).clip(0.0, 1.0)
    windows["statistical_score"] = baseline
    windows["multivariate_score"] = baseline
    windows["sequence_score"] = windows["periodic_beacon_score"].clip(0.0, 1.0)
    windows["destination_context_score"] = windows["novelty_score"].clip(0.0, 1.0)
    windows["logistic_score"] = baseline
    windows["gbdt_score"] = baseline
    return windows


def main() -> None:
    args = parse_args()
    frame = _load_scored_windows(Path(args.input), args.score_columns)
    missing = [column for column in args.score_columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing fusion score columns: {missing}")
    if frame["label"].fillna(0).astype(int).nunique() < 2:
        raise ValueError("Fusion training requires at least two label classes.")

    split = source_aware_train_test_split(frame, label_column="label", test_size=0.3, random_seed=args.random_seed)
    train = frame.iloc[split.train_idx].reset_index(drop=True)
    test = frame.iloc[split.test_idx].reset_index(drop=True)
    X_train = train[args.score_columns].fillna(0.0).to_numpy(dtype=float)
    y_train = train["label"].fillna(0).astype(int).to_numpy()
    X_test = test[args.score_columns].fillna(0.0).to_numpy(dtype=float)
    y_test = test["label"].fillna(0).astype(int).to_numpy()

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=800, class_weight="balanced", random_state=args.random_seed)),
        ]
    )
    pipeline.fit(X_train, y_train)
    scores = pipeline.predict_proba(X_test)[:, 1]
    threshold = select_threshold_by_f1(y_test, scores)
    metrics = operational_binary_metrics(y_test, scores, threshold)
    scaler: StandardScaler = pipeline.named_steps["scaler"]
    clf: LogisticRegression = pipeline.named_steps["clf"]

    model = {
        "model_type": "learned_logistic_fusion",
        "version": 1,
        "score_order": args.score_columns,
        "means": scaler.mean_.astype(float).tolist(),
        "scales": np.where(scaler.scale_ == 0, 1.0, scaler.scale_).astype(float).tolist(),
        "weights": clf.coef_[0].astype(float).tolist(),
        "bias": float(clf.intercept_[0]),
        "recommended_threshold": threshold,
    }
    report = {
        "rows_train": int(len(train)),
        "rows_test": int(len(test)),
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        **metrics,
    }

    Path(args.output_model).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_model).write_text(json.dumps(model, indent=2), encoding="utf-8")
    Path(args.output_report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_report).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
