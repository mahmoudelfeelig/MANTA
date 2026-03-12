from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .cache_utils import _sample_by_source, load_feature_windows_cached
from .features import build_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import binary_classification_metrics
from .splits import split_for_strategy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the corpus under multiple grouped split protocols")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--max-windows", type=int, default=250000)
    return parser.parse_args()


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    best = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.0, 1.0, 201):
        pred = (scores >= threshold).astype(int)
        tp = float(((pred == 1) & (y_true == 1)).sum())
        fp = float(((pred == 1) & (y_true == 0)).sum())
        fn = float(((pred == 0) & (y_true == 1)).sum())
        precision = 0.0 if (tp + fp) <= 0 else tp / (tp + fp)
        recall = 0.0 if (tp + fn) <= 0 else tp / (tp + fn)
        current = 0.0 if (precision + recall) <= 1e-9 else ((2.0 * precision * recall) / (precision + recall))
        if current > best_f1:
            best_f1 = current
            best = float(threshold)
    return best


def main() -> None:
    args = parse_args()
    windows = load_feature_windows_cached(
        args.input,
        build_windows_fn=build_feature_windows,
        read_frame_fn=read_csv_resilient,
    )
    if len(windows) > args.max_windows > 0:
        labels = pd.to_numeric(windows["label"], errors="coerce").fillna(0).astype(int)
        positives = windows[labels == 1]
        negatives = windows[labels == 0]
        negative_limit = max(0, args.max_windows - len(positives))
        negatives = _sample_by_source(negatives, negative_limit, 42)
        windows = pd.concat([positives, negatives], ignore_index=True, sort=False)
    if "label" not in windows.columns:
        raise SystemExit("Evaluation protocol report requires labels.")

    strategies = ["source_env_session", "source_env_family_time", "source_family", "family_time", "app_family_time", "temporal_holdout"]
    results: dict[str, dict[str, object]] = {}
    X_all = feature_matrix(windows)
    y_all = windows["label"].fillna(0).astype(int).to_numpy()

    for strategy in strategies:
        runs: list[dict[str, object]] = []
        for seed_index in range(max(1, args.seeds)):
            split = split_for_strategy(
                windows,
                strategy=strategy,
                label_column="label",
                test_size=args.test_size,
                random_seed=42 + (seed_index * 17),
            )
            train_df = windows.iloc[split.train_idx].reset_index(drop=True)
            test_df = windows.iloc[split.test_idx].reset_index(drop=True)
            y_train = y_all[split.train_idx]
            y_test = y_all[split.test_idx]
            pipe = Pipeline(
                steps=[
                    ("scaler", StandardScaler()),
                    ("clf", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=42 + seed_index)),
                ]
            )
            pipe.fit(X_all.iloc[split.train_idx], y_train)
            scores = pipe.predict_proba(X_all.iloc[split.test_idx])[:, 1]
            threshold = _best_threshold(y_test, scores)
            runs.append(
                {
                    "seed": int(seed_index),
                    "split_strategy": split.strategy,
                    "split_summary": split.summary,
                    **binary_classification_metrics(y_test, scores, threshold),
                }
            )
        aggregate: dict[str, object] = {"runs": runs}
        for metric in ("precision", "recall", "f1", "pr_auc", "roc_auc", "brier_score", "ece", "threshold"):
            values = np.asarray([float(run[metric]) for run in runs if isinstance(run.get(metric), (int, float))], dtype=float)
            if values.size:
                aggregate[metric] = float(values.mean())
                aggregate[f"{metric}_std"] = float(values.std(ddof=0))
        results[strategy] = aggregate

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"rows_windows": int(len(windows)), "strategies": results}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
