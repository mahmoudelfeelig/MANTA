from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .evaluate import normalize_scores
from .features import FEATURE_COLUMNS, build_feature_windows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate privacy-utility trade-offs with feature ablation")
    parser.add_argument("--input", required=True, help="Flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.0, 1.0, 101):
        pred = (scores >= threshold).astype(int)
        current_f1 = float(f1_score(y_true, pred, zero_division=0))
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = float(threshold)
    return best_threshold


def _evaluate_set(
    windows: pd.DataFrame,
    feature_set: list[str],
    contamination: float,
    random_seed: int,
) -> dict[str, float | int | None]:
    sorted_windows = windows.sort_values("window_bucket", kind="mergesort").reset_index(drop=True)
    split_index = max(1, int(len(sorted_windows) * 0.7))
    train_df = sorted_windows.iloc[:split_index]
    test_df = sorted_windows.iloc[split_index:]

    if test_df.empty:
        test_df = train_df.tail(max(1, len(train_df) // 3))

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "detector",
                IsolationForest(
                    contamination=contamination,
                    n_estimators=200,
                    random_state=random_seed,
                ),
            ),
        ]
    )
    model.fit(train_df[feature_set].fillna(0.0))

    decision = -model.decision_function(test_df[feature_set].fillna(0.0))
    scores = normalize_scores(decision)

    result: dict[str, float | int | None] = {
        "rows_train": int(len(train_df)),
        "rows_test": int(len(test_df)),
        "score_min": float(scores.min()) if len(scores) else 0.0,
        "score_max": float(scores.max()) if len(scores) else 0.0,
    }

    if "label" not in test_df.columns:
        return result

    y_true = test_df["label"].fillna(0).astype(int).to_numpy()
    threshold = _best_threshold(y_true=y_true, scores=scores)
    pred = (scores >= threshold).astype(int)

    result.update(
        {
            "threshold": threshold,
            "precision": float(precision_score(y_true, pred, zero_division=0)),
            "recall": float(recall_score(y_true, pred, zero_division=0)),
            "f1": float(f1_score(y_true, pred, zero_division=0)),
            "pr_auc": float(average_precision_score(y_true, scores)),
            "roc_auc": float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) > 1 else None,
        }
    )
    return result


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    windows = build_feature_windows(df)

    feature_sets: dict[str, list[str]] = {
        "full_features": FEATURE_COLUMNS,
        # Drop explicit novelty signal as a privacy-first reduction.
        "no_novelty": [name for name in FEATURE_COLUMNS if name != "novelty_score"],
        # Keep only aggregate traffic behavior, drop directional novelty and packet-size granularity.
        "coarse_behavior_only": [
            "flow_count",
            "total_bytes_out",
            "total_bytes_in",
            "burstiness",
            "connection_frequency_delta",
        ],
    }

    results: dict[str, dict[str, float | int | None]] = {}
    for name, feature_set in feature_sets.items():
        results[name] = _evaluate_set(
            windows=windows,
            feature_set=feature_set,
            contamination=args.contamination,
            random_seed=args.random_seed,
        )

    deltas: dict[str, dict[str, float | None]] = {}
    baseline_f1 = results["full_features"].get("f1")
    if isinstance(baseline_f1, float):
        for name, metrics in results.items():
            f1_value = metrics.get("f1")
            if isinstance(f1_value, float):
                deltas[name] = {"f1_delta_vs_full": f1_value - baseline_f1}
            else:
                deltas[name] = {"f1_delta_vs_full": None}

    payload = {
        "rows": int(len(windows)),
        "feature_sets": {name: {"features": features} for name, features in feature_sets.items()},
        "results": results,
        "deltas": deltas,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
