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

from .privacy_views import PRIVACY_FEATURE_SETS, build_window_privacy_views


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate privacy-utility trade-offs across MANTA privacy views")
    parser.add_argument("--input", required=True, help="Flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument(
        "--contamination",
        type=float,
        default=None,
        help="Deprecated compatibility flag retained for older experiment-suite commands; ignored by the current supervised privacy ablation.",
    )
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


def _evaluate_view(
    frame: pd.DataFrame,
    view_name: str,
    random_seed: int,
) -> dict[str, float | int | None]:
    if "label" not in frame.columns:
        raise SystemExit("Privacy ablation requires labels.")
    feature_columns = [column for column in PRIVACY_FEATURE_SETS[view_name] if column in frame.columns]
    labels = frame["label"].fillna(0).astype(int).to_numpy()
    train_idx, test_idx = train_test_split(
        np.arange(len(frame)),
        test_size=0.3,
        random_state=random_seed,
        stratify=labels,
    )
    train_df = frame.iloc[train_idx]
    test_df = frame.iloc[test_idx]
    y_train = labels[train_idx]
    y_test = labels[test_idx]
    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=random_seed)),
        ]
    )
    model.fit(train_df[feature_columns].fillna(0.0), y_train)
    scores = model.predict_proba(test_df[feature_columns].fillna(0.0))[:, 1]
    threshold = _best_threshold(y_true=y_test, scores=scores)
    pred = (scores >= threshold).astype(int)
    return {
        "rows_train": int(len(train_df)),
        "rows_test": int(len(test_df)),
        "threshold": threshold,
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_test, scores)),
        "roc_auc": float(roc_auc_score(y_test, scores)) if len(np.unique(y_test)) > 1 else None,
    }


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    views = build_window_privacy_views(df)

    results: dict[str, dict[str, float | int | None]] = {}
    for view_name, frame in views.items():
        results[view_name] = _evaluate_view(
            frame=frame,
            view_name=view_name,
            random_seed=args.random_seed,
        )

    baseline_f1 = float(results["full"]["f1"])
    deltas: dict[str, dict[str, float | None]] = {}
    for name, metrics in results.items():
        f1_value = metrics.get("f1")
        deltas[name] = {
            "f1_delta_vs_full": (float(f1_value) - baseline_f1) if isinstance(f1_value, (int, float)) else None
        }

    payload = {
        "rows": int(len(next(iter(views.values())))),
        "compatibility": {
            "ignored_contamination": args.contamination,
        },
        "feature_sets": {name: {"features": features} for name, features in PRIVACY_FEATURE_SETS.items()},
        "results": results,
        "deltas": deltas,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
