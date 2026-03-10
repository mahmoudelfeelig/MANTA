from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, mean_squared_error, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_SETS, build_window_privacy_views


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a privacy-preserving student model from a full-view teacher")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-model", required=True, help="Output JSON path for the distilled student")
    parser.add_argument("--output-report", required=True, help="Output JSON report path")
    parser.add_argument("--student-view", choices=sorted(PRIVACY_FEATURE_SETS), default="semantic_private")
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Privacy student training")
    progress.update(5, "Loading flow CSV")
    flows = pd.read_csv(args.input)
    progress.update(15, "Building privacy views")
    views = build_window_privacy_views(flows)
    full = views["full"]
    student = views[args.student_view]
    if "label" not in full.columns:
        raise SystemExit("Privacy-student training requires labels.")

    indices = np.arange(len(full))
    train_idx, test_idx = train_test_split(
        indices,
        test_size=0.3,
        random_state=args.random_seed,
        stratify=full["label"].fillna(0).astype(int).to_numpy(),
    )
    y = full["label"].fillna(0).astype(int).to_numpy()

    teacher_pipe = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=args.random_seed)),
        ]
    )
    full_features = [column for column in PRIVACY_FEATURE_SETS["full"] if column in full.columns]
    student_features = [column for column in PRIVACY_FEATURE_SETS[args.student_view] if column in student.columns]
    progress.update(35, "Training full-view teacher")
    teacher_pipe.fit(full.iloc[train_idx][full_features], y[train_idx])
    teacher_scores_train = teacher_pipe.predict_proba(full.iloc[train_idx][full_features])[:, 1]
    teacher_scores_test = teacher_pipe.predict_proba(full.iloc[test_idx][full_features])[:, 1]

    student_pipe = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("mlp", MLPRegressor(hidden_layer_sizes=(32, 16), random_state=args.random_seed, max_iter=400)),
        ]
    )
    progress.update(62, f"Training {args.student_view} student")
    student_pipe.fit(student.iloc[train_idx][student_features], teacher_scores_train)
    student_scores_test = np.clip(student_pipe.predict(student.iloc[test_idx][student_features]), 0.0, 1.0)
    pred = (student_scores_test >= 0.5).astype(int)

    scaler: StandardScaler = student_pipe.named_steps["scaler"]
    mlp: MLPRegressor = student_pipe.named_steps["mlp"]
    model = {
        "model_type": "privacy_distilled_student",
        "student_view": args.student_view,
        "feature_order": student_features,
        "scaler_mean": scaler.mean_.astype(float).tolist(),
        "scaler_scale": scaler.scale_.astype(float).tolist(),
        "hidden_layer_sizes": list(mlp.hidden_layer_sizes if isinstance(mlp.hidden_layer_sizes, tuple) else [mlp.hidden_layer_sizes]),
        "coefs": [coef.astype(float).tolist() for coef in mlp.coefs_],
        "intercepts": [bias.astype(float).tolist() for bias in mlp.intercepts_],
    }
    report = {
        "rows_train": int(len(train_idx)),
        "rows_test": int(len(test_idx)),
        "student_view": args.student_view,
        "teacher_student_mse": float(mean_squared_error(teacher_scores_test, student_scores_test)),
        "precision": float(precision_score(y[test_idx], pred, zero_division=0)),
        "recall": float(recall_score(y[test_idx], pred, zero_division=0)),
        "f1": float(f1_score(y[test_idx], pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y[test_idx], student_scores_test)),
        "roc_auc": float(roc_auc_score(y[test_idx], student_scores_test)),
    }

    output_model = Path(args.output_model).expanduser().resolve()
    output_model.parent.mkdir(parents=True, exist_ok=True)
    progress.update(88, "Writing student model and report")
    output_model.write_text(json.dumps(model, indent=2), encoding="utf-8")
    output_report = Path(args.output_report).expanduser().resolve()
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
