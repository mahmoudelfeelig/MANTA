from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_SETS, build_window_privacy_views


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark privacy leakage by app re-identification from exported features")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--min-class-rows", type=int, default=20)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Privacy leakage benchmark")
    progress.update(5, "Loading flow CSV")
    flows = pd.read_csv(args.input)
    progress.update(15, "Building privacy views")
    views = build_window_privacy_views(flows)
    results: dict[str, dict[str, float | int]] = {}
    total_views = max(1, len(views))
    for index, (view_name, frame) in enumerate(views.items(), start=1):
        progress.update(20 + (60 * (index - 1) / total_views), f"Evaluating {view_name}")
        counts = frame["app_id"].astype(str).value_counts()
        keep = counts[counts >= args.min_class_rows].index
        filtered = frame[frame["app_id"].astype(str).isin(keep)].copy()
        if len(filtered) < args.min_class_rows * 2:
            continue
        y_encoder = LabelEncoder()
        y = y_encoder.fit_transform(filtered["app_id"].astype(str))
        feature_columns = [column for column in PRIVACY_FEATURE_SETS[view_name] if column in filtered.columns]
        train_x, test_x, train_y, test_y = train_test_split(
            filtered[feature_columns].fillna(0.0),
            y,
            test_size=0.3,
            random_state=args.random_seed,
            stratify=y,
        )
        clf = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(max_iter=1200, random_state=args.random_seed)),
            ]
        )
        clf.fit(train_x, train_y)
        pred = clf.predict(test_x)
        results[view_name] = {
            "rows_train": int(len(train_x)),
            "rows_test": int(len(test_x)),
            "class_count": int(len(y_encoder.classes_)),
            "app_reidentification_accuracy": float(accuracy_score(test_y, pred)),
            "macro_f1": float(f1_score(test_y, pred, average="macro")),
        }

    payload = {"benchmark": "app_reidentification_from_privacy_views", "results": results}
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
