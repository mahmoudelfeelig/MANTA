from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .cache_utils import load_privacy_views_cached
from .features import build_feature_windows
from .io_utils import read_csv_resilient
from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_GROUPS, PRIVACY_FEATURE_SETS, build_window_privacy_views_from_windows
from .splits import add_split_metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark privacy leakage by app re-identification from exported features")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--min-class-rows", type=int, default=20)
    parser.add_argument("--max-class-rows", type=int, default=400)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _build_leakage_classifier(random_seed: int) -> Pipeline:
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "clf",
                OneVsRestClassifier(
                    LogisticRegression(
                        max_iter=400,
                        random_state=random_seed,
                        tol=1e-3,
                    ),
                    n_jobs=-1,
                ),
            ),
        ]
    )


def _grouped_app_holdout_split(
    frame: pd.DataFrame,
    *,
    app_column: str = "app_id",
    test_size: float = 0.3,
    random_seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, str, dict[str, object]]:
    enriched = add_split_metadata(frame).reset_index(drop=True)
    rng = np.random.default_rng(random_seed)
    class_values = enriched[app_column].astype(str)
    group_keys = (
        enriched["dataset_source"].astype(str) + "|" +
        enriched["environment_id"].astype(str) + "|" +
        enriched["session_id"].astype(str) + "|" +
        enriched["time_fold"].astype(str)
    )
    train_idx: list[int] = []
    test_idx: list[int] = []
    group_strategy_used = False

    for app_id in sorted(class_values.unique().tolist()):
        class_mask = class_values == app_id
        class_indices = np.flatnonzero(class_mask.to_numpy())
        if len(class_indices) < 2:
            continue
        class_groups = group_keys.iloc[class_indices].reset_index(drop=True)
        unique_groups = class_groups.unique().tolist()

        selected_test: np.ndarray | None = None
        if len(unique_groups) >= 2:
            shuffled_groups = rng.permutation(unique_groups).tolist()
            target_rows = max(1, int(round(len(class_indices) * test_size)))
            chosen_groups: set[str] = set()
            chosen_count = 0
            for group_name in shuffled_groups:
                group_rows = class_indices[(class_groups.to_numpy(dtype=object) == group_name)]
                remaining_rows = len(class_indices) - (chosen_count + len(group_rows))
                if remaining_rows < 1:
                    continue
                chosen_groups.add(str(group_name))
                chosen_count += len(group_rows)
                if chosen_count >= target_rows and len(chosen_groups) < len(unique_groups):
                    break
            if chosen_groups and len(chosen_groups) < len(unique_groups):
                mask = class_groups.isin(chosen_groups).to_numpy()
                selected_test = class_indices[mask]
                group_strategy_used = True

        if selected_test is None or len(selected_test) == 0 or len(selected_test) >= len(class_indices):
            test_count = min(max(1, int(round(len(class_indices) * test_size))), len(class_indices) - 1)
            permutation = rng.permutation(class_indices)
            selected_test = permutation[:test_count]

        selected_train = np.setdiff1d(class_indices, selected_test, assume_unique=False)
        if len(selected_train) == 0 or len(selected_test) == 0:
            fallback_train, fallback_test = train_test_split(
                class_indices,
                test_size=test_size,
                random_state=random_seed,
                shuffle=True,
            )
            selected_train = np.asarray(fallback_train, dtype=int)
            selected_test = np.asarray(fallback_test, dtype=int)

        train_idx.extend(selected_train.astype(int).tolist())
        test_idx.extend(selected_test.astype(int).tolist())

    train_arr = np.asarray(sorted(set(train_idx)), dtype=int)
    test_arr = np.asarray(sorted(set(test_idx)), dtype=int)
    if len(train_arr) == 0 or len(test_arr) == 0:
        encoded = LabelEncoder().fit_transform(class_values)
        train_arr, test_arr = train_test_split(
            np.arange(len(enriched)),
            test_size=test_size,
            random_state=random_seed,
            stratify=encoded,
        )
        strategy = "stratified_random_fallback"
    else:
        strategy = "per_app_group_holdout" if group_strategy_used else "per_app_row_holdout"

    train_frame = enriched.iloc[train_arr]
    test_frame = enriched.iloc[test_arr]
    summary = {
        "rows_train": int(len(train_frame)),
        "rows_test": int(len(test_frame)),
        "train_dataset_sources": sorted(train_frame["dataset_source"].astype(str).unique().tolist()),
        "test_dataset_sources": sorted(test_frame["dataset_source"].astype(str).unique().tolist()),
        "train_group_count": int(train_frame[["dataset_source", "environment_id", "session_id", "time_fold"]].drop_duplicates().shape[0]),
        "test_group_count": int(test_frame[["dataset_source", "environment_id", "session_id", "time_fold"]].drop_duplicates().shape[0]),
    }
    return train_arr, test_arr, strategy, summary


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Privacy leakage benchmark")
    progress.update(5, "Loading flow CSV")
    progress.update(15, "Building privacy views")
    views = load_privacy_views_cached(
        args.input,
        build_feature_windows_fn=build_feature_windows,
        build_privacy_views_from_windows_fn=build_window_privacy_views_from_windows,
        read_frame_fn=read_csv_resilient,
    )
    results: dict[str, dict[str, float | int]] = {}
    total_views = max(1, len(views))
    for index, (view_name, frame) in enumerate(views.items(), start=1):
        progress.update(20 + (60 * (index - 1) / total_views), f"Evaluating {view_name}")
        counts = frame["app_id"].astype(str).value_counts()
        keep = counts[counts >= args.min_class_rows].index
        filtered = frame[frame["app_id"].astype(str).isin(keep)].copy()
        if args.max_class_rows > 0:
            filtered = (
                filtered.groupby(filtered["app_id"].astype(str), group_keys=False, sort=False)
                .apply(lambda group: group.head(args.max_class_rows))
                .reset_index(drop=True)
            )
        if len(filtered) < args.min_class_rows * 2:
            continue
        y_encoder = LabelEncoder()
        y = y_encoder.fit_transform(filtered["app_id"].astype(str))
        feature_columns = [column for column in PRIVACY_FEATURE_SETS[view_name] if column in filtered.columns]
        if not feature_columns:
            raise SystemExit(f"Privacy view '{view_name}' has no usable feature columns. Delete stale privacy caches or rerun with the patched cache validation.")
        train_idx, test_idx, split_strategy, split_summary = _grouped_app_holdout_split(
            filtered,
            app_column="app_id",
            test_size=0.3,
            random_seed=args.random_seed,
        )
        train_x = filtered.iloc[train_idx][feature_columns].fillna(0.0)
        test_x = filtered.iloc[test_idx][feature_columns].fillna(0.0)
        train_y = y[train_idx]
        test_y = y[test_idx]
        clf = _build_leakage_classifier(args.random_seed)
        clf.fit(train_x, train_y)
        pred = clf.predict(test_x)
        feature_group_results: dict[str, dict[str, float | int]] = {}
        for group_name, candidate_features in PRIVACY_FEATURE_GROUPS.items():
            subset = [column for column in candidate_features if column in filtered.columns and column in feature_columns]
            if not subset:
                continue
            group_train_x = filtered.iloc[train_idx][subset].fillna(0.0)
            group_test_x = filtered.iloc[test_idx][subset].fillna(0.0)
            group_clf = _build_leakage_classifier(args.random_seed)
            group_clf.fit(group_train_x, train_y)
            group_pred = group_clf.predict(group_test_x)
            feature_group_results[group_name] = {
                "feature_count": int(len(subset)),
                "app_reidentification_accuracy": float(accuracy_score(test_y, group_pred)),
                "macro_f1": float(f1_score(test_y, group_pred, average="macro")),
            }
        results[view_name] = {
            "rows_train": int(len(train_x)),
            "rows_test": int(len(test_x)),
            "split_strategy": split_strategy,
            "split_summary": split_summary,
            "class_count": int(len(y_encoder.classes_)),
            "app_reidentification_accuracy": float(accuracy_score(test_y, pred)),
            "macro_f1": float(f1_score(test_y, pred, average="macro")),
            "feature_group_results": feature_group_results,
        }

    payload = {"benchmark": "app_reidentification_from_privacy_views", "results": results}
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
