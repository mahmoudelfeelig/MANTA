from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder

from .features import FEATURE_COLUMNS, feature_matrix
from .metrics import binary_classification_metrics, select_threshold_by_f1, threshold_sweep_metrics
from .splits import source_aware_train_test_split
from .train_android_model import (
    _ANDROID_PRIVACY_MEDIUM_RETAINED,
    _android_privacy_medium_plus_transform,
    _android_privacy_medium_transform,
    _target_threshold,
)
from .window_builders import add_window_protocol_args, adaptive_cache_name, load_android_windows_for_protocol


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare privacy feature reduction strategies with one shared split")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-json", required=True, help="Output JSON report")
    parser.add_argument("--output-csv", default="", help="Optional CSV summary")
    parser.add_argument("--output-md", default="", help="Optional Markdown summary")
    parser.add_argument("--max-rows", type=int, default=120000, help="Optional source-aware row cap before splitting; 0 means full windows")
    parser.add_argument("--max-eval-rows", type=int, default=5000, help="Rows per evaluation view; 0 means full holdout")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--target-precision", type=float, default=0.70)
    parser.add_argument("--target-recall", type=float, default=0.70)
    parser.add_argument("--target-max-fpr", type=float, default=0.20)
    parser.add_argument("--hash-buckets", type=int, default=64)
    parser.add_argument("--salt", default="manta-privacy-experiment")
    add_window_protocol_args(parser)
    return parser.parse_args()


def _source_label_cap(frame: pd.DataFrame, max_rows: int, random_seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(frame) <= max_rows:
        return frame.reset_index(drop=True)
    rng = np.random.default_rng(random_seed)
    labels = frame["label"].fillna(0).astype(int)
    selected: list[int] = []
    group_columns = ["dataset_source", "label"] if "dataset_source" in frame.columns else ["label"]
    grouped = frame.assign(_label=labels).groupby(group_columns if "dataset_source" in frame.columns else ["_label"], sort=False)
    total = max(1, len(frame))
    for index, group in grouped:
        share = len(group) / total
        take = min(len(group), max(1, int(round(max_rows * share))))
        if take >= len(group):
            selected.extend(group.index.tolist())
        else:
            selected.extend(rng.choice(group.index.to_numpy(dtype=int), size=take, replace=False).tolist())
    if len(selected) > max_rows:
        selected = rng.choice(np.asarray(selected, dtype=int), size=max_rows, replace=False).tolist()
    return frame.loc[sorted(set(selected))].reset_index(drop=True)


def _sample_natural(frame: pd.DataFrame, max_rows: int, random_seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(frame) <= max_rows:
        return frame.reset_index(drop=True)
    return frame.sample(n=max_rows, random_state=random_seed).reset_index(drop=True)


def _sample_balanced(frame: pd.DataFrame, max_rows: int, random_seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(frame) <= max_rows:
        return frame.reset_index(drop=True)
    groups = list(frame.groupby(frame["label"].fillna(0).astype(int), sort=False))
    if len(groups) < 2:
        return _sample_natural(frame, max_rows, random_seed)
    per_group = max(1, max_rows // len(groups))
    samples = [group.sample(n=min(len(group), per_group), random_state=random_seed) for _, group in groups]
    sampled = pd.concat(samples, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=random_seed)
    return sampled.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


def _hash_float(value: float, *, feature: str, salt: str, buckets: int) -> float:
    clean = 0.0 if not np.isfinite(value) else float(value)
    rounded = f"{clean:.6g}"
    digest = hashlib.sha256(f"{salt}:{feature}:{rounded}".encode("utf-8")).hexdigest()
    bucket = int(digest[:12], 16) % max(2, buckets)
    return bucket / float(max(1, buckets - 1))


def _android_privacy_medium_hashed_transform(frame: pd.DataFrame, *, salt: str, buckets: int) -> pd.DataFrame:
    transformed = _android_privacy_medium_transform(frame)
    for column in FEATURE_COLUMNS:
        if column in _ANDROID_PRIVACY_MEDIUM_RETAINED:
            continue
        if column not in frame.columns:
            transformed[column] = 0.0
            continue
        values = pd.to_numeric(frame[column], errors="coerce").fillna(0.0).astype(float)
        transformed[column] = values.map(lambda value: _hash_float(float(value), feature=column, salt=salt, buckets=buckets)).astype(float)
    return transformed


def _representation(frame: pd.DataFrame, name: str, *, salt: str, hash_buckets: int) -> pd.DataFrame:
    if name == "full_reference":
        return frame.copy()
    if name == "deleted_reduced_features":
        return _android_privacy_medium_transform(frame)
    if name == "hashed_reduced_features":
        return _android_privacy_medium_hashed_transform(frame, salt=salt, buckets=hash_buckets)
    if name == "bucketed_medium_plus":
        return _android_privacy_medium_plus_transform(frame)
    raise ValueError(f"Unknown representation: {name}")


def _fit_detector(train_frame: pd.DataFrame, labels: np.ndarray, random_seed: int) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=80,
        max_depth=12,
        min_samples_leaf=20,
        max_features="sqrt",
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=random_seed,
    )
    model.fit(feature_matrix(train_frame), labels)
    return model


def _evaluate_detector(
    model: RandomForestClassifier,
    frame: pd.DataFrame,
    labels: np.ndarray,
    *,
    threshold: float,
    view_name: str,
) -> dict[str, Any]:
    scores = model.predict_proba(feature_matrix(frame))[:, 1]
    metrics = binary_classification_metrics(labels, scores, threshold)
    best_threshold = select_threshold_by_f1(labels, scores)
    best_metrics = binary_classification_metrics(labels, scores, best_threshold)
    frontier = threshold_sweep_metrics(labels, scores)
    target = frontier[(frontier["precision"] >= 0.70) & (frontier["recall"] >= 0.70)]
    return {
        "view": view_name,
        **metrics,
        "best_f1_threshold": float(best_threshold),
        "best_f1": float(best_metrics["f1"]),
        "best_f1_precision": float(best_metrics["precision"]),
        "best_f1_recall": float(best_metrics["recall"]),
        "achieves_70_precision_70_recall": bool(not target.empty),
    }


def _leakage_task(
    train_features: pd.DataFrame,
    test_features: pd.DataFrame,
    train_meta: pd.DataFrame,
    test_meta: pd.DataFrame,
    *,
    target_column: str,
    random_seed: int,
    min_class_rows: int = 20,
    max_class_rows: int = 300,
) -> dict[str, Any] | None:
    train_target = train_meta[target_column].astype(str)
    test_target = test_meta[target_column].astype(str)
    counts = pd.concat([train_target, test_target]).value_counts()
    keep = set(counts[counts >= min_class_rows].index)
    train_mask = train_target.isin(keep)
    test_mask = test_target.isin(keep)
    if int(train_mask.sum()) < 16 or int(test_mask.sum()) < 16 or len(keep) < 2:
        return None
    train_x = train_features.loc[train_mask].copy()
    test_x = test_features.loc[test_mask].copy()
    train_y_raw = train_target.loc[train_mask].reset_index(drop=True)
    test_y_raw = test_target.loc[test_mask].reset_index(drop=True)
    if max_class_rows > 0:
        train_keep_idx = (
            pd.DataFrame({"target": train_y_raw})
            .groupby("target", sort=False, group_keys=False)
            .head(max_class_rows)
            .index
        )
        test_keep_idx = (
            pd.DataFrame({"target": test_y_raw})
            .groupby("target", sort=False, group_keys=False)
            .head(max_class_rows)
            .index
        )
        train_x = train_x.iloc[train_keep_idx]
        test_x = test_x.iloc[test_keep_idx]
        train_y_raw = train_y_raw.iloc[train_keep_idx].reset_index(drop=True)
        test_y_raw = test_y_raw.iloc[test_keep_idx].reset_index(drop=True)
        train_x = train_x.reset_index(drop=True)
        test_x = test_x.reset_index(drop=True)
    common_classes = sorted(set(train_y_raw) & set(test_y_raw))
    if len(common_classes) < 2:
        return None
    train_mask_common = train_y_raw.isin(common_classes)
    test_mask_common = test_y_raw.isin(common_classes)
    train_x = train_x.loc[train_mask_common.to_numpy()].reset_index(drop=True)
    test_x = test_x.loc[test_mask_common.to_numpy()].reset_index(drop=True)
    train_y_raw = train_y_raw.loc[train_mask_common].reset_index(drop=True)
    test_y_raw = test_y_raw.loc[test_mask_common].reset_index(drop=True)
    encoder = LabelEncoder()
    encoder.fit(common_classes)
    train_y = encoder.transform(train_y_raw)
    test_y = encoder.transform(test_y_raw)
    attacker = RandomForestClassifier(
        n_estimators=80,
        max_depth=12,
        min_samples_leaf=5,
        max_features="sqrt",
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=random_seed,
    )
    attacker.fit(feature_matrix(train_x), train_y)
    pred = attacker.predict(feature_matrix(test_x))
    accuracy = float(accuracy_score(test_y, pred))
    macro_f1 = float(f1_score(test_y, pred, average="macro", zero_division=0))
    chance = 1.0 / max(1, len(common_classes))
    normalized = max(0.0, (accuracy - chance) / max(1e-9, 1.0 - chance))
    return {
        "target": target_column,
        "rows_train": int(len(train_x)),
        "rows_test": int(len(test_x)),
        "class_count": int(len(common_classes)),
        "chance_accuracy": float(chance),
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "normalized_leakage": float(normalized),
    }


def _write_markdown(rows: list[dict[str, Any]], output: str | Path) -> None:
    columns = [
        "representation",
        "evaluation_view",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "threshold",
        "app_family_leakage_accuracy",
        "app_id_leakage_accuracy",
    ]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in rows:
        values = []
        for column in columns:
            value = row.get(column, "")
            if isinstance(value, float):
                value = f"{value:.4f}"
            values.append(str(value))
        lines.append("| " + " | ".join(values) + " |")
    Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    windows = load_android_windows_for_protocol(args.input, args, cache_prefix="android")
    if "label" not in windows.columns or windows["label"].fillna(0).astype(int).nunique() < 2:
        raise SystemExit("Privacy reduction experiment requires labeled windows with both classes.")
    windows = _source_label_cap(windows, int(args.max_rows), int(args.random_seed))
    split = source_aware_train_test_split(
        windows,
        label_column="label",
        test_size=float(args.test_ratio),
        random_seed=int(args.random_seed),
    )
    train_meta = windows.iloc[split.train_idx].reset_index(drop=True)
    test_meta = windows.iloc[split.test_idx].reset_index(drop=True)
    y_train = train_meta["label"].fillna(0).astype(int).to_numpy()
    y_test_full = test_meta["label"].fillna(0).astype(int).to_numpy()
    eval_views = {
        "natural_holdout": _sample_natural(test_meta, int(args.max_eval_rows), int(args.random_seed)),
        "balanced_holdout": _sample_balanced(test_meta, int(args.max_eval_rows), int(args.random_seed)),
    }

    representation_names = [
        "full_reference",
        "deleted_reduced_features",
        "hashed_reduced_features",
        "bucketed_medium_plus",
    ]
    rows: list[dict[str, Any]] = []
    details: dict[str, Any] = {}
    for index, name in enumerate(representation_names):
        train_features = _representation(train_meta, name, salt=args.salt, hash_buckets=int(args.hash_buckets))
        test_features_full = _representation(test_meta, name, salt=args.salt, hash_buckets=int(args.hash_buckets))
        model = _fit_detector(train_features, y_train, int(args.random_seed) + index)
        holdout_scores = model.predict_proba(feature_matrix(test_features_full))[:, 1]
        threshold = _target_threshold(
            y_test_full,
            holdout_scores,
            min_precision=float(args.target_precision),
            min_recall=float(args.target_recall),
            max_fpr=float(args.target_max_fpr),
        )
        leakage = {
            "app_family": _leakage_task(
                train_features,
                test_features_full,
                train_meta,
                test_meta,
                target_column="app_family",
                random_seed=int(args.random_seed) + 100 + index,
            ),
            "app_id": _leakage_task(
                train_features,
                test_features_full,
                train_meta,
                test_meta,
                target_column="app_id",
                random_seed=int(args.random_seed) + 200 + index,
            ),
        }
        details[name] = {
            "threshold": float(threshold),
            "leakage": leakage,
        }
        for view_name, view_meta in eval_views.items():
            view_features = _representation(view_meta, name, salt=args.salt, hash_buckets=int(args.hash_buckets))
            metrics = _evaluate_detector(
                model,
                view_features,
                view_meta["label"].fillna(0).astype(int).to_numpy(),
                threshold=float(threshold),
                view_name=view_name,
            )
            rows.append(
                {
                    "representation": name,
                    "evaluation_view": view_name,
                    **metrics,
                    "app_family_leakage_accuracy": None if leakage["app_family"] is None else leakage["app_family"]["accuracy"],
                    "app_id_leakage_accuracy": None if leakage["app_id"] is None else leakage["app_id"]["accuracy"],
                    "app_family_normalized_leakage": None if leakage["app_family"] is None else leakage["app_family"]["normalized_leakage"],
                    "app_id_normalized_leakage": None if leakage["app_id"] is None else leakage["app_id"]["normalized_leakage"],
                }
            )

    rows.sort(key=lambda row: (row["evaluation_view"], -float(row["f1"]), row["representation"]))
    payload = {
        "input": str(Path(args.input).expanduser().resolve()),
        "methodology": {
            "window_protocol": {
                "window_mode": args.window_mode,
                "window_seconds": int(args.window_seconds),
                "label_strategy": args.label_strategy,
                "max_adaptive_windows": int(args.max_adaptive_windows),
                "max_flow_rows": int(args.max_flow_rows),
                "multi_horizon_training": bool(args.multi_horizon_training),
                "cache_name": adaptive_cache_name(args, "android"),
            },
            "split_strategy": split.strategy,
            "split_summary": split.summary,
            "max_rows": int(args.max_rows),
            "max_eval_rows": int(args.max_eval_rows),
            "hash_buckets": int(args.hash_buckets),
            "target_precision": float(args.target_precision),
            "target_recall": float(args.target_recall),
            "target_max_fpr": float(args.target_max_fpr),
        },
        "representation_definitions": {
            "full_reference": "All current Android runtime features, no privacy reduction.",
            "deleted_reduced_features": "Medium reduced representation: retained coarse runtime features are bucketed; all other Android features are set to zero.",
            "hashed_reduced_features": "Same retained coarse features as deleted; features that would be deleted are replaced by deterministic salted hash buckets.",
            "bucketed_medium_plus": "Current app-facing privacy-local representation: broad Android features are coarse-bucketed, direct identity/threat-tag ratio fields are zeroed.",
        },
        "evaluation_views": {
            name: {
                "rows": int(len(frame)),
                "label_counts": {str(key): int(value) for key, value in frame["label"].fillna(0).astype(int).value_counts().to_dict().items()},
            }
            for name, frame in eval_views.items()
        },
        "details": details,
        "rows": rows,
    }
    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_csv:
        csv_path = Path(args.output_csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(csv_path, index=False)
    if args.output_md:
        md_path = Path(args.output_md)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        _write_markdown(rows, md_path)


if __name__ == "__main__":
    main()
