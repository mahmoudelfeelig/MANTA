from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedShuffleSplit, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .splits import add_split_metadata


ATTACK_MODEL_CHOICES: tuple[str, ...] = (
    "logistic_regression",
    "hist_gradient_boosting",
    "mlp",
)


@dataclass
class HoldoutSplit:
    train_idx: np.ndarray
    test_idx: np.ndarray
    strategy: str
    summary: dict[str, object]


def parse_attack_model_names(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ATTACK_MODEL_CHOICES
    selected: list[str] = []
    for item in raw.split(","):
        normalized = item.strip().lower()
        if not normalized:
            continue
        if normalized not in ATTACK_MODEL_CHOICES:
            raise ValueError(f"Unknown attack model '{normalized}'. Expected one of: {', '.join(ATTACK_MODEL_CHOICES)}")
        if normalized not in selected:
            selected.append(normalized)
    return tuple(selected or ATTACK_MODEL_CHOICES)


def chance_accuracy(class_count: int) -> float:
    return float(1.0 / max(1, int(class_count)))


def normalized_leakage(accuracy: float | int | None, class_count: int) -> float | None:
    if not isinstance(accuracy, (int, float)) or class_count <= 1:
        return None
    baseline = chance_accuracy(class_count)
    denominator = max(1e-9, 1.0 - baseline)
    return float(max(0.0, (float(accuracy) - baseline) / denominator))


def top_k_accuracy(y_true: np.ndarray, probs: np.ndarray | None, k: int) -> float | None:
    if probs is None or probs.size == 0:
        return None
    if probs.ndim != 2:
        return None
    labels = np.asarray(y_true, dtype=int)
    effective_k = max(1, min(int(k), probs.shape[1]))
    top_indices = np.argpartition(probs, -effective_k, axis=1)[:, -effective_k:]
    hits = [int(label in row) for label, row in zip(labels, top_indices, strict=False)]
    return float(np.mean(hits)) if hits else None


def quantile_bucket(series: pd.Series, buckets: int) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0).astype(float)
    bucket_count = max(2, int(buckets))
    if values.nunique(dropna=False) <= 1:
        return pd.Series(np.zeros(len(values), dtype=int), index=series.index)
    ranks = values.rank(method="average", pct=True).fillna(0.0).to_numpy(dtype=float)
    bucket_ids = np.floor(np.clip(ranks, 0.0, 0.999999) * bucket_count).astype(int)
    return pd.Series(np.clip(bucket_ids, 0, bucket_count - 1), index=series.index, dtype=int)


def build_context_bucket(frame: pd.DataFrame) -> pd.Series:
    enriched = add_split_metadata(frame)
    return enriched["environment_id"].astype(str) + "|" + enriched["time_fold"].astype(str)


def build_destination_behavior_bucket(frame: pd.DataFrame, buckets: int = 3) -> pd.Series:
    working = add_split_metadata(frame)
    novelty = quantile_bucket(working.get("novelty_score", pd.Series(np.zeros(len(working)), index=working.index)), buckets)
    diversity = quantile_bucket(working.get("destination_diversity", pd.Series(np.zeros(len(working)), index=working.index)), buckets)
    high_port = quantile_bucket(working.get("high_port_ratio", pd.Series(np.zeros(len(working)), index=working.index)), buckets)
    beacon = quantile_bucket(working.get("periodic_beacon_score", pd.Series(np.zeros(len(working)), index=working.index)), buckets)
    return (
        "nov" + novelty.astype(str) +
        "|div" + diversity.astype(str) +
        "|port" + high_port.astype(str) +
        "|beacon" + beacon.astype(str)
    )


def build_attack_model(name: str, random_seed: int):
    if name == "logistic_regression":
        return Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=600,
                        random_state=random_seed,
                        class_weight="balanced",
                    ),
                ),
            ]
        )
    if name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(
            max_iter=220,
            learning_rate=0.08,
            max_leaf_nodes=31,
            min_samples_leaf=24,
            l2_regularization=1e-4,
            random_state=random_seed,
        )
    if name == "mlp":
        return Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "clf",
                    MLPClassifier(
                        hidden_layer_sizes=(96, 48),
                        activation="relu",
                        alpha=1e-4,
                        batch_size=256,
                        learning_rate_init=1e-3,
                        max_iter=220,
                        early_stopping=True,
                        n_iter_no_change=12,
                        random_state=random_seed,
                    ),
                ),
            ]
        )
    raise ValueError(f"Unknown attack model: {name}")


def _strategy_label(label_name: str, grouped: bool) -> str:
    safe = label_name.strip().lower().replace(" ", "_")
    if safe in {"app_id", "app"}:
        safe = "app"
    return f"per_{safe}_{'group' if grouped else 'row'}_holdout"


def _build_group_key(frame: pd.DataFrame, columns: tuple[str, ...]) -> pd.Series:
    enriched = add_split_metadata(frame)
    normalized_parts = [
        enriched[column].astype(str).replace({"": f"unknown_{column}", "nan": f"unknown_{column}", "None": f"unknown_{column}"})
        for column in columns
    ]
    if not normalized_parts:
        return pd.Series([f"row_{index:06d}" for index in range(len(enriched))], index=enriched.index, dtype="object")
    key = normalized_parts[0]
    for part in normalized_parts[1:]:
        key = key + "|" + part
    return key


def grouped_label_holdout_split(
    frame: pd.DataFrame,
    *,
    target: pd.Series,
    label_name: str,
    group_columns: tuple[str, ...],
    test_size: float = 0.3,
    random_seed: int = 42,
) -> HoldoutSplit:
    working = add_split_metadata(frame).reset_index(drop=True)
    target_values = target.astype(str).reset_index(drop=True)
    if len(working) != len(target_values):
        raise ValueError("Frame and target length mismatch for grouped holdout split.")

    group_keys = _build_group_key(working, group_columns)
    rng = np.random.default_rng(random_seed)
    train_idx: list[int] = []
    test_idx: list[int] = []
    grouped_used = False

    for class_value in sorted(target_values.unique().tolist()):
        class_indices = np.flatnonzero((target_values == class_value).to_numpy())
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
            class_group_values = class_groups.to_numpy(dtype=object)
            for group_name in shuffled_groups:
                group_rows = class_indices[class_group_values == group_name]
                remaining_rows = len(class_indices) - (chosen_count + len(group_rows))
                if remaining_rows < 1:
                    continue
                chosen_groups.add(str(group_name))
                chosen_count += len(group_rows)
                if chosen_count >= target_rows and len(chosen_groups) < len(unique_groups):
                    break
            if chosen_groups and len(chosen_groups) < len(unique_groups):
                selected_test = class_indices[class_groups.isin(chosen_groups).to_numpy()]
                grouped_used = True

        if selected_test is None or len(selected_test) == 0 or len(selected_test) >= len(class_indices):
            test_count = min(max(1, int(round(len(class_indices) * test_size))), len(class_indices) - 1)
            permutation = rng.permutation(class_indices)
            selected_test = np.asarray(permutation[:test_count], dtype=int)

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

        train_idx.extend(selected_train.tolist())
        test_idx.extend(selected_test.tolist())

    train_arr = np.asarray(sorted(set(train_idx)), dtype=int)
    test_arr = np.asarray(sorted(set(test_idx)), dtype=int)
    if len(train_arr) == 0 or len(test_arr) == 0:
        encoded = LabelEncoder().fit_transform(target_values)
        try:
            splitter = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_seed)
            train_arr, test_arr = next(splitter.split(np.arange(len(working)), encoded))
            strategy = "stratified_random_fallback"
        except ValueError:
            train_arr, test_arr = train_test_split(
                np.arange(len(working)),
                test_size=test_size,
                random_state=random_seed,
                shuffle=True,
            )
            strategy = "random_fallback"
    else:
        strategy = _strategy_label(label_name, grouped_used)

    train_frame = working.iloc[train_arr]
    test_frame = working.iloc[test_arr]
    summary = {
        "rows_train": int(len(train_frame)),
        "rows_test": int(len(test_frame)),
        "train_dataset_sources": sorted(train_frame["dataset_source"].astype(str).unique().tolist()),
        "test_dataset_sources": sorted(test_frame["dataset_source"].astype(str).unique().tolist()),
        "train_group_count": int(_build_group_key(train_frame, group_columns).nunique(dropna=False)),
        "test_group_count": int(_build_group_key(test_frame, group_columns).nunique(dropna=False)),
        "train_unique_targets": int(target_values.iloc[train_arr].nunique(dropna=False)),
        "test_unique_targets": int(target_values.iloc[test_arr].nunique(dropna=False)),
        "group_columns": list(group_columns),
    }
    return HoldoutSplit(train_idx=np.asarray(train_arr, dtype=int), test_idx=np.asarray(test_arr, dtype=int), strategy=strategy, summary=summary)


def evaluate_multiclass_models(
    train_x: pd.DataFrame,
    test_x: pd.DataFrame,
    train_y: np.ndarray,
    test_y: np.ndarray,
    *,
    model_names: tuple[str, ...],
    random_seed: int,
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    results: dict[str, dict[str, object]] = {}
    class_count = int(len(np.unique(train_y)))
    for index, model_name in enumerate(model_names):
        try:
            model = build_attack_model(model_name, random_seed + (index * 11))
            model.fit(train_x, train_y)
            pred = model.predict(test_x)
            probs = model.predict_proba(test_x) if hasattr(model, "predict_proba") else None
            accuracy = float(accuracy_score(test_y, pred))
            result = {
                "status": "ok",
                "accuracy": accuracy,
                "macro_f1": float(f1_score(test_y, pred, average="macro", zero_division=0)),
                "balanced_accuracy": float(balanced_accuracy_score(test_y, pred)),
                "top_5_accuracy": top_k_accuracy(test_y, probs, 5),
                "random_baseline_accuracy": chance_accuracy(class_count),
                "normalized_leakage": normalized_leakage(accuracy, class_count),
            }
        except Exception as exc:
            result = {
                "status": "error",
                "error": str(exc),
            }
        results[model_name] = result

    completed = [
        {"model_name": model_name, **metrics}
        for model_name, metrics in results.items()
        if metrics.get("status") == "ok"
    ]
    if not completed:
        return results, None
    strongest = max(
        completed,
        key=lambda row: (
            float(row.get("normalized_leakage") or 0.0),
            float(row.get("macro_f1") or 0.0),
            float(row.get("accuracy") or 0.0),
        ),
    )
    return results, strongest


def evaluate_feature_group_attacks(
    frame: pd.DataFrame,
    *,
    feature_groups: dict[str, tuple[str, ...] | list[str]],
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    labels: np.ndarray,
    random_seed: int,
) -> dict[str, dict[str, object]]:
    results: dict[str, dict[str, object]] = {}
    for group_name, candidate_features in feature_groups.items():
        subset = [column for column in candidate_features if column in frame.columns]
        if not subset:
            continue
        model = build_attack_model("logistic_regression", random_seed)
        train_x = frame.iloc[train_idx][subset].fillna(0.0)
        test_x = frame.iloc[test_idx][subset].fillna(0.0)
        train_y = labels[train_idx]
        test_y = labels[test_idx]
        model.fit(train_x, train_y)
        pred = model.predict(test_x)
        accuracy = float(accuracy_score(test_y, pred))
        class_count = int(len(np.unique(train_y)))
        results[group_name] = {
            "feature_count": int(len(subset)),
            "app_reidentification_accuracy": accuracy,
            "macro_f1": float(f1_score(test_y, pred, average="macro", zero_division=0)),
            "normalized_leakage": normalized_leakage(accuracy, class_count),
        }
    return results


def evaluate_open_world_unknown_detection(
    frame: pd.DataFrame,
    *,
    feature_columns: list[str],
    target_column: str,
    group_columns: tuple[str, ...],
    model_names: tuple[str, ...],
    random_seed: int,
    unknown_ratio: float = 0.25,
    known_recall_floor: float = 0.90,
) -> dict[str, object] | None:
    working = add_split_metadata(frame).reset_index(drop=True)
    if target_column not in working.columns:
        return None
    target_values = working[target_column].astype(str)
    classes = sorted(target_values.unique().tolist())
    if len(classes) < 4:
        return None

    rng = np.random.default_rng(random_seed)
    unknown_count = min(max(1, int(round(len(classes) * unknown_ratio))), len(classes) - 2)
    unknown_classes = set(rng.choice(classes, size=unknown_count, replace=False).tolist())
    known_frame = working[~target_values.isin(unknown_classes)].reset_index(drop=True)
    unknown_frame = working[target_values.isin(unknown_classes)].reset_index(drop=True)
    if known_frame[target_column].astype(str).nunique() < 2 or len(unknown_frame) == 0:
        return None

    outer_split = grouped_label_holdout_split(
        known_frame,
        target=known_frame[target_column].astype(str),
        label_name=f"known_{target_column}",
        group_columns=group_columns,
        test_size=0.25,
        random_seed=random_seed,
    )
    train_known = known_frame.iloc[outer_split.train_idx].reset_index(drop=True)
    test_known = known_frame.iloc[outer_split.test_idx].reset_index(drop=True)
    if train_known[target_column].astype(str).nunique() < 2 or len(test_known) == 0:
        return None
    eligible_counts = train_known[target_column].astype(str).value_counts()
    eligible_classes = set(eligible_counts[eligible_counts >= 2].index.tolist())
    train_known = train_known[train_known[target_column].astype(str).isin(eligible_classes)].reset_index(drop=True)
    test_known = test_known[test_known[target_column].astype(str).isin(eligible_classes)].reset_index(drop=True)
    if train_known[target_column].astype(str).nunique() < 2 or len(test_known) == 0:
        return None

    calibration_split = grouped_label_holdout_split(
        train_known,
        target=train_known[target_column].astype(str),
        label_name=f"calibration_{target_column}",
        group_columns=group_columns,
        test_size=0.2,
        random_seed=random_seed + 17,
    )
    model_train = train_known.iloc[calibration_split.train_idx].reset_index(drop=True)
    calibration_known = train_known.iloc[calibration_split.test_idx].reset_index(drop=True)
    if len(model_train) == 0 or len(calibration_known) == 0:
        return None

    label_encoder = LabelEncoder()
    train_y = label_encoder.fit_transform(model_train[target_column].astype(str))
    known_test_labels = label_encoder.transform(test_known[target_column].astype(str))
    models: dict[str, dict[str, object]] = {}
    for index, model_name in enumerate(model_names):
        try:
            model = build_attack_model(model_name, random_seed + (index * 13))
            model.fit(model_train[feature_columns].fillna(0.0), train_y)
            calibration_probs = model.predict_proba(calibration_known[feature_columns].fillna(0.0))
            known_probs = model.predict_proba(test_known[feature_columns].fillna(0.0))
            unknown_probs = model.predict_proba(unknown_frame[feature_columns].fillna(0.0))
            calibration_max = np.max(calibration_probs, axis=1)
            threshold = float(np.quantile(calibration_max, max(0.0, 1.0 - float(known_recall_floor))))
            known_scores = 1.0 - np.max(known_probs, axis=1)
            unknown_scores = 1.0 - np.max(unknown_probs, axis=1)
            y_binary = np.asarray([0] * len(known_scores) + [1] * len(unknown_scores), dtype=int)
            scores = np.concatenate([known_scores, unknown_scores], dtype=float)
            pred_unknown = (scores >= (1.0 - threshold)).astype(int)
            models[model_name] = {
                "status": "ok",
                "threshold_max_known_probability": threshold,
                "unknown_precision": float(precision_score(y_binary, pred_unknown, zero_division=0)),
                "unknown_recall": float(recall_score(y_binary, pred_unknown, zero_division=0)),
                "unknown_f1": float(f1_score(y_binary, pred_unknown, zero_division=0)),
                "known_classification_accuracy": float(accuracy_score(known_test_labels, np.argmax(known_probs, axis=1))),
                "unknown_auroc": float(roc_auc_score(y_binary, scores)) if len(np.unique(y_binary)) > 1 else None,
            }
        except Exception as exc:
            models[model_name] = {"status": "error", "error": str(exc)}

    completed = [
        {"model_name": model_name, **metrics}
        for model_name, metrics in models.items()
        if metrics.get("status") == "ok"
    ]
    strongest = max(
        completed,
        key=lambda row: (
            float(row.get("unknown_auroc") or 0.0),
            float(row.get("unknown_f1") or 0.0),
            float(row.get("unknown_recall") or 0.0),
        ),
        default=None,
    )
    return {
        "known_classes": int(known_frame[target_column].astype(str).nunique()),
        "unknown_classes": int(len(unknown_classes)),
        "rows_known_train": int(len(model_train)),
        "rows_known_test": int(len(test_known)),
        "rows_unknown_test": int(len(unknown_frame)),
        "split_strategy": outer_split.strategy,
        "split_summary": outer_split.summary,
        "models": models,
        "strongest_model": strongest,
    }
