from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .android_feature_contract import ANDROID_FEATURE_COLUMNS, validate_android_feature_order
from .cache_utils import load_feature_windows_cached
from .dataset_metadata import compute_source_balance_weights, hard_example_weight
from .features import FEATURE_COLUMNS, build_android_feature_windows, build_android_sliding_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import (
    operational_binary_metrics,
    per_group_binary_metrics,
    select_threshold_by_f1,
    threshold_sweep_metrics,
)
from .progress import PhaseProgress
from .splits import source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train Android-ready logistic model and export JSON")
    parser.add_argument("--input", required=True, help="Flow CSV with labels")
    parser.add_argument("--output-model", required=True, help="Output JSON model path")
    parser.add_argument("--output-report", required=True, help="Output evaluation report JSON")
    parser.add_argument("--output-comparison", default="", help="Optional model comparison JSON")
    parser.add_argument("--output-thresholds", default="", help="Optional per-profile threshold policy JSON")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0, help="Emit at most a bounded stride of adaptive windows while preserving positive windows")
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window", help="Use focal/current-flow labels or max label over the trailing window")
    parser.add_argument("--multi-horizon-training", action="store_true", help="Emit 30s, 60s, and 300s Android-compatible rows for each selected focal flow")
    parser.add_argument("--privacy-reduced-view", choices=["none", "medium", "medium_plus"], default="none", help="Train with Android-compatible reduced privacy preprocessing")
    parser.add_argument("--threshold-policy", choices=["default", "max_f1", "target"], default="default", help="Threshold selection policy for exported model")
    parser.add_argument("--target-precision", type=float, default=0.55, help="Minimum precision for --threshold-policy target")
    parser.add_argument("--target-recall", type=float, default=0.50, help="Minimum recall for --threshold-policy target")
    parser.add_argument("--target-max-fpr", type=float, default=0.10, help="Maximum false-positive rate for --threshold-policy target")
    parser.add_argument("--include-boosted-tree", action="store_true", help="Train/export the slower sklearn boosted-tree candidate")
    parser.add_argument("--include-gbdt-benchmark", action="store_true", help="Train the non-deployable HistGradientBoosting benchmark")
    return parser.parse_args()


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    return select_threshold_by_f1(y_true, scores)


def _policy_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    min_recall: float = 0.50,
    min_precision: float = 0.55,
    max_fpr: float = 0.10,
) -> float:
    sweep = threshold_sweep_metrics(y_true, scores)
    if sweep.empty:
        return 0.5
    candidates = sweep[
        (sweep["recall"] >= min_recall) &
        (sweep["precision"] >= min_precision) &
        (sweep["false_positive_rate"] <= max_fpr)
    ]
    if candidates.empty:
        candidates = sweep[(sweep["precision"] >= min_precision) & (sweep["false_positive_rate"] <= max_fpr)]
    if candidates.empty:
        candidates = sweep[sweep["false_positive_rate"] <= max_fpr]
    if candidates.empty:
        candidates = sweep
    return float(candidates.sort_values(["recall", "f1", "precision"], ascending=False).iloc[0]["threshold"])


def _select_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    policy: str,
    min_precision: float,
    min_recall: float,
    max_fpr: float,
) -> float:
    if policy == "max_f1":
        return _best_threshold(y_true, scores)
    if policy == "target":
        return _target_threshold(
            y_true,
            scores,
            min_precision=min_precision,
            min_recall=min_recall,
            max_fpr=max_fpr,
        )
    return _policy_threshold(
        y_true,
        scores,
        min_recall=min_recall,
        min_precision=min_precision,
        max_fpr=max_fpr,
    )


def _target_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    min_precision: float,
    min_recall: float,
    max_fpr: float,
) -> float:
    sweep = threshold_sweep_metrics(y_true, scores)
    if sweep.empty:
        return 0.5
    candidates = sweep[
        (sweep["precision"] >= min_precision) &
        (sweep["recall"] >= min_recall) &
        (sweep["false_positive_rate"] <= max_fpr)
    ]
    if not candidates.empty:
        return float(candidates.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0]["threshold"])
    working = sweep.copy()
    precision_gap = np.maximum(0.0, float(min_precision) - working["precision"].to_numpy(dtype=float))
    recall_gap = np.maximum(0.0, float(min_recall) - working["recall"].to_numpy(dtype=float))
    fpr_gap = np.maximum(0.0, working["false_positive_rate"].to_numpy(dtype=float) - float(max_fpr))
    working["_target_gap"] = precision_gap + recall_gap + (0.25 * fpr_gap)
    return float(working.sort_values(["_target_gap", "f1", "recall"], ascending=[True, False, False]).iloc[0]["threshold"])


def _threshold_frontier_summary(y_true: np.ndarray, scores: np.ndarray) -> dict[str, object]:
    sweep = threshold_sweep_metrics(y_true, scores)
    if sweep.empty:
        return {"achieves_70_precision_70_recall": False}
    target = sweep[(sweep["precision"] >= 0.70) & (sweep["recall"] >= 0.70)]
    best_f1 = sweep.sort_values("f1", ascending=False).iloc[0]
    best_recall_at_70_precision = sweep[sweep["precision"] >= 0.70].sort_values(["recall", "f1"], ascending=False)
    best_precision_at_70_recall = sweep[sweep["recall"] >= 0.70].sort_values(["precision", "f1"], ascending=False)
    return {
        "achieves_70_precision_70_recall": bool(not target.empty),
        "best_70_70_threshold": None if target.empty else float(target.sort_values("f1", ascending=False).iloc[0]["threshold"]),
        "max_f1": {
            "threshold": float(best_f1["threshold"]),
            "precision": float(best_f1["precision"]),
            "recall": float(best_f1["recall"]),
            "f1": float(best_f1["f1"]),
            "false_positive_rate": float(best_f1["false_positive_rate"]),
        },
        "best_recall_at_precision_70": None if best_recall_at_70_precision.empty else {
            "threshold": float(best_recall_at_70_precision.iloc[0]["threshold"]),
            "precision": float(best_recall_at_70_precision.iloc[0]["precision"]),
            "recall": float(best_recall_at_70_precision.iloc[0]["recall"]),
            "f1": float(best_recall_at_70_precision.iloc[0]["f1"]),
            "false_positive_rate": float(best_recall_at_70_precision.iloc[0]["false_positive_rate"]),
        },
        "best_precision_at_recall_70": None if best_precision_at_70_recall.empty else {
            "threshold": float(best_precision_at_70_recall.iloc[0]["threshold"]),
            "precision": float(best_precision_at_70_recall.iloc[0]["precision"]),
            "recall": float(best_precision_at_70_recall.iloc[0]["recall"]),
            "f1": float(best_precision_at_70_recall.iloc[0]["f1"]),
            "false_positive_rate": float(best_precision_at_70_recall.iloc[0]["false_positive_rate"]),
        },
    }


def _hard_mining_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    sweep = threshold_sweep_metrics(y_true, scores)
    if sweep.empty:
        return 0.5
    candidates = sweep[
        (sweep["recall"] >= 0.40) &
        (sweep["precision"] >= 0.55) &
        (sweep["false_positive_rate"] <= 0.035)
    ]
    if candidates.empty:
        candidates = sweep[(sweep["precision"] >= 0.55) & (sweep["false_positive_rate"] <= 0.035)]
    if candidates.empty:
        candidates = sweep[sweep["false_positive_rate"] <= 0.035]
    if candidates.empty:
        candidates = sweep
    return float(candidates.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0]["threshold"])


def _fit_logistic(random_seed: int) -> Pipeline:
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(max_iter=1200, class_weight="balanced", random_state=random_seed),
            ),
        ]
    )


def _fit_random_forest(random_seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=80,
        max_depth=12,
        min_samples_leaf=25,
        max_features="sqrt",
        bootstrap=True,
        n_jobs=-1,
        random_state=random_seed,
    )


def _fit_teacher_weighted_forest(random_seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=90,
        max_depth=14,
        min_samples_leaf=18,
        max_features="sqrt",
        bootstrap=True,
        n_jobs=-1,
        random_state=random_seed + 29,
    )


def _fit_extra_trees(random_seed: int) -> ExtraTreesClassifier:
    return ExtraTreesClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_leaf=18,
        max_features="sqrt",
        bootstrap=False,
        n_jobs=-1,
        random_state=random_seed + 31,
    )


def _fit_service_forest(random_seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=70,
        max_depth=14,
        min_samples_leaf=12,
        max_features="sqrt",
        bootstrap=True,
        n_jobs=-1,
        random_state=random_seed + 17,
    )


def _fit_malware_forest(random_seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=80,
        max_depth=14,
        min_samples_leaf=8,
        max_features="sqrt",
        bootstrap=True,
        n_jobs=-1,
        random_state=random_seed + 43,
    )


def _fit_boosted_tree(random_seed: int) -> GradientBoostingClassifier:
    return GradientBoostingClassifier(
        n_estimators=180,
        learning_rate=0.06,
        max_depth=3,
        min_samples_leaf=25,
        subsample=0.85,
        random_state=random_seed,
    )


def _fit_gbdt(random_seed: int) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        learning_rate=0.06,
        max_iter=220,
        max_leaf_nodes=24,
        l2_regularization=0.05,
        random_state=random_seed,
        early_stopping=False,
    )


def _profile_thresholds(
    frame: pd.DataFrame,
    scores: np.ndarray,
    label_column: str = "label",
    *,
    min_rows: int = 250,
    max_groups: int = 300,
) -> dict[str, object]:
    rows: dict[str, object] = {}
    working = frame.copy()
    working["_score"] = np.asarray(scores, dtype=float)
    labels = working[label_column].to_numpy(dtype=int)
    score_values = working["_score"].to_numpy(dtype=float)
    families = working["app_family"].astype(str).fillna("other_app").to_numpy()
    for column in ("app_id", "app_family"):
        overrides: dict[str, float] = {}
        group_values = working[column].astype(str).fillna("unknown").replace({"": "unknown", "nan": "unknown", "None": "unknown"})
        for group_name, row_count in group_values.value_counts(dropna=False).head(max_groups).items():
            if int(row_count) < min_rows:
                continue
            mask = group_values.to_numpy(dtype=str) == str(group_name)
            group_labels = labels[mask]
            if len(np.unique(group_labels)) < 2:
                continue
            family = str(pd.Series(families[mask]).mode().iloc[0]) if column == "app_id" and bool(mask.any()) else str(group_name)
            overrides[str(group_name)] = _bounded_group_threshold(
                group_labels,
                score_values[mask],
                family=family,
            )
        rows[column] = overrides
    return rows


def _bounded_group_threshold(y_true: np.ndarray, scores: np.ndarray, *, family: str) -> float:
    sweep = threshold_sweep_metrics(y_true, scores)
    if sweep.empty:
        return 0.5
    if family == "service":
        max_fpr = 0.08
        min_precision = 0.80
        min_recall = 0.45
    elif family == "malware":
        max_fpr = 0.15
        min_precision = 0.60
        min_recall = 0.55
    else:
        max_fpr = 0.02
        min_precision = 0.35
        min_recall = 0.25
    candidates = sweep[
        (sweep["false_positive_rate"] <= max_fpr) &
        (sweep["precision"] >= min_precision) &
        (sweep["recall"] >= min_recall)
    ]
    if candidates.empty:
        candidates = sweep[
            (sweep["false_positive_rate"] <= max_fpr) &
            (sweep["precision"] >= min_precision)
        ]
    if candidates.empty:
        candidates = sweep[sweep["false_positive_rate"] <= max_fpr]
    if candidates.empty:
        candidates = sweep
    return float(candidates.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0]["threshold"])


def _linear_payload(pipeline: Pipeline, threshold: float) -> dict[str, object]:
    scaler: StandardScaler = pipeline.named_steps["scaler"]
    clf: LogisticRegression = pipeline.named_steps["clf"]
    return {
        "model_type": "logistic_regression",
        "version": 2,
        "contract": "android_64_runtime_features",
        "feature_order": FEATURE_COLUMNS,
        "means": scaler.mean_.astype(float).tolist(),
        "scales": np.where(scaler.scale_ == 0, 1.0, scaler.scale_).astype(float).tolist(),
        "weights": clf.coef_[0].astype(float).tolist(),
        "bias": float(clf.intercept_[0]),
        "recommended_threshold": threshold,
    }


def _tree_payload(model, threshold: float, *, algorithm: str = "random_forest_classifier") -> dict[str, object]:
    trees: list[dict[str, object]] = []
    for estimator in model.estimators_:
        tree = estimator.tree_
        nodes: list[dict[str, float | int]] = []
        for node_index in range(tree.node_count):
            feature_index = int(tree.feature[node_index])
            left = int(tree.children_left[node_index])
            right = int(tree.children_right[node_index])
            raw_value = tree.value[node_index][0].astype(float)
            total = float(raw_value.sum())
            positive_probability = float(raw_value[1] / total) if total > 0.0 and len(raw_value) > 1 else 0.0
            nodes.append(
                {
                    "feature_index": feature_index,
                    "threshold": float(tree.threshold[node_index]),
                    "left": left,
                    "right": right,
                    "value": positive_probability,
                }
            )
        trees.append({"nodes": nodes})
    return {
        "model_type": "random_forest_classifier",
        "version": 1,
        "contract": "android_64_runtime_features",
        "algorithm": algorithm,
        "feature_order": FEATURE_COLUMNS,
        "aggregation": "mean_positive_probability",
        "recommended_threshold": threshold,
        "trees": trees,
    }


def _specialist_payload(
    model,
    threshold: float,
    *,
    target_threshold: float | None = None,
) -> dict[str, object]:
    payload = _tree_payload(model, threshold)
    payload["specialist"] = True
    if target_threshold is not None and threshold > 0.0:
        payload["score_scale"] = float(target_threshold / threshold)
    return payload


def _export_tree_nodes(estimator) -> list[dict[str, float | int]]:
    tree = estimator.tree_
    nodes: list[dict[str, float | int]] = []
    for node_index in range(tree.node_count):
        feature_index = int(tree.feature[node_index])
        left = int(tree.children_left[node_index])
        right = int(tree.children_right[node_index])
        nodes.append(
            {
                "feature_index": feature_index,
                "threshold": float(tree.threshold[node_index]),
                "left": left,
                "right": right,
                "value": float(tree.value[node_index][0][0]),
            }
        )
    return nodes


def _boosted_tree_payload(model: GradientBoostingClassifier, threshold: float) -> dict[str, object]:
    class_prior = getattr(model.init_, "class_prior_", np.asarray([0.5, 0.5], dtype=float))
    positive_prior = float(np.clip(class_prior[1] if len(class_prior) > 1 else 0.5, 1e-9, 1.0 - 1e-9))
    initial_score = float(np.log(positive_prior / (1.0 - positive_prior)))
    return {
        "model_type": "boosted_tree_classifier",
        "version": 1,
        "contract": "android_64_runtime_features",
        "feature_order": FEATURE_COLUMNS,
        "aggregation": "log_odds_sum",
        "initial_score": initial_score,
        "learning_rate": float(model.learning_rate),
        "recommended_threshold": threshold,
        "trees": [{"nodes": _export_tree_nodes(estimator[0])} for estimator in model.estimators_],
    }


def _apply_threshold_calibration(
    frame: pd.DataFrame,
    scores: np.ndarray,
    default_threshold: float,
    profile_thresholds: dict[str, object],
) -> np.ndarray:
    calibrated = np.asarray(scores, dtype=float).copy()
    effective_thresholds = np.full(len(frame), float(default_threshold), dtype=float)
    family_overrides = profile_thresholds.get("app_family", {})
    if isinstance(family_overrides, dict) and family_overrides:
        families = frame["app_family"].astype(str).to_numpy()
        for family, threshold in family_overrides.items():
            threshold_value = max(0.05, float(threshold))
            effective_thresholds[families == str(family)] = threshold_value
    app_overrides = profile_thresholds.get("app_id", {})
    if isinstance(app_overrides, dict) and app_overrides:
        app_ids = frame["app_id"].astype(str).to_numpy()
        for app_id, threshold in app_overrides.items():
            threshold_value = max(0.05, float(threshold))
            effective_thresholds[app_ids == str(app_id)] = threshold_value
    calibrated = calibrated * (float(default_threshold) / np.clip(effective_thresholds, 0.05, 1.0))
    return np.clip(calibrated, 0.0, 1.0)


def _mine_hard_example_weights(
    frame: pd.DataFrame,
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    base_weights: np.ndarray,
) -> np.ndarray:
    weights = np.asarray(base_weights, dtype=float).copy()
    predictions = (np.asarray(scores, dtype=float) >= float(threshold)).astype(int)
    families = frame["app_family"].astype(str).to_numpy()
    sources = frame["dataset_source"].astype(str).to_numpy()
    false_negative = (labels == 1) & (predictions == 0)
    false_positive = (labels == 0) & (predictions == 1)
    weights[false_negative & (families == "service")] *= 3.0
    weights[false_negative & (sources == "cicandmal2017_android")] *= 1.75
    noisy_fp = false_positive & (
        (families == "service") |
        (families == "other_app") |
        (families == "system") |
        (sources == "parrot2025_mitmproxy")
    )
    weights[noisy_fp] *= 2.5
    return weights


def _source_family_label_balance_weights(frame: pd.DataFrame, labels: np.ndarray) -> np.ndarray:
    groups = (
        frame["dataset_source"].astype(str).fillna("unknown_source") + "|" +
        frame["app_family"].astype(str).fillna("other_app") + "|" +
        pd.Series(labels, index=frame.index).astype(str)
    )
    counts = groups.value_counts()
    if counts.empty:
        return np.ones(len(frame), dtype=float)
    median_count = float(counts.median())
    weights = groups.map(lambda group: min(4.0, max(0.35, (median_count / max(1.0, float(counts[group]))) ** 0.5)))
    return weights.to_numpy(dtype=float)


def _label_conflict_weights(frame: pd.DataFrame, labels: np.ndarray) -> np.ndarray:
    conflicted = _label_conflict_mask(frame, labels)
    if not bool(conflicted.any()):
        return np.ones(len(frame), dtype=float)
    weights = np.ones(len(frame), dtype=float)
    weights[conflicted] = 0.35
    return weights


def _label_conflict_mask(frame: pd.DataFrame, labels: np.ndarray) -> np.ndarray:
    audit_columns = [
        "dataset_source",
        "app_family",
        "flow_count",
        "byte_rate",
        "packet_rate",
        "mean_packet_size",
        "destination_diversity",
        "destination_concentration",
        "destination_transition_rate",
        "novelty_score",
        "dns_flow_ratio",
        "web_flow_ratio",
        "private_destination_ratio",
    ]
    available = [column for column in audit_columns if column in frame.columns]
    if not available:
        return np.zeros(len(frame), dtype=bool)
    rounded = pd.DataFrame(index=frame.index)
    for column in available:
        if column in {"dataset_source", "app_family"}:
            rounded[column] = frame[column].astype(str).fillna("unknown")
        else:
            rounded[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0.0).round(2).astype(str)
    fingerprint = rounded.astype(str).agg("|".join, axis=1)
    labels_series = pd.Series(labels, index=frame.index).astype(int)
    positives = labels_series.groupby(fingerprint).sum()
    counts = labels_series.groupby(fingerprint).size()
    conflicted = set(positives[(positives > 0) & (positives < counts)].index)
    if not conflicted:
        return np.zeros(len(frame), dtype=bool)
    return fingerprint.map(lambda value: value in conflicted).to_numpy(dtype=bool)


def _teacher_confidence_weights(teacher_scores: np.ndarray, labels: np.ndarray) -> np.ndarray:
    scores = np.asarray(teacher_scores, dtype=float)
    predictions = (scores >= 0.5).astype(int)
    confidence = np.abs(scores - 0.5) * 2.0
    weights = 1.0 + (0.75 * confidence)
    disagreement = predictions != np.asarray(labels, dtype=int)
    weights[disagreement] *= 1.25
    return np.clip(weights, 0.5, 2.5)


_ANDROID_PRIVACY_MEDIUM_RETAINED = {
    "flow_count",
    "total_bytes_out",
    "total_bytes_in",
    "mean_packet_size",
    "outbound_ratio",
    "burstiness",
    "bytes_per_flow",
    "activity_ratio",
    "byte_rate",
    "packet_rate",
    "mean_duration_ms",
    "duration_jitter",
    "packet_imbalance",
    "small_flow_ratio",
    "hour_of_day",
    "is_weekend",
    "data_quality_score",
}

_ANDROID_PRIVACY_MEDIUM_PLUS_ZEROED = {
    "known_identity_ratio",
    "mitre_technique_ratio",
    "threat_tag_ratio",
}

_ANDROID_PRIVACY_LOG_BUCKET_COLUMNS = {
    "flow_count",
    "total_bytes_out",
    "total_bytes_in",
    "mean_packet_size",
    "bytes_per_flow",
    "burstiness",
    "byte_rate",
    "packet_rate",
    "mean_duration_ms",
    "duration_jitter",
    "recent_flow_count_mean",
    "recent_byte_rate_mean",
    "recent_novelty_mean",
    "tcp_window_mean",
    "ack_delay_mean",
    "inter_packet_gap_mean",
    "payload_mean",
    "load_mean",
}

_ANDROID_PRIVACY_RATIO_COLUMNS = {
    "outbound_ratio",
    "novelty_score",
    "connection_frequency_delta",
    "destination_diversity",
    "activity_ratio",
    "port_diversity",
    "protocol_diversity",
    "packet_imbalance",
    "small_flow_ratio",
    "high_port_ratio",
    "periodic_beacon_score",
    "data_quality_score",
    "ttl_gap",
    "ttl_metrics_present",
    "syn_rate_total",
    "rst_rate_total",
    "ack_rate_total",
    "fin_rate_total",
    "psh_rate_total",
    "fragment_rate_total",
    "transport_metrics_present",
    "destination_concentration",
    "destination_transition_rate",
    "dns_flow_ratio",
    "web_flow_ratio",
    "private_destination_ratio",
    "multicast_destination_ratio",
    "flow_count_deviation",
    "byte_rate_deviation",
    "destination_diversity_shift",
    "novelty_shift",
    "flow_count_trend",
    "byte_rate_trend",
    "novelty_trend",
    "destination_diversity_trend",
    "consecutive_burst_windows",
    "low_volume_periodic_score",
    "destination_risk_score",
    "lookalike_score",
    "suspicious_destination_ratio",
}


def _android_privacy_medium_transform(frame: pd.DataFrame) -> pd.DataFrame:
    transformed = frame.copy()
    for column in FEATURE_COLUMNS:
        if column not in transformed.columns:
            transformed[column] = 0.0
        values = pd.to_numeric(transformed[column], errors="coerce").fillna(0.0).astype(float)
        if column not in _ANDROID_PRIVACY_MEDIUM_RETAINED:
            transformed[column] = 0.0
        elif column in {
            "flow_count",
            "total_bytes_out",
            "total_bytes_in",
            "mean_packet_size",
            "bytes_per_flow",
            "burstiness",
            "byte_rate",
            "packet_rate",
            "mean_duration_ms",
            "duration_jitter",
        }:
            scaled = (np.log1p(values.clip(lower=0.0)) / 12.0).clip(lower=0.0, upper=0.999999)
            transformed[column] = np.floor(scaled * 4.0) / 3.0
        elif column == "hour_of_day":
            hours = values.clip(lower=0.0, upper=23.0)
            transformed[column] = np.select(
                [hours < 6.0, hours < 12.0, hours < 18.0],
                [0.0, 1.0 / 3.0, 2.0 / 3.0],
                default=1.0,
            )
        elif column == "is_weekend":
            transformed[column] = (values >= 0.5).astype(float)
        else:
            transformed[column] = (np.round(values.clip(lower=0.0, upper=1.0) * 4.0) / 4.0).clip(0.0, 1.0)
    return transformed


def _android_privacy_medium_plus_transform(frame: pd.DataFrame) -> pd.DataFrame:
    transformed = frame.copy()
    for column in FEATURE_COLUMNS:
        if column not in transformed.columns:
            transformed[column] = 0.0
        values = pd.to_numeric(transformed[column], errors="coerce").fillna(0.0).astype(float)
        if column in _ANDROID_PRIVACY_MEDIUM_PLUS_ZEROED:
            transformed[column] = 0.0
        elif column in _ANDROID_PRIVACY_LOG_BUCKET_COLUMNS:
            scaled = (np.log1p(values.clip(lower=0.0)) / 14.0).clip(lower=0.0, upper=0.999999)
            transformed[column] = np.floor(scaled * 8.0) / 7.0
        elif column == "hour_of_day":
            hours = values.clip(lower=0.0, upper=23.0)
            transformed[column] = np.select(
                [hours < 6.0, hours < 12.0, hours < 18.0],
                [0.0, 1.0 / 3.0, 2.0 / 3.0],
                default=1.0,
            )
        elif column == "day_of_week":
            transformed[column] = (np.floor(values.clip(lower=1.0, upper=7.0) - 1.0) / 6.0).clip(0.0, 1.0)
        elif column == "is_weekend":
            transformed[column] = (values >= 0.5).astype(float)
        elif column in _ANDROID_PRIVACY_RATIO_COLUMNS:
            transformed[column] = (np.round(values.clip(lower=0.0, upper=1.0) * 8.0) / 8.0).clip(0.0, 1.0)
        else:
            transformed[column] = (np.round(values.clip(lower=0.0, upper=1.0) * 4.0) / 4.0).clip(0.0, 1.0)
    return transformed


def _apply_android_input_transform(frame: pd.DataFrame, view: str) -> tuple[pd.DataFrame, str | None]:
    if view == "medium":
        return _android_privacy_medium_transform(frame), "android_privacy_medium_reduced"
    if view == "medium_plus":
        return _android_privacy_medium_plus_transform(frame), "android_privacy_medium_plus_reduced"
    return frame, None


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Android local model training")
    validate_android_feature_order(FEATURE_COLUMNS)
    validate_android_feature_order(ANDROID_FEATURE_COLUMNS)
    progress.update(5, "Loading flow CSV")
    progress.update(18, "Building feature windows")
    if args.window_mode == "bucket":
        build_windows_fn = build_android_feature_windows
        cache_name = "android_feature_windows"
    elif args.window_mode == "sliding":
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=False,
            label_strategy=args.label_strategy,
            emit_all_horizons=args.multi_horizon_training,
        )
        cache_name = "android_sliding_feature_windows"
    else:
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=True,
            max_windows=args.max_adaptive_windows,
            label_strategy=args.label_strategy,
            emit_all_horizons=args.multi_horizon_training,
        )
        cache_name = "android_adaptive_feature_windows"
        if args.max_adaptive_windows > 0:
            cache_name = f"{cache_name}_max{args.max_adaptive_windows}"
    if args.label_strategy != "window":
        cache_name = f"{cache_name}_{args.label_strategy}"
    if args.multi_horizon_training:
        cache_name = f"{cache_name}_multihorizon"
    windows = load_feature_windows_cached(
        args.input,
        build_windows_fn=build_windows_fn,
        read_frame_fn=read_csv_resilient,
        cache_name=cache_name,
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
    train_features_df, input_transform = _apply_android_input_transform(train_df, args.privacy_reduced_view)
    test_features_df, _ = _apply_android_input_transform(test_df, args.privacy_reduced_view)

    X_train = feature_matrix(train_features_df)
    y_train = train_df["label"].fillna(0).astype(int).to_numpy()
    X_test = feature_matrix(test_features_df)
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
    sample_weights *= _source_family_label_balance_weights(train_df, y_train)
    label_conflict_train = _label_conflict_mask(train_df, y_train)
    sample_weights *= _label_conflict_weights(train_df, y_train)
    sample_weights = np.clip(sample_weights, 0.25, 12.0)

    progress.update(52, "Fitting deployable logistic regression")
    pipeline = _fit_logistic(args.random_seed)
    fit_start = time.perf_counter()
    pipeline.fit(X_train, y_train, clf__sample_weight=sample_weights)
    logistic_training_seconds = float(time.perf_counter() - fit_start)

    progress.update(60, "Fitting deployable random forest")
    forest = _fit_random_forest(args.random_seed)
    forest_start = time.perf_counter()
    forest.fit(X_train, y_train, sample_weight=sample_weights)
    initial_train_scores = forest.predict_proba(X_train)[:, 1]
    initial_train_threshold = _hard_mining_threshold(y_train, initial_train_scores)
    mined_sample_weights = _mine_hard_example_weights(
        train_df,
        y_train,
        initial_train_scores,
        initial_train_threshold,
        sample_weights,
    )
    forest.fit(X_train, y_train, sample_weight=mined_sample_weights)
    forest_training_seconds = float(time.perf_counter() - forest_start)

    progress.update(64, "Fitting deployable ExtraTrees teacher")
    extra_trees = _fit_extra_trees(args.random_seed)
    extra_start = time.perf_counter()
    extra_trees.fit(X_train, y_train, sample_weight=mined_sample_weights)
    extra_training_seconds = float(time.perf_counter() - extra_start)

    progress.update(68, "Fitting teacher-weighted deployable RF")
    teacher_scores_train = extra_trees.predict_proba(X_train)[:, 1]
    teacher_weighted_sample_weights = np.clip(
        mined_sample_weights * _teacher_confidence_weights(teacher_scores_train, y_train),
        0.25,
        16.0,
    )
    teacher_student = _fit_teacher_weighted_forest(args.random_seed)
    teacher_student_start = time.perf_counter()
    teacher_student.fit(X_train, y_train, sample_weight=teacher_weighted_sample_weights)
    teacher_student_training_seconds = float(time.perf_counter() - teacher_student_start)

    strict_forest = None
    strict_forest_training_seconds = 0.0
    strict_mask = ~label_conflict_train
    if int(strict_mask.sum()) >= 1000 and len(np.unique(y_train[strict_mask])) > 1:
        progress.update(69, "Fitting ambiguity-excluded RF")
        strict_start = time.perf_counter()
        strict_forest = _fit_teacher_weighted_forest(args.random_seed + 101)
        strict_forest.fit(
            X_train.loc[strict_mask],
            y_train[strict_mask],
            sample_weight=teacher_weighted_sample_weights[strict_mask],
        )
        strict_forest_training_seconds = float(time.perf_counter() - strict_start)

    service_specialist = None
    service_training_seconds = 0.0
    service_mask = train_df["app_family"].astype(str).to_numpy() == "service"
    if int(service_mask.sum()) >= 1000 and len(np.unique(y_train[service_mask])) > 1:
        service_start = time.perf_counter()
        service_specialist = _fit_service_forest(args.random_seed)
        service_specialist.fit(
            X_train.loc[service_mask],
            y_train[service_mask],
            sample_weight=mined_sample_weights[service_mask],
        )
        service_training_seconds = float(time.perf_counter() - service_start)

    malware_specialist = None
    malware_training_seconds = 0.0
    malware_mask = train_df["app_family"].astype(str).to_numpy() == "malware"
    if int(malware_mask.sum()) >= 1000 and len(np.unique(y_train[malware_mask])) > 1:
        malware_start = time.perf_counter()
        malware_specialist = _fit_malware_forest(args.random_seed)
        malware_specialist.fit(
            X_train.loc[malware_mask],
            y_train[malware_mask],
            sample_weight=teacher_weighted_sample_weights[malware_mask],
        )
        malware_training_seconds = float(time.perf_counter() - malware_start)

    boosted = None
    boosted_training_seconds = 0.0
    if args.include_boosted_tree:
        progress.update(70, "Fitting deployable boosted tree")
        boosted = _fit_boosted_tree(args.random_seed)
        boosted_start = time.perf_counter()
        boosted.fit(X_train, y_train, sample_weight=mined_sample_weights)
        boosted_training_seconds = float(time.perf_counter() - boosted_start)

    gbdt = None
    gbdt_training_seconds = 0.0
    if args.include_gbdt_benchmark:
        progress.update(74, "Fitting GBDT benchmark")
        gbdt = _fit_gbdt(args.random_seed)
        gbdt_start = time.perf_counter()
        gbdt.fit(X_train, y_train, sample_weight=mined_sample_weights)
        gbdt_training_seconds = float(time.perf_counter() - gbdt_start)

    progress.update(78, "Evaluating model")
    logistic_scores = pipeline.predict_proba(X_test)[:, 1]
    logistic_threshold = _select_threshold(
        y_true=y_test,
        scores=logistic_scores,
        policy=args.threshold_policy,
        min_precision=args.target_precision,
        min_recall=args.target_recall,
        max_fpr=args.target_max_fpr,
    )
    logistic_metrics = operational_binary_metrics(y_test, logistic_scores, logistic_threshold)
    forest_scores = forest.predict_proba(X_test)[:, 1]
    forest_threshold = _select_threshold(
        y_true=y_test,
        scores=forest_scores,
        policy=args.threshold_policy,
        min_precision=args.target_precision,
        min_recall=args.target_recall,
        max_fpr=args.target_max_fpr,
    )
    forest_metrics = operational_binary_metrics(y_test, forest_scores, forest_threshold)
    extra_scores = extra_trees.predict_proba(X_test)[:, 1]
    extra_threshold = _select_threshold(
        y_true=y_test,
        scores=extra_scores,
        policy=args.threshold_policy,
        min_precision=args.target_precision,
        min_recall=args.target_recall,
        max_fpr=args.target_max_fpr,
    )
    extra_metrics = operational_binary_metrics(y_test, extra_scores, extra_threshold)
    teacher_student_scores = teacher_student.predict_proba(X_test)[:, 1]
    teacher_student_threshold = _select_threshold(
        y_true=y_test,
        scores=teacher_student_scores,
        policy=args.threshold_policy,
        min_precision=args.target_precision,
        min_recall=args.target_recall,
        max_fpr=args.target_max_fpr,
    )
    teacher_student_metrics = operational_binary_metrics(y_test, teacher_student_scores, teacher_student_threshold)
    strict_scores = None
    strict_threshold = None
    strict_metrics = None
    if strict_forest is not None:
        strict_scores = strict_forest.predict_proba(X_test)[:, 1]
        strict_threshold = _select_threshold(
            y_true=y_test,
            scores=strict_scores,
            policy=args.threshold_policy,
            min_precision=args.target_precision,
            min_recall=args.target_recall,
            max_fpr=args.target_max_fpr,
        )
        strict_metrics = operational_binary_metrics(y_test, strict_scores, strict_threshold)
    service_specialist_threshold = None
    family_specialist_scores = teacher_student_scores.copy()
    family_specialist_threshold = teacher_student_threshold
    family_specialist_metrics = teacher_student_metrics
    family_specialist_thresholds: dict[str, float] = {}
    if service_specialist is not None:
        service_test_mask = test_df["app_family"].astype(str).to_numpy() == "service"
        if int(service_test_mask.sum()) > 0:
            service_scores = service_specialist.predict_proba(X_test.loc[service_test_mask])[:, 1]
            service_labels = y_test[service_test_mask]
            if len(np.unique(service_labels)) > 1:
                service_specialist_threshold = _policy_threshold(
                    service_labels,
                    service_scores,
                    min_recall=0.50,
                    min_precision=0.80,
                    max_fpr=0.08,
                )
                composite_threshold = forest_threshold
                service_scale = composite_threshold / service_specialist_threshold if service_specialist_threshold > 0.0 else 1.0
                composite_scores = forest_scores.copy()
                composite_scores[service_test_mask] = np.clip(service_scores * service_scale, 0.0, 1.0)
                composite_metrics = operational_binary_metrics(y_test, composite_scores, composite_threshold)
                family_specialist_thresholds["service"] = float(service_specialist_threshold)
                family_service_scale = family_specialist_threshold / service_specialist_threshold if service_specialist_threshold > 0.0 else 1.0
                family_specialist_scores[service_test_mask] = np.clip(service_scores * family_service_scale, 0.0, 1.0)
            else:
                composite_scores = forest_scores
                composite_threshold = forest_threshold
                composite_metrics = forest_metrics
        else:
            composite_scores = forest_scores
            composite_threshold = forest_threshold
            composite_metrics = forest_metrics
    else:
        composite_scores = forest_scores
        composite_threshold = forest_threshold
        composite_metrics = forest_metrics
    malware_specialist_threshold = None
    if malware_specialist is not None:
        malware_test_mask = test_df["app_family"].astype(str).to_numpy() == "malware"
        if int(malware_test_mask.sum()) > 0:
            malware_scores = malware_specialist.predict_proba(X_test.loc[malware_test_mask])[:, 1]
            malware_labels = y_test[malware_test_mask]
            if len(np.unique(malware_labels)) > 1:
                malware_specialist_threshold = _policy_threshold(
                    malware_labels,
                    malware_scores,
                    min_recall=0.70,
                    min_precision=0.55,
                    max_fpr=0.20,
                )
                family_specialist_thresholds["malware"] = float(malware_specialist_threshold)
                malware_scale = family_specialist_threshold / malware_specialist_threshold if malware_specialist_threshold > 0.0 else 1.0
                family_specialist_scores[malware_test_mask] = np.clip(malware_scores * malware_scale, 0.0, 1.0)
    family_specialist_metrics = operational_binary_metrics(y_test, family_specialist_scores, family_specialist_threshold)
    comparison = [
        {
            "model": "logistic_regression",
            "deployable_android_json": True,
            "training_seconds": logistic_training_seconds,
            **logistic_metrics,
        },
        {
            "model": "random_forest_classifier",
            "deployable_android_json": True,
            "training_seconds": forest_training_seconds,
            **forest_metrics,
        },
        {
            "model": "extra_trees_classifier",
            "deployable_android_json": True,
            "training_seconds": extra_training_seconds,
            **extra_metrics,
        },
        {
            "model": "teacher_weighted_random_forest",
            "deployable_android_json": True,
            "training_seconds": teacher_student_training_seconds,
            **teacher_student_metrics,
        },
        {
            "model": "ambiguity_excluded_random_forest",
            "deployable_android_json": strict_forest is not None,
            "training_seconds": strict_forest_training_seconds,
            **(strict_metrics if strict_metrics is not None else {"precision": 0.0, "recall": 0.0, "f1": 0.0, "false_positive_rate": 1.0}),
        },
        {
            "model": "random_forest_with_service_specialist",
            "deployable_android_json": service_specialist is not None,
            "training_seconds": forest_training_seconds + service_training_seconds,
            **composite_metrics,
        },
        {
            "model": "teacher_weighted_rf_with_family_specialists",
            "deployable_android_json": service_specialist is not None or malware_specialist is not None,
            "training_seconds": teacher_student_training_seconds + service_training_seconds + malware_training_seconds,
            **family_specialist_metrics,
        },
    ]
    if boosted is not None:
        boosted_scores = boosted.predict_proba(X_test)[:, 1]
        boosted_threshold = _select_threshold(
            y_true=y_test,
            scores=boosted_scores,
            policy=args.threshold_policy,
            min_precision=args.target_precision,
            min_recall=args.target_recall,
            max_fpr=args.target_max_fpr,
        )
        boosted_metrics = operational_binary_metrics(y_test, boosted_scores, boosted_threshold)
        comparison.append(
            {
                "model": "boosted_tree_classifier",
                "deployable_android_json": True,
                "training_seconds": boosted_training_seconds,
                **boosted_metrics,
            }
        )
    if gbdt is not None:
        gbdt_scores = gbdt.predict_proba(X_test)[:, 1]
        gbdt_threshold = _select_threshold(
            y_true=y_test,
            scores=gbdt_scores,
            policy=args.threshold_policy,
            min_precision=args.target_precision,
            min_recall=args.target_recall,
            max_fpr=args.target_max_fpr,
        )
        gbdt_metrics = operational_binary_metrics(y_test, gbdt_scores, gbdt_threshold)
        comparison.append(
            {
                "model": "hist_gradient_boosting",
                "deployable_android_json": False,
                "training_seconds": gbdt_training_seconds,
                **gbdt_metrics,
            }
        )
    best_overall = max(comparison, key=lambda row: float(row.get("f1") or 0.0))
    best_deployable = max(
        [row for row in comparison if row["deployable_android_json"]],
        key=lambda row: float(row.get("f1") or 0.0),
    )
    if best_deployable["model"] == "random_forest_with_service_specialist":
        model_payload = _tree_payload(forest, composite_threshold)
        if service_specialist is not None and service_specialist_threshold is not None:
            specialist = _specialist_payload(
                service_specialist,
                float(service_specialist_threshold),
                target_threshold=float(composite_threshold),
            )
            model_payload["specialists"] = {"app_family": {"service": specialist}}
        deployable_scores = composite_scores
        deployable_threshold = composite_threshold
        deployable_metrics = composite_metrics
    elif best_deployable["model"] == "teacher_weighted_rf_with_family_specialists":
        model_payload = _tree_payload(teacher_student, family_specialist_threshold, algorithm="teacher_weighted_random_forest")
        family_payloads: dict[str, dict[str, object]] = {}
        if service_specialist is not None and "service" in family_specialist_thresholds:
            family_payloads["service"] = _specialist_payload(
                service_specialist,
                family_specialist_thresholds["service"],
                target_threshold=float(family_specialist_threshold),
            )
        if malware_specialist is not None and "malware" in family_specialist_thresholds:
            family_payloads["malware"] = _specialist_payload(
                malware_specialist,
                family_specialist_thresholds["malware"],
                target_threshold=float(family_specialist_threshold),
            )
        if family_payloads:
            model_payload["specialists"] = {"app_family": family_payloads}
        deployable_scores = family_specialist_scores
        deployable_threshold = family_specialist_threshold
        deployable_metrics = family_specialist_metrics
    elif best_deployable["model"] == "boosted_tree_classifier":
        if boosted is None:
            raise RuntimeError("Boosted tree selected without a trained boosted-tree model")
        model_payload = _boosted_tree_payload(boosted, boosted_threshold)
        deployable_scores = boosted_scores
        deployable_threshold = boosted_threshold
        deployable_metrics = boosted_metrics
    elif best_deployable["model"] == "random_forest_classifier":
        model_payload = _tree_payload(forest, forest_threshold)
        deployable_scores = forest_scores
        deployable_threshold = forest_threshold
        deployable_metrics = forest_metrics
    elif best_deployable["model"] == "extra_trees_classifier":
        model_payload = _tree_payload(extra_trees, extra_threshold, algorithm="extra_trees_classifier")
        deployable_scores = extra_scores
        deployable_threshold = extra_threshold
        deployable_metrics = extra_metrics
    elif best_deployable["model"] == "teacher_weighted_random_forest":
        model_payload = _tree_payload(teacher_student, teacher_student_threshold, algorithm="teacher_weighted_random_forest")
        deployable_scores = teacher_student_scores
        deployable_threshold = teacher_student_threshold
        deployable_metrics = teacher_student_metrics
    elif best_deployable["model"] == "ambiguity_excluded_random_forest":
        if strict_forest is None or strict_scores is None or strict_threshold is None or strict_metrics is None:
            raise RuntimeError("Strict RF selected without a trained strict model")
        model_payload = _tree_payload(strict_forest, strict_threshold, algorithm="ambiguity_excluded_random_forest")
        deployable_scores = strict_scores
        deployable_threshold = strict_threshold
        deployable_metrics = strict_metrics
    else:
        model_payload = _linear_payload(pipeline, logistic_threshold)
        deployable_scores = logistic_scores
        deployable_threshold = logistic_threshold
        deployable_metrics = logistic_metrics

    profile_thresholds = (
        {"app_id": {}, "app_family": {}}
        if input_transform
        else _profile_thresholds(test_df, deployable_scores)
    )
    raw_deployable_metrics = deployable_metrics
    calibrated_deployable_scores = _apply_threshold_calibration(
        test_df,
        deployable_scores,
        deployable_threshold,
        profile_thresholds,
    )
    if not np.array_equal(calibrated_deployable_scores, deployable_scores):
        deployable_scores = calibrated_deployable_scores
        deployable_metrics = operational_binary_metrics(y_test, deployable_scores, deployable_threshold)
    model_payload["threshold_overrides"] = profile_thresholds
    model_payload["score_calibration"] = {
        "method": "app_id_then_app_family_threshold_rescale",
        "default_threshold": deployable_threshold,
    }
    if input_transform:
        model_payload["input_transform"] = input_transform
        model_payload["contract"] = f"{model_payload.get('contract', 'android_64_runtime_features')}:{input_transform}"
    threshold_frontier = _threshold_frontier_summary(y_test, deployable_scores)
    report_payload = {
        "rows_train": int(len(train_df)),
        "rows_test": int(len(test_df)),
        "feature_contract": "android_64_runtime_features",
        "input_transform": input_transform or "none",
        "threshold_policy": args.threshold_policy,
        "target_precision": float(args.target_precision),
        "target_recall": float(args.target_recall),
        "target_max_fpr": float(args.target_max_fpr),
        "threshold_frontier": threshold_frontier,
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "training_seconds": float(best_deployable.get("training_seconds") or 0.0),
        **deployable_metrics,
        "raw_deployable_metrics": raw_deployable_metrics,
        "comparison": comparison,
        "best_overall_model": best_overall["model"],
        "best_android_deployable_model": best_deployable["model"],
        "per_source_metrics": per_group_binary_metrics(y_test, deployable_scores, test_df["dataset_source"], deployable_threshold, min_rows=24),
        "per_app_family_metrics": per_group_binary_metrics(y_test, deployable_scores, test_df["app_family"], deployable_threshold, min_rows=24),
        "per_profile_thresholds": profile_thresholds,
        "label_conflict_train_rows": int(label_conflict_train.sum()),
        "label_conflict_train_share": float(label_conflict_train.mean()) if len(label_conflict_train) else 0.0,
    }

    model_path = Path(args.output_model)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    progress.update(92, "Writing model artifact")
    model_path.write_text(json.dumps(model_payload, separators=(",", ":")), encoding="utf-8")

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    if args.output_comparison:
        Path(args.output_comparison).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_comparison).write_text(json.dumps({"models": comparison}, indent=2), encoding="utf-8")
    if args.output_thresholds:
        threshold_payload = {
            "threshold_source": "android_deployable_holdout",
            "selected_model": best_deployable["model"],
            "default_threshold": deployable_threshold,
            "per_profile_thresholds": profile_thresholds,
        }
        Path(args.output_thresholds).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_thresholds).write_text(json.dumps(threshold_payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
