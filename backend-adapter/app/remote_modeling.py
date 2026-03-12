from __future__ import annotations

import math
import time
from typing import Any, Mapping


REMOTE_MODEL_FEATURES = [
    "flow_count_log",
    "bytes_out_log",
    "bytes_in_log",
    "mean_packet_size_log",
    "outbound_ratio",
    "burstiness",
    "novelty_score",
    "connection_frequency_delta",
    "bytes_per_flow_log",
    "destination_diversity",
    "activity_ratio",
    "periodic_beacon_score",
    "byte_rate_log",
    "packet_rate_log",
    "mean_duration_ms_log",
    "duration_jitter_log",
    "port_diversity",
    "protocol_diversity",
    "packet_imbalance",
    "small_flow_ratio",
    "high_port_ratio",
    "hour_of_day_sin",
    "hour_of_day_cos",
    "is_weekend",
    "data_quality_penalty",
    "ttl_gap_norm",
    "ttl_metrics_present",
    "syn_rate_total",
    "rst_rate_total",
    "ack_rate_total",
    "fin_rate_total",
    "psh_rate_total",
    "fragment_rate_total",
    "tcp_window_mean_log",
    "ack_delay_mean_log",
    "inter_packet_gap_mean_log",
    "payload_mean_log",
    "load_mean_log",
    "transport_metrics_present",
    "phishing_domain_pattern",
    "credential_lure_pattern",
    "tracking_destination",
]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _site_risk_flags(site_hint: str | None) -> dict[str, float]:
    host = (site_hint or "").strip().lower()
    if not host:
        return {
            "phishing_domain_pattern": 0.0,
            "credential_lure_pattern": 0.0,
            "tracking_destination": 0.0,
        }

    suspicious_tld = host.endswith((".zip", ".mov", ".top", ".xyz", ".click"))
    punycode = "xn--" in host
    lure = any(part in host for part in ("login-", "verify-", "secure-", "update-", "account-", "auth-"))
    tls_test_host = host.endswith(".badssl.com") or host == "badssl.com"
    tracking = any(
        part in host
        for part in ("doubleclick", "googlesyndication", "googleadservices", "tracking", "telemetry", "analytics")
    )
    return {
        "phishing_domain_pattern": 1.0 if suspicious_tld or punycode or tls_test_host else 0.0,
        "credential_lure_pattern": 1.0 if lure or tls_test_host else 0.0,
        "tracking_destination": 1.0 if tracking else 0.0,
    }


def build_remote_feature_map(feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, float]:
    hour_of_day = int(_safe_float(feature_window.get("hour_of_day"), 0.0)) % 24
    data_quality_score = _safe_float(feature_window.get("data_quality_score"), 1.0)
    risk_flags = _site_risk_flags(site_hint)
    return {
        "flow_count_log": math.log1p(max(0.0, _safe_float(feature_window.get("flow_count")))),
        "bytes_out_log": math.log1p(max(0.0, _safe_float(feature_window.get("bytes_out")))),
        "bytes_in_log": math.log1p(max(0.0, _safe_float(feature_window.get("bytes_in")))),
        "mean_packet_size_log": math.log1p(max(0.0, _safe_float(feature_window.get("mean_packet_size")))),
        "outbound_ratio": _safe_float(feature_window.get("outbound_ratio")),
        "burstiness": _safe_float(feature_window.get("burstiness")),
        "novelty_score": _safe_float(feature_window.get("novelty_score")),
        "connection_frequency_delta": _safe_float(feature_window.get("connection_frequency_delta")),
        "bytes_per_flow_log": math.log1p(max(0.0, _safe_float(feature_window.get("bytes_per_flow")))),
        "destination_diversity": _safe_float(feature_window.get("destination_diversity")),
        "activity_ratio": _safe_float(feature_window.get("activity_ratio")),
        "periodic_beacon_score": _safe_float(feature_window.get("periodic_beacon_score")),
        "byte_rate_log": math.log1p(max(0.0, _safe_float(feature_window.get("byte_rate")))),
        "packet_rate_log": math.log1p(max(0.0, _safe_float(feature_window.get("packet_rate")))),
        "mean_duration_ms_log": math.log1p(max(0.0, _safe_float(feature_window.get("mean_duration_ms")))),
        "duration_jitter_log": math.log1p(max(0.0, _safe_float(feature_window.get("duration_jitter")))),
        "port_diversity": _safe_float(feature_window.get("port_diversity")),
        "protocol_diversity": _safe_float(feature_window.get("protocol_diversity")),
        "packet_imbalance": _safe_float(feature_window.get("packet_imbalance")),
        "small_flow_ratio": _safe_float(feature_window.get("small_flow_ratio")),
        "high_port_ratio": _safe_float(feature_window.get("high_port_ratio")),
        "hour_of_day_sin": math.sin((2.0 * math.pi * hour_of_day) / 24.0),
        "hour_of_day_cos": math.cos((2.0 * math.pi * hour_of_day) / 24.0),
        "is_weekend": 1.0 if bool(feature_window.get("is_weekend")) else 0.0,
        "data_quality_penalty": (1.0 - data_quality_score),
        "ttl_gap_norm": _safe_float(feature_window.get("ttl_gap")),
        "ttl_metrics_present": _safe_float(feature_window.get("ttl_metrics_present")),
        "syn_rate_total": _safe_float(feature_window.get("syn_rate_total")),
        "rst_rate_total": _safe_float(feature_window.get("rst_rate_total")),
        "ack_rate_total": _safe_float(feature_window.get("ack_rate_total")),
        "fin_rate_total": _safe_float(feature_window.get("fin_rate_total")),
        "psh_rate_total": _safe_float(feature_window.get("psh_rate_total")),
        "fragment_rate_total": _safe_float(feature_window.get("fragment_rate_total")),
        "tcp_window_mean_log": math.log1p(max(0.0, _safe_float(feature_window.get("tcp_window_mean")))),
        "ack_delay_mean_log": math.log1p(max(0.0, _safe_float(feature_window.get("ack_delay_mean")))),
        "inter_packet_gap_mean_log": math.log1p(max(0.0, _safe_float(feature_window.get("inter_packet_gap_mean")))),
        "payload_mean_log": math.log1p(max(0.0, _safe_float(feature_window.get("payload_mean")))),
        "load_mean_log": math.log1p(max(0.0, _safe_float(feature_window.get("load_mean")))),
        "transport_metrics_present": _safe_float(feature_window.get("transport_metrics_present")),
        **risk_flags,
    }


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def _sample_group_key(sample: Mapping[str, Any], strategy: str) -> str:
    dataset_source = str(sample.get("dataset_source") or "unknown_source")
    environment_id = str(sample.get("environment_id") or "unknown_environment")
    session_id = str(sample.get("session_id") or sample.get("dataset_variant") or "unknown_session")
    app_family = str(sample.get("app_family") or "other_app")
    time_bucket = str(int(sample.get("window_bucket") or 0) // 240)
    if strategy == "source_env_session":
        return "|".join((dataset_source, environment_id, session_id))
    if strategy == "source_env_family_time":
        return "|".join((dataset_source, environment_id, app_family, time_bucket))
    if strategy == "source_family":
        return "|".join((dataset_source, app_family))
    return "|".join((app_family, time_bucket))


def _source_aware_sample_split(
    samples: list[dict[str, Any]],
    labels: "np.ndarray",
    *,
    test_size: float,
    random_seed: int,
) -> tuple["np.ndarray", "np.ndarray", str]:
    from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
    import numpy as np

    if len(samples) != len(labels):
        raise ValueError("Sample/label length mismatch.")
    strategies = ("source_env_session", "source_env_family_time", "source_family", "family_time")
    for strategy in strategies:
        groups = np.asarray([_sample_group_key(sample, strategy) for sample in samples], dtype=object)
        unique_groups = len(set(groups.tolist()))
        if unique_groups < 2:
            continue
        splitter = GroupShuffleSplit(n_splits=max(1, min(10, unique_groups)), test_size=test_size, random_state=random_seed)
        try:
            iterator = splitter.split(np.arange(len(labels)), labels, groups=groups)
        except ValueError:
            continue
        for train_idx, test_idx in iterator:
            if len(set(labels[train_idx].tolist())) >= 2 and len(set(labels[test_idx].tolist())) >= 2:
                return np.asarray(train_idx, dtype=int), np.asarray(test_idx, dtype=int), strategy

    try:
        fallback = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_seed)
        train_idx, test_idx = next(fallback.split(np.arange(len(labels)), labels))
        return np.asarray(train_idx, dtype=int), np.asarray(test_idx, dtype=int), "stratified_random_fallback"
    except ValueError:
        permutation = np.random.default_rng(random_seed).permutation(len(labels))
        split_point = max(1, min(len(labels) - 1, int(round(len(labels) * (1.0 - test_size)))))
        return np.asarray(permutation[:split_point], dtype=int), np.asarray(permutation[split_point:], dtype=int), "random_fallback"


def _expected_calibration_error(y_true: "np.ndarray", scores: "np.ndarray", bins: int = 10) -> float:
    import numpy as np

    if len(y_true) == 0:
        return 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = float(len(y_true))
    error = 0.0
    for lower, upper in zip(edges[:-1], edges[1:], strict=False):
        if upper >= 1.0:
            mask = (scores >= lower) & (scores <= upper)
        else:
            mask = (scores >= lower) & (scores < upper)
        if not np.any(mask):
            continue
        accuracy = float(np.mean(y_true[mask]))
        confidence = float(np.mean(scores[mask]))
        error += (float(mask.sum()) / total) * abs(accuracy - confidence)
    return float(error)


def _binary_metrics(y_true: "np.ndarray", scores: "np.ndarray", threshold: float) -> dict[str, float | None]:
    from sklearn.metrics import average_precision_score, brier_score_loss, f1_score, precision_score, recall_score, roc_auc_score
    import numpy as np

    pred = (scores >= threshold).astype(int)
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, scores)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if len(set(y_true.tolist())) > 1 else None,
        "brier_score": float(brier_score_loss(y_true, np.clip(scores, 0.0, 1.0))),
        "ece": float(_expected_calibration_error(y_true, np.clip(scores, 0.0, 1.0))),
    }


def _per_source_metrics(samples: list[dict[str, Any]], y_true: "np.ndarray", scores: "np.ndarray", threshold: float) -> dict[str, dict[str, float | int | None]]:
    import numpy as np

    payload: dict[str, dict[str, float | int | None]] = {}
    sources = np.asarray([str(sample.get("dataset_source") or "unknown_source") for sample in samples], dtype=object)
    for source in sorted(set(sources.tolist())):
        mask = sources == source
        if int(mask.sum()) < 24 or len(set(y_true[mask].tolist())) < 2:
            continue
        payload[str(source)] = {
            "rows": int(mask.sum()),
            **_binary_metrics(y_true[mask], scores[mask], threshold),
        }
    return payload


def _stacking_fold_indices(labels: "np.ndarray", n_splits: int, random_seed: int) -> list[tuple["np.ndarray", "np.ndarray"]]:
    from sklearn.model_selection import StratifiedKFold
    import numpy as np

    class_counts = np.bincount(labels)
    min_count = int(class_counts.min()) if class_counts.size else 0
    actual_splits = max(2, min(n_splits, min_count))
    if actual_splits < 2:
        return []
    splitter = StratifiedKFold(n_splits=actual_splits, shuffle=True, random_state=random_seed)
    return [(np.asarray(train_idx, dtype=int), np.asarray(val_idx, dtype=int)) for train_idx, val_idx in splitter.split(np.arange(len(labels)), labels)]


def _best_threshold_for_scores(y_true: "np.ndarray", scores: "np.ndarray") -> float:
    import numpy as np

    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.05, 0.95, 181):
        metrics = _binary_metrics(y_true, scores, float(threshold))
        current = float(metrics["f1"] or 0.0)
        if current > best_f1:
            best_f1 = current
            best_threshold = float(threshold)
    return best_threshold


def _hard_example_weights(samples: list[dict[str, Any]], labels: list[int] | "np.ndarray") -> list[float]:
    source_counts: dict[str, int] = {}
    for sample in samples:
        dataset_source = str(sample.get("dataset_source") or "unknown_source")
        source_counts[dataset_source] = source_counts.get(dataset_source, 0) + 1
    median_count = float(sorted(source_counts.values())[len(source_counts) // 2]) if source_counts else 1.0
    weights: list[float] = []
    for sample, label in zip(samples, labels, strict=False):
        dataset_source = str(sample.get("dataset_source") or "unknown_source")
        app_family = str(sample.get("app_family") or "other_app")
        weight = 1.0
        if int(label) == 0:
            if dataset_source in {"sdncampus_flow_statistics", "itc_net_blend60_scenario_e"}:
                weight += 0.85
            if app_family in {"browser", "telemetry", "system", "background"}:
                weight += 0.45
        elif app_family == "malware":
            weight += 0.15
        source_ratio = median_count / max(1.0, float(source_counts.get(dataset_source, 1)))
        weight *= float(min(3.0, max(0.65, source_ratio ** 0.5)))
        weights.append(float(weight))
    return weights


def default_remote_model(model_type: str = "logistic_regression") -> dict[str, Any]:
    if model_type == "hybrid_dual_channel":
        return {
            "model_type": "hybrid_dual_channel",
            "model_family": "hybrid_dual_channel",
            "meta_feature_order": ["anomaly_score", "context_score", "tree_score", "score_gap", "risk_flag_sum"],
            "meta_weights": [1.8, 1.2, 1.4, 0.6, 0.5],
            "meta_bias": -1.1,
            "meta_threshold": 0.62,
            "anomaly_model": default_remote_model("mahalanobis_covariance"),
            "context_model": default_remote_model("logistic_regression"),
            "tree_model": default_remote_model("gradient_boosted_tree"),
            "recommended_threshold": 0.62,
            "trained_from_samples": 0,
            "class_counts": {"0": 0, "1": 0},
            "metrics": {},
            "updated_epoch": int(time.time()),
        }
    if model_type == "gradient_boosted_tree":
        return {
            "model_type": "gradient_boosted_tree",
            "model_family": "gradient_boosted_tree",
            "feature_order": list(REMOTE_MODEL_FEATURES),
            "trees": [],
            "learning_rate": 0.05,
            "init_bias": -1.0,
            "calibration_slope": 1.0,
            "calibration_bias": 0.0,
            "recommended_threshold": 0.62,
            "trained_from_samples": 0,
            "class_counts": {"0": 0, "1": 0},
            "metrics": {},
            "updated_epoch": int(time.time()),
        }
    if model_type == "mahalanobis_covariance":
        return {
            "model_type": "mahalanobis_covariance",
            "model_family": "mahalanobis_covariance",
            "feature_order": list(REMOTE_MODEL_FEATURES),
            "mean": [0.0] * len(REMOTE_MODEL_FEATURES),
            "precision_matrix": [[1.0 if i == j else 0.0 for j in range(len(REMOTE_MODEL_FEATURES))] for i in range(len(REMOTE_MODEL_FEATURES))],
            "threshold_distance": float(len(REMOTE_MODEL_FEATURES)),
            "recommended_threshold": 0.62,
            "trained_from_samples": 0,
            "class_counts": {"0": 0, "1": 0},
            "metrics": {},
            "updated_epoch": int(time.time()),
        }
    weights = {
        "flow_count_log": 0.18,
        "bytes_out_log": 0.12,
        "bytes_in_log": 0.12,
        "mean_packet_size_log": 0.10,
        "outbound_ratio": 0.08,
        "burstiness": 0.10,
        "novelty_score": 0.85,
        "connection_frequency_delta": 0.12,
        "bytes_per_flow_log": 0.12,
        "destination_diversity": 0.38,
        "activity_ratio": 0.12,
        "periodic_beacon_score": 0.72,
        "byte_rate_log": 0.10,
        "packet_rate_log": 0.10,
        "mean_duration_ms_log": 0.08,
        "duration_jitter_log": 0.08,
        "port_diversity": 0.22,
        "protocol_diversity": 0.12,
        "packet_imbalance": 0.16,
        "small_flow_ratio": 0.14,
        "high_port_ratio": 0.08,
        "hour_of_day_sin": 0.02,
        "hour_of_day_cos": 0.02,
        "is_weekend": 0.03,
        "data_quality_penalty": -0.42,
        "ttl_gap_norm": 0.18,
        "ttl_metrics_present": 0.04,
        "syn_rate_total": 0.18,
        "rst_rate_total": 0.18,
        "ack_rate_total": 0.10,
        "fin_rate_total": 0.10,
        "psh_rate_total": 0.10,
        "fragment_rate_total": 0.10,
        "tcp_window_mean_log": 0.06,
        "ack_delay_mean_log": 0.10,
        "inter_packet_gap_mean_log": 0.10,
        "payload_mean_log": 0.10,
        "load_mean_log": 0.08,
        "transport_metrics_present": 0.08,
        "phishing_domain_pattern": 0.60,
        "credential_lure_pattern": 0.55,
        "tracking_destination": 0.16,
    }
    return {
        "model_type": "bootstrap_logistic_seed",
        "model_family": "logistic_regression",
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "means": [0.0] * len(REMOTE_MODEL_FEATURES),
        "scales": [1.0] * len(REMOTE_MODEL_FEATURES),
        "weights": [weights[name] for name in REMOTE_MODEL_FEATURES],
        "bias": -1.35,
        "recommended_threshold": 0.62,
        "trained_from_samples": 0,
        "class_counts": {"0": 0, "1": 0},
        "metrics": {},
        "updated_epoch": int(time.time()),
    }


def _extract_training_matrix(samples: list[dict[str, Any]]) -> tuple["np.ndarray", "np.ndarray"]:
    import numpy as np

    rows, labels, _ = _extract_training_rows(samples)
    if not rows:
        raise ValueError("No trainable samples contain window_features; upgrade the phone app and collect new triaged alerts.")
    return np.asarray(rows, dtype=float), np.asarray(labels, dtype=int)


def _extract_training_rows(samples: list[dict[str, Any]]) -> tuple[list[list[float]], list[int], list[dict[str, Any]]]:
    rows: list[list[float]] = []
    labels: list[int] = []
    filtered_samples: list[dict[str, Any]] = []
    for sample in samples:
        window = sample.get("window_features")
        if not isinstance(window, dict):
            continue
        label = int(sample.get("label", -1))
        if label not in {0, 1}:
            continue
        feature_map = build_remote_feature_map(feature_window=window, site_hint=sample.get("site_hint"))
        rows.append([float(feature_map.get(name, 0.0)) for name in REMOTE_MODEL_FEATURES])
        labels.append(label)
        filtered_samples.append(sample)
    return rows, labels, filtered_samples


def _score_logistic_values(model: Mapping[str, Any], values_by_name: Mapping[str, float]) -> dict[str, Any]:
    feature_order = [str(item) for item in (model.get("feature_order") or REMOTE_MODEL_FEATURES)]
    means = [float(item) for item in (model.get("means") or [0.0] * len(feature_order))]
    scales = [float(item) if float(item) != 0.0 else 1.0 for item in (model.get("scales") or [1.0] * len(feature_order))]
    weights = [float(item) for item in (model.get("weights") or [0.0] * len(feature_order))]
    bias = float(model.get("bias", 0.0))
    threshold = float(model.get("recommended_threshold", 0.5))

    linear = bias
    contributions: dict[str, float] = {}
    normalized_values: dict[str, float] = {}
    for index, name in enumerate(feature_order):
        raw_value = float(values_by_name.get(name, 0.0))
        mean = means[index] if index < len(means) else 0.0
        scale = scales[index] if index < len(scales) else 1.0
        weight = weights[index] if index < len(weights) else 0.0
        normalized = (raw_value - mean) / (scale or 1.0)
        weighted = normalized * weight
        normalized_values[name] = normalized
        contributions[name] = abs(weighted)
        linear += weighted

    score = 1.0 / (1.0 + math.exp(-linear))
    threshold_distance = min(1.0, abs(score - threshold))
    confidence = max(0.35, min(0.98, 0.45 + (threshold_distance * 0.55)))
    top_features = [
        item[0]
        for item in sorted(contributions.items(), key=lambda item: item[1], reverse=True)
        if item[1] > 0
    ][:4]

    return {
        "score": max(0.0, min(1.0, score)),
        "anomaly_score": max(0.0, min(1.0, score)),
        "context_score": 0.0,
        "response_score": max(0.0, min(1.0, score)),
        "top_features": top_features,
        "feature_contributions": contributions,
        "confidence": confidence,
        "uncertainty": 1.0 - confidence,
        "diagnostics": {
            "threshold_distance": threshold_distance,
            "backend_model_version": float(model.get("version", 1)),
            "model_type": str(model.get("model_type", "unknown")),
            "normalized_features": normalized_values,
        },
    }


def _score_logistic_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    feature_map = build_remote_feature_map(feature_window=feature_window, site_hint=site_hint)
    return _score_logistic_values(model=model, values_by_name=feature_map)


def _walk_tree(nodes: Mapping[str, Any], values: list[float]) -> float:
    feature = [int(item) for item in nodes.get("feature", [])]
    threshold = [float(item) for item in nodes.get("threshold", [])]
    left = [int(item) for item in nodes.get("left", [])]
    right = [int(item) for item in nodes.get("right", [])]
    node_values = [float(item) for item in nodes.get("value", [])]
    node = 0
    while node < len(feature) and feature[node] >= 0:
        compare_value = values[feature[node]] if feature[node] < len(values) else 0.0
        node = left[node] if compare_value <= threshold[node] else right[node]
        if node < 0:
            break
    if 0 <= node < len(node_values):
        return node_values[node]
    return 0.0


def _score_tree_values(model: Mapping[str, Any], values_by_name: Mapping[str, float]) -> dict[str, Any]:
    feature_order = [str(item) for item in (model.get("feature_order") or REMOTE_MODEL_FEATURES)]
    ordered_values = [float(values_by_name.get(name, 0.0)) for name in feature_order]
    raw_logit = float(model.get("init_bias", -1.0))
    learning_rate = float(model.get("learning_rate", 0.05))
    tree_contributions: dict[str, float] = {name: 0.0 for name in feature_order}
    for tree in model.get("trees", []):
        leaf_value = _walk_tree(tree, ordered_values)
        raw_logit += learning_rate * float(leaf_value)
        split_features = [int(index) for index in tree.get("feature", []) if int(index) >= 0]
        if split_features:
            share = abs(float(leaf_value)) / float(len(split_features))
            for feature_index in split_features:
                if feature_index < len(feature_order):
                    tree_contributions[feature_order[feature_index]] += share
    calibrated_logit = (float(model.get("calibration_slope", 1.0)) * raw_logit) + float(model.get("calibration_bias", 0.0))
    score = _sigmoid(calibrated_logit)
    threshold = float(model.get("recommended_threshold", 0.5))
    threshold_distance = min(1.0, abs(score - threshold))
    confidence = max(0.35, min(0.98, 0.45 + (threshold_distance * 0.55)))
    contributions = {key: value for key, value in tree_contributions.items() if value > 0.0}
    top_features = [name for name, _ in sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:4]]
    return {
        "score": max(0.0, min(1.0, score)),
        "anomaly_score": max(0.0, min(1.0, score)),
        "context_score": 0.0,
        "response_score": max(0.0, min(1.0, score)),
        "top_features": top_features,
        "feature_contributions": contributions,
        "confidence": confidence,
        "uncertainty": 1.0 - confidence,
        "diagnostics": {
            "threshold_distance": threshold_distance,
            "backend_model_version": float(model.get("version", 1)),
            "model_type": str(model.get("model_type", "gradient_boosted_tree")),
            "raw_logit": raw_logit,
            "calibrated_logit": calibrated_logit,
        },
    }


def _score_tree_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    feature_map = build_remote_feature_map(feature_window=feature_window, site_hint=site_hint)
    return _score_tree_values(model=model, values_by_name=feature_map)


def _score_mahalanobis_values(model: Mapping[str, Any], values_by_name: Mapping[str, float]) -> dict[str, Any]:
    import numpy as np

    feature_order = [str(item) for item in (model.get("feature_order") or REMOTE_MODEL_FEATURES)]
    mean = np.asarray(model.get("mean") or [0.0] * len(feature_order), dtype=float)
    precision_matrix = np.asarray(
        model.get("precision_matrix") or [[1.0 if i == j else 0.0 for j in range(len(feature_order))] for i in range(len(feature_order))],
        dtype=float,
    )
    values = np.asarray([float(values_by_name.get(name, 0.0)) for name in feature_order], dtype=float)
    centered = values - mean
    distance = float(centered.T @ precision_matrix @ centered)
    threshold_distance = float(model.get("threshold_distance", len(feature_order)))
    scale = max(threshold_distance, float(len(feature_order)), 1.0)
    score = 1.0 - math.exp(-(distance / scale))
    recommended_threshold = float(model.get("recommended_threshold", 0.62))
    confidence = max(0.35, min(0.98, 0.45 + (min(1.0, abs(score - recommended_threshold)) * 0.55)))
    contributions = {
        name: float(abs(centered[index]) * math.sqrt(max(precision_matrix[index][index], 1e-9)))
        for index, name in enumerate(feature_order)
    }
    top_features = [name for name, _ in sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:4]]
    return {
        "score": max(0.0, min(1.0, score)),
        "anomaly_score": max(0.0, min(1.0, score)),
        "context_score": 0.0,
        "response_score": max(0.0, min(1.0, score)),
        "top_features": top_features,
        "feature_contributions": contributions,
        "confidence": confidence,
        "uncertainty": 1.0 - confidence,
        "diagnostics": {
            "threshold_distance": min(1.0, abs(score - recommended_threshold)),
            "mahalanobis_distance": distance,
            "model_type": str(model.get("model_type", "unknown")),
        },
    }


def _score_mahalanobis_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    feature_map = build_remote_feature_map(feature_window=feature_window, site_hint=site_hint)
    return _score_mahalanobis_values(model=model, values_by_name=feature_map)


def _stack_score_payloads(
    anomaly_result: Mapping[str, Any],
    context_result: Mapping[str, Any],
    tree_result: Mapping[str, Any],
    model: Mapping[str, Any],
) -> dict[str, Any]:
    anomaly_score = float(anomaly_result.get("score", 0.0))
    context_score = float(context_result.get("score", 0.0))
    tree_score = float(tree_result.get("score", 0.0))
    risk_flag_sum = float(
        tree_result.get("feature_contributions", {}).get("phishing_domain_pattern", 0.0)
        + tree_result.get("feature_contributions", {}).get("credential_lure_pattern", 0.0)
        + tree_result.get("feature_contributions", {}).get("tracking_destination", 0.0)
    )
    score_gap = max(anomaly_score, context_score, tree_score) - min(anomaly_score, context_score, tree_score)
    meta_values = {
        "anomaly_score": anomaly_score,
        "context_score": context_score,
        "tree_score": tree_score,
        "score_gap": score_gap,
        "risk_flag_sum": risk_flag_sum,
    }
    linear = float(model.get("meta_bias", -1.0))
    for name, weight in zip(model.get("meta_feature_order", []), model.get("meta_weights", []), strict=False):
        linear += float(weight) * float(meta_values.get(str(name), 0.0))
    combined_score = _sigmoid(linear)
    contributions: dict[str, float] = {}
    for feature, value in (anomaly_result.get("feature_contributions") or {}).items():
        contributions[str(feature)] = contributions.get(str(feature), 0.0) + (0.34 * float(value))
    for feature, value in (context_result.get("feature_contributions") or {}).items():
        contributions[str(feature)] = contributions.get(str(feature), 0.0) + (0.33 * float(value))
    for feature, value in (tree_result.get("feature_contributions") or {}).items():
        contributions[str(feature)] = contributions.get(str(feature), 0.0) + (0.33 * float(value))
    top_features = [name for name, _ in sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:4]]
    confidence = (
        (0.34 * float(anomaly_result.get("confidence", 0.5))) +
        (0.33 * float(context_result.get("confidence", 0.5))) +
        (0.33 * float(tree_result.get("confidence", 0.5)))
    )
    return {
        "score": combined_score,
        "anomaly_score": anomaly_score,
        "context_score": context_score,
        "response_score": combined_score,
        "top_features": top_features,
        "feature_contributions": contributions,
        "confidence": confidence,
        "uncertainty": max(0.0, min(1.0, 1.0 - confidence)),
        "diagnostics": {
            "model_type": "hybrid_dual_channel",
            "anomaly_component_score": anomaly_score,
            "context_component_score": context_score,
            "tree_component_score": tree_score,
            "meta_linear": linear,
            "meta_feature_values": meta_values,
        },
    }


def _score_hybrid_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    anomaly_model = model.get("anomaly_model") or default_remote_model("mahalanobis_covariance")
    context_model = model.get("context_model") or default_remote_model("logistic_regression")
    tree_model = model.get("tree_model") or default_remote_model("gradient_boosted_tree")
    anomaly_result = _score_mahalanobis_model(anomaly_model, feature_window=feature_window, site_hint=site_hint)
    context_result = _score_logistic_model(context_model, feature_window=feature_window, site_hint=site_hint)
    tree_result = _score_tree_model(tree_model, feature_window=feature_window, site_hint=site_hint)
    merged = _stack_score_payloads(anomaly_result, context_result, tree_result, model=model)
    merged["diagnostics"].update(
        {
            "anomaly_model_type": str((anomaly_model or {}).get("model_type", "unknown")),
            "context_model_type": str((context_model or {}).get("model_type", "unknown")),
            "tree_model_type": str((tree_model or {}).get("model_type", "unknown")),
        }
    )
    return merged


def score_remote_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    model_type = str(model.get("model_type", "bootstrap_logistic_seed"))
    if "hybrid_dual_channel" in model_type:
        return _score_hybrid_model(model=model, feature_window=feature_window, site_hint=site_hint)
    if "gradient_boosted_tree" in model_type:
        return _score_tree_model(model=model, feature_window=feature_window, site_hint=site_hint)
    if "mahalanobis" in model_type:
        return _score_mahalanobis_model(model=model, feature_window=feature_window, site_hint=site_hint)
    return _score_logistic_model(model=model, feature_window=feature_window, site_hint=site_hint)


def _train_logistic_model(samples: list[dict[str, Any]], previous_model: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    rows, labels, filtered_samples = _extract_training_rows(samples)
    X = np.asarray(rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    class_counts = {0: labels.count(0), 1: labels.count(1)}
    if min(class_counts.values()) < 8:
        raise ValueError("Need at least 8 FALSE_POSITIVE and 8 RESOLVED samples with window features to retrain the remote model.")

    split_ready = len(rows) >= 32 and min(class_counts.values()) >= 12
    if split_ready:
        train_idx, test_idx, split_strategy = _source_aware_sample_split(filtered_samples, y, test_size=0.25, random_seed=42)
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        train_samples = [filtered_samples[int(index)] for index in train_idx]
        metrics_split = split_strategy
    else:
        X_train, X_test, y_train, y_test = X, X, y, y
        train_samples = filtered_samples
        metrics_split = "training_only"

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
        ]
    )
    pipeline.fit(X_train, y_train, clf__sample_weight=np.asarray(_hard_example_weights(train_samples, y_train), dtype=float))
    scores = pipeline.predict_proba(X_test)[:, 1]
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.1, 0.9, 81):
        pred = (scores >= threshold).astype(int)
        current = float(f1_score(y_test, pred, zero_division=0))
        if current > best_f1:
            best_f1 = current
            best_threshold = float(threshold)

    scaler: StandardScaler = pipeline.named_steps["scaler"]
    clf: LogisticRegression = pipeline.named_steps["clf"]
    metrics = _binary_metrics(y_test, scores, best_threshold)
    model = {
        "model_type": "sklearn_logistic_regression",
        "model_family": "logistic_regression",
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "means": scaler.mean_.astype(float).tolist(),
        "scales": [1.0 if value == 0.0 else float(value) for value in scaler.scale_.astype(float).tolist()],
        "weights": clf.coef_[0].astype(float).tolist(),
        "bias": float(clf.intercept_[0]),
        "recommended_threshold": best_threshold,
        "trained_from_samples": int(len(rows)),
        "class_counts": {"0": int(class_counts[0]), "1": int(class_counts[1])},
        "metrics": {
            "split": metrics_split,
            "rows_train": int(len(X_train)),
            "rows_eval": int(len(X_test)),
            "threshold": best_threshold,
            **metrics,
            "per_source_metrics": _per_source_metrics(
                [filtered_samples[int(index)] for index in test_idx] if split_ready else filtered_samples,
                y_test,
                scores,
                best_threshold,
            ),
        },
        "updated_epoch": int(time.time()),
    }
    if previous_model and previous_model.get("version") is not None:
        model["previous_version"] = int(previous_model["version"])
    report = {
        "sample_count": int(len(rows)),
        "class_counts": model["class_counts"],
        "metrics": model["metrics"],
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "model_family": "logistic_regression",
    }
    return model, report


def _train_mahalanobis_model(samples: list[dict[str, Any]], previous_model: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    import numpy as np
    from sklearn.model_selection import train_test_split

    rows, labels, filtered_samples = _extract_training_rows(samples)
    X = np.asarray(rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    benign_mask = y == 0
    if int(benign_mask.sum()) < 12:
        raise ValueError("Mahalanobis training needs at least 12 FALSE_POSITIVE/benign samples with window features.")

    split_ready = len(rows) >= 32 and len(set(y.tolist())) > 1 and min(np.bincount(y)) >= 8
    if split_ready:
        indices = np.arange(len(X), dtype=int)
        train_idx, test_idx = train_test_split(indices, test_size=0.25, random_state=42, stratify=y)
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        metrics_split = "holdout"
    else:
        X_train, X_test, y_train, y_test = X, X, y, y
        train_idx = np.arange(len(X), dtype=int)
        test_idx = np.arange(len(X), dtype=int)
        metrics_split = "training_only"

    X_train_benign = X_train[y_train == 0]
    mean = X_train_benign.mean(axis=0)
    covariance = np.cov(X_train_benign, rowvar=False)
    if covariance.ndim == 0:
        covariance = np.eye(X_train_benign.shape[1], dtype=float)
    diagonal = np.diag(np.diag(covariance))
    shrunk_covariance = ((1.0 - 0.20) * covariance) + (0.20 * diagonal) + (np.eye(covariance.shape[0]) * 1e-3)
    precision = np.linalg.pinv(shrunk_covariance)

    train_centered = X_train_benign - mean
    train_distances = np.einsum("ij,jk,ik->i", train_centered, precision, train_centered)
    threshold_distance = float(np.percentile(train_distances, 95))
    scale = max(threshold_distance, float(len(REMOTE_MODEL_FEATURES)), 1.0)
    scores = 1.0 - np.exp(-(np.einsum("ij,jk,ik->i", X_test - mean, precision, X_test - mean) / scale))
    recommended_threshold = 1.0 - math.exp(-(threshold_distance / scale))
    metrics = _binary_metrics(y_test, scores, recommended_threshold)

    metrics = {
        "split": metrics_split,
        "rows_train": int(len(X_train)),
        "rows_eval": int(len(X_test)),
        "threshold": float(recommended_threshold),
        **metrics,
        "per_source_metrics": _per_source_metrics(
            [filtered_samples[int(index)] for index in test_idx] if filtered_samples else [],
            y_test,
            scores,
            recommended_threshold,
        ) if len(set(y_test.tolist())) > 1 else {},
    }
    class_counts = {"0": int((y == 0).sum()), "1": int((y == 1).sum())}
    model = {
        "model_type": "mahalanobis_covariance",
        "model_family": "mahalanobis_covariance",
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "mean": mean.astype(float).tolist(),
        "precision_matrix": precision.astype(float).tolist(),
        "threshold_distance": threshold_distance,
        "recommended_threshold": float(recommended_threshold),
        "trained_from_samples": int(len(rows)),
        "class_counts": class_counts,
        "metrics": metrics,
        "updated_epoch": int(time.time()),
    }
    if previous_model and previous_model.get("version") is not None:
        model["previous_version"] = int(previous_model["version"])
    report = {
        "sample_count": int(len(rows)),
        "class_counts": class_counts,
        "metrics": metrics,
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "model_family": "mahalanobis_covariance",
    }
    return model, report


def _export_gradient_tree(estimator: Any) -> dict[str, Any]:
    tree = estimator.tree_
    return {
        "feature": tree.feature.astype(int).tolist(),
        "threshold": tree.threshold.astype(float).tolist(),
        "left": tree.children_left.astype(int).tolist(),
        "right": tree.children_right.astype(int).tolist(),
        "value": tree.value[:, 0, 0].astype(float).tolist(),
    }


def _train_gradient_boosted_tree_model(samples: list[dict[str, Any]], previous_model: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score

    rows, labels, filtered_samples = _extract_training_rows(samples)
    X = np.asarray(rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    class_counts = {0: labels.count(0), 1: labels.count(1)}
    if min(class_counts.values()) < 12:
        raise ValueError("Gradient-boosted tree training needs at least 12 benign and 12 anomalous samples with window features.")

    if len(rows) >= 48 and min(class_counts.values()) >= 16:
        outer_train_idx, test_idx, split_strategy = _source_aware_sample_split(filtered_samples, y, test_size=0.25, random_seed=42)
        outer_train_samples = [filtered_samples[int(index)] for index in outer_train_idx]
        outer_train_y = y[outer_train_idx]
        inner_train_idx, calibration_idx, inner_strategy = _source_aware_sample_split(outer_train_samples, outer_train_y, test_size=0.25, random_seed=59)
        train_idx = outer_train_idx[inner_train_idx]
        cal_idx = outer_train_idx[calibration_idx]
        X_train, y_train = X[train_idx], y[train_idx]
        X_cal, y_cal = X[cal_idx], y[cal_idx]
        X_test, y_test = X[test_idx], y[test_idx]
        train_samples = [filtered_samples[int(index)] for index in train_idx]
        metrics_split = f"{split_strategy}+{inner_strategy}"
    else:
        X_train, y_train = X, y
        X_cal, y_cal = X, y
        X_test, y_test = X, y
        train_samples = filtered_samples
        metrics_split = "training_only"

    model = GradientBoostingClassifier(
        random_state=42,
        n_estimators=120,
        learning_rate=0.05,
        max_depth=3,
        subsample=0.85,
    )
    model.fit(X_train, y_train, sample_weight=np.asarray(_hard_example_weights(train_samples, y_train), dtype=float))

    cal_logits = model.decision_function(X_cal)
    if len(set(y_cal.tolist())) > 1:
        calibrator = LogisticRegression(random_state=42)
        calibrator.fit(cal_logits.reshape(-1, 1), y_cal)
        cal_slope = float(calibrator.coef_[0][0])
        cal_bias = float(calibrator.intercept_[0])
    else:
        cal_slope = 1.0
        cal_bias = 0.0

    test_logits = model.decision_function(X_test)
    scores = np.asarray([_sigmoid((cal_slope * float(logit)) + cal_bias) for logit in test_logits], dtype=float)
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.1, 0.9, 81):
        pred = (scores >= threshold).astype(int)
        current = float(f1_score(y_test, pred, zero_division=0))
        if current > best_f1:
            best_f1 = current
            best_threshold = float(threshold)
    prior = float(np.clip(np.mean(y_train), 1e-4, 1.0 - 1e-4))
    init_bias = math.log(prior / (1.0 - prior))
    exported_trees = [_export_gradient_tree(tree_wrapper[0]) for tree_wrapper in model.estimators_]
    metrics = _binary_metrics(y_test, scores, best_threshold)
    trained_model = {
        "model_type": "gradient_boosted_tree",
        "model_family": "gradient_boosted_tree",
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "trees": exported_trees,
        "learning_rate": float(model.learning_rate),
        "init_bias": init_bias,
        "calibration_slope": cal_slope,
        "calibration_bias": cal_bias,
        "recommended_threshold": best_threshold,
        "trained_from_samples": int(len(rows)),
        "class_counts": {"0": int(class_counts[0]), "1": int(class_counts[1])},
        "metrics": {
            "split": metrics_split,
            "rows_train": int(len(X_train)),
            "rows_eval": int(len(X_test)),
            "threshold": best_threshold,
            **metrics,
            "per_source_metrics": _per_source_metrics(
                [filtered_samples[int(index)] for index in test_idx] if len(rows) >= 48 and min(class_counts.values()) >= 16 else filtered_samples,
                y_test,
                scores,
                best_threshold,
            ),
        },
        "updated_epoch": int(time.time()),
    }
    if previous_model and previous_model.get("version") is not None:
        trained_model["previous_version"] = int(previous_model["version"])
    report = {
        "sample_count": int(len(rows)),
        "class_counts": trained_model["class_counts"],
        "metrics": trained_model["metrics"],
        "feature_order": list(REMOTE_MODEL_FEATURES),
        "model_family": "gradient_boosted_tree",
    }
    return trained_model, report


def _train_hybrid_model(samples: list[dict[str, Any]], previous_model: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    rows, labels, filtered_samples = _extract_training_rows(samples)
    X = np.asarray(rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    class_counts = {"0": int((y == 0).sum()), "1": int((y == 1).sum())}
    previous_anomaly = (previous_model or {}).get("anomaly_model") if isinstance(previous_model, dict) else None
    previous_context = (previous_model or {}).get("context_model") if isinstance(previous_model, dict) else None
    previous_tree = (previous_model or {}).get("tree_model") if isinstance(previous_model, dict) else None
    split_ready = len(rows) >= 32 and min(class_counts.values()) >= 12

    def _meta_features_from_rows(anomaly_model: Mapping[str, Any], context_model: Mapping[str, Any], tree_model: Mapping[str, Any], matrix: "np.ndarray") -> "np.ndarray":
        anomaly_scores_local = np.asarray(
            [_score_mahalanobis_values(anomaly_model, dict(zip(REMOTE_MODEL_FEATURES, row, strict=False)))["score"] for row in matrix],
            dtype=float,
        )
        context_scores_local = np.asarray(
            [_score_logistic_values(context_model, dict(zip(REMOTE_MODEL_FEATURES, row, strict=False)))["score"] for row in matrix],
            dtype=float,
        )
        tree_scores_local = np.asarray(
            [_score_tree_values(tree_model, dict(zip(REMOTE_MODEL_FEATURES, row, strict=False)))["score"] for row in matrix],
            dtype=float,
        )
        score_gap = np.max(np.column_stack([anomaly_scores_local, context_scores_local, tree_scores_local]), axis=1) - np.min(
            np.column_stack([anomaly_scores_local, context_scores_local, tree_scores_local]), axis=1
        )
        return np.column_stack(
            [
                anomaly_scores_local,
                context_scores_local,
                tree_scores_local,
                score_gap,
                np.zeros(len(matrix), dtype=float),
            ]
        )

    if split_ready:
        outer_train_idx, test_idx, split_strategy = _source_aware_sample_split(
            filtered_samples,
            y,
            test_size=0.25,
            random_seed=42,
        )
        outer_train_samples = [filtered_samples[int(index)] for index in outer_train_idx]
        outer_train_y = y[outer_train_idx]
        meta_rows = X[outer_train_idx]
        meta_labels = outer_train_y
        test_rows = X[test_idx]
        test_labels = y[test_idx]
        folds = _stacking_fold_indices(meta_labels, 4, 59)
        if folds:
            meta_features = np.zeros((len(meta_rows), 5), dtype=float)
            for fold_train_idx, fold_val_idx in folds:
                fold_train_samples = [outer_train_samples[int(index)] for index in fold_train_idx]
                fold_anomaly_model, _ = _train_mahalanobis_model(samples=fold_train_samples, previous_model=previous_anomaly)
                fold_context_model, _ = _train_logistic_model(samples=fold_train_samples, previous_model=previous_context)
                fold_tree_model, _ = _train_gradient_boosted_tree_model(samples=fold_train_samples, previous_model=previous_tree)
                meta_features[fold_val_idx] = _meta_features_from_rows(fold_anomaly_model, fold_context_model, fold_tree_model, meta_rows[fold_val_idx])
            metrics_split = f"{split_strategy}+stacked_oof_{len(folds)}fold"
        else:
            inner_train_idx, meta_idx, inner_strategy = _source_aware_sample_split(
                outer_train_samples,
                outer_train_y,
                test_size=0.25,
                random_seed=59,
            )
            train_samples = [outer_train_samples[int(index)] for index in inner_train_idx]
            meta_rows = X[outer_train_idx][meta_idx]
            meta_labels = outer_train_y[meta_idx]
            fold_anomaly_model, _ = _train_mahalanobis_model(samples=train_samples, previous_model=previous_anomaly)
            fold_context_model, _ = _train_logistic_model(samples=train_samples, previous_model=previous_context)
            fold_tree_model, _ = _train_gradient_boosted_tree_model(samples=train_samples, previous_model=previous_tree)
            meta_features = _meta_features_from_rows(fold_anomaly_model, fold_context_model, fold_tree_model, meta_rows)
            metrics_split = f"{split_strategy}+{inner_strategy}"
        final_train_samples = outer_train_samples
    else:
        final_train_samples = filtered_samples
        meta_rows = X
        meta_labels = y
        test_rows = X
        test_labels = y
        meta_features = np.zeros((len(meta_rows), 5), dtype=float)
        metrics_split = "training_only"

    anomaly_model, anomaly_report = _train_mahalanobis_model(samples=final_train_samples, previous_model=previous_anomaly)
    context_model, context_report = _train_logistic_model(samples=final_train_samples, previous_model=previous_context)
    tree_model, tree_report = _train_gradient_boosted_tree_model(samples=final_train_samples, previous_model=previous_tree)
    if not split_ready:
        meta_features = _meta_features_from_rows(anomaly_model, context_model, tree_model, meta_rows)

    meta_clf = LogisticRegression(class_weight="balanced", random_state=42)
    meta_clf.fit(meta_features, meta_labels)
    threshold_candidates: list[float] = []
    for fold_train_idx, fold_val_idx in _stacking_fold_indices(meta_labels, 4, 97):
        tmp_meta = LogisticRegression(class_weight="balanced", random_state=97)
        tmp_meta.fit(meta_features[fold_train_idx], meta_labels[fold_train_idx])
        val_scores = tmp_meta.predict_proba(meta_features[fold_val_idx])[:, 1]
        threshold_candidates.append(_best_threshold_for_scores(meta_labels[fold_val_idx], val_scores))
    meta_train_scores = meta_clf.predict_proba(meta_features)[:, 1]
    best_threshold = _best_threshold_for_scores(meta_labels, meta_train_scores)
    stacked_features = _meta_features_from_rows(anomaly_model, context_model, tree_model, test_rows)
    combined_scores = meta_clf.predict_proba(stacked_features)[:, 1]
    anomaly_scores = stacked_features[:, 0]
    context_scores = stacked_features[:, 1]
    tree_scores = stacked_features[:, 2]
    metrics = _binary_metrics(test_labels, combined_scores, best_threshold)
    metrics = {
        "split": metrics_split,
        "rows_train": int(len(final_train_samples)),
        "rows_eval": int(len(test_rows)),
        "threshold": best_threshold,
        "threshold_stability_std": float(np.std(np.asarray(threshold_candidates, dtype=float), ddof=0)) if threshold_candidates else 0.0,
        **metrics,
        "per_source_metrics": _per_source_metrics(
            [filtered_samples[int(index)] for index in test_idx] if split_ready else filtered_samples,
            test_labels,
            combined_scores,
            best_threshold,
        ),
        "anomaly_component_pr_auc": _binary_metrics(test_labels, anomaly_scores, 0.5).get("pr_auc") if len(set(test_labels.tolist())) > 1 else None,
        "context_component_pr_auc": _binary_metrics(test_labels, context_scores, 0.5).get("pr_auc") if len(set(test_labels.tolist())) > 1 else None,
        "tree_component_pr_auc": _binary_metrics(test_labels, tree_scores, 0.5).get("pr_auc") if len(set(test_labels.tolist())) > 1 else None,
    }
    model = {
        "model_type": "hybrid_dual_channel",
        "model_family": "hybrid_dual_channel",
        "meta_feature_order": ["anomaly_score", "context_score", "tree_score", "score_gap", "risk_flag_sum"],
        "meta_weights": meta_clf.coef_[0].astype(float).tolist(),
        "meta_bias": float(meta_clf.intercept_[0]),
        "meta_threshold": best_threshold,
        "anomaly_model": anomaly_model,
        "context_model": context_model,
        "tree_model": tree_model,
        "recommended_threshold": best_threshold,
        "trained_from_samples": int(len(X)),
        "class_counts": class_counts,
        "metrics": metrics,
        "updated_epoch": int(time.time()),
    }
    if previous_model and previous_model.get("version") is not None:
        model["previous_version"] = int(previous_model["version"])
    report = {
        "sample_count": int(len(X)),
        "class_counts": class_counts,
        "metrics": metrics,
        "model_family": "hybrid_dual_channel",
        "components": {
            "anomaly_model": anomaly_report,
            "context_model": context_report,
            "tree_model": tree_report,
        },
    }
    return model, report


def train_remote_model(
    samples: list[dict[str, Any]],
    previous_model: Mapping[str, Any] | None = None,
    model_type: str = "logistic_regression",
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Remote model training requires numpy/scikit-learn. Reinstall backend-adapter dependencies."
        ) from exc
    _ = np  # keeps dependency check explicit
    family = (model_type or "logistic_regression").strip().lower()
    if family == "hybrid_dual_channel":
        return _train_hybrid_model(samples=samples, previous_model=previous_model)
    if family == "gradient_boosted_tree":
        return _train_gradient_boosted_tree_model(samples=samples, previous_model=previous_model)
    if family == "mahalanobis_covariance":
        return _train_mahalanobis_model(samples=samples, previous_model=previous_model)
    return _train_logistic_model(samples=samples, previous_model=previous_model)
