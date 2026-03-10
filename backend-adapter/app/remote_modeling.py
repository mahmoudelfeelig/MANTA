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


def default_remote_model(model_type: str = "logistic_regression") -> dict[str, Any]:
    if model_type == "hybrid_dual_channel":
        return {
            "model_type": "hybrid_dual_channel",
            "model_family": "hybrid_dual_channel",
            "anomaly_weight": 0.72,
            "context_weight": 0.28,
            "anomaly_model": default_remote_model("mahalanobis_covariance"),
            "context_model": default_remote_model("logistic_regression"),
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


def _merge_score_payloads(anomaly_result: Mapping[str, Any], context_result: Mapping[str, Any], anomaly_weight: float, context_weight: float) -> dict[str, Any]:
    total = max(anomaly_weight + context_weight, 1e-6)
    normalized_anomaly = anomaly_weight / total
    normalized_context = context_weight / total
    anomaly_score = float(anomaly_result.get("score", 0.0))
    context_score = float(context_result.get("score", 0.0))
    combined_score = max(0.0, min(1.0, (normalized_anomaly * anomaly_score) + (normalized_context * context_score)))
    contributions: dict[str, float] = {}
    for feature, value in (anomaly_result.get("feature_contributions") or {}).items():
        contributions[str(feature)] = contributions.get(str(feature), 0.0) + (normalized_anomaly * float(value))
    for feature, value in (context_result.get("feature_contributions") or {}).items():
        contributions[str(feature)] = contributions.get(str(feature), 0.0) + (normalized_context * float(value))
    top_features = [name for name, _ in sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:4]]
    confidence = (
        (normalized_anomaly * float(anomaly_result.get("confidence", 0.5))) +
        (normalized_context * float(context_result.get("confidence", 0.5)))
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
            "anomaly_weight": normalized_anomaly,
            "context_weight": normalized_context,
        },
    }


def _score_hybrid_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    anomaly_weight = float(model.get("anomaly_weight", 0.72))
    context_weight = float(model.get("context_weight", 0.28))
    anomaly_model = model.get("anomaly_model") or default_remote_model("mahalanobis_covariance")
    context_model = model.get("context_model") or default_remote_model("logistic_regression")
    anomaly_result = _score_mahalanobis_model(anomaly_model, feature_window=feature_window, site_hint=site_hint)
    context_result = _score_logistic_model(context_model, feature_window=feature_window, site_hint=site_hint)
    merged = _merge_score_payloads(anomaly_result, context_result, anomaly_weight=anomaly_weight, context_weight=context_weight)
    merged["diagnostics"].update(
        {
            "anomaly_model_type": str((anomaly_model or {}).get("model_type", "unknown")),
            "context_model_type": str((context_model or {}).get("model_type", "unknown")),
        }
    )
    return merged


def score_remote_model(model: Mapping[str, Any], feature_window: Mapping[str, Any], site_hint: str | None) -> dict[str, Any]:
    model_type = str(model.get("model_type", "bootstrap_logistic_seed"))
    if "hybrid_dual_channel" in model_type:
        return _score_hybrid_model(model=model, feature_window=feature_window, site_hint=site_hint)
    if "mahalanobis" in model_type:
        return _score_mahalanobis_model(model=model, feature_window=feature_window, site_hint=site_hint)
    return _score_logistic_model(model=model, feature_window=feature_window, site_hint=site_hint)


def _train_logistic_model(samples: list[dict[str, Any]], previous_model: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    X, y = _extract_training_matrix(samples)
    rows = X.tolist()
    labels = y.tolist()
    class_counts = {0: labels.count(0), 1: labels.count(1)}
    if min(class_counts.values()) < 8:
        raise ValueError("Need at least 8 FALSE_POSITIVE and 8 RESOLVED samples with window features to retrain the remote model.")

    split_ready = len(rows) >= 32 and min(class_counts.values()) >= 12
    if split_ready:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
        metrics_split = "holdout"
    else:
        X_train, X_test, y_train, y_test = X, X, y, y
        metrics_split = "training_only"

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
        ]
    )
    pipeline.fit(X_train, y_train)
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
    pred = (scores >= best_threshold).astype(int)
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
            "precision": float(precision_score(y_test, pred, zero_division=0)),
            "recall": float(recall_score(y_test, pred, zero_division=0)),
            "f1": float(f1_score(y_test, pred, zero_division=0)),
            "pr_auc": float(average_precision_score(y_test, scores)),
            "roc_auc": float(roc_auc_score(y_test, scores)) if len(set(y_test.tolist())) > 1 else None,
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
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split

    X, y = _extract_training_matrix(samples)
    rows = X.tolist()
    benign_mask = y == 0
    if int(benign_mask.sum()) < 12:
        raise ValueError("Mahalanobis training needs at least 12 FALSE_POSITIVE/benign samples with window features.")

    split_ready = len(rows) >= 32 and len(set(y.tolist())) > 1 and min(np.bincount(y)) >= 8
    if split_ready:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
        metrics_split = "holdout"
    else:
        X_train, X_test, y_train, y_test = X, X, y, y
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
    pred = (scores >= recommended_threshold).astype(int)

    metrics = {
        "split": metrics_split,
        "rows_train": int(len(X_train)),
        "rows_eval": int(len(X_test)),
        "precision": float(precision_score(y_test, pred, zero_division=0)) if len(set(y_test.tolist())) > 1 else None,
        "recall": float(recall_score(y_test, pred, zero_division=0)) if len(set(y_test.tolist())) > 1 else None,
        "f1": float(f1_score(y_test, pred, zero_division=0)) if len(set(y_test.tolist())) > 1 else None,
        "pr_auc": float(average_precision_score(y_test, scores)) if len(set(y_test.tolist())) > 1 else None,
        "roc_auc": float(roc_auc_score(y_test, scores)) if len(set(y_test.tolist())) > 1 else None,
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


def _train_hybrid_model(samples: list[dict[str, Any]], previous_model: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    import numpy as np
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split

    rows, labels, filtered_samples = _extract_training_rows(samples)
    X = np.asarray(rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    class_counts = {"0": int((y == 0).sum()), "1": int((y == 1).sum())}
    previous_anomaly = (previous_model or {}).get("anomaly_model") if isinstance(previous_model, dict) else None
    previous_context = (previous_model or {}).get("context_model") if isinstance(previous_model, dict) else None
    split_ready = len(rows) >= 32 and min(class_counts.values()) >= 12
    if split_ready:
        train_idx, test_idx = train_test_split(
            np.arange(len(filtered_samples)),
            test_size=0.25,
            random_state=42,
            stratify=y,
        )
        train_samples = [filtered_samples[int(index)] for index in train_idx]
        test_rows = X[test_idx]
        test_labels = y[test_idx]
        metrics_split = "holdout"
    else:
        train_samples = filtered_samples
        test_rows = X
        test_labels = y
        metrics_split = "training_only"

    anomaly_model, anomaly_report = _train_mahalanobis_model(samples=train_samples, previous_model=previous_anomaly)
    context_model, context_report = _train_logistic_model(samples=train_samples, previous_model=previous_context)

    anomaly_scores = np.asarray(
        [_score_mahalanobis_values(anomaly_model, dict(zip(REMOTE_MODEL_FEATURES, row, strict=False)))["score"] for row in test_rows],
        dtype=float,
    )
    context_scores = np.asarray(
        [_score_logistic_values(context_model, dict(zip(REMOTE_MODEL_FEATURES, row, strict=False)))["score"] for row in test_rows],
        dtype=float,
    )
    combined_scores = np.clip((0.72 * anomaly_scores) + (0.28 * context_scores), 0.0, 1.0)
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.1, 0.9, 81):
        pred = (combined_scores >= threshold).astype(int)
        current = float(f1_score(test_labels, pred, zero_division=0))
        if current > best_f1:
            best_f1 = current
            best_threshold = float(threshold)
    pred = (combined_scores >= best_threshold).astype(int)
    metrics = {
        "split": metrics_split,
        "rows_train": int(len(train_samples)),
        "rows_eval": int(len(test_rows)),
        "precision": float(precision_score(test_labels, pred, zero_division=0)),
        "recall": float(recall_score(test_labels, pred, zero_division=0)),
        "f1": float(f1_score(test_labels, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(test_labels, combined_scores)) if len(set(test_labels.tolist())) > 1 else None,
        "roc_auc": float(roc_auc_score(test_labels, combined_scores)) if len(set(test_labels.tolist())) > 1 else None,
        "anomaly_component_pr_auc": float(average_precision_score(test_labels, anomaly_scores)) if len(set(test_labels.tolist())) > 1 else None,
        "context_component_pr_auc": float(average_precision_score(test_labels, context_scores)) if len(set(test_labels.tolist())) > 1 else None,
    }
    model = {
        "model_type": "hybrid_dual_channel",
        "model_family": "hybrid_dual_channel",
        "anomaly_weight": 0.72,
        "context_weight": 0.28,
        "anomaly_model": anomaly_model,
        "context_model": context_model,
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
    if family == "mahalanobis_covariance":
        return _train_mahalanobis_model(samples=samples, previous_model=previous_model)
    return _train_logistic_model(samples=samples, previous_model=previous_model)
