from __future__ import annotations

import pytest

pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from app.remote_modeling import default_remote_model, score_remote_model, train_remote_model


def _window(flow_count: int, novelty: float, beacon: float, diversity: float, byte_rate: float, site_hint: str | None = None) -> dict:
    return {
        "flow_count": flow_count,
        "bytes_out": int(byte_rate * 4),
        "bytes_in": int(byte_rate * 3),
        "mean_packet_size": 180.0,
        "outbound_ratio": 0.58,
        "burstiness": 0.20 + novelty,
        "novelty_score": novelty,
        "connection_frequency_delta": max(1.0, flow_count / 3.0),
        "bytes_per_flow": byte_rate,
        "destination_diversity": diversity,
        "activity_ratio": 0.35 + min(0.4, novelty),
        "periodic_beacon_score": beacon,
        "byte_rate": byte_rate,
        "packet_rate": byte_rate / 150.0,
        "mean_duration_ms": 800.0 + (novelty * 500.0),
        "duration_jitter": 20.0 + (novelty * 40.0),
        "port_diversity": diversity,
        "protocol_diversity": 0.15 + (diversity * 0.2),
        "packet_imbalance": 0.1 + novelty,
        "small_flow_ratio": 0.2,
        "high_port_ratio": 0.7,
        "hour_of_day": 12,
        "is_weekend": False,
        "data_quality_score": 1.0,
        "ttl_gap": 0.05 + novelty,
        "ttl_metrics_present": 1.0,
        "syn_rate_total": 0.1 + novelty,
        "rst_rate_total": 0.02 + novelty * 0.5,
        "ack_rate_total": 0.9,
        "fin_rate_total": 0.03,
        "psh_rate_total": 0.12,
        "fragment_rate_total": 0.0,
        "tcp_window_mean": 512.0,
        "ack_delay_mean": 0.2,
        "inter_packet_gap_mean": 0.3,
        "payload_mean": 150.0,
        "load_mean": byte_rate / 1000.0,
        "transport_metrics_present": 1.0,
        "site_hint": site_hint,
    }


def test_default_hybrid_model_scores_with_separate_channels() -> None:
    model = default_remote_model("hybrid_dual_channel")
    result = score_remote_model(
        model=model,
        feature_window=_window(flow_count=18, novelty=0.82, beacon=0.78, diversity=0.71, byte_rate=1200.0),
        site_hint="login-badssl.com",
    )
    assert result["score"] >= 0.0
    assert result["anomaly_score"] >= 0.0
    assert result["context_score"] >= 0.0
    assert result["response_score"] == result["score"]
    assert result["diagnostics"]["model_type"] == "hybrid_dual_channel"


def test_train_hybrid_remote_model_returns_component_reports() -> None:
    samples = []
    for index in range(32):
        benign = index < 16
        samples.append(
            {
                "window_features": _window(
                    flow_count=4 if benign else 22,
                    novelty=0.08 if benign else 0.88,
                    beacon=0.10 if benign else 0.84,
                    diversity=0.12 if benign else 0.74,
                    byte_rate=180.0 if benign else 2100.0,
                    site_hint="example.com" if benign else "login-badssl.com",
                ),
                "site_hint": "example.com" if benign else "login-badssl.com",
                "label": 0 if benign else 1,
            }
        )

    model, report = train_remote_model(samples=samples, model_type="hybrid_dual_channel")
    assert model["model_family"] == "hybrid_dual_channel"
    assert "anomaly_model" in model
    assert "context_model" in model
    assert report["model_family"] == "hybrid_dual_channel"
    assert "components" in report
    assert report["components"]["anomaly_model"]["model_family"] == "mahalanobis_covariance"
    assert report["components"]["context_model"]["model_family"] == "logistic_regression"
    assert report["components"]["tree_model"]["model_family"] == "gradient_boosted_tree"


def test_train_gradient_boosted_tree_remote_model_scores() -> None:
    samples = []
    for index in range(40):
        benign = index < 20
        samples.append(
            {
                "window_features": _window(
                    flow_count=5 if benign else 24,
                    novelty=0.06 if benign else 0.91,
                    beacon=0.08 if benign else 0.86,
                    diversity=0.14 if benign else 0.79,
                    byte_rate=160.0 if benign else 2400.0,
                    site_hint="example.com" if benign else "login-badssl.com",
                ),
                "site_hint": "example.com" if benign else "login-badssl.com",
                "label": 0 if benign else 1,
                "dataset_source": "sdncampus_flow_statistics" if benign else "android_spyware_mendeley",
                "environment_id": "lab_wifi",
                "session_id": f"session_{index // 5}",
                "app_family": "browser" if benign else "malware",
                "window_bucket": index,
            }
        )

    model, report = train_remote_model(samples=samples, model_type="gradient_boosted_tree")
    scored = score_remote_model(
        model=model,
        feature_window=_window(flow_count=26, novelty=0.92, beacon=0.88, diversity=0.82, byte_rate=2600.0),
        site_hint="login-badssl.com",
    )
    assert model["model_family"] == "gradient_boosted_tree"
    assert report["model_family"] == "gradient_boosted_tree"
    assert scored["score"] > 0.0
