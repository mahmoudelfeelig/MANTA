from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


DB_PATH = Path(tempfile.gettempdir()) / "manta_backend_test_adapter.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["ADAPTER_SHARED_TOKEN"] = "test-token"
os.environ["ADAPTER_OPERATOR_TOKEN"] = "test-operator-token"
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["WAZUH_INGEST_URL"] = ""
os.environ["MAX_RETRIES"] = "3"
os.environ["RETRY_BASE_SECONDS"] = "1"

from app.main import (  # noqa: E402
    auto_tune_policy_from_feedback,
    device_heartbeat,
    dashboard_login_page,
    export_forensics_bundle,
    export_retraining_samples,
    get_device_policy,
    health,
    ingest_mobile_alert,
    ingest_mobile_flow,
    list_dead_letter_queue,
    list_devices,
    list_recent_events,
    list_incidents,
    list_pending_queue,
    list_alerts,
    quality_summary,
    resistine_connection,
    resistine_register,
    resistine_send_data,
    replay_dead_letter_queue,
    retry_pending,
    set_device_policy,
    simulate_policy,
    storage,
    update_alert_triage,
    wazuh_client,
)
from app.models import (  # noqa: E402
    AlertTriageUpdate,
    DeviceHeartbeatPayload,
    DevicePolicyPayload,
    MobileAlertEvent,
    MobileFlowEvent,
    PolicySimulationRequest,
    ThresholdProfile,
)


def _fake_request() -> SimpleNamespace:
    return SimpleNamespace(headers={"content-length": "1024"})


def test_dashboard_login_error_is_html_escaped() -> None:
    payload = '<script>alert("x")</script>'
    rendered = dashboard_login_page(payload)
    assert payload not in rendered
    assert "&lt;script&gt;" in rendered


def _flow_payload() -> MobileFlowEvent:
    return MobileFlowEvent(
        event_type="mobile_flow",
        event_version="1.1",
        device_id_pseudo="abcd1234",
        app_id="com.test",
        protocol="TCP",
        src_ip="10.0.0.2",
        src_port=44444,
        dst_ip="8.8.8.8",
        dst_port=443,
        dst_host_hash="abcd1234",
        bytes_out=100,
        bytes_in=200,
        packets_out=1,
        packets_in=1,
        duration_ms=100,
        timestamp_start=1000,
        timestamp_end=2000,
        is_new_destination_for_app=1.0,
        threat_tags=["phishing_lookalike"],
        netflow_version=9,
        ipfix_template_id=256,
        ipfix_elements=[{"id": 8, "name": "sourceIPv4Address", "value": "10.0.0.2"}],
    )


def _alert_payload(alert_id: str = "alert-12345") -> MobileAlertEvent:
    return MobileAlertEvent(
        event_type="mobile_alert",
        event_version="1.0",
        device_id_pseudo="abcd1234",
        alert_id=alert_id,
        app_id="com.test",
        anomaly_score=0.91,
        base_anomaly_score=0.83,
        context_score=0.18,
        response_score=0.91,
        severity="HIGH",
        top_features=["novelty", "burstiness"],
        feature_contributions={"novelty": 0.61, "burstiness": 0.39},
        explanation="Unusual destination novelty and burst traffic",
        source_model="statistical",
        triage_status="OPEN",
        triage_note="",
        timestamp=2000,
    )


def test_health_returns_ok() -> None:
    result = health()
    assert result["status"] == "ok"
    assert "queue" in result
    assert "config_warnings" in result


def test_accepts_mobile_flow_with_ipfix_fields() -> None:
    response = asyncio.run(ingest_mobile_flow(request=_fake_request(), event=_flow_payload(), _=None))
    assert response.status == "accepted"
    assert response.event_id

    recent = list_recent_events(event_type="mobile_flow", limit=20, _=None)
    stored = next(item for item in recent["events"] if item["event_id"] == response.event_id)
    assert stored["payload"]["is_new_destination_for_app"] == pytest.approx(1.0)
    assert stored["payload"]["threat_tags"] == ["phishing_lookalike"]


def test_device_heartbeat_marks_device_online() -> None:
    result = device_heartbeat(
        payload=DeviceHeartbeatPayload(
            device_id_pseudo="heartbeat-device-123",
            device_label="Pixel Test",
            capture_enabled=True,
            export_enabled=True,
            policy_version=3,
        ),
        _=None,
    )
    assert result["status"] == "ok"

    devices = list_devices(limit=20, _=None)
    matching = [item for item in devices["devices"] if item["device_id_pseudo"] == "heartbeat-device-123"]
    assert matching
    assert matching[0]["activity_source"] == "heartbeat"
    assert matching[0]["online"] is True


def test_mobile_alert_triage_lifecycle() -> None:
    response = asyncio.run(ingest_mobile_alert(request=_fake_request(), event=_alert_payload(), _=None))
    assert response.status == "accepted"

    open_alerts = list_alerts(triage_status="OPEN", limit=100, _=None)
    stored = next(item for item in open_alerts["alerts"] if item["alert_id"] == "alert-12345")
    assert stored["anomaly_score"] == pytest.approx(0.91)
    assert stored["base_anomaly_score"] == pytest.approx(0.83)
    assert stored["context_score"] == pytest.approx(0.18)
    assert stored["response_score"] == pytest.approx(0.91)

    patched = update_alert_triage(
        alert_id="alert-12345",
        payload=AlertTriageUpdate(status="INVESTIGATING", note="Analyst review started"),
        _=None,
    )
    assert patched["status"] == "ok"
    assert patched["alert"]["triage_status"] == "INVESTIGATING"


def test_list_alerts_supports_multiple_severity_filters() -> None:
    high_alert = _alert_payload(alert_id="multi-severity-high").model_copy(
        update={
            "severity": "HIGH",
            "triage_status": "OPEN",
            "timestamp": 2_100_001,
        }
    )
    medium_alert = _alert_payload(alert_id="multi-severity-medium").model_copy(
        update={
            "severity": "MEDIUM",
            "triage_status": "OPEN",
            "timestamp": 2_100_002,
        }
    )
    low_alert = _alert_payload(alert_id="multi-severity-low").model_copy(
        update={
            "severity": "LOW",
            "triage_status": "OPEN",
            "timestamp": 2_100_003,
        }
    )

    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=high_alert, _=None))
    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=medium_alert, _=None))
    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=low_alert, _=None))

    filtered = list_alerts(triage_status="OPEN", severity="HIGH,MEDIUM", limit=100, _=None)
    severities = {
        item["alert_id"]: item["severity"]
        for item in filtered["alerts"]
        if item["alert_id"] in {"multi-severity-high", "multi-severity-medium", "multi-severity-low"}
    }

    assert severities == {
        "multi-severity-high": "HIGH",
        "multi-severity-medium": "MEDIUM",
    }


def test_device_policy_roundtrip() -> None:
    set_response = set_device_policy(
        device_id_pseudo="abcd1234",
        payload=DevicePolicyPayload(
            policy_version=2,
            default_thresholds=ThresholdProfile(low=0.3, medium=0.55, high=0.8),
            app_threshold_overrides={"com.test": ThresholdProfile(low=0.25, medium=0.5, high=0.75)},
            export_enabled=True,
            retention_days=14,
        ),
        _=None,
    )
    assert set_response["status"] == "ok"

    get_response = get_device_policy(device_id_pseudo="abcd1234", _=None)
    assert get_response["policy"]["policy_version"] == 2
    assert get_response["policy"]["default_thresholds"]["low"] == 0.3
    assert get_response["policy"]["default_thresholds"]["medium"] == 0.55
    assert get_response["policy"]["protected_brands_csv"] is None


def test_device_policy_roundtrip_with_protected_brands() -> None:
    set_response = set_device_policy(
        device_id_pseudo="protected-brands-device",
        payload=DevicePolicyPayload(
            policy_version=3,
            default_thresholds=ThresholdProfile(low=0.3, medium=0.6, high=0.85),
            export_enabled=True,
            retention_days=90,
            protected_brands_csv="google\nmicrosoft\nexamplebank",
        ),
        _=None,
    )
    assert set_response["status"] == "ok"

    get_response = get_device_policy(device_id_pseudo="protected-brands-device", _=None)
    assert get_response["policy"]["protected_brands_csv"] == "google\nmicrosoft\nexamplebank"


def test_retry_moves_to_dead_letter_after_max_retries(monkeypatch) -> None:
    monkeypatch.setattr(wazuh_client, "send", lambda payload_json: (_ for _ in ()).throw(RuntimeError("boom")))

    response = asyncio.run(ingest_mobile_flow(request=_fake_request(), event=_flow_payload(), _=None))
    assert response.status == "accepted"

    retry_pending(limit=100, _=None)
    time.sleep(1.1)
    retry_pending(limit=100, _=None)
    time.sleep(2.1)
    retry_pending(limit=100, _=None)

    stats = storage.stats()
    assert stats["dead_letter"] >= 1


def test_dead_letter_replay_lifecycle(monkeypatch) -> None:
    monkeypatch.setattr(wazuh_client, "send", lambda payload_json: (_ for _ in ()).throw(RuntimeError("boom")))

    response = asyncio.run(ingest_mobile_flow(request=_fake_request(), event=_flow_payload(), _=None))
    assert response.status == "accepted"

    retry_pending(limit=100, _=None)
    time.sleep(1.1)
    retry_pending(limit=100, _=None)
    time.sleep(2.1)
    retry_pending(limit=100, _=None)

    dead_letter_before = list_dead_letter_queue(limit=100, _=None)
    assert dead_letter_before["dead_letter"]

    replay = replay_dead_letter_queue(limit=10, _=None)
    assert replay["replayed"] >= 1

    pending = list_pending_queue(limit=100, _=None)
    assert pending["pending"]


def test_resistine_endpoints_require_configuration() -> None:
    with pytest.raises(HTTPException):
        resistine_register(payload={"device_id": "abc"}, _=None)

    with pytest.raises(HTTPException):
        resistine_connection(device_id="abc", _=None)

    with pytest.raises(HTTPException):
        resistine_send_data(stream_id="s1", payload={"k": "v"}, _=None)


def test_incidents_quality_and_forensics_exports() -> None:
    first = _alert_payload(alert_id="corr-alert-1").model_copy(
        update={
            "correlation_key": "corr-key-1",
            "data_quality_warnings": ["zero_bytes_flow", "duration_non_positive"],
            "severity": "HIGH",
        }
    )
    second = _alert_payload(alert_id="corr-alert-2").model_copy(
        update={
            "correlation_key": "corr-key-1",
            "data_quality_warnings": ["zero_bytes_flow"],
            "severity": "MEDIUM",
        }
    )
    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=first, _=None))
    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=second, _=None))

    incidents = list_incidents(device_id_pseudo="abcd1234", limit=100, _=None)
    assert incidents["status"] == "ok"
    assert any(item["correlation_key"] == "corr-key-1" for item in incidents["incidents"])
    assert all("max_severity" in item for item in incidents["incidents"])

    quality = quality_summary(device_id_pseudo="abcd1234", _=None)
    assert quality["status"] == "ok"
    assert quality["quality"]["alerts_scanned"] >= 2
    assert quality["quality"]["warning_counts"].get("zero_bytes_flow", 0) >= 2

    bundle = export_forensics_bundle(device_id_pseudo="abcd1234", limit=100, _=None)
    assert bundle["status"] == "ok"
    assert bundle["device_id_pseudo"] == "abcd1234"
    assert isinstance(bundle["alerts"], list)
    assert isinstance(bundle["incidents"], list)


def test_policy_auto_tune_simulation_and_retraining_samples() -> None:
    alert_fp = _alert_payload(alert_id="feedback-alert-fp").model_copy(
        update={
            "anomaly_score": 0.71,
            "triage_status": "FALSE_POSITIVE",
            "triage_note": "noise",
            "source_model": "ensemble_fusion",
            "timestamp": 2_000_001,
        }
    )
    alert_tp = _alert_payload(alert_id="feedback-alert-tp").model_copy(
        update={
            "anomaly_score": 0.92,
            "triage_status": "RESOLVED",
            "triage_note": "confirmed",
            "source_model": "local",
            "timestamp": 2_000_002,
        }
    )
    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=alert_fp, _=None))
    asyncio.run(ingest_mobile_alert(request=_fake_request(), event=alert_tp, _=None))

    tuned = auto_tune_policy_from_feedback(device_id_pseudo="abcd1234", _=None)
    assert tuned["status"] == "ok"
    assert tuned["policy"]["policy_version"] >= 2
    assert isinstance(tuned["feedback_stats"], dict)

    simulation_request = PolicySimulationRequest(
        policy=DevicePolicyPayload(
            policy_version=1,
            default_thresholds=ThresholdProfile(low=0.3, medium=0.55, high=0.85),
            app_threshold_overrides={},
            export_enabled=True,
            retention_days=90,
        ),
        limit=500,
    )
    simulation = simulate_policy(
        device_id_pseudo="abcd1234",
        payload=simulation_request,
        _=None,
    )
    assert simulation["status"] == "ok"
    assert "severity_distribution" in simulation["simulation"]

    samples = export_retraining_samples(device_id_pseudo="abcd1234", limit=500, _=None)
    assert samples["status"] == "ok"
    assert samples["samples"]
    assert all(item["label"] in {0, 1} for item in samples["samples"])
