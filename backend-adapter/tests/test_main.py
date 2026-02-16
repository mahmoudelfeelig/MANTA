from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace


DB_PATH = Path(tempfile.gettempdir()) / "feel_backend_test_adapter.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["ADAPTER_SHARED_TOKEN"] = "test-token"
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["WAZUH_INGEST_URL"] = ""
os.environ["MAX_RETRIES"] = "3"
os.environ["RETRY_BASE_SECONDS"] = "1"

from app.main import (  # noqa: E402
    get_device_policy,
    health,
    ingest_mobile_alert,
    ingest_mobile_flow,
    list_alerts,
    retry_pending,
    set_device_policy,
    storage,
    update_alert_triage,
    wazuh_client,
)
from app.models import AlertTriageUpdate, DevicePolicyPayload, MobileAlertEvent, MobileFlowEvent, ThresholdProfile  # noqa: E402


def _fake_request() -> SimpleNamespace:
    return SimpleNamespace(headers={"content-length": "1024"})


def _flow_payload() -> MobileFlowEvent:
    return MobileFlowEvent(
        event_type="mobile_flow",
        event_version="1.0",
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
        severity="HIGH",
        top_features=["novelty", "burstiness"],
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


def test_accepts_mobile_flow_with_ipfix_fields() -> None:
    response = asyncio.run(ingest_mobile_flow(request=_fake_request(), event=_flow_payload(), _=None))
    assert response.status == "accepted"
    assert response.event_id


def test_mobile_alert_triage_lifecycle() -> None:
    response = asyncio.run(ingest_mobile_alert(request=_fake_request(), event=_alert_payload(), _=None))
    assert response.status == "accepted"

    open_alerts = list_alerts(triage_status="OPEN", limit=100, _=None)
    assert any(item["alert_id"] == "alert-12345" for item in open_alerts["alerts"])

    patched = update_alert_triage(
        alert_id="alert-12345",
        payload=AlertTriageUpdate(status="INVESTIGATING", note="Analyst review started"),
        _=None,
    )
    assert patched["status"] == "ok"
    assert patched["alert"]["triage_status"] == "INVESTIGATING"


def test_device_policy_roundtrip() -> None:
    set_response = set_device_policy(
        device_id_pseudo="abcd1234",
        payload=DevicePolicyPayload(
            policy_version=2,
            default_thresholds=ThresholdProfile(medium=0.55, high=0.8),
            app_threshold_overrides={"com.test": ThresholdProfile(medium=0.5, high=0.75)},
            export_enabled=True,
            retention_days=14,
        ),
        _=None,
    )
    assert set_response["status"] == "ok"

    get_response = get_device_policy(device_id_pseudo="abcd1234", _=None)
    assert get_response["policy"]["policy_version"] == 2
    assert get_response["policy"]["default_thresholds"]["medium"] == 0.55


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
