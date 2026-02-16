import os
from pathlib import Path

from fastapi.testclient import TestClient


os.environ["ADAPTER_SHARED_TOKEN"] = "test-token"
os.environ["SQLITE_PATH"] = str(Path(__file__).parent / "test_adapter.db")
os.environ["WAZUH_INGEST_URL"] = ""

from app.main import app  # noqa: E402


client = TestClient(app)


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-token"}


def test_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_rejects_without_auth() -> None:
    payload = {
        "event_type": "mobile_flow",
        "event_version": "1.0",
        "device_id_pseudo": "abcd1234",
        "app_id": "com.test",
        "protocol": "TCP",
        "src_ip": "10.0.0.2",
        "src_port": 44444,
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "dst_host_hash": "abcd1234",
        "bytes_out": 100,
        "bytes_in": 200,
        "packets_out": 1,
        "packets_in": 1,
        "duration_ms": 100,
        "timestamp_start": 1000,
        "timestamp_end": 2000,
    }
    response = client.post("/api/v1/events/mobile-flow", json=payload)
    assert response.status_code == 401


def test_accepts_valid_event() -> None:
    payload = {
        "event_type": "mobile_flow",
        "event_version": "1.0",
        "device_id_pseudo": "abcd1234",
        "app_id": "com.test",
        "protocol": "TCP",
        "src_ip": "10.0.0.2",
        "src_port": 44444,
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "dst_host_hash": "abcd1234",
        "bytes_out": 100,
        "bytes_in": 200,
        "packets_out": 1,
        "packets_in": 1,
        "duration_ms": 100,
        "timestamp_start": 1000,
        "timestamp_end": 2000,
    }
    response = client.post("/api/v1/events/mobile-flow", json=payload, headers=_headers())
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert "event_id" in body
