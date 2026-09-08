from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException


DB_PATH = Path(tempfile.gettempdir()) / "manta_backend_test_adapter_edge.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["ADAPTER_SHARED_TOKEN"] = "test-token"
os.environ["ADAPTER_OPERATOR_TOKEN"] = "test-operator-token"
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["WAZUH_INGEST_URL"] = ""

from app.main import get_device_policy, list_alerts, update_alert_triage  # noqa: E402
from app.models import AlertTriageUpdate  # noqa: E402


def test_policy_default_exists_when_not_set() -> None:
    response = get_device_policy(device_id_pseudo="unknown-device", _=None)
    payload = response["policy"]
    assert payload["policy_version"] >= 1
    assert payload["default_thresholds"]["high"] >= payload["default_thresholds"]["medium"]


def test_patch_triage_returns_not_found_for_unknown_alert() -> None:
    with pytest.raises(HTTPException) as exc:
        update_alert_triage(
            alert_id="does-not-exist",
            payload=AlertTriageUpdate(status="RESOLVED", note="none"),
            _=None,
        )

    assert exc.value.status_code == 404


def test_list_alerts_rejects_invalid_status() -> None:
    with pytest.raises(HTTPException) as exc:
        list_alerts(triage_status="INVALID", limit=100, _=None)

    assert exc.value.status_code == 400
