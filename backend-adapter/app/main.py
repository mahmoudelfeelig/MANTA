from __future__ import annotations

import json
import time
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status

from .config import load_settings
from .models import (
    AdapterEventAck,
    AlertTriageUpdate,
    DevicePolicyPayload,
    MobileAlertEvent,
    MobileFlowEvent,
)
from .security import require_auth
from .storage import AdapterStorage, QueueItem
from .wazuh_client import WazuhClient, WazuhConfig


def _retry_delay_seconds(base: int, attempts: int) -> int:
    return min(300, base * (2 ** max(0, attempts - 1)))


settings = load_settings()
storage = AdapterStorage(settings.sqlite_path)
wazuh_client = WazuhClient(
    WazuhConfig(
        ingest_url=settings.wazuh_ingest_url,
        api_token=settings.wazuh_api_token,
        allow_insecure=settings.allow_insecure_wazuh,
    )
)
storage.initialize()
app = FastAPI(title="Feel Backend Adapter", version="0.2.0")


def auth_dependency(
    authorization: str | None = Header(default=None),
    x_endpoint_token: str | None = Header(default=None),
) -> None:
    require_auth(
        expected_token=settings.shared_token,
        authorization=authorization,
        x_endpoint_token=x_endpoint_token,
    )


def _validate_payload_size(request: Request) -> None:
    body_size = int(request.headers.get("content-length", "0") or 0)
    if body_size > settings.max_event_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds maximum allowed size",
        )


def _enqueue_and_try_forward(event_type: str, payload: dict) -> tuple[str, bool]:
    event_id = str(uuid.uuid4())
    storage.enqueue_event(event_id=event_id, event_type=event_type, payload=payload)

    pending_items = storage.pending_events(now_epoch=int(time.time()), limit=1)
    forwarded = False
    if pending_items:
        _process_pending_item(pending_items[0])
        refreshed = storage.pending_events(now_epoch=int(time.time()), limit=1)
        # If queue head changed, likely the previous item was sent/dead-lettered.
        forwarded = not refreshed or refreshed[0].event_id != pending_items[0].event_id

    return event_id, forwarded


def _process_pending_item(item: QueueItem) -> None:
    try:
        wazuh_client.send(item.payload_json)
        storage.mark_sent(item.event_id)
    except Exception as exc:  # noqa: BLE001
        attempts = item.attempts + 1
        if attempts >= settings.max_retries:
            storage.move_to_dead_letter(item.event_id, item.event_type, item.payload_json, str(exc))
        else:
            next_epoch = int(time.time()) + _retry_delay_seconds(settings.retry_base_seconds, attempts)
            storage.mark_retry(item.event_id, attempts, next_epoch, str(exc))


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "wazuh_configured": wazuh_client.configured(),
        "queue": storage.stats(),
    }


@app.post("/api/v1/events/mobile-flow", status_code=status.HTTP_202_ACCEPTED, response_model=AdapterEventAck)
async def ingest_mobile_flow(
    request: Request,
    event: MobileFlowEvent,
    _: None = Depends(auth_dependency),
):
    _validate_payload_size(request)

    event_id, forwarded = _enqueue_and_try_forward(
        event_type="mobile_flow",
        payload=event.model_dump(mode="json"),
    )
    return AdapterEventAck(status="accepted", event_id=event_id, forwarded=forwarded)


@app.post("/api/v1/events/mobile-alert", status_code=status.HTTP_202_ACCEPTED, response_model=AdapterEventAck)
async def ingest_mobile_alert(
    request: Request,
    event: MobileAlertEvent,
    _: None = Depends(auth_dependency),
):
    _validate_payload_size(request)

    payload = event.model_dump(mode="json")
    storage.upsert_alert(payload)

    event_id, forwarded = _enqueue_and_try_forward(
        event_type="mobile_alert",
        payload=payload,
    )
    return AdapterEventAck(status="accepted", event_id=event_id, forwarded=forwarded)


@app.post("/api/v1/events/retry")
def retry_pending(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(auth_dependency),
):
    now = int(time.time())
    pending = storage.pending_events(now_epoch=now, limit=limit)

    sent = 0
    failed = 0
    for item in pending:
        before_stats = storage.stats()
        _process_pending_item(item)
        after_stats = storage.stats()
        if after_stats["sent"] > before_stats["sent"]:
            sent += 1
        else:
            failed += 1

    return {
        "status": "ok",
        "processed": len(pending),
        "sent": sent,
        "failed": failed,
    }


@app.get("/api/v1/alerts")
def list_alerts(
    triage_status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(auth_dependency),
):
    if triage_status is not None and triage_status not in {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid triage status")

    alerts = storage.list_alerts(status=triage_status, limit=limit)
    return {
        "status": "ok",
        "alerts": [alert.__dict__ for alert in alerts],
    }


@app.patch("/api/v1/alerts/{alert_id}/triage")
def update_alert_triage(
    alert_id: str,
    payload: AlertTriageUpdate,
    _: None = Depends(auth_dependency),
):
    updated = storage.update_alert_triage(
        alert_id=alert_id,
        triage_status=payload.status,
        triage_note=payload.note,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert = storage.get_alert(alert_id)
    return {
        "status": "ok",
        "alert": alert.__dict__ if alert else None,
    }


_DEFAULT_POLICY = {
    "policy_version": 1,
    "default_thresholds": {"medium": 0.6, "high": 0.85},
    "app_threshold_overrides": {},
    "export_enabled": True,
    "retention_days": 7,
}


@app.get("/api/v1/policy/device/{device_id_pseudo}")
def get_device_policy(
    device_id_pseudo: str,
    _: None = Depends(auth_dependency),
):
    policy = storage.get_policy(device_id_pseudo) or _DEFAULT_POLICY
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "policy": policy,
    }


@app.put("/api/v1/policy/device/{device_id_pseudo}")
def set_device_policy(
    device_id_pseudo: str,
    payload: DevicePolicyPayload,
    _: None = Depends(auth_dependency),
):
    policy = payload.model_dump(mode="json")
    storage.set_policy(device_id_pseudo=device_id_pseudo, policy=policy)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "policy": policy,
    }
