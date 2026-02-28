from __future__ import annotations

import json
import time
import uuid
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from starlette.responses import Response

from .config import load_settings
from .models import (
    AdapterEventAck,
    AlertTriageUpdate,
    DevicePolicyPayload,
    MobileAlertEvent,
    MobileFlowEvent,
    PolicySimulationRequest,
)
from .resistine_client import ResistineClient, ResistineConfig
from .security import require_auth
from .storage import AdapterStorage, QueueItem
from .wazuh_client import WazuhClient, WazuhConfig


def _retry_delay_seconds(base: int, attempts: int) -> int:
    return min(300, base * (2 ** max(0, attempts - 1)))


def _severity_label(rank: int) -> str:
    if rank >= 3:
        return "HIGH"
    if rank == 2:
        return "MEDIUM"
    return "LOW"


def _alert_payload(alert) -> dict:
    payload = dict(alert.__dict__)
    raw_warnings = payload.pop("data_quality_warnings_json", "[]")
    try:
        warnings = json.loads(raw_warnings) if raw_warnings else []
    except Exception:  # noqa: BLE001
        warnings = []
    if not isinstance(warnings, list):
        warnings = []
    payload["data_quality_warnings"] = [str(item) for item in warnings]
    return payload


def _incident_payload(incident) -> dict:
    payload = dict(incident.__dict__)
    payload["max_severity"] = _severity_label(int(payload.get("max_severity_rank", 1)))
    return payload


settings = load_settings()
storage = AdapterStorage(settings.sqlite_path)
wazuh_client = WazuhClient(
    WazuhConfig(
        ingest_url=settings.wazuh_ingest_url,
        api_token=settings.wazuh_api_token,
        allow_insecure=settings.allow_insecure_wazuh,
    )
)
resistine_client = ResistineClient(
    ResistineConfig(
        base_url=settings.resistine_base_url,
        api_token=settings.resistine_api_token,
        allow_insecure=settings.allow_insecure_resistine,
    )
)
storage.initialize()
app = FastAPI(title="Feel Backend Adapter", version="0.2.0")


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


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
    config_warnings: list[str] = []
    if len(settings.shared_token) < 16:
        config_warnings.append("ADAPTER_SHARED_TOKEN is shorter than recommended minimum length (16)")

    return {
        "status": "ok",
        "wazuh_configured": wazuh_client.configured(),
        "resistine_configured": resistine_client.configured(),
        "config_warnings": config_warnings,
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
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
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


@app.get("/api/v1/queue/pending")
def list_pending_queue(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    records = storage.list_pending(limit=limit)
    return {
        "status": "ok",
        "pending": [record.__dict__ for record in records],
    }


@app.get("/api/v1/queue/dead-letter")
def list_dead_letter_queue(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    records = storage.list_dead_letter(limit=limit)
    return {
        "status": "ok",
        "dead_letter": [record.__dict__ for record in records],
    }


@app.post("/api/v1/queue/dead-letter/replay")
def replay_dead_letter_queue(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    moved = storage.replay_dead_letter(limit=limit)
    return {
        "status": "ok",
        "replayed": moved,
        "queue": storage.stats(),
    }


@app.post("/api/v1/resistine/register")
def resistine_register(
    payload: dict,
    _: None = Depends(auth_dependency),
):
    if not resistine_client.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Resistine is not configured")
    response = resistine_client.register_endpoint(payload)
    return {"status": "ok", "response": response}


@app.get("/api/v1/resistine/connection/{device_id}")
def resistine_connection(
    device_id: str,
    _: None = Depends(auth_dependency),
):
    if not resistine_client.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Resistine is not configured")
    response = resistine_client.get_connection(device_id=device_id)
    return {"status": "ok", "response": response}


@app.post("/api/v1/resistine/send/{stream_id}")
def resistine_send_data(
    stream_id: str,
    payload: dict,
    _: None = Depends(auth_dependency),
):
    if not resistine_client.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Resistine is not configured")
    response = resistine_client.send_data(stream_id=stream_id, payload=payload)
    return {"status": "ok", "response": response}


@app.get("/api/v1/alerts")
def list_alerts(
    triage_status: Annotated[str | None, Query()] = None,
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    if triage_status is not None and triage_status not in {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid triage status")

    alerts = storage.list_alerts(status=triage_status, limit=limit, device_id_pseudo=device_id_pseudo)
    return {
        "status": "ok",
        "alerts": [_alert_payload(alert) for alert in alerts],
    }


@app.get("/api/v1/incidents")
def list_incidents(
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 250,
    _: None = Depends(auth_dependency),
):
    incidents = storage.list_incidents(limit=limit, device_id_pseudo=device_id_pseudo)
    return {
        "status": "ok",
        "incidents": [_incident_payload(incident) for incident in incidents],
    }


@app.get("/api/v1/quality/summary")
def quality_summary(
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    _: None = Depends(auth_dependency),
):
    summary = storage.quality_summary(device_id_pseudo=device_id_pseudo)
    return {
        "status": "ok",
        "quality": summary,
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
        "alert": _alert_payload(alert) if alert else None,
    }


_DEFAULT_POLICY = {
    "policy_version": 1,
    "default_thresholds": {"medium": 0.6, "high": 0.85},
    "app_threshold_overrides": {},
    "export_enabled": True,
    "retention_days": 7,
    "detection_model": "ensemble_fusion",
    "shadow_model": None,
    "false_positive_budget_per_app_day": 12,
    "drift_high_threshold": 0.65,
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


@app.post("/api/v1/policy/device/{device_id_pseudo}/auto-tune")
def auto_tune_policy_from_feedback(
    device_id_pseudo: str,
    _: None = Depends(auth_dependency),
):
    current_policy = storage.get_policy(device_id_pseudo) or dict(_DEFAULT_POLICY)
    default_thresholds = current_policy.get("default_thresholds", {})
    base_medium = float(default_thresholds.get("medium", 0.6))
    base_high = float(default_thresholds.get("high", 0.85))

    overrides, feedback_stats = storage.feedback_adjust_policy(
        device_id_pseudo=device_id_pseudo,
        base_medium=base_medium,
        base_high=base_high,
    )

    merged_policy = dict(current_policy)
    merged_overrides = dict(merged_policy.get("app_threshold_overrides", {}))
    merged_overrides.update(overrides)
    merged_policy["app_threshold_overrides"] = merged_overrides
    merged_policy["policy_version"] = int(merged_policy.get("policy_version", 1)) + 1

    storage.set_policy(device_id_pseudo=device_id_pseudo, policy=merged_policy)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "feedback_stats": feedback_stats,
        "policy": merged_policy,
    }


@app.post("/api/v1/policy/simulate/{device_id_pseudo}")
def simulate_policy(
    device_id_pseudo: str,
    payload: PolicySimulationRequest,
    _: None = Depends(auth_dependency),
):
    simulation = storage.simulate_policy(
        device_id_pseudo=device_id_pseudo,
        policy=payload.policy.model_dump(mode="json"),
        limit=payload.limit,
    )
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "simulation": simulation,
    }


@app.get("/api/v1/retraining/samples/{device_id_pseudo}")
def export_retraining_samples(
    device_id_pseudo: str,
    limit: Annotated[int, Query(ge=10, le=50000)] = 5000,
    _: None = Depends(auth_dependency),
):
    samples = storage.export_retraining_samples(device_id_pseudo=device_id_pseudo, limit=limit)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "samples": samples,
    }


@app.get("/api/v1/forensics/device/{device_id_pseudo}/bundle")
def export_forensics_bundle(
    device_id_pseudo: str,
    limit: Annotated[int, Query(ge=10, le=50000)] = 5000,
    _: None = Depends(auth_dependency),
):
    policy = storage.get_policy(device_id_pseudo) or dict(_DEFAULT_POLICY)
    alerts = storage.list_alerts(status=None, limit=limit, device_id_pseudo=device_id_pseudo)
    incidents = storage.list_incidents(limit=min(limit, 5000), device_id_pseudo=device_id_pseudo)
    quality = storage.quality_summary(device_id_pseudo=device_id_pseudo)
    payload = {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "generated_epoch": int(time.time()),
        "policy": policy,
        "queue": storage.stats(),
        "quality": quality,
        "alerts": [_alert_payload(alert) for alert in alerts],
        "incidents": [_incident_payload(incident) for incident in incidents],
    }
    return payload
