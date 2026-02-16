from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status

from .config import Settings, load_settings
from .models import MobileFlowEvent
from .security import require_auth
from .storage import AdapterStorage
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


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.initialize()
    yield


app = FastAPI(title="Feel Backend Adapter", version="0.1.0", lifespan=lifespan)


def auth_dependency(
    authorization: str | None = Header(default=None),
    x_endpoint_token: str | None = Header(default=None),
) -> None:
    require_auth(
        expected_token=settings.shared_token,
        authorization=authorization,
        x_endpoint_token=x_endpoint_token,
    )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "wazuh_configured": wazuh_client.configured(),
        "queue": storage.stats(),
    }


@app.post("/api/v1/events/mobile-flow", status_code=status.HTTP_202_ACCEPTED)
async def ingest_mobile_flow(
    request: Request,
    event: MobileFlowEvent,
    _: None = Depends(auth_dependency),
):
    body_size = int(request.headers.get("content-length", "0") or 0)
    if body_size > settings.max_event_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds maximum allowed size",
        )

    event_id = str(uuid.uuid4())
    payload = event.model_dump(mode="json")
    storage.enqueue_event(event_id, payload)

    forwarded = False
    pending_items = storage.pending_events(now_epoch=int(time.time()), limit=1)
    if pending_items:
        item = pending_items[0]
        try:
            wazuh_client.send(item.payload_json)
            storage.mark_sent(item.event_id)
            forwarded = True
        except Exception as exc:  # noqa: BLE001
            attempts = item.attempts + 1
            if attempts >= settings.max_retries:
                storage.move_to_dead_letter(item.event_id, item.payload_json, str(exc))
            else:
                next_epoch = int(time.time()) + _retry_delay_seconds(settings.retry_base_seconds, attempts)
                storage.mark_retry(item.event_id, attempts, next_epoch, str(exc))

    return {
        "status": "accepted",
        "event_id": event_id,
        "forwarded": forwarded,
    }


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
        try:
            wazuh_client.send(item.payload_json)
            storage.mark_sent(item.event_id)
            sent += 1
        except Exception as exc:  # noqa: BLE001
            attempts = item.attempts + 1
            if attempts >= settings.max_retries:
                storage.move_to_dead_letter(item.event_id, item.payload_json, str(exc))
            else:
                next_epoch = int(time.time()) + _retry_delay_seconds(settings.retry_base_seconds, attempts)
                storage.mark_retry(item.event_id, attempts, next_epoch, str(exc))
            failed += 1

    return {
        "status": "ok",
        "processed": len(pending),
        "sent": sent,
        "failed": failed,
    }
