# Backend Adapter

Secure ingest service for Android mobile flow events with optional Wazuh forwarding.

## Features
- Token-authenticated event ingest endpoint.
- Strict schema validation for mobile flow payloads.
- Local SQLite queue with retry scheduling and dead-letter storage.
- Optional forwarding to Wazuh/SIEM over HTTPS.
- Alert triage lifecycle storage and update endpoints.
- Device policy sync endpoints for adaptive thresholds and retention/export controls.
- Security hardening middleware headers and payload shape limits.

## Run
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
uvicorn app.main:app --reload --port 8080
```

## Endpoints
- `GET /health`
- `POST /api/v1/events/mobile-flow`
- `POST /api/v1/events/mobile-alert`
- `POST /api/v1/events/retry?limit=100`
- `GET /api/v1/alerts?triage_status=OPEN`
- `PATCH /api/v1/alerts/{alert_id}/triage`
- `GET /api/v1/policy/device/{device_id_pseudo}`
- `PUT /api/v1/policy/device/{device_id_pseudo}`

Auth header options:
- `Authorization: Bearer <token>`
- `X-Endpoint-Token: <token>`
