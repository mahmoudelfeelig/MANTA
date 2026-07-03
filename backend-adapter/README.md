# MANTA Backend Adapter

Secure ingest service for MANTA mobile flow events with optional Wazuh forwarding.

## Features
- Token-authenticated event ingest endpoint.
- Strict schema validation for mobile flow payloads.
- Local SQLite queue with retry scheduling and dead-letter storage.
- Optional forwarding to Wazuh/SIEM over HTTPS.
- Optional Resistine manager connector routes (register, connection lookup, stream send).
- Alert triage lifecycle storage and update endpoints.
- Device policy sync endpoints for adaptive thresholds and retention/export controls.
- Device heartbeat and device-presence tracking endpoints.
- Incident grouping, quality summary, policy simulation, retraining sample export, and forensics bundle endpoints.
- Security hardening middleware headers and payload shape limits.

## Run
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
# Required
export ADAPTER_SHARED_TOKEN='replace-with-long-random-token'
# Optional
export WAZUH_INGEST_URL=''
export WAZUH_API_TOKEN=''
export RESISTINE_BASE_URL=''
export RESISTINE_API_TOKEN=''
uvicorn app.main:app --reload --port 8080
```

Note: environment variables are read from process env (`os.getenv`) at startup; `.env` is a template, not auto-loaded.

## Endpoints
- `GET /health`
- `POST /api/v1/events/mobile-flow`
- `POST /api/v1/events/mobile-alert`
- `POST /api/v1/inference/window`
- `POST /api/v1/enrichment/destination`
- `GET /api/v1/model/device/{device_id_pseudo}`
- `POST /api/v1/model/device/{device_id_pseudo}/retrain`
- `POST /api/v1/events/retry?limit=100`
- `GET /api/v1/events/recent?status=sent&limit=100`
- `GET /api/v1/queue/pending?limit=100`
- `GET /api/v1/queue/dead-letter?limit=100`
- `POST /api/v1/queue/dead-letter/replay?limit=100`
- `POST /api/v1/resistine/register`
- `GET /api/v1/resistine/connection/{device_id}`
- `POST /api/v1/resistine/send/{stream_id}`
- `GET /api/v1/alerts?triage_status=OPEN`
- `GET /api/v1/incidents?device_id_pseudo=...`
- `GET /api/v1/quality/summary?device_id_pseudo=...`
- `PATCH /api/v1/alerts/{alert_id}/triage`
- `GET /api/v1/policy/device/{device_id_pseudo}`
- `PUT /api/v1/policy/device/{device_id_pseudo}`
- `POST /api/v1/policy/device/{device_id_pseudo}/auto-tune`
- `POST /api/v1/policy/simulate/{device_id_pseudo}`
- `GET /api/v1/retraining/samples/{device_id_pseudo}`
- `GET /api/v1/forensics/device/{device_id_pseudo}/bundle`

Auth header options:
- `Authorization: Bearer <token>`
- `X-Endpoint-Token: <token>`
