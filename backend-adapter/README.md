# Backend Adapter

Secure ingest service for Android mobile flow events with optional Wazuh forwarding.

## Features
- Token-authenticated event ingest endpoint.
- Strict schema validation for mobile flow payloads.
- Local SQLite queue with retry scheduling and dead-letter storage.
- Optional forwarding to Wazuh/SIEM over HTTPS.

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
- `POST /api/v1/events/retry?limit=100`

Auth header options:
- `Authorization: Bearer <token>`
- `X-Endpoint-Token: <token>`
