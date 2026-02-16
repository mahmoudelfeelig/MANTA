# feel-bachelor
Anomaly detection of application network traffic on Android devices.

## Implementation scaffold
- `android-app/` - Android endpoint prototype (`VpnService`, flow pipeline, Room storage, anomaly scoring, export queue workers, Compose UI).
- `backend-adapter/` - Secure FastAPI ingest adapter with auth, validation, queue/retry, optional Wazuh forwarding.
- `ml-pipeline/` - Feature extraction, baseline anomaly training/evaluation, optional TFLite export.

## Thesis planning docs
- `docs/features-and-requirements.md` - scope, MVP features, requirements, and experiment/evaluation plan.
- `docs/architecture-and-resources.md` - system architecture, integration model, required resources, and risk register.
- `docs/references.md` - curated implementation, standards, datasets, and research references.
- `docs/license-audit-checklist.md` - implementation-time compliance checklist.
- `THIRD_PARTY_NOTICES.md` - running register of reused code, dependencies, and data terms.

## Quick start
1. Android app scaffold:
   - open `android-app/` in Android Studio.
   - configure backend URL/token in app UI.
   - grant VPN permission and start capture.
2. Backend adapter:
   - `cd backend-adapter`
   - create venv and install: `pip install -e .`
   - configure `.env` from `.env.example`
   - run: `uvicorn app.main:app --reload --port 8080`
3. ML pipeline:
   - `cd ml-pipeline`
   - create venv and install: `pip install -e .`
   - train/evaluate with scripts in `README.md`.
