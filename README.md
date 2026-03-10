# MANTA

`MANTA: Can We Detect Threats Without Seeing the Payload?`

MANTA (Mobile Anomaly and Network Threat Analysis) is an anomaly-first hybrid IDS for encrypted mobile and endpoint traffic. It captures metadata-only flows, performs on-device anomaly scoring, supports privacy-tiered export and remote assistance, and provides backend/SIEM integration for triage, policy, and model management.

## Components
- `android-app/` - MANTA Endpoint app for Android (`VpnService`, flow pipeline, local storage, privacy controls, on-device scoring, export queue, policy sync)
- `backend-adapter/` - MANTA Backend Adapter (FastAPI ingest, queueing, triage, policy APIs, model control, optional SIEM forwarding)
- `ml-pipeline/` - feature extraction, model training, evaluation, privacy/utility benchmarking, experiment orchestration, artifact export
- `docs/` - scope, feature checklist, references, licenses, and architecture-facing project documentation
- `thesis-paper/` - manuscript source and bibliography
- `tools/` - helper scripts for experiment operations and project maintenance

## Core Docs
- `docs/FEATURES.md` - feature checklist and implementation scope grouped by subsystem
- `docs/REFERENCES.md` - implementation references, literature register, and thesis-story paper links
- `docs/LICENSES.md` - license, dataset, and raw-vs-derived data compliance policy
- `docs/VALIDATION.md` - formal metric, privacy, reliability, and performance gates
- `docs/PRIVACY_ETHICS.md` - privacy-tier, leakage, and ethics analysis
- `docs/SIEM_CONTRACTS.md` - backend/SIEM integration contracts and live verification entrypoint
- `docs/EVIDENCE_PACKAGE.md` - appendix/publication evidence archiving flow
- `THIRD_PARTY_NOTICES.md` - provenance and reuse notices

## Quick Start

### Backend adapter
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
export ADAPTER_SHARED_TOKEN='replace-with-long-random-token'
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### ML pipeline
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest -q -s tests
```

### Android app
- Open `android-app/` in Android Studio.
- Configure the backend URL and token in the app.
- Choose the privacy tier you want for local-only, pseudonymous, semantic-private, strict, research, or custom export behavior.
- Accept consent, start capture, and validate alerts, export, and policy sync.

## Project Direction
MANTA is being rewritten toward:
- anomaly-first hybrid IDS framing
- stronger multivariate and sequence-aware anomaly detection
- light on-device inference and heavier remote model options
- privacy-tier benchmarking with documented utility degradation
- rigorous replay, integration, and long-running evaluation gates
- GitHub Actions-driven CI/CD and benchmark evidence

## Component READMEs
- `android-app/README.md`
- `backend-adapter/README.md`
- `ml-pipeline/README.md`
- `cloudflared/README.md`
- `thesis-paper/README.md`
