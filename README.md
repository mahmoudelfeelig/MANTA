# MANTA

`MANTA: Can We Detect Threats Without Seeing the Payload?`

MANTA (Mobile Anomaly and Network Threat Analysis) is an anomaly-first hybrid IDS for encrypted mobile and endpoint traffic. It captures metadata-only flows, performs on-device anomaly scoring, supports privacy-tiered export and remote assistance, and provides backend/SIEM integration for triage, policy, and model management.

## Components
- `android-app/` - MANTA Endpoint app for Android (`VpnService`, flow pipeline, local storage, privacy controls, on-device scoring, export queue, policy sync)
- `backend-adapter/` - MANTA Backend Adapter (FastAPI ingest, queueing, triage, policy APIs, model control, optional SIEM forwarding)
- `website/` - public thesis/demo website
- `ml-pipeline/` - feature extraction, model training, evaluation, privacy/utility benchmarking, experiment orchestration, artifact export
- `docs/` - scope, feature checklist, references, licenses, and architecture-facing project documentation
- `thesis-paper/` - manuscript source and bibliography
- `tools/` - helper scripts for experiment operations and project maintenance

## Core Docs
- `docs/FEATURES.md` - feature checklist and implementation scope grouped by subsystem
- `docs/REFERENCES.md` - implementation references, literature register, and thesis-story paper links
- `docs/LICENSES.md` - license, dataset, and raw-vs-derived data compliance policy
- `docs/EVIDENCE_PACKAGE.md` - appendix/publication evidence archiving flow

## Quick Start

### Backend adapter
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
export ADAPTER_SHARED_TOKEN='replace-with-long-random-token'
export ADAPTER_OPERATOR_TOKEN='replace-with-a-different-long-random-token'
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Website
```bash
cd website
npm install
cp ../main.pdf public/manta-thesis.pdf
npm run dev
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
- Choose the privacy tier you want for local-only, off, low, medium, strict, or custom export behavior.
- Accept consent, start capture, and validate alerts, export, and policy sync.

## Project Direction
MANTA is framed around:
- anomaly-first hybrid IDS design
- metadata-only Android/endpoint traffic capture
- light on-device inference and heavier remote model options
- privacy-tier benchmarking with release-leakage and observer-leakage audits
- reproducible public-corpus evidence for the thesis

## Component READMEs
- `android-app/README.md`
- `backend-adapter/README.md`
- `ml-pipeline/README.md`
- `thesis-paper/README.md`
