# feel-bachelor

Anomaly detection of Android application network traffic using metadata-only flow collection, on-device anomaly detection, and optional backend export for triage and SIEM integration.

## Components
- `android-app/` - Android endpoint app (`VpnService`, flow pipeline, local storage, anomaly scoring, export queue, privacy/consent UI)
- `backend-adapter/` - FastAPI ingest adapter (auth, validation, retry/dead-letter queue, triage/policy APIs, optional Wazuh forwarding, Resistine connector routes)
- `ml-pipeline/` - feature extraction, anomaly training/evaluation, IDS-style baseline comparison, drift/privacy/policy analyses, Android model export
- `thesis-paper/` - LaTeX thesis manuscript source

## Project Docs (Minimal Set)
- `docs/features-checklist.md` - scope, feature checklist, current completion snapshot, and remaining publish-readiness tasks
- `docs/licenses.md` - license + dataset compliance checklist and optional audit commands
- `docs/references.md` - implementation, standards, datasets, privacy, and research references
- `THIRD_PARTY_NOTICES.md` - third-party notices and reuse provenance register

## Quick Start

## Backend adapter (local)
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
export ADAPTER_SHARED_TOKEN='replace-with-long-random-token'
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## ML pipeline (tests + experiment)
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest -q -s tests

python -m ml_pipeline.generate_controlled_dataset \
  --output data/controlled_flows.csv \
  --rows-per-scenario 400 \
  --seed 42

python -m ml_pipeline.run_experiment_suite \
  --input data/controlled_flows.csv \
  --output-dir experiment-runs/run-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

## Android app
- Open `android-app/` in Android Studio.
- Ensure Android SDK path is configured (`ANDROID_HOME` or `android-app/local.properties`).
- Configure backend URL/token in app UI (HTTPS required for app export).
- Accept consent/disclosure, start capture, and validate alerts/export behavior.

## Automated test commands (root)
```bash
make smoke
make test-backend
make test-ml
# Requires Android SDK setup:
make test-android
```

## CI workflows
- `.github/workflows/ci-python.yml`
- `.github/workflows/ci-android.yml`

## Thesis / Submission Notes
- Use `docs/features-checklist.md` as the single progress + remaining-work tracker.
- Use `docs/licenses.md` before release/thesis submission for compliance sign-off.
- Use `docs/references.md` as the curated source list for implementation and writing.
- `thesis-paper/README.md` contains manuscript build instructions.

## Component READMEs
- `android-app/README.md`
- `backend-adapter/README.md`
- `ml-pipeline/README.md`
- `thesis-paper/README.md`
