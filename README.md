# feel-bachelor
Anomaly detection of application network traffic on Android devices.

## Implementation
- `android-app/` - Android endpoint app (`VpnService`, flow pipeline, Room storage, statistical + exported-model + TFLite scoring path, export queue workers, consent gate, anonymized local dataset export, Compose UI).
- `backend-adapter/` - Secure FastAPI ingest adapter with auth, validation, queue/retry/dead-letter, queue replay/inspection, triage APIs, policy sync APIs, optional Wazuh forwarding, and Resistine connector routes.
- `ml-pipeline/` - Feature extraction, baseline anomaly training/evaluation, IDS-style comparison baseline, privacy ablation analysis, drift reporting, policy simulation, retraining dataset build, Android model export, threshold calibration, optional TFLite export.

## Thesis planning docs
- `docs/features-and-requirements.md` - scope, MVP features, requirements, and experiment/evaluation plan.
- `docs/architecture-and-resources.md` - system architecture, integration model, required resources, and risk register.
- `docs/references.md` - curated implementation, standards, datasets, and research references.
- `docs/license-audit-checklist.md` - implementation-time compliance checklist.
- `docs/testing-and-validation.md` - test coverage matrix, integration scope, and execution commands.
- `docs/execution-playbook.md` - exact end-to-end execution workflow for local runs.
- `docs/publication-experiment-package.md` - thesis-grade experiment run and artifact packaging contract.
- `docs/validation-evidence.md` - latest recorded validation outcomes.
- `docs/production-readiness.md` - readiness checklist and explicit external-only remainder.
- `THIRD_PARTY_NOTICES.md` - running register of reused code, dependencies, and data terms.

## Quick start
1. Android app scaffold:
   - open `android-app/` in Android Studio.
   - configure backend URL/token in app UI.
   - grant VPN permission and start capture.
2. Backend adapter:
   - `cd backend-adapter`
   - create venv and install: `pip install -e .[test]`
   - set runtime env vars in shell (at minimum `ADAPTER_SHARED_TOKEN`)
   - run: `uvicorn app.main:app --reload --port 8080`
3. ML pipeline:
   - `cd ml-pipeline`
   - create venv and install: `pip install -e .[test]`
   - train/evaluate with scripts in `README.md`.

## Validation and release docs
- `docs/testing-and-validation.md` - exhaustive automated + manual test procedures and pass criteria.
- `docs/execution-playbook.md` - end-to-end reproducible run commands.
- `docs/production-readiness.md` - publish-readiness gate and remaining external integration work.
