# Production Readiness (Non-external Scope)

This checklist tracks what is complete without requiring Wazuh/Resistine integration.

## Completed
- Android VPN capture, metadata-only flow processing, feature extraction, anomaly scoring.
- Consent/disclosure gate before capture and explicit local dataset export snapshot.
- Adaptive thresholds and remote policy consumption support.
- Alert triage lifecycle in endpoint and backend adapter.
- Backend authenticated ingest + validation + retry/dead-letter queue.
- Reproducible ML suite (dataset generation, training, evaluation, calibration, explanations, IDS baseline comparison).
- Automated tests for backend and ML.
- CI workflows for backend/ML and Android unit tests.
- License/compliance tracking docs and validation docs.

## Remaining (external-only)
- Real Wazuh deployment and dashboard tuning in a live SIEM environment.
- Resistine plugin packaging and contract-level integration validation.

## Remaining (environment-limited, non-external)
- Execute Android Gradle unit tests in an environment with working native Gradle runtime.
- Execute Python backend/ML tests in a network-enabled environment where pip dependencies can be resolved.
- Run final on-device battery/performance benchmarks and publish measurements.

## Definition of complete for current scope
The scope is complete when:
- backend and ML tests pass in CI,
- Android unit tests pass in a compatible Gradle environment,
- experiment suite artifacts can be generated from a fresh checkout using documented commands.
