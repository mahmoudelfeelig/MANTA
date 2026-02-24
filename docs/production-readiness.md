# Production and Publication Readiness

This checklist tracks readiness for thesis publication and demo delivery.

## Current status
- Core product scope is implemented across `android-app/`, `backend-adapter/`, and `ml-pipeline/`.
- Automated backend tests pass.
- ML test suite is passing on user machine.
- Android runtime start/stop stability fixes are in place.
- Remaining technical work is primarily publication hardening and external integration validation.
- Latest command evidence is recorded in `docs/validation-evidence.md`.

## Completed
- Android metadata-only VPN capture, flow processing, feature extraction, anomaly scoring.
- Local userspace VPN forwarding (TCP/UDP) with `VpnService.protect(...)` for upstream sockets.
- Consent/disclosure gate, local data purge, export toggle, dataset snapshot export.
- Adaptive thresholds and remote policy model support.
- Alert triage lifecycle in app and backend adapter.
- Backend authenticated ingest, payload validation, retry/dead-letter queue, replay APIs.
- Resistine connector API boundary (`register`, `connection`, `send`) implemented.
- Reproducible ML suite with IDS comparison and privacy-ablation reports.
- Drift-reporting, policy-simulation, and retraining-dataset build tooling for analyst feedback loops.
- Android-ready linear model training/export and app-side scorer integration.
- CI workflows for Python and Android unit tests.
- License/compliance tracking docs and third-party notices.

## Remaining before publish-ready

## A) Repository hygiene and release packaging
- Create clean commit sequence from current working tree.
- Ensure no local runtime artifacts are committed.
- Tag a release candidate once all gates pass.

## B) Final validation evidence
- Run full automated test matrix in CI and archive results.
- Run full manual Android validation protocol from `docs/testing-and-validation.md`.
- Archive test logs/screenshots for thesis appendix.

## C) Publication-grade experiment package
- Produce at least one large experiment run (`rows-per-scenario >= 2000`).
- Freeze and archive `reports/` outputs and `manifest.json`.
- Export final bundled Android model from publication run.

## D) Performance and UX evidence
- Capture battery/CPU/memory/latency measurements on target device(s).
- Document user-visible impact and mitigation notes.

## E) Compliance sign-off
- Finalize `THIRD_PARTY_NOTICES.md` with date and reviewer.
- Complete `docs/license-audit-checklist.md` sign-off entries.
- Confirm dataset citation/redistribution constraints in thesis text.

## Remaining external-only
- Live Wazuh deployment, indexing verification, and dashboard tuning.
- Resistine plugin packaging and contract-level integration validation.

## Definition of done
Publication-ready status is reached when:
1. backend, ML, and Android unit tests pass in CI,
2. manual Android + backend connectivity validation passes end-to-end,
3. publication experiment artifacts are reproducible from a fresh checkout,
4. compliance documentation and attributions are complete,
5. only external environment integration tasks (Wazuh/Resistine live hookup) remain.
