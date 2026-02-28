# Features Checklist

This is the single project checklist for thesis scope tracking, implementation status summary, validation snapshot notes, and remaining publish-readiness work.

## Scope (thesis prototype)
Build an Android security prototype that captures app network metadata with `VpnService`, detects anomalies on-device, and can export selected flow/alert events to a backend/SIEM path.

## Expected outputs
- [x] Working Android prototype
- [x] Mobile flow dataset generation/export capability
- [x] Evaluated anomaly detection pipeline
- [x] IDS-style baseline comparison pipeline
- [ ] Final privacy/ethics analysis write-up and thesis-ready conclusions
- [ ] Final publication-ready evidence package (archived outputs/logs)

## Feature checklist

## Android collection and flow pipeline
- [x] VPN lifecycle manager (`VpnService`)
- [x] Local TCP/UDP forwarding layer with `protect(...)`
- [x] Packet-to-flow converter (5-tuple + counters + timing)
- [x] App attribution (UID to package)
- [x] Local flow storage (Room/SQLite)
- [x] Retention policy (TTL + storage cap)
- [x] Export queue with retry
- [x] NetFlow/IPFIX-style mapping (P1)

## On-device anomaly detection
- [x] Feature window builder
- [x] Statistical baseline detector
- [x] Offline training pipeline
- [x] TFLite inference integration path
- [x] Alert explanation output (P1)
- [x] Adaptive thresholds (P1)

## Backend and SIEM integration
- [x] Backend API client (Android -> adapter)
- [x] Wazuh-compatible ingestion adapter
- [x] Dashboard starter artifact
- [x] Alert triage fields/workflow
- [x] Queue/dead-letter inspection and replay APIs
- [x] Incident grouping and quality summary APIs
- [x] Policy simulation / feedback auto-tune APIs
- [x] Retraining sample export + forensics bundle APIs
- [x] Remote policy sync (P2)
- [ ] Live Wazuh deployment verification and dashboard tuning (external environment)
- [ ] Resistine plugin packaging + contract-level validation (external environment)

## UX and privacy controls
- [x] Consent and disclosure screen
- [x] Metadata-only hard lock (no payload capture in MVP)
- [x] Local data purge
- [x] Export toggle (local-only mode)
- [x] Alert center UI with triage fields

## Evaluation tooling
- [x] Controlled scenario runner
- [x] Dataset export utility (anonymized CSV snapshot)
- [x] IDS comparison pipeline
- [x] Metric report generator (evaluation + ROC/PR + comparisons)
- [x] Reproducibility manifest generation
- [x] Privacy-utility ablation evaluation
- [x] Drift report + policy simulation tooling
- [x] Retraining dataset builder from analyst feedback
- [x] Android-ready linear model export and scorer

## MVP boundary (implemented)
- [x] VPN capture + flow pipeline + storage + reliable export
- [x] On-device anomaly inference (baseline + ML path)
- [x] SIEM/Wazuh ingestion path + dashboard starter artifact
- [x] Consent/privacy/export toggle/purge controls
- [x] Reproducible experiment pipeline and metric reporting

## Out of scope for MVP
- [ ] Payload DPI (out of scope)
- [ ] Federated training on-device (out of scope)
- [ ] Full enterprise MDM deployment automation (out of scope)

## Current validation snapshot (2026-02-22)
- [x] `make smoke` passed
- [x] Backend tests passed (`14 passed` at recorded snapshot)
- [ ] ML tests passed in this environment (blocked then due missing `pandas` in local venv)
- [ ] Android unit tests passed in this environment (blocked then due invalid local Android SDK path)
- [x] ML tests passed on user machine (user-reported 2026-02-16)
- [x] Android runtime start/stop stabilization validated on user machine

## Remaining before publish-ready

## A) Repository hygiene and release packaging
- [ ] Create clean commit sequence from current working tree
- [ ] Ensure no local runtime artifacts are committed
- [ ] Tag a release candidate once all gates pass

## B) Final validation evidence
- [ ] Run full automated test matrix in CI and archive results
- [ ] Run full manual Android validation protocol (consent/capture/connectivity/export/alerts/policy sync)
- [ ] Run backend connectivity validation (HTTPS tunnel + queue verification)
- [ ] Archive test logs/screenshots for thesis appendix

## C) Publication-grade experiment package
- [ ] Produce at least one large experiment run (`rows-per-scenario >= 2000`)
- [ ] Freeze and archive `reports/` outputs and `manifest.json`
- [ ] Export final bundled Android model from publication run
- [ ] Package artifacts for thesis submission handoff

## D) Performance and UX evidence
- [ ] Capture battery/CPU/memory/latency measurements on target device(s)
- [ ] Document user-visible impact and mitigation notes

## E) Compliance sign-off
- [ ] Finalize `THIRD_PARTY_NOTICES.md` with date and reviewer
- [ ] Complete `docs/licenses.md` sign-off entries
- [ ] Confirm dataset citation/redistribution constraints in thesis text

## Definition of done (publication-ready)
Publication-ready status is reached when:
1. backend, ML, and Android unit tests pass in CI,
2. manual Android + backend connectivity validation passes end-to-end,
3. publication experiment artifacts are reproducible from a fresh checkout,
4. compliance documentation and attributions are complete,
5. only external environment integration tasks (Wazuh/Resistine live hookup) remain.

## Implementation map (high-level)
- Android app: `android-app/app/src/main/java/com/feelbachelor/app/`
- Backend adapter: `backend-adapter/app/`
- ML pipeline: `ml-pipeline/src/ml_pipeline/`
- Tests:
  - `backend-adapter/tests/`
  - `ml-pipeline/tests/`
  - `android-app/app/src/test/java/com/feelbachelor/app/`
