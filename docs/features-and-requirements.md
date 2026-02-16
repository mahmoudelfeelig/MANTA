# Features and Requirements

## Scope
Build a usable Android security prototype that captures app network metadata with `VpnService`, detects anomalies on-device, and can export selected flow and alert events to SIEM/Wazuh.  
Target completion for core thesis results: May 2026.

## Expected outputs
- Working Android prototype.
- Mobile flow dataset from controlled traces.
- Evaluated anomaly detection pipeline.
- Comparison with classical IDS-style baseline methods.
- Privacy and ethics analysis with limitations and future work.

## Feature set

## Android collection and flow pipeline
| Feature | Priority | Acceptance criteria | Dependencies |
|---|---|---|---|
| VPN lifecycle manager (`VpnService`) | P0 | User can start/stop capture reliably and recover after app restart | Android app skeleton |
| Packet-to-flow converter | P0 | 5-tuple flows generated with bytes/packets and start/end time | VPN lifecycle manager |
| App attribution (UID to package) | P0 | At least 90% of flows linked to package in test scenarios | Packet-to-flow converter |
| Local flow storage (Room/SQLite) | P0 | Captured flows persist and can be queried/exported | Packet-to-flow converter |
| Retention policy | P0 | TTL + storage cap enforced without crashes | Local flow storage |
| Export queue with retry | P0 | No data loss under temporary outage in controlled test | Local flow storage |
| NetFlow/IPFIX-style mapping | P1 | Schema and normalized fields available for backend ingest | Packet-to-flow converter, local storage |

## On-device anomaly detection
| Feature | Priority | Acceptance criteria | Dependencies |
|---|---|---|---|
| Feature window builder | P0 | Window and session features generated for model input | Flow pipeline and storage |
| Statistical baseline detector | P0 | Produces anomaly score per window/session | Feature window builder |
| Offline training pipeline | P0 | Reproducible training scripts with fixed seeds | Feature window builder |
| TFLite inference integration | P0 | On-device inference runs on representative test device | Offline training pipeline |
| Alert explanation (top features) | P1 | Each alert displays top contributing features | TFLite inference |
| Adaptive thresholds | P1 | Threshold configurable per app/device profile | Baseline or TFLite model |

## Backend and SIEM integration
| Feature | Priority | Acceptance criteria | Dependencies |
|---|---|---|---|
| Backend API client | P0 | Authenticated event POST works against target endpoint | Export queue |
| Wazuh-compatible ingestion | P0 | Events searchable in SIEM index | Backend API client |
| Dashboard views | P0 | At least 3 useful widgets with app/time filters | Wazuh ingestion |
| Alert triage fields | P1 | Severity, explanation, and status fields available | Wazuh ingestion |
| Remote policy sync | P2 | Backend can update endpoint policy | Backend API client |

## UX and privacy controls
| Feature | Priority | Acceptance criteria | Dependencies |
|---|---|---|---|
| Consent and disclosure screen | P0 | User sees clear data collection explanation before capture | VPN lifecycle manager |
| Metadata-only hard lock | P0 | Payload capture disabled by design | Packet-to-flow converter |
| Local data purge | P0 | User can delete local records from settings | Local flow storage |
| Export toggle | P0 | User can run local-only mode without backend export | Backend API client |
| Alert center UI | P1 | User can review recent anomalies and details | TFLite inference |

## Evaluation tooling
| Feature | Priority | Acceptance criteria | Dependencies |
|---|---|---|---|
| Controlled scenario runner | P0 | Scripted normal/abnormal sessions produce labeled traces | Flow capture |
| Dataset export utility | P0 | Exports anonymized CSV/Parquet for analysis | Local flow storage |
| IDS comparison pipeline | P0 | Same traces evaluated by classical baseline | Scenario runner |
| Metric report generator | P0 | Precision/Recall/F1 and ROC/PR metrics generated | Scenario runner and training |
| Reproducibility manifest | P0 | Versions, configs, seeds, and hardware recorded | Metric reports |

## MVP boundary
- VPN capture and flow pipeline with storage and reliable export.
- On-device anomaly inference with at least one baseline model and one ML model.
- SIEM/Wazuh event ingestion and dashboards.
- Consent, metadata-only privacy mode, export toggle, and purge controls.
- Reproducible experiment pipeline and metric reporting.

## Implementation status (scaffold)
Current status as of February 7, 2026:

| Scope area | Status | Implementation location |
|---|---|---|
| VPN lifecycle manager | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/service/FlowVpnService.kt` |
| Packet-to-flow converter | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/service/TunPacketParser.kt` |
| App attribution | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/domain/flow/AppAttributionResolver.kt` |
| Local flow storage | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/data/db/` |
| Retention policy | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/worker/RetentionCleanupWorker.kt` |
| Export queue with retry | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/data/FlowRepository.kt` |
| Feature window builder | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/domain/flow/FeatureWindowBuilder.kt` |
| Statistical baseline detector | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/domain/detection/StatisticalAnomalyDetector.kt` |
| Offline training pipeline | Implemented scaffold | `ml-pipeline/src/ml_pipeline/train_baseline.py` |
| TFLite integration path | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/domain/detection/TfliteAnomalyScorer.kt`, `ml-pipeline/src/ml_pipeline/export_tflite.py` |
| Backend API client | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/core/net/OkHttpEventClient.kt` |
| Wazuh-compatible ingestion adapter | Implemented scaffold | `backend-adapter/app/main.py` |
| Dashboard starter artifact | Implemented scaffold | `backend-adapter/dashboards/wazuh-mobile-anomaly-dashboard.ndjson` |
| Privacy controls + purge + export toggle | Implemented scaffold | `android-app/app/src/main/java/com/feelbachelor/app/ui/` |
| NetFlow/IPFIX-style mapping (P1) | Implemented | `android-app/app/src/main/java/com/feelbachelor/app/core/model/IpfixMapper.kt` |
| Alert explanation output (P1) | Implemented | `android-app/app/src/main/java/com/feelbachelor/app/domain/detection/ExplanationFormatter.kt` |
| Adaptive thresholds (P1) | Implemented | `android-app/app/src/main/java/com/feelbachelor/app/core/settings/SecureSettingsStore.kt`, `ml-pipeline/src/ml_pipeline/calibration.py` |
| Alert triage fields and workflow (P1) | Implemented | `android-app/app/src/main/java/com/feelbachelor/app/ui/MainScreen.kt`, `backend-adapter/app/main.py` |
| Remote policy sync (P2) | Implemented | `android-app/app/src/main/java/com/feelbachelor/app/worker/PolicySyncWorker.kt`, `backend-adapter/app/main.py` |

## Out of scope for MVP
- Payload DPI.
- Federated training on-device.
- Full enterprise MDM deployment automation.

## Non-functional requirements
- Battery overhead target under 8% across an 8-hour moderate-usage test.
- No major user-visible network degradation while capture is active.
- Capture should recover after app/process restart.
- Export must use encrypted transport.
- Exported identifiers should be pseudonymized by default.

## Experiment and evaluation plan

## Research focus
- `RQ1`: Can app-level network metadata captured via Android `VpnService` detect anomalous behavior with useful accuracy?
- `RQ3`: What privacy/utility trade-off appears when restricting to metadata-only features?

## Hypotheses
- `H1`: Metadata-only features can achieve meaningful anomaly detection performance above simple statistical baselines.
- `H3`: Privacy-preserving feature selection can retain most detection value while reducing sensitive exposure.

## Data strategy
- Controlled traces from prototype app:
  - normal usage sessions
  - abnormal sessions (beacon-like repetition, unusual burst traffic, atypical destinations)
- At least one public mobile traffic dataset with compatible flow-level metadata.

## Validation strategy
- Time-aware train/validation/test split.
- Fixed random seeds for reproducibility.
- Cross-scenario checks to reduce overfitting to one usage pattern.

## Models and baselines
- Proposed model: lightweight anomaly model exported to TFLite.
- Baselines:
  - statistical threshold baseline
  - classical unsupervised baseline
  - IDS-style rule baseline on matched traces

## Metrics
- Detection metrics: Precision, Recall, F1, ROC-AUC, PR-AUC.
- Operational metrics: inference latency, CPU/memory load, battery impact.
- Privacy-utility metrics: performance change when reducing feature granularity and metadata scope.

## Minimum evidence package
- Confusion matrices by scenario.
- ROC/PR curves and threshold sensitivity.
- Comparison table against IDS baseline on same traces.
- Device resource impact summary.
- Privacy impact summary of collected/exported fields.
