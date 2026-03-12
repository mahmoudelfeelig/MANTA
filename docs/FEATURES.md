# MANTA Feature Checklist

This is the single feature checklist for MANTA. Unchecked items are still in scope but not yet complete. Categories are grouped by subsystem instead of by temporary release state.

## System identity and paper framing
- [x] Rename project/system-facing docs to `MANTA`
- [x] Paper title set to `MANTA: Can We Detect Threats Without Seeing the Payload?`
- [x] Remove remaining live legacy project identifiers from code, package names, assets, and manuscript text
- [x] Align dashboard, backend, Android, pipeline, and thesis wording to anomaly-first hybrid IDS framing

## Android collection and flow pipeline
- [x] VPN lifecycle manager (`VpnService`)
- [x] Local TCP/UDP forwarding with `protect(...)`
- [x] Packet-to-flow conversion with timing/counter metadata
- [x] App attribution from UID/package mapping
- [x] Local Room/SQLite storage for flows, windows, alerts, and export queue
- [x] Export queue with retry scheduling
- [x] Retention cleanup workers
- [x] NetFlow/IPFIX-style event mapping
- [x] Rich device/network context capture for reproducible environment metadata

## On-device anomaly detection
- [x] Feature window builder
- [x] Statistical baseline detector
- [x] Drift monitor
- [x] Periodic beacon detector
- [x] Sequence and transition anomaly detection
- [x] Linear scorer path
- [x] TFLite scorer path
- [x] Fusion ensemble
- [x] Explanation output with top contributors
- [x] Adaptive thresholds and app profiles
- [x] Rigorous multivariate anomaly detector that models feature dependence explicitly
- [x] Multiscale baselines (short/medium/long horizon)
- [x] One-class / reconstruction-oriented neural anomaly model
- [x] Explicit anomaly/context/response score separation
- [x] Feedback-aware baseline adaptation beyond threshold tuning

## Privacy and data minimization
- [x] Consent and disclosure workflow
- [x] Metadata-only hard lock (no payload capture)
- [x] Local purge controls
- [x] Export toggle and local-only mode
- [x] Privacy tiers: off, low, medium, strict
- [x] Custom privacy tier scaffolding with field-level export controls
- [x] Pseudonymous device identifier export
- [x] Privacy-aware export preview in the app
- [x] Privacy-aware backend connectivity and policy sync behavior
- [x] Full custom-tier UX and all local UI behaviors aligned with custom export controls
- [x] Privacy-preserving representation learning and teacher-student distillation
- [x] Federated or secure-aggregation collaboration path for privacy-preserving model improvement
- [x] Privacy leakage benchmark suite
- [x] Privacy/utility Pareto reporting and thesis-ready analysis

## Backend, model serving, and SIEM integration
- [x] Token-authenticated ingest adapter
- [x] Queue, retry, and dead-letter handling
- [x] Alert storage and triage workflow
- [x] Device policy sync APIs
- [x] Policy simulation and feedback auto-tune APIs
- [x] Retraining sample export and forensics bundles
- [x] Incident grouping and quality summary APIs
- [x] Device rename, removal, and heartbeat presence tracking
- [x] Dashboard with filters, pagination, and device management
- [x] Wazuh-compatible forwarding path
- [x] Resistine connector routes
- [x] Remote model registry with multiple model families, versioning, and per-device/global selection
- [x] Hybrid remote anomaly/context scorer bundle with separate channels
- [x] Live SIEM deployment verification and packaged integration contracts

## Evaluation, experiments, and CI/CD
- [x] Controlled scenario generator
- [x] Baseline comparison pipeline
- [x] Threshold calibration tooling
- [x] Privacy ablation tooling
- [x] Drift and policy simulation tooling
- [x] Android-ready artifact export
- [x] Model comparison matrix tooling for remote model families
- [x] Large real-data experiment suite covering multiple privacy tiers and model families
- [x] Thorough replay, soak, and integration tests with formal pass/fail thresholds
- [x] Performance gates for latency, battery, CPU, memory, and export overhead
- [x] Full comparison matrix for anomaly, supervised, hybrid, and privacy-preserving variants
- [x] GitHub Actions workflows updated for MANTA naming, benchmark jobs, and richer validation gates
- [x] Archived experiment evidence suitable for thesis appendix and publication handoff

## Documentation, references, and compliance
- [x] Root README updated to MANTA identity
- [x] Feature checklist reorganized by subsystem
- [x] References register updated for thesis-story literature
- [x] License and dataset handling policy updated
- [x] Component READMEs fully aligned to MANTA naming and architecture
- [x] Manuscript references fully aligned with the MANTA system name
- [x] Final privacy/ethics analysis write-up
- [x] Final publication-ready evidence package

## Dataset curation and privacy views
- [x] Multi-view dataset derivation (`off`, `low`, `medium`, `strict`)
- [x] Raw-vs-derived storage separation and documentation
- [x] Additional mobile encrypted-traffic datasets integrated where legally usable

## Enterprise deployment automation
- [x] Full enterprise MDM deployment automation
