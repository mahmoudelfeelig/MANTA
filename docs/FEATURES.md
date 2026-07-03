# MANTA Feature Checklist

This is the single feature checklist for MANTA. Unchecked items are still in scope but not yet complete. Categories are grouped by subsystem instead of by temporary release state.

## System identity and paper framing
- [x] Rename project/system-facing docs to `MANTA`
- [x] Paper title set to `MANTA: Measuring the Detection-Privacy Trade-off in Metadata-Only Mobile Traffic Monitoring`
- [x] Remove remaining live legacy project identifiers from code, package names, assets, and manuscript text
- [x] Align dashboard, backend, Android, pipeline, and thesis wording to anomaly-first hybrid IDS framing

## Android collection and flow pipeline
- [x] VPN lifecycle manager (`VpnService`)
- [x] Local TCP/UDP forwarding with `protect(...)`
- [x] Packet-to-flow conversion with timing/counter metadata
- [x] Symmetric transport-flow identity with canonical endpoint ordering
- [x] Sharded packet-analysis queueing with explicit overflow/drop accounting
- [x] Capture statistics for packets, bytes, queue depth, and local pipeline loss
- [x] App attribution from UID/package mapping
- [x] Local Room/SQLite storage for flows, windows, alerts, and export queue
- [x] Export queue with retry scheduling
- [x] Retention cleanup workers
- [x] NetFlow/IPFIX-style event mapping
- [x] Rich device/network context capture for reproducible environment metadata
- [x] DNS, TLS, HTTP, and QUIC metadata extraction from packet/handshake bytes
- [x] Destination identity, lookalike-domain detection, and ATT&CK-style technique tagging

## On-device anomaly detection
- [x] Feature window builder
- [x] Internal context and graph-inspired window features kept out of reduced privacy tiers
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
- [x] Release-privacy methodology separated from observer-leakage methodology
- [x] Source-aware distribution-preserving bucketization for `medium` and `strict`
- [x] Multi-target privacy student suppression of app ID, app family, and destination behavior
- [x] Reconstruction-style privacy-student pretraining to recover utility after coarsening
- [x] Federated or secure-aggregation collaboration path for privacy-preserving model improvement
- [x] Multi-attacker privacy leakage benchmark suite with closed-world and open-world tasks
- [x] Encrypted-flow sequence fingerprint benchmark for observer-leakage auditing
- [x] Privacy/utility Pareto reporting and thesis-ready analysis
- [x] Combined privacy gate report with strongest-attacker and observer-audit summaries

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
- [x] Optional remote destination-enrichment endpoint for certificate/domain context
- [x] Backend retention enforcement for events, alerts, jobs, and enrichment cache
- [x] Automatic high-risk alert enrichment and escalation logic
- [x] ATT&CK tags exposed in backend alert views and filters
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
- [x] Thorough replay, soak, and integration test support
- [x] Performance gates for latency, battery, CPU, memory, and export overhead
- [x] Full comparison matrix for anomaly, supervised, hybrid, and privacy-preserving variants
- [x] GitHub Actions workflows updated for MANTA naming and benchmark jobs
- [x] Archived experiment evidence suitable for thesis appendix and publication handoff

## Documentation, references, and compliance
- [x] Root README updated to MANTA identity
- [x] Feature checklist reorganized by subsystem
- [x] References register updated for thesis-story literature
- [x] License and dataset handling policy updated
- [x] Component READMEs fully aligned to MANTA naming and architecture
- [x] Manuscript references fully aligned with the MANTA system name
- [x] Final privacy/ethics analysis write-up
- [x] Final thesis evidence package

## Dataset curation and privacy views
- [x] Multi-view dataset derivation (`off`, `low`, `medium`, `strict`)
- [x] Raw-vs-derived storage separation and documentation
- [x] Additional mobile encrypted-traffic datasets integrated where legally usable

## Enterprise deployment automation
- [x] Full enterprise MDM deployment automation
