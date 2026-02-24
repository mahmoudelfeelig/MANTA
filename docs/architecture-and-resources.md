# Architecture and Resources

## Architecture goals
- Capture Android app network flow metadata on-device.
- Detect anomalies locally with lightweight models.
- Export selected flow and alert events to SIEM/Wazuh.
- Keep privacy controls explicit and enforce metadata-first collection.

## System overview
- Android endpoint app
- SIEM/Wazuh backend
- Offline training and analysis pipeline

## Implemented repository layout
- `android-app/`: Android endpoint implementation.
- `backend-adapter/`: secure ingest and Wazuh forwarding adapter.
- `ml-pipeline/`: feature engineering, training, evaluation, TFLite export.
- `THIRD_PARTY_NOTICES.md`: license and reuse tracking.

## Android endpoint design

## VPN capture
- Uses `VpnService` to establish a local tunnel.
- Uses a local userspace forwarding layer (TCP/UDP) so capture and internet access run at the same time.
- Protects upstream sockets with `VpnService.protect(...)` to prevent VPN routing loops.
- Captures flow/session metadata only:
  - timestamps
  - app attribution (UID/package)
  - IPs, ports, protocol
  - packet and byte counters
  - duration and timing summaries
  - optional domain indicators where feasible
- No payload inspection in MVP mode.

## Flow processing and feature engineering
- Packet stream aggregated into NetFlow/IPFIX-style flow records.
- Session/window features include:
  - burstiness
  - average packet size
  - directional ratio
  - per-app destination novelty
  - connection frequency change
- Feature schema is versioned.

## Local storage
- Room/SQLite tables:
  - `raw_flow_records`
  - `feature_windows`
  - `anomaly_scores`
  - `export_queue`
- Retention controls:
  - rolling TTL
  - storage cap
  - manual user purge

## On-device detection
- Runtime: TensorFlow Lite.
- Candidate model options:
  - lightweight autoencoder
  - classical unsupervised baseline
  - statistical threshold fallback
- bundled Android-ready linear model (`assets/models/anomaly-linear.json`) as an always-available ML scorer
- Output includes anomaly score and top contributing features.
- Adaptive threshold profile:
  - default medium/high thresholds
  - per-app threshold overrides
  - remotely synced policy versioning

## Alerting and UI
- Alert list with app, score, time, and explanation.
- User controls:
  - start/stop VPN
  - local-only vs export mode
  - privacy and consent settings
  - local data purge
- Triage workflow states:
  - `OPEN`
  - `INVESTIGATING`
  - `RESOLVED`
  - `FALSE_POSITIVE`

## Backend connector
- HTTPS client with token/API-key auth.
- Reliable delivery with queue and retry backoff.
- Optionally dead-letter queue for failed events.
- Queue observability and replay APIs:
  - pending queue inspection
  - dead-letter inspection
  - dead-letter replay to pending queue

## Implemented secure defaults
- Android exporter rejects non-HTTPS backend URLs.
- Cleartext traffic disabled in Android network security config.
- Endpoint secrets stored via encrypted shared preferences.
- Adapter requires token auth and validates payload size.
- Adapter stores failed forwarding attempts and moves exhausted retries to dead-letter.

## SIEM/Wazuh side
- Ingestion endpoint or adapter to normalize event schema.
- Indexes for:
  - flow events
  - anomaly alerts
  - contextual snapshots
- Dashboards for:
  - anomalous apps
  - trend over time
  - destination novelty and burst patterns
- Additional management APIs:
  - alert triage update endpoint
  - device policy read/update endpoints for remote threshold/export control
  - Resistine integration boundary endpoints:
    - register endpoint
    - retrieve connection context
    - send stream data

## Event schema draft
```json
{
  "event_type": "mobile_flow",
  "event_version": "1.0",
  "device_id_pseudo": "hashed-id",
  "app_id": "com.example.app",
  "protocol": "TCP",
  "dst_port": 443,
  "dst_host_hash": "sha256:...",
  "bytes_out": 3201,
  "bytes_in": 18420,
  "duration_ms": 912,
  "timestamp_start": "2026-03-20T10:32:01Z",
  "timestamp_end": "2026-03-20T10:32:02Z",
  "anomaly_score": 0.87,
  "explain_top_features": [
    "dst_novelty",
    "burstiness",
    "conn_freq_delta"
  ]
}
```

## Resistine integration shape
- Keep plugin boundaries explicit:
  - `collector-core`
  - `detection-core`
  - `resistine-connector`
- Stable interfaces:
  - `FlowEventProducer`
  - `AnomalyScorer`
  - `AlertSink`

## Privacy and security rules
- Data minimization by default.
- Pseudonymization before export where possible.
- Explicit user consent for export.
- TLS transport and strict certificate validation.
- Sensitive local fields encrypted at rest where practical.
- Clear retention and deletion policy.

## Needed resources

## Hardware and environment
- At least two Android devices with different versions/vendors.
- Repeatable test network for controlled traces.
- Development machine with Android Studio and profiling tools.

## Software stack
- Android app stack:
  - Kotlin/Java
  - `VpnService`
  - Room/SQLite
  - TensorFlow Lite
- Backend stack:
  - Wazuh/SIEM instance
  - ingestion adapter if needed
- Data and ML stack:
  - reproducible training/evaluation environment
  - experiment config/version tracking

## Data and documentation assets
- Controlled scenario scripts.
- Feature dictionary and schema docs.
- Public dataset shortlist with license notes.
- Consent/disclosure text.
- Privacy and data-protection write-up.

## Risk register
| Risk | Probability | Impact | Mitigation | Trigger |
|---|---|---|---|---|
| VPN capture unstable across devices | Medium | High | Start with a narrow device matrix and harden lifecycle management | Frequent tunnel drops |
| High false positive rate | High | High | Per-app baselines, threshold calibration, explanation support | Alert fatigue during pilot runs |
| SIEM integration delays | Medium | Medium | Local JSON export first, adapter service second | Endpoint unavailable or schema mismatch |
| Dataset mismatch | Medium | Medium | Use controlled traces as primary evidence, public datasets as secondary | Missing labels/features |
| Battery/performance overhead | Medium | High | Reduce feature set and sampling cost, profile frequently | Overhead exceeds target |
| Privacy concerns block deployment | Medium | High | Metadata-only default, pseudonymization, clear consent and retention | Supervisor or ethics feedback |

## Decision log template
- Decision ID
- Date
- Context
- Decision
- Alternatives considered
- Scope/time/risk impact
