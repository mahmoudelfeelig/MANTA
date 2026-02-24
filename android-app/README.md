# Android App

## Implemented P0 components
- `VpnService` lifecycle and foreground capture service.
- Local userspace forwarding engine for TCP/UDP traffic so capture does not break connectivity.
- Packet parsing to metadata-only flow records.
- App attribution resolver (`ConnectivityManager#getConnectionOwnerUid` where available).
- Room storage for flows, feature windows, anomaly scores, and export queue.
- Retention cleanup and export queue workers via WorkManager.
- Statistical anomaly detector, bundled linear ML scorer, and optional TFLite scorer.
- Compose UI for consent, backend config, export toggle, capture control, alert view, local purge, and dataset snapshot export.

## Implemented P1 and P2 components
- NetFlow/IPFIX-style flow export mapping in event payloads.
- Rich alert explanations with top feature contributors.
- Adaptive thresholds (global + per-app override support).
- Alert triage workflow (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- Policy sync worker for remote threshold/export/retention updates from backend.

## Security defaults
- Cleartext HTTP disabled by `network_security_config`.
- Backend exporter rejects non-HTTPS URLs.
- Forwarder upstream sockets are explicitly protected with `VpnService.protect(...)` to avoid tunnel loops.
- API token and endpoint settings stored with `EncryptedSharedPreferences`.
- Device identifier export is pseudonymous (salted hash).
- Metadata-only capture policy (no payload storage).
- Policy fetch and event export both require HTTPS endpoints.

## Build
Open this folder in Android Studio and sync Gradle.

Minimum configuration:
- JDK 17
- Android SDK 35

## Operational notes
- First capture start requires VPN permission grant.
- Capture is blocked until consent is explicitly accepted in UI.
- Export requires a backend URL and API token in settings.
- A bundled linear model is loaded from `app/src/main/assets/models/anomaly-linear.json`.
- If no TFLite model exists in `app/src/main/assets/models/anomaly.tflite`, scoring uses linear + statistical paths.
- Dataset snapshots are written to app external files under `exports/` as anonymized CSV.
- Policy sync expects backend endpoint `GET /api/v1/policy/device/{device_id_pseudo}`.
