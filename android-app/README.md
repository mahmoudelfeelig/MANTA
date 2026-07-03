# MANTA Endpoint (Android)

## Implemented P0 components
- `VpnService` lifecycle and foreground capture service.
- Local userspace forwarding engine for TCP/UDP traffic so capture does not break connectivity.
- Packet parsing to metadata-only flow records.
- App attribution resolver (`ConnectivityManager#getConnectionOwnerUid` where available).
- Room storage for flows, feature windows, anomaly scores, and export queue.
- Retention cleanup and export queue workers via WorkManager.
- Statistical, multivariate, and sequence anomaly detectors, plus bundled local ML scoring and optional one-class TFLite scoring.
- Compose UI for consent, backend config, export toggle, capture control, alert view, local purge, and dataset snapshot export.

## Implemented P1 and P2 components
- NetFlow/IPFIX-style flow export mapping in event payloads.
- Rich alert explanations with top feature contributors.
- Adaptive thresholds (global + per-app override support).
- Alert triage workflow (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- Policy sync worker for remote threshold/export/retention updates from backend.
- Remote-assisted scoring now exports transport/header-side window metadata such as TTL gap, TCP flag rates, TCP window mean, ACK timing, payload mean, load mean, and transport-metric availability.

## Security defaults
- Cleartext HTTP disabled by `network_security_config`.
- Public backend export requires HTTPS; local development hosts may use HTTP.
- Forwarder upstream sockets are explicitly protected with `VpnService.protect(...)` to avoid tunnel loops.
- API token and endpoint settings stored with `EncryptedSharedPreferences`.
- Device identifier export is pseudonymous (salted hash).
- Metadata-only capture policy (no payload storage).
- Policy fetch and event export support privacy-tiered export behavior, including a custom tier.

## Build
Open this folder in Android Studio and sync Gradle.

Minimum configuration:
- JDK 17
- Android SDK 35

## Operational notes
- First capture start requires VPN permission grant.
- Capture is blocked until consent is explicitly accepted in UI.
- Export requires a backend URL and API token in settings.
- Privacy modes include off, low, medium, strict, and custom field-level export controls.
- An exported automation receiver is available for adb-driven test orchestration.
- Managed app restrictions are supported for Android Enterprise / EMM deployment via `mdm/managed-configurations.json`.
- A bundled local model is loaded from `app/src/main/assets/models/anomaly-local.json`.
- If no TFLite model exists in `app/src/main/assets/models/anomaly.tflite`, scoring uses local + statistical paths.
- Dataset snapshots are written to app external files under `exports/` as privacy-mode-aware CSV.
- Policy sync expects backend endpoint `GET /api/v1/policy/device/{device_id_pseudo}`.
