# Android App (P0 Scaffold)

## Implemented P0 components
- `VpnService` lifecycle and foreground capture service.
- Packet parsing to metadata-only flow records.
- App attribution resolver (`ConnectivityManager#getConnectionOwnerUid` where available).
- Room storage for flows, feature windows, anomaly scores, and export queue.
- Retention cleanup and export queue workers via WorkManager.
- Statistical anomaly detector and TFLite scorer wrapper.
- Compose UI for backend config, export toggle, capture control, alert view, and local purge.

## Security defaults
- Cleartext HTTP disabled by `network_security_config`.
- Backend exporter rejects non-HTTPS URLs.
- API token and endpoint settings stored with `EncryptedSharedPreferences`.
- Device identifier export is pseudonymous (salted hash).
- Metadata-only capture policy (no payload storage).

## Build
Open this folder in Android Studio and sync Gradle.

Minimum configuration:
- JDK 17
- Android SDK 35

## Operational notes
- First capture start requires VPN permission grant.
- Export requires a backend URL and API token in settings.
- If no TFLite model exists in `app/src/main/assets/models/anomaly.tflite`, scoring falls back to statistical baseline.
