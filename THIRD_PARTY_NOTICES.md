# Third-Party Notices

This file tracks third-party code, tools, datasets, and documentation used in this project.

## Project policy
- Preserve original license notices for any reused code.
- Keep commit hashes for copied or adapted snippets.
- Do not copy code from GPL sources into non-GPL project code unless project licensing is intentionally made GPL-compatible.
- Verify dataset usage, citation, and redistribution terms before publishing artifacts.

## Direct code reuse and adaptations
Add one row per reused/adapted snippet or file.

| ID | Source | URL | Commit/Version | License | Local files | Reuse type | Notes |
|---|---|---|---|---|---|---|---|
| REF-001 | NetGuard | https://github.com/M66B/NetGuard | latest consulted on 2026-02-07 | GPL-3.0 | N/A | Reference only | Used for architecture inspiration only; no direct source copy. |
| REF-002 | elastic-agent-android | https://github.com/swiftbird07/elastic-agent-android | `799a8b79f42009a860d5b5c83e0f8a4897ac6a39` | MIT | N/A | Reference only | Used for endpoint telemetry structure ideas. |
| REF-003 | PCAPdroid | https://github.com/emanuele-f/PCAPdroid | latest consulted on 2026-02-07 | GPL-3.0 | N/A | Reference only | Used for UX and capture constraints awareness only. |

`Reuse type` values:
- `Reference only`
- `Adapted snippet`
- `Copied file`
- `Generated from schema/tool`

## Runtime/build dependencies
List dependencies that ship with or are required to build the project.

| Ecosystem | Package | Version | License | Purpose | Included in distribution |
|---|---|---|---|---|---|
| Android/Gradle | androidx.room:room-runtime | 2.6.1 | Apache-2.0 | Local metadata storage | Yes |
| Android/Gradle | androidx.work:work-runtime-ktx | 2.9.1 | Apache-2.0 | Retry and retention background jobs | Yes |
| Android/Gradle | com.squareup.okhttp3:okhttp | 4.12.0 | Apache-2.0 | Secure backend transport | Yes |
| Android/Gradle | org.tensorflow:tensorflow-lite | 2.14.0 | Apache-2.0 | On-device inference runtime | Yes |
| Python | fastapi | 0.115.6 | MIT | Backend ingest API | Yes |
| Python | httpx | 0.28.1 | BSD-3-Clause | Backend forwarding client | Yes |
| Python | scikit-learn | 1.6.0 | BSD-3-Clause | Baseline anomaly model | No (training stage) |

## Tools used in development
Track important tooling that may affect generated output or compliance.

| Tool | Version | License | Purpose | Output included in repo |
|---|---|---|---|---|
| OpenAPI Generator | planned | Apache-2.0 | Optional typed backend client generation | No |

## Datasets and data assets
Track dataset terms and publication constraints.

| Dataset | Source URL | Version/Date | License/Terms | Allowed use | Redistribution allowed | Citation required |
|---|---|---|---|---|---|---|
| CICAndMal2017 | https://www.unb.ca/cic/datasets/andmal2017.html | access pending | Verify on access | Thesis experiments | Verify on access | Yes |
| CICMalDroid 2020 | https://www.unb.ca/cic/datasets/maldroid-2020.html | access pending | Verify on access | Thesis experiments | Verify on access | Yes |

## Documentation and standards references
Keep references for quoted or closely paraphrased standards/docs.

| Reference | URL | Terms | Used in |
|---|---|---|---|
| RFC example | https://www.rfc-editor.org/ | IETF Trust terms | Schema design |

## Sign-off
- Last reviewed on: `YYYY-MM-DD`
- Reviewed by: `NAME`
- Notes:
  - Pending items:
  - Exceptions:
