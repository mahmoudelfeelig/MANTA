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
| EX-001 | Example project | https://example.com | abc1234 | MIT | `path/to/file.kt` | Adapted snippet | Rewritten for local architecture. |

`Reuse type` values:
- `Reference only`
- `Adapted snippet`
- `Copied file`
- `Generated from schema/tool`

## Runtime/build dependencies
List dependencies that ship with or are required to build the project.

| Ecosystem | Package | Version | License | Purpose | Included in distribution |
|---|---|---|---|---|---|
| Gradle | example-lib | 1.2.3 | Apache-2.0 | Networking client | Yes |

## Tools used in development
Track important tooling that may affect generated output or compliance.

| Tool | Version | License | Purpose | Output included in repo |
|---|---|---|---|---|
| OpenAPI Generator | 7.x | Apache-2.0 | API client generation | Yes/No |

## Datasets and data assets
Track dataset terms and publication constraints.

| Dataset | Source URL | Version/Date | License/Terms | Allowed use | Redistribution allowed | Citation required |
|---|---|---|---|---|---|---|
| Example dataset | https://example.com | 2026-01-01 | Research-only | Thesis experiments | No | Yes |

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
