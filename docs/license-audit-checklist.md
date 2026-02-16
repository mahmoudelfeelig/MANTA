# License Audit Checklist

Use this checklist during implementation and before sharing any code, binaries, or datasets.

## Development start checklist
- Define target project license for your own code.
- Confirm GPL handling rule:
  - no direct GPL code copy into non-GPL codebase.
- Create and maintain `THIRD_PARTY_NOTICES.md`.
- Record all direct snippet reuse with source URL and commit hash.
- Record all datasets with explicit usage and redistribution terms.

## Dependency onboarding checklist
For every new dependency:
- Record package name, version, and license.
- Verify license compatibility with your project license.
- Check if NOTICE file obligations exist (Apache-2.0 and similar).
- Check whether dependency introduces transitive copyleft obligations.
- Add dependency entry to `THIRD_PARTY_NOTICES.md`.

## Implementation-phase checks
- Re-check licenses after dependency version bumps.
- Keep generated code provenance:
  - schema source
  - generator tool version
  - generation date
- Avoid copying documentation text beyond short quotations.
- Keep publication-safe attribution notes for all non-trivial reused logic.

## Dataset compliance checks
- Verify dataset license or terms page is archived (URL + access date).
- Confirm allowed use includes academic research and your planned publication format.
- Confirm redistribution status for raw data and derived features.
- Remove or anonymize sensitive identifiers as required by terms and ethics policy.
- Store required dataset citations in thesis draft and repo docs.

## Pre-demo / pre-submission checks
- Run dependency license scan for Android and ML components.
- Review transitive dependencies manually for unknown/ambiguous licenses.
- Ensure `THIRD_PARTY_NOTICES.md` is complete and date-stamped.
- Ensure citations and acknowledgements are present in thesis text.
- Confirm no restricted dataset content is accidentally committed.

## Suggested tooling
Use tools based on the tech stack once scaffold is in place.

Android/Gradle options:
- Gradle license reporting plugins.
- Dependency tree export + manual license reconciliation.

Python/ML options:
- `pip-licenses`
- `pipdeptree` plus manual license checks where metadata is missing.

General:
- SPDX-style IDs in internal notes.
- A small script to fail CI when unknown licenses are detected.

## Audit log template
| Date | Scope | Findings | Actions | Reviewer |
|---|---|---|---|---|
| YYYY-MM-DD | Android deps | 2 unknown licenses | Replaced one, pinned one | Name |

## Exit criteria
- No unknown licenses in shipped dependencies.
- No direct GPL code copy in non-GPL codebase (unless intentionally relicensed).
- All datasets used in experiments have explicit permitted use and citation coverage.
- Third-party notices and thesis citations are consistent.
