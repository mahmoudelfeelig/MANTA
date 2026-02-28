# Licenses and Dataset Compliance

Use this checklist before demo/release and before thesis publication.

## Current audit snapshot (2026-02-22)
- Third-party registry exists and is updated: `../THIRD_PARTY_NOTICES.md`
- Direct GPL repositories are marked as reference-only (no direct code copy)
- Core shipped dependencies are predominantly Apache-2.0 / MIT / BSD
- Public dataset license terms are still marked as verify-before-publish

## Project policy
- GPL sources are used for architecture inspiration/reference unless project licensing strategy explicitly changes.
- Track reuse provenance (URL/version/commit + license/terms) for copied/adapted snippets and assets.
- Re-check dependency and dataset terms before any public release or thesis submission.
- Preserve notices/attributions required by dependencies and reused materials.

## Release / submission checklist

## 1) Project-level policy
- [x] Project license decision documented
- [x] GPL copy policy documented
- [x] Third-party notices file maintained
- [x] Reuse provenance (URL/version) tracked

## 2) Dependency compliance
For each newly added dependency:
- [x] package and version recorded
- [x] license recorded
- [x] compatibility with project licensing reviewed
- [x] notice obligations reviewed

## 3) Dataset compliance
- [x] project-generated synthetic dataset status documented
- [ ] external dataset terms archived with access date
- [ ] external dataset redistribution rights explicitly confirmed
- [ ] final thesis citations prepared for all external datasets

## 4) Pre-publication checks
- [ ] run dependency license scan and archive result files
- [x] ensure no local secrets or env files are committed
- [x] ensure no generated runtime artifacts are committed
- [x] ensure third-party notices are date-stamped

## Suggested tooling
Android:
- Gradle dependency tree + manual license reconciliation

Python:
- `pip-licenses`
- `pipdeptree`

## Optional audit commands
Backend:
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test] pip-licenses pipdeptree
pip-licenses --format=markdown --with-urls > ../docs/license-scan-backend.md
pipdeptree > ../docs/license-tree-backend.txt
```

ML:
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test] pip-licenses pipdeptree
pip-licenses --format=markdown --with-urls > ../docs/license-scan-ml.md
pipdeptree > ../docs/license-tree-ml.txt
```

## Expected optional outputs
- `docs/license-scan-backend.md`
- `docs/license-tree-backend.txt`
- `docs/license-scan-ml.md`
- `docs/license-tree-ml.txt`

## Exit criteria
- no unknown licenses in shipped dependencies
- no unapproved copyleft code copied into project source
- dataset terms and citations complete for all published experiment inputs
- `THIRD_PARTY_NOTICES.md` matches shipped artifacts and thesis acknowledgements
