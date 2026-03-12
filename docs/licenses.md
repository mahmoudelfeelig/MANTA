# MANTA License and Data Compliance

Use this checklist before public demos, thesis submission, or distribution of code, models, or datasets.

## Project policy
- Treat GPL repositories as design references unless the project licensing strategy is explicitly changed.
- Track provenance for every copied or adapted third-party snippet, asset, or script.
- Keep raw private captures separate from any derived dataset intended for experiments or publication.
- Re-check dependency and dataset terms before any public release.

## Raw vs derived data policy
- Raw packet captures and locally collected private traffic are internal research assets by default.
- Public, license-compatible datasets are preferred for thesis artifacts whenever they cover the same evaluation need.
- The default thesis path is now a public-only corpus; private collection is optional, not required.
- Derived datasets for experiments should be generated from scripts, not edited manually.
- Derived privacy views should be explicitly labeled, for example:
  - `off`
  - `low`
  - `medium`
  - `strict`
- If a dataset cannot be redistributed, publish only transformation scripts, manifests, and reproducibility metadata.

## Public dataset inventory
| Dataset | License / terms | Publication guidance |
|---|---|---|
| Westermo network traffic dataset | `CC BY 4.0` | Safe to cite and use as part of the public thesis corpus; redistribute only under the dataset terms. |
| Android Spyware Detection Through a VPN-Based App | `CC BY 4.0` | Safe to cite and use in the public thesis corpus. |
| Android Mischief Dataset | `CC BY 4.0` | Safe to cite and use in the public thesis corpus. |
| SDNCampus application-flow dataset | `CC BY 4.0` | Safe to cite and use in the public thesis corpus. |
| ITC-Net-Blend-60 scenario E | `CC BY 4.0` | Safe to cite and use in the public thesis corpus and privacy-leakage experiments. |
| CIC-AndMal2017 | Public research dataset from CIC | Use for experiments and citation, but treat redistribution more conservatively than the CC BY datasets. |
| PARROT2025_mitmproxy | See Zenodo record metadata | Use as an auxiliary public dataset only after confirming the exact record terms in the archived metadata. |
| Labeled Multi-Stage Android APT Datasets | `CC BY 4.0` | Safe to cite and use as an auxiliary suspicious-behavior dataset. |

## Dependency compliance checklist
- [x] project-level notice file maintained
- [x] GPL reference-only policy documented
- [ ] dependency license scan archived for backend
- [ ] dependency license scan archived for ML pipeline
- [ ] Android dependency/license reconciliation archived
- [ ] final shipped dependency set reviewed for compatibility

## Dataset compliance checklist
- [x] synthetic/project-generated dataset status documented
- [ ] external dataset terms archived with access dates
- [ ] redistribution rights confirmed for every published derived artifact
- [ ] thesis citations prepared for every external dataset used
- [ ] local capture consent and storage policy documented if any private collection is used
- [ ] raw-vs-derived separation enforced in collection and curation scripts

## Privacy-specific compliance checklist
- [ ] privacy-tier descriptions documented for thesis and user docs
- [ ] leakage-risk evaluation methodology documented
- [ ] data-minimization rationale written for exported fields
- [ ] retention and purge behavior documented for local and backend stores

## Suggested audit tooling
Backend:
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test] pip-licenses pipdeptree
pip-licenses --format=markdown --with-urls > ../docs/license-scan-backend.md
pipdeptree > ../docs/license-tree-backend.txt
```

ML pipeline:
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test] pip-licenses pipdeptree
pip-licenses --format=markdown --with-urls > ../docs/license-scan-ml.md
pipdeptree > ../docs/license-tree-ml.txt
```

## Exit criteria
- no unknown licenses in shipped dependencies
- no copied copyleft code beyond documented, intentional policy
- no dataset used without terms, attribution path, and publication decision documented
- raw private captures are never confused with redistributable benchmark artifacts
