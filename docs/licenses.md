# MANTA Licenses

## Dataset Licenses
- Westermo network traffic dataset, CC BY 4.0
- Android Spyware Detection Through a VPN-Based App, CC BY 4.0
- Android Mischief Dataset, CC BY 4.0
- SDNCampus application-flow dataset, CC BY 4.0
- ITC-Net-Blend-60 scenario E, CC BY 4.0
- CIC-AndMal2017, public research dataset from CIC
- PARROT2025_mitmproxy, see Zenodo record metadata
- Labeled Multi-Stage Android APT Datasets, CC BY 4.0

## Derived Artifact Policy
- The privacy leakage and encrypted-flow fingerprint benchmarks reuse the same public-only corpus and do not introduce a separate proprietary dataset.
- Derived packet, flow-sequence, and feature-manifest artifacts remain governed by the upstream dataset terms and should only be redistributed where the source dataset license explicitly allows it.
- The thesis evidence bundle should prefer normalized feature reports and aggregate benchmark outputs over raw capture redistribution unless the upstream dataset terms clearly permit shipping the raw traces.

## Audit Commands
Backend
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test] pip-licenses pipdeptree
pip-licenses --format=markdown --with-urls > ../docs/license-scan-backend.md
pipdeptree > ../docs/license-tree-backend.txt
```

ML pipeline
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test] pip-licenses pipdeptree
pip-licenses --format=markdown --with-urls > ../docs/license-scan-ml.md
pipdeptree > ../docs/license-tree-ml.txt
```
