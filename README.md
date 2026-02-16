# feel-bachelor
Anomaly detection of application network traffic on Android devices.

## Thesis planning docs
- `docs/features-and-requirements.md` - scope, MVP features, requirements, and experiment/evaluation plan.
- `docs/architecture-and-resources.md` - system architecture, integration model, required resources, and risk register.
- `docs/references.md` - curated implementation, standards, datasets, and research references.
- `docs/license-audit-checklist.md` - implementation-time compliance checklist.
- `THIRD_PARTY_NOTICES.md` - running register of reused code, dependencies, and data terms.

## Immediate execution order
- Freeze scope and MVP in `docs/features-and-requirements.md`.
- Build Android VPN metadata collector prototype.
- Establish SIEM/Wazuh ingestion path and validate event schema.
- Run first controlled experiments and establish baseline metrics.
