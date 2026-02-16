# References

This is the working source list for architecture decisions, implementation, experiments, and thesis writing.

## License policy for this thesis project
- GPL sources are used for architecture inspiration only unless we decide to license our own code as GPL-compatible.
- MIT, Apache-2.0, and BSD-3-Clause sources can be reused in code with attribution and license notice preservation.
- Documentation and standards are primarily for citation and design guidance; do not copy large text verbatim.
- Dataset usage must follow each dataset's explicit terms, attribution, and redistribution constraints.
- Before shipping any prototype publicly, run a final dependency and source-license audit.

## Core implementation and inspiration
| Reference | Link | License | Why relevant | License usage note |
|---|---|---|---|---|
| NetGuard (Android local VPN firewall) | https://github.com/M66B/NetGuard | GPL-3.0 | Strong practical reference for `VpnService` lifecycle and packet handling on Android. | Do not copy source into non-GPL project; use for design patterns and reimplementation. |
| elastic-agent-android (prototype-style Android telemetry app) | https://github.com/swiftbird07/elastic-agent-android/tree/main/app/src/main/java/de/swiftbird/elasticandroid | MIT | Useful structure for endpoint telemetry flow and backend export patterns. | Permissive reuse allowed with attribution and license retention. |
| PCAPdroid | https://github.com/emanuele-f/PCAPdroid | GPL-3.0 | Good reference for traffic capture UX and Android packet capture constraints. | Treat as inspiration only unless project licensing changes to GPL-compatible. |

## Android platform documentation
| Reference | Link | License/terms | Why relevant | License usage note |
|---|---|---|---|---|
| Android `VpnService` | https://developer.android.com/reference/android/net/VpnService | Developer docs terms | Core API for on-device VPN capture design. | Use as technical reference and cite URL; avoid copying large doc text. |
| Android networking overview | https://developer.android.com/develop/connectivity/network-ops/reading-network-state | Developer docs terms | Useful for connectivity state handling and resilient networking behavior. | Same as above. |
| Foreground services | https://developer.android.com/develop/background-work/services/foreground-services | Developer docs terms | Needed for reliable long-running VPN capture. | Same as above. |
| WorkManager | https://developer.android.com/topic/libraries/architecture/workmanager | Developer docs terms | Useful for deferred/retry export jobs and robust background sync. | Same as above. |
| Room persistence library | https://developer.android.com/training/data-storage/room | Developer docs terms | Primary local storage layer for flows, features, and export queue. | Same as above. |

## Network flow standards and telemetry schema
| Reference | Link | License/terms | Why relevant | License usage note |
|---|---|---|---|---|
| RFC 7011 (IPFIX protocol specification) | https://www.rfc-editor.org/rfc/rfc7011 | IETF Trust legal provisions | Core standard for flow-style record design. | Cite and paraphrase; avoid large verbatim excerpts. |
| RFC 7012 (IPFIX information model) | https://www.rfc-editor.org/rfc/rfc7012 | IETF Trust legal provisions | Defines reusable flow field semantics for schema design. | Cite and paraphrase. |
| RFC 3954 (Cisco NetFlow v9) | https://www.rfc-editor.org/rfc/rfc3954 | IETF Trust legal provisions | Practical NetFlow template/reference for event mapping. | Cite and paraphrase. |
| IANA IPFIX registry | https://www.iana.org/assignments/ipfix/ipfix.xhtml | IANA terms | Canonical field IDs for interoperability-minded schema choices. | Use field definitions with attribution. |

## SIEM and backend integration
| Reference | Link | License | Why relevant | License usage note |
|---|---|---|---|---|
| Wazuh API reference | https://documentation.wazuh.com/current/user-manual/api/reference.html | Product components include GPLv2 and Apache-2.0 | Primary source for manager communication endpoints and auth. | API integration is fine; do not copy internal Wazuh source unless license obligations are met. |
| Wazuh documentation root | https://documentation.wazuh.com/current/ | Documentation terms | Ingestion, indexing, rules, and dashboard operational guidance. | Cite docs; avoid copying large doc text blocks. |
| OpenAPI Generator | https://openapi-generator.tech/ | Apache-2.0 | Generate typed API clients for backend manager communication. | Tool is permissive; generated code is generally user-owned per project docs. |

## On-device ML and anomaly detection
| Reference | Link | License | Why relevant | License usage note |
|---|---|---|---|---|
| TensorFlow Lite guide | https://www.tensorflow.org/lite/guide | TensorFlow Apache-2.0 (docs and samples have separate site terms) | On-device inference runtime and deployment workflow. | Library use is permissive; keep NOTICE and dependency license records. |
| TensorFlow Lite Android quickstart | https://www.tensorflow.org/lite/android | TensorFlow Apache-2.0 | Android integration details for model loading/inference. | Same as above. |
| Keras timeseries anomaly example (autoencoder) | https://keras.io/examples/timeseries/timeseries_anomaly_detection/ | Keras project Apache-2.0 | Practical baseline approach for anomaly modeling with sequence data. | Reuse concepts and adapt code with attribution. |
| scikit-learn Isolation Forest | https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html | BSD-3-Clause | Classical unsupervised baseline for anomaly scoring. | Permissive use; include attribution in dependency docs. |
| SHAP documentation | https://shap.readthedocs.io/en/latest/ | SHAP library MIT | Candidate explanation method for feature contribution insights. | Permissive use; include license notice when distributing components. |

## Datasets and benchmarking sources
| Reference | Link | License/terms status | Why relevant | License usage note |
|---|---|---|---|---|
| CICAndMal2017 dataset page | https://www.unb.ca/cic/datasets/andmal2017.html | Check dataset page terms and request conditions | Mobile malware traffic benchmark candidate. | Verify redistribution/citation terms before publishing derived artifacts. |
| CICMalDroid 2020 dataset page | https://www.unb.ca/cic/datasets/maldroid-2020.html | Access typically via request form for research use | Additional Android malware traffic benchmark candidate. | Keep proof of allowed use and include required citation text. |
| Android Malware Dataset (Kaggle mirror variants) | https://www.kaggle.com/ | Varies per dataset (CC, GPL, ODbL, proprietary, unknown) | Practical source for exploratory benchmark supplements. | Approve each dataset license individually; avoid mixing incompatible terms in redistributed bundles. |

## Privacy, ethics, and compliance framing
| Reference | Link | License/terms | Why relevant | License usage note |
|---|---|---|---|---|
| GDPR official portal | https://gdpr.eu/ | Website terms; legal-text reference | Baseline privacy principles for data minimization and transparency framing. | Treat as legal context reference, not as reusable software asset. |
| EDPB guidelines (European Data Protection Board) | https://edpb.europa.eu/our-work-tools/our-documents/guidelines_en | Public regulatory guidance terms | Better legal/ethical grounding for consent, purpose limitation, and retention discussion. | Cite guideline identifiers and publication dates. |
| OWASP MASVS | https://mas.owasp.org/MASVS/ | OWASP project terms | Mobile app security best practices relevant to secure endpoint implementation. | Use as compliance guidance and cite version used. |

## Thesis writing and scientific method support
| Reference | Link | License/terms | Why relevant | License usage note |
|---|---|---|---|---|
| ACM Digital Library | https://dl.acm.org/ | Publisher access and copyright terms | Primary literature source for anomaly detection and mobile security papers. | Use proper citation; do not redistribute full copyrighted PDFs. |
| IEEE Xplore | https://ieeexplore.ieee.org/ | Publisher access and copyright terms | Primary literature source for networking and IDS comparisons. | Same as above. |
| Google Scholar | https://scholar.google.com/ | Indexing/discovery service terms | Fast discovery and citation chaining for related work. | Use for discovery, then verify primary source licenses/copyright. |

## Compliance checklist for implementation
- Keep a `THIRD_PARTY_NOTICES` file once coding starts.
- Track each direct code reuse snippet with source URL, commit hash, and license.
- Avoid direct code copy from GPL repositories unless your distribution license strategy is decided.
- Record dataset license/terms and citation requirement before using any dataset in experiments.
- Run a dependency license scan before sharing binaries or source outside the thesis environment.

## Verification note
License statuses above were checked from project repositories and official docs where possible on February 7, 2026.  
Re-check before final submission or any public release.
