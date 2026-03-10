# MANTA References

This is the curated implementation and literature register for:
- system design
- datasets
- privacy/utility benchmarking
- anomaly-detection model comparisons
- thesis writing for `MANTA: Can We Detect Threats Without Seeing the Payload?`

## Thesis story anchor
MANTA is framed as an anomaly-first hybrid IDS for encrypted mobile traffic. The literature story should move in this order:
- payload-free anomaly detection is feasible
- encrypted traffic still exposes behavioral structure
- multivariate and self-supervised methods improve anomaly quality
- privacy-preserving and federated methods can reduce leakage while retaining utility
- hybrid anomaly/context systems are practically stronger than pure rule engines

## Core literature register
All links below are intended to be directly readable full-text or open-access pages.

| Paper / source | Link | Why it matters for MANTA |
|---|---|---|
| Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection | https://arxiv.org/abs/1802.09089 | Lightweight online anomaly detection reference and strong anomaly-first baseline. |
| N-BaIoT: Network-based Detection of IoT Botnet Attacks Using Deep Autoencoders | https://arxiv.org/abs/1805.03409 | Deep autoencoder anomaly detection with deployment-oriented framing. |
| ET-SSL: Self-Supervised Learning for Anomaly Detection in Encrypted Traffic | https://www.nature.com/articles/s41598-025-08568-0 | Strong reference for privacy-compatible representation learning over encrypted traffic. |
| ARGUS: Context-Based Detection of Stealthy IoT Infiltration Attacks | https://www.usenix.org/conference/usenixsecurity23/presentation/rieger | Good comparison point for context-enriched anomaly detection. |
| NetVigil: Robust and Low-Cost Anomaly Detection for East-West Data Center Security | https://www.usenix.org/conference/nsdi24/presentation/hsieh | Good modern reference for robust and low-cost anomaly detection design. |
| An adaptive smartphone anomaly detection model based on data mining | https://link.springer.com/article/10.1186/s13638-018-1158-6 | Mobile-device anomaly detection reference that fits the smartphone angle directly. |
| Deep Learning for Encrypted Traffic Classification and Unknown Data Detection | https://www.mdpi.com/1424-8220/22/19/7643 | Useful for the classification/unknown-detection side of the comparison section. |
| A Mobile Application-Classifying Method Based on a Graph Attention Network from Encrypted Network Traffic | https://www.mdpi.com/2079-9292/12/10/2313 | Mobile encrypted-traffic classification comparison point. |
| Artificial Intelligence-Based Anomaly Detection Technology over Encrypted Traffic: A Systematic Literature Review | https://www.mdpi.com/1424-8220/24/3/898 | Survey anchor for related-work positioning. |
| Privacy-Preserving FL-Based IDS for Cyber-Physical Systems | https://www.mdpi.com/2227-7390/12/20/3194 | Federated privacy-preserving IDS training reference. |
| Enhancing Privacy-Preserving Intrusion Detection through Federated Learning | https://www.mdpi.com/2079-9292/12/16/3382 | Strong reference for collaborative training without central raw-data collection. |
| NIDS-FGPA: Privacy-Preserved Federated Learning for Network Intrusion Detection | https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0308639 | Secure-aggregation-oriented federated NIDS reference. |
| PD-PAn: Prefix- and Distribution-Preserving Packet Anonymization | https://www.mdpi.com/2079-9292/12/20/4369 | Useful for the dataset transformation and anonymization discussion. |

## Literature-to-thesis mapping
- Use `Kitsune`, `N-BaIoT`, `ARGUS`, and `NetVigil` to justify the anomaly side.
- Use the mobile encrypted-traffic classification papers to justify why classification baselines must still be compared.
- Use `ET-SSL` and the federated/privacy papers to justify the privacy-preserving extension and the custom privacy-tier evaluation.
- Use `PD-PAn` to justify derived anonymized dataset variants and the utility-leakage trade-off discussion.

## Model-comparison section targets
The paper should compare at least these model families:
- rigorous multivariate statistical anomaly detector
- one-class or reconstruction neural anomaly detector
- drift-aware anomaly stack
- supervised tabular classifier
- remote neural classifier
- hybrid late-fusion model
- privacy-preserving and federated variants of the strongest models

## Implementation and platform references
| Reference | Link | Why relevant |
|---|---|---|
| Android `VpnService` | https://developer.android.com/reference/android/net/VpnService | Core capture primitive on Android. |
| WorkManager | https://developer.android.com/topic/libraries/architecture/workmanager | Reliable export, sync, and retention jobs. |
| Room persistence library | https://developer.android.com/training/data-storage/room | Local on-device storage. |
| RFC 7011 (IPFIX) | https://www.rfc-editor.org/rfc/rfc7011 | Flow export/event schema grounding. |
| RFC 7012 (IPFIX information model) | https://www.rfc-editor.org/rfc/rfc7012 | Canonical flow field semantics. |
| RFC 3954 (NetFlow v9) | https://www.rfc-editor.org/rfc/rfc3954 | Template-based flow export reference. |
| TensorFlow Lite guide | https://www.tensorflow.org/lite/guide | On-device model deployment path. |
| scikit-learn IsolationForest docs | https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html | Classical anomaly baseline candidate. |
| Wazuh API reference | https://documentation.wazuh.com/current/user-manual/api/reference.html | SIEM integration reference. |

## Datasets already in play or planned
| Dataset / source | Link | Role in MANTA |
|---|---|---|
| Westermo network traffic dataset | https://github.com/westermo/network-traffic-dataset | Rich open attack/anomaly source. |
| Android Spyware Detection Through a VPN-Based App | https://data.mendeley.com/datasets/mhvgtywrxf/1 | Android/mobile malware-oriented traffic. |
| SDNCampus application-flow dataset | https://data.mendeley.com/datasets/wvp9tksn72/1 | Benign app diversity. |
| PARROT2025_mitmproxy | https://zenodo.org/records/16368932 | Mobile/browser behavior enrichment. |
| Android Mischief Dataset | https://data.mendeley.com/datasets/xbx2j63xfd/2 | Android RAT traffic with benign and malicious phases. |
| CIC-AndMal2017 | https://www.unb.ca/cic/datasets/andmal2017.html | Official Android malware traffic and flow benchmark on real devices. |
| Labeled Multi-Stage Android APT Datasets | https://data.mendeley.com/datasets/bdtn9vj7d7/3 | Android device-behavior dataset for multi-stage attack evaluation. |

## Citation policy
- Prefer the paper or official project page over secondary summaries.
- Keep this file as the working register for thesis citations and implementation rationale.
- Add every paper/dataset actually used in experiments to `thesis-paper/bibliography/references.bib`.
