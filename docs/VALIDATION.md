# MANTA Validation Gates

This document defines the default acceptance gates for MANTA experiments, regression checks, and thesis figures. These are the baseline targets unless a specific experiment explicitly documents a different protocol.

## Identity
MANTA is evaluated as an anomaly-first hybrid IDS for encrypted mobile and endpoint traffic. Validation therefore has to cover:
- anomaly quality
- context-assisted ranking quality
- privacy degradation
- on-device performance
- backend/export reliability

## Default model-quality gates

### On-device anomaly path
- Android linear or TFLite anomaly report:
  - `roc_auc >= 0.95`
  - `pr_auc >= 0.90`
  - `f1 >= 0.90`
  - `precision >= 0.88`
  - `recall >= 0.92`
- One-class TFLite autoencoder report:
  - `roc_auc >= 0.90`
  - `pr_auc >= 0.88`
  - `f1 >= 0.86`
  - `precision >= 0.84`
  - `recall >= 0.88`
- Threshold sanity:
  - recommended threshold must stay in `[0.02, 0.85]`
  - thresholds below `0.02` or above `0.85` are treated as calibration warnings

### Remote anomaly / context path
- Remote backend report:
  - `roc_auc >= 0.95`
  - `pr_auc >= 0.92`
  - `f1 >= 0.90`
  - `precision >= 0.88`
  - `recall >= 0.92`
- Training corpus sanity:
  - at least `500` anomalous windows
  - at least `10_000` benign windows

## Privacy-tier gates

The privacy tiers are compared against the same benchmark split.

- `PSEUDONYMOUS`: no hard degradation gate, should be approximately equal to full
- `SEMANTIC_PRIVATE`: no more than `5%` relative drop in `roc_auc` or `pr_auc`
- `STRICT`: no more than `10%` relative drop in `roc_auc` or `pr_auc`
- `CUSTOM`: must document the exact field mask and compare against the nearest stricter standard tier

## Reliability gates
- Export queue success rate in soak/replay testing: `>= 99%`
- Policy sync success rate in stable-network integration tests: `>= 95%`
- Device heartbeat visibility on backend/dashboard: `>= 99%` after successful ping/heartbeat

## Performance gates
- On-device scoring latency:
  - `p95 <= 25 ms` per scored window
  - `p99 <= 40 ms`
- Backend inference latency:
  - `p95 <= 150 ms` for remote inference endpoint under nominal load
- Memory:
  - on-device incremental detector state must remain within the configured retention budget

## Alerting quality gates
- False alerts on benign-only replay:
  - `<= 1.5` alerts per app-day at default thresholds
- Controlled suspicious scenario recall:
  - `>= 90%` of scripted browser-risk and known-danger scenarios should produce at least one non-low finding in the evaluation window

## Required experiment outputs
Every thesis-grade run should archive:
- config snapshot
- dataset manifest
- privacy tier or custom mask
- model family and version
- training/evaluation reports
- replay/integration results
- threshold-gate verdicts

Use `tools/check_manta_validation.py` for report-level gate checks.
