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

- MANTA now distinguishes two privacy claims:
  - `release privacy`: privacy of the exported or derived feature representation
  - `observer leakage risk`: privacy against a passive network observer over encrypted-flow sequences
- `medium` and `strict` should pass the release-privacy checks.
- If the thesis also claims tunnel-observer privacy, they must additionally pass the observer-level checks.
- The privacy gate should therefore emit:
  - `release_privacy_pass`
  - `observer_privacy_pass`
  - `overall_pass`, interpreted according to the configured claim scope

- The anomaly/privacy utility benchmarks should use the grouped source-aware split keyed by dataset source, environment, app family, and time bucket whenever the corpus metadata supports it.
- The metadata leakage benchmark should use per-class grouped holdout over dataset/environment/session/time groups, not a plain random row split, and should report the strongest attacker across:
  - exact `app_id`
  - `app_family`
  - `dataset_source`
  - `context_bucket`
  - `destination_behavior`
- The leakage benchmark should include at least a linear model, a boosted-tree model, and a small neural attacker, and should report both raw accuracy and normalized leakage over chance.
- The `app_id` task should also include open-world unknown-app detection based on held-out app classes.
- The privacy gate should not rely only on exact `app_id` leakage. It should also evaluate at least:
  - `app_family` metadata leakage
  - `destination_behavior` metadata leakage
  - observer-level `app_id` leakage from the encrypted-flow sequence benchmark
  - observer-level `app_family` leakage from the encrypted-flow sequence benchmark

- `low`: no hard degradation gate, should be approximately equal to off
- `medium`: no more than `5%` relative drop in `roc_auc` or `pr_auc`, `app_reidentification_accuracy <= 0.45`, `normalized_app_reidentification <= 0.35`, `app_family_normalized_leakage <= 0.50`, `destination_behavior_normalized_leakage <= 0.50`, observer `app_id_normalized_leakage <= 0.25`, and observer `app_family_normalized_leakage <= 0.60`
- `strict`: no more than `10%` relative drop in `roc_auc` or `pr_auc`, `app_reidentification_accuracy <= 0.25`, `normalized_app_reidentification <= 0.15`, `app_family_normalized_leakage <= 0.30`, `destination_behavior_normalized_leakage <= 0.30`, observer `app_id_normalized_leakage <= 0.10`, and observer `app_family_normalized_leakage <= 0.35`
- `custom`: must document the exact field mask and compare against the nearest stricter standard tier

## Observer-inference audit

- Thesis-grade runs should also archive an encrypted-flow sequence fingerprint audit over the same public corpus.
- This benchmark is an observer-leakage audit for encrypted flow sequences. It is part of the `medium` and `strict` privacy gate whenever those tiers are used to support a tunnel-observer privacy claim.
- Minimum tasks:
  - `app_id`
  - `app_family`
  - `dataset_source`
  - `context_bucket`
- The benchmark should use grouped session/source holdout and open-world unknown-app detection for `app_id`.
- If the thesis makes a tunnel-observer privacy claim, that claim must explicitly reference the sequence benchmark rather than only the metadata privacy tiers.
- The observer audit is no longer advisory-only for `medium` and `strict`; it should be incorporated into the privacy gate verdicts.

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
- evaluation protocol matrix
- privacy tier or custom mask
- privacy leakage attack suite
- encrypted-flow sequence fingerprint report
- privacy gate verdict
- model family and version
- training/evaluation reports
- replay/integration results
- threshold-gate verdicts

Use `tools/check_manta_validation.py` for report-level gate checks.
