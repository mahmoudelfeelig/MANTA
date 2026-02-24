# Testing and Validation

## Objective
This document defines the full verification protocol for publish readiness:
- automated tests (backend, ML, Android unit)
- manual Android behavior and UX validation
- backend connectivity verification
- experiment reproducibility checks

## Automated test suites

## Backend adapter
Command:
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest -q -s tests
```
Pass criteria:
- all tests pass
- no failing schema/auth/queue/triage/policy/incident/forensics tests

Covered files:
- `backend-adapter/tests/test_main.py`
- `backend-adapter/tests/test_policy_and_triage_edges.py`
- `backend-adapter/tests/test_model_validation.py`
- `backend-adapter/tests/test_config.py`

## ML pipeline
Command:
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest -q -s tests
```
Pass criteria:
- all tests pass
- no failing feature extraction, evaluation artifact, comparison, drift/policy simulation, privacy ablation, retraining dataset, or Android model export tests

Covered files:
- `ml-pipeline/tests/test_features.py`
- `ml-pipeline/tests/test_calibration.py`
- `ml-pipeline/tests/test_explain.py`
- `ml-pipeline/tests/test_pipeline_integration.py`
- `ml-pipeline/tests/test_generate_controlled_dataset.py`
- `ml-pipeline/tests/test_run_experiment_suite.py`
- `ml-pipeline/tests/test_ids_baseline.py`
- `ml-pipeline/tests/test_compare_baselines.py`
- `ml-pipeline/tests/test_privacy_ablation.py`
- `ml-pipeline/tests/test_train_android_model.py`
- `ml-pipeline/tests/test_evaluate_outputs.py`
- `ml-pipeline/tests/test_drift_report.py`
- `ml-pipeline/tests/test_simulate_policy.py`
- `ml-pipeline/tests/test_build_retraining_dataset.py`

## Android unit tests
Command:
```bash
cd android-app
./gradlew :app:testDebugUnitTest --stacktrace
```
Pass criteria:
- all JVM unit tests pass
- no compile errors
- no resource/manifest failures

Covered files:
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/FlowAggregatorTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/FlowPipelineIntegrationTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/IpfixMapperTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/RemotePolicyParserTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/StatisticalAnomalyDetectorTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/ThresholdResolverTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/ExplanationFormatterTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/LinearModelScorerTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/AdvancedDetectionComponentsTest.kt`

## Manual Android validation (required)
Run on at least one emulator and one physical Android device if available.

## A) Consent and capture lifecycle
1. Launch app from clean install.
2. Verify consent card appears.
3. Try `Start capture` before consent.
4. Accept consent.
5. Start capture and grant VPN permission.
6. Stop capture.
7. Repeat start/stop 5 times.

Pass criteria:
- capture blocked pre-consent
- no crash on start/stop
- foreground notification appears while running and disappears when stopped
- no `FATAL EXCEPTION` in logcat

## A.1) Connectivity under capture
1. Start capture and keep it active for at least 2 minutes.
2. Open browser and load multiple HTTPS websites.
3. Run a DNS-dependent app action (e.g., app search/refresh).
4. Stop capture and confirm connectivity remains normal.

Pass criteria:
- internet connectivity remains functional while capture is active
- no persistent DNS failures while capture is active
- no routing loop errors in logcat (forwarder sockets are protected via `VpnService.protect(...)`)

## B) Storage, export snapshot, purge
1. Run capture for 2-5 minutes while generating app traffic.
2. Tap `Export dataset snapshot`.
3. Verify CSV exists in app external files `exports/` directory.
4. Tap `Purge local data`.

Pass criteria:
- snapshot path is returned in UI
- exported CSV contains pseudonymized identifiers
- local alerts/data cleared after purge

## C) Alerting behavior
1. Set thresholds low (for smoke test).
2. Capture for 1-2 minutes.
3. Verify alerts populate.
4. Change triage state for sample alerts.

Pass criteria:
- alert cards render with score, severity, explanation, and triage controls
- triage status changes persist locally

## D) Policy sync behavior
1. With export disabled or non-HTTPS backend, observe periodic worker behavior.
2. Ensure no retry storm.
3. Configure valid HTTPS backend + token.
4. Tap `Sync policy`.

Pass criteria:
- when not configured, policy worker exits success (skip) rather than endless retry
- when configured, policy fetch and apply succeed

## Backend connectivity test (thorough)
The Android client enforces HTTPS for backend endpoints.

## 1) Backend runtime
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
export ADAPTER_SHARED_TOKEN='replace-with-long-random-token'
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 2) Expose backend via HTTPS tunnel
Examples: ngrok or cloudflared.
Use the HTTPS public URL in app settings.

## 3) App config + capture
1. Set backend URL to HTTPS tunnel URL.
2. Set API token to same `ADAPTER_SHARED_TOKEN`.
3. Enable export.
4. Start capture and generate traffic for 2-3 minutes.

## 4) Verify queue state
PowerShell:
```powershell
$TOKEN = "replace-with-long-random-token"
$BASE = "http://127.0.0.1:8080"
$H = @{ Authorization = "Bearer $TOKEN" }

Invoke-RestMethod "$BASE/health" -Headers $H | ConvertTo-Json -Depth 10
Invoke-RestMethod "$BASE/api/v1/queue/pending?limit=50" -Headers $H | ConvertTo-Json -Depth 10
Invoke-RestMethod "$BASE/api/v1/queue/dead-letter?limit=50" -Headers $H | ConvertTo-Json -Depth 10
```

Pass criteria:
- `health.status == "ok"`
- queue `sent` increases after capture/export
- `dead_letter` remains 0 for stable network

## Experiment reproducibility validation

## Standard run
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]

python -m ml_pipeline.generate_controlled_dataset \
  --output data/controlled_flows.csv \
  --rows-per-scenario 400 \
  --seed 42

python -m ml_pipeline.run_experiment_suite \
  --input data/controlled_flows.csv \
  --output-dir experiment-runs/run-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

## Publication run (recommended)
```bash
python -m ml_pipeline.generate_controlled_dataset \
  --output data/controlled_flows_pub.csv \
  --rows-per-scenario 2000 \
  --seed 42

python -m ml_pipeline.run_experiment_suite \
  --input data/controlled_flows_pub.csv \
  --output-dir experiment-runs/run-pub-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

Required artifacts in `reports/`:
- `evaluation.json`
- `threshold-sweep.csv`
- `roc-curve.csv`
- `pr-curve.csv`
- `confusion-matrix.json`
- `comparison.json`
- `window-comparison.csv`
- `privacy-ablation.json`
- `drift-report.json`
- `drift-series.csv`
- `policy-simulation.json`
- `policy-simulation-per-app.csv`
- `android-model-evaluation.json`
- `manifest.json`

## Validation evidence snapshot
As of February 22, 2026 (this environment + user-confirmed runs):
- `make smoke`: passed.
- Backend tests: passed (`14 passed`).
- ML tests in this sandbox: blocked due missing `pandas` in local venv.
- ML tests on user machine: passed (user-reported on February 16, 2026).
- Android unit tests in this sandbox: blocked by unavailable Android SDK path.
- Android runtime manual tests on user machine: start/stop crash fixes validated and app now runs.

Detailed run log is tracked in `docs/validation-evidence.md`.

## CI reference
- `.github/workflows/ci-python.yml`
- `.github/workflows/ci-android.yml`
