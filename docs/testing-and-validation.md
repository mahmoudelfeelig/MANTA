# Testing and Validation

## Test strategy
- Unit tests for feature engineering, threshold logic, parsers, and detectors.
- Integration tests for backend API workflows (flow ingest, alert triage, policy sync, retry/dead-letter).
- Pipeline integration test for end-to-end ML CLI flow.

## Implemented test suites

## Android module (`android-app`)
Unit and integration-like JVM tests:
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/FlowAggregatorTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/FlowPipelineIntegrationTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/IpfixMapperTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/flow/RemotePolicyParserTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/StatisticalAnomalyDetectorTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/ThresholdResolverTest.kt`
- `android-app/app/src/test/java/com/feelbachelor/app/domain/detection/ExplanationFormatterTest.kt`

## Backend adapter (`backend-adapter`)
Integration tests covering endpoint logic and persistence behavior:
- `backend-adapter/tests/test_main.py`
- `backend-adapter/tests/test_policy_and_triage_edges.py`
- `backend-adapter/tests/test_model_validation.py`
- `backend-adapter/tests/test_config.py`

Covered behaviors:
- Authenticated mobile flow ingest with IPFIX fields.
- Mobile alert ingest and triage update lifecycle.
- Device policy put/get roundtrip.
- Retry scheduling and dead-letter transition.
- Alert filtering and edge validation.

## ML pipeline (`ml-pipeline`)
Unit + integration tests:
- `ml-pipeline/tests/test_features.py`
- `ml-pipeline/tests/test_calibration.py`
- `ml-pipeline/tests/test_explain.py`
- `ml-pipeline/tests/test_pipeline_integration.py`
- `ml-pipeline/tests/test_generate_controlled_dataset.py`
- `ml-pipeline/tests/test_run_experiment_suite.py`
- `ml-pipeline/tests/test_ids_baseline.py`
- `ml-pipeline/tests/test_compare_baselines.py`

Covered behaviors:
- Feature window extraction correctness.
- Threshold calibration generation.
- Explanation generation output.
- IDS-style rule baseline scoring.
- ML vs IDS baseline comparison report generation.
- End-to-end train/evaluate/compare CLI flow with generated artifacts.

## Executed validation in this environment
Executed on February 10, 2026:
- `python3 -m compileall backend-adapter/app backend-adapter/tests ml-pipeline/src ml-pipeline/tests`
- `gradle -v` check (failed due native runtime load issue in this environment)
- Dependency install and local pytest execution were blocked by offline package index resolution (`pip` could not resolve `setuptools` and test dependencies).
- GitHub workflows in repo for full validation:
  - `.github/workflows/ci-python.yml`
  - `.github/workflows/ci-android.yml`

## Known environment limitation
- Android Gradle compilation/tests could not be executed in this environment due Gradle native runtime issues (`libnative-platform.so` load failure).
- Python test dependencies could not be installed in this environment due network/index resolution restrictions.
- Android and Python test sources are in place and ready for CI or local execution in a network-enabled setup.

## Recommended CI commands
Backend:
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest -q -s tests
```

ML:
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest -q -s tests
```

Android:
```bash
cd android-app
./gradlew test
```
