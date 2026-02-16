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

Covered behaviors:
- Feature window extraction correctness.
- Threshold calibration generation.
- Explanation generation output.
- End-to-end train/evaluate CLI flow with generated artifacts.

## Executed validation in this environment
Executed on February 7, 2026:
- `python3 -m compileall backend-adapter/app backend-adapter/tests`
- `python3 -m compileall ml-pipeline/src ml-pipeline/tests`
- `pytest -q -s backend-adapter/tests` (in temporary venv)
- `pytest -q -s ml-pipeline/tests` (in temporary venv)

## Known environment limitation
- Android Gradle compilation/tests could not be executed in this environment due Gradle native runtime issues (`libnative-platform.so` load failure).
- Android test sources and build configuration are in place and ready for local Android Studio/CI execution.

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
