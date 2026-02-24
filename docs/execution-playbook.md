# Execution Playbook

This playbook executes the full non-external workflow end-to-end.

## 1) Run backend adapter locally
```bash
cd backend-adapter
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
# required
export ADAPTER_SHARED_TOKEN='replace-with-long-random-token'
# optional
export WAZUH_INGEST_URL=''
export WAZUH_API_TOKEN=''
export RESISTINE_BASE_URL=''
export RESISTINE_API_TOKEN=''
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 2) Run ML synthetic-data experiment suite
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

Artifacts generated:
- `experiment-runs/run-001/artifacts/baseline/baseline_model.joblib`
- `experiment-runs/run-001/artifacts/android/anomaly-linear.json`
- `experiment-runs/run-001/reports/evaluation.json`
- `experiment-runs/run-001/reports/threshold-sweep.csv`
- `experiment-runs/run-001/reports/roc-curve.csv`
- `experiment-runs/run-001/reports/pr-curve.csv`
- `experiment-runs/run-001/reports/confusion-matrix.json`
- `experiment-runs/run-001/reports/comparison.json`
- `experiment-runs/run-001/reports/window-comparison.csv`
- `experiment-runs/run-001/reports/privacy-ablation.json`
- `experiment-runs/run-001/reports/drift-report.json`
- `experiment-runs/run-001/reports/drift-series.csv`
- `experiment-runs/run-001/reports/policy-simulation.json`
- `experiment-runs/run-001/reports/policy-simulation-per-app.csv`
- `experiment-runs/run-001/reports/android-model-evaluation.json`
- `experiment-runs/run-001/reports/explanations.csv`
- `experiment-runs/run-001/reports/policy-calibrated.json`
- `experiment-runs/run-001/reports/manifest.json`

## 2b) Publication-grade run size
Use a larger controlled dataset before thesis submission:
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

## 3) Android app local run
```bash
# Open android-app/ in Android Studio
# Ensure Android SDK path is set (ANDROID_HOME or android-app/local.properties)
# Accept the consent/disclosure card once
# Configure backend URL and API token in app UI
# Start capture and verify alert + policy behavior
# Use "Export dataset snapshot" for anonymized local CSV export
```

## 4) Run all non-Android tests
```bash
make test-backend
make test-ml
```

## 5) Run Android unit tests (when Gradle runtime works)
```bash
make test-android
```

## 6) CI checks
GitHub Actions workflows:
- `.github/workflows/ci-python.yml`
- `.github/workflows/ci-android.yml`
