# ML Pipeline

Pipeline for flow feature extraction, anomaly model training, evaluation, and optional TFLite export.

## Install
```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional TFLite support:
```bash
pip install -e .[tflite]
```

## Usage
Generate controlled synthetic traces:
```bash
python -m ml_pipeline.generate_controlled_dataset \
  --output data/controlled_flows.csv \
  --rows-per-scenario 400 \
  --seed 42
```

Train baseline:
```bash
python -m ml_pipeline.train_baseline --input data/controlled_flows.csv --output artifacts/baseline
```

Evaluate:
```bash
python -m ml_pipeline.evaluate \
  --input data/controlled_flows.csv \
  --artifacts artifacts/baseline \
  --output reports/eval.json \
  --auto-threshold \
  --window-scores-output reports/windows-scored.csv \
  --threshold-sweep-output reports/threshold-sweep.csv \
  --roc-output reports/roc-curve.csv \
  --pr-output reports/pr-curve.csv \
  --confusion-output reports/confusion-matrix.json \
  --explanations-output reports/explanations.csv \
  --policy-output reports/policy-calibrated.json
```

Compare ML baseline against IDS-style rules:
```bash
python -m ml_pipeline.compare_baselines \
  --input data/controlled_flows.csv \
  --artifacts artifacts/baseline \
  --output reports/comparison.json \
  --windows-output reports/window-comparison.csv
```

Evaluate privacy/utility trade-off under feature ablation:
```bash
python -m ml_pipeline.privacy_ablation \
  --input data/controlled_flows.csv \
  --output reports/privacy-ablation.json
```

Generate a drift report from scored windows:
```bash
python -m ml_pipeline.drift_report \
  --input reports/windows-scored.csv \
  --output reports/drift-report.json \
  --series-output reports/drift-series.csv
```

Simulate threshold policy impact on severity distribution:
```bash
python -m ml_pipeline.simulate_policy \
  --input reports/windows-scored.csv \
  --policy reports/policy-calibrated.json \
  --output reports/policy-simulation.json \
  --per-app-output reports/policy-simulation-per-app.csv
```

Build retraining dataset from backend analyst samples:
```bash
python -m ml_pipeline.build_retraining_dataset \
  --input samples/retraining-samples.json \
  --output artifacts/retraining/retraining-dataset.csv \
  --report reports/retraining-dataset-report.json
```

Train an Android-ready linear model JSON:
```bash
python -m ml_pipeline.train_android_model \
  --input data/controlled_flows.csv \
  --output-model artifacts/android/anomaly-linear.json \
  --output-report reports/android-model-evaluation.json
```

Export TFLite autoencoder:
```bash
python -m ml_pipeline.export_tflite --input data/flows.csv --output artifacts/tflite/anomaly.tflite
```

Calibrate policy thresholds from scored windows:
```bash
python -m ml_pipeline.calibrate_thresholds \
  --input reports/windows-with-scores.csv \
  --output reports/policy.json \
  --policy-version 2 \
  --export-enabled
```

Run complete baseline suite in one command:
```bash
python -m ml_pipeline.run_experiment_suite \
  --input data/controlled_flows.csv \
  --output-dir experiment-runs/run-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

Generated reports include:
- `evaluation.json` (core metrics + policy calibration references)
- `threshold-sweep.csv`, `roc-curve.csv`, `pr-curve.csv`, `confusion-matrix.json`
- `comparison.json` (ML vs IDS baseline)
- `privacy-ablation.json` (privacy/utility deltas by feature set)
- `drift-report.json`, `drift-series.csv` (concept drift timeline by app)
- `policy-simulation.json`, `policy-simulation-per-app.csv` (policy threshold what-if)
- `android-model-evaluation.json` (metrics for exported Android model)
- `window-comparison.csv` (per-window scores)
- `manifest.json` (commands, dependency versions, input hash, platform metadata)

Android model delivery:
- Copy `artifacts/android/anomaly-linear.json` to `android-app/app/src/main/assets/models/anomaly-linear.json`
  when updating the bundled on-device model from newly trained data.
