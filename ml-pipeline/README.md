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
- `comparison.json` (ML vs IDS baseline)
- `window-comparison.csv` (per-window scores)
- `manifest.json` (commands, dependency versions, input hash, platform metadata)
