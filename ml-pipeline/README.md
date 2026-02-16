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
Train baseline:
```bash
python -m ml_pipeline.train_baseline --input data/flows.csv --output artifacts/baseline
```

Evaluate:
```bash
python -m ml_pipeline.evaluate \
  --input data/flows.csv \
  --artifacts artifacts/baseline \
  --output reports/eval.json \
  --explanations-output reports/explanations.csv \
  --policy-output reports/policy-calibrated.json
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
