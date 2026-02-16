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
python -m ml_pipeline.evaluate --input data/flows.csv --artifacts artifacts/baseline --output reports/eval.json
```

Export TFLite autoencoder:
```bash
python -m ml_pipeline.export_tflite --input data/flows.csv --output artifacts/tflite/anomaly.tflite
```
