# Publication Experiment Package

This document defines the exact experiment package to include with thesis submission.

## Goal
Produce a reproducible, publication-grade experiment run with stable artifacts and traceable configuration.

## Environment
- Python 3.12
- `ml-pipeline` dependencies installed with `pip install -e .[test]`
- fixed seed values recorded in `manifest.json`

## Run commands

## 1) Generate controlled dataset
```bash
cd ml-pipeline
python -m ml_pipeline.generate_controlled_dataset \
  --output data/controlled_flows_pub.csv \
  --rows-per-scenario 2000 \
  --seed 42
```

## 2) Run full suite
```bash
python -m ml_pipeline.run_experiment_suite \
  --input data/controlled_flows_pub.csv \
  --output-dir experiment-runs/run-pub-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

## 3) Optional calibrated comparison rerun
Use calibrated threshold from `evaluation.json` for head-to-head table:
```bash
python -m ml_pipeline.compare_baselines \
  --input data/controlled_flows_pub.csv \
  --artifacts experiment-runs/run-pub-001/artifacts/baseline \
  --output experiment-runs/run-pub-001/reports/comparison-calibrated.json \
  --model-threshold 0.27 \
  --ids-threshold 0.55 \
  --windows-output experiment-runs/run-pub-001/reports/window-comparison-calibrated.csv
```

## Required artifacts
Expected in `experiment-runs/run-pub-001/reports/`:
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
- `policy-calibrated.json`
- `explanations.csv`
- `manifest.json`

Expected in `experiment-runs/run-pub-001/artifacts/`:
- `baseline/baseline_model.joblib`
- `android/anomaly-linear.json`

## Package handoff
Create a release archive containing:
- `reports/`
- `artifacts/android/anomaly-linear.json`
- `manifest.json`
- a short `RUN_INFO.md` with execution date, machine, and command copy.

## Acceptance criteria
- run exits successfully without manual file edits
- all required artifacts exist and are non-empty
- `manifest.json` includes dependency versions and input hash
- metrics are plausible (no obviously degenerate threshold-only results)
