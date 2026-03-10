# MANTA ML Pipeline

Pipeline for MANTA flow feature extraction, anomaly model training, evaluation, privacy/utility benchmarking, and model export.

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
python -m ml_pipeline.export_tflite \
  --input data/flows.csv \
  --output artifacts/tflite/anomaly.tflite \
  --output-report reports/tflite-autoencoder-evaluation.json
```

Compare remote model families on the same corpus:
```bash
python -m ml_pipeline.compare_model_families \
  --input data/flows.csv \
  --output-dir reports/model-family-matrix
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

## Real data instead of synthetic
The synthetic generator is only a smoke-test and regression fixture. The training commands also accept real flow CSVs, as long as they are normalized into the canonical columns expected by `ml_pipeline.features`:

- `app_id`
- `timestamp_end`
- `bytes_out`
- `bytes_in`
- `packets_out`
- `packets_in`
- `dst_novelty`
- `label` or `is_anomaly`

Recommended public datasets:

- `Westermo network traffic dataset` (`CC BY 4.0`): realistic flow/attack coverage with downloadable public archive
  `https://github.com/westermo/network-traffic-dataset`
- `Android Spyware Detection Through a VPN-Based App` (`CC BY 4.0`): Android/mobile malware-oriented traffic corpus
  `https://data.mendeley.com/datasets/mhvgtywrxf/1`
- `SDNCampus flow statistics data across 30 applications` (`CC BY 4.0`): benign application-flow coverage with app diversity
  `https://data.mendeley.com/datasets/wvp9tksn72/1`
- `PARROT2025_mitmproxy`: useful for mobile/browser behavior enrichment via Zenodo
  `https://zenodo.org/records/16368932`

Practical split for MANTA:

- Use `Westermo` as the strongest open attack/anomaly source.
- Use `SDNCampus` and `Android Spyware` to add app/application diversity and mobile-oriented coverage.
- Use `PARROT2025_mitmproxy` if you want richer browser/mobile capture material and you are willing to convert PCAP-style exports into flow CSV first.
- Use backend-triaged alert windows to continuously retrain the per-device remote-assisted model on real deployment data.

### Exact workflow
1. Install dependencies:

```bash
cd ml-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -e .[tflite,test]
```

2. List supported public datasets and download what can be automated:

```bash
python -m ml_pipeline.download_real_datasets --list
python -m ml_pipeline.download_real_datasets --dataset westermo --output-dir downloads
python -m ml_pipeline.download_real_datasets --dataset parrot2025_mitmproxy --output-dir downloads
```

Notes:

- `westermo` downloads directly.
- `parrot2025_mitmproxy` downloads via the public Zenodo API. The current record exposes a ZIP archive, so the default command is the correct one.
- `android_spyware_mendeley` and `sdncampus_flow_statistics` are intentionally manual-download only because their public landing pages do not expose a stable direct-download API. The script prints the exact landing-page URL for those.

3. Normalize raw real-data exports into MANTA canonical CSV:

```bash
python -m ml_pipeline.normalize_real_dataset \
  --input downloads/westermo/<raw-file>.csv \
  --profile westermo \
  --output data/real/westermo-normalized.csv \
  --report reports/westermo-normalized.json

python -m ml_pipeline.normalize_real_dataset \
  --input downloads/manual/android-spyware/<raw-file>.csv \
  --profile generic_flow \
  --output data/real/android-spyware-normalized.csv \
  --report reports/android-spyware-normalized.json
```

The normalizer accepts CSV, TSV, and Parquet. It will auto-map common aliases for:

- timestamps
- bytes and packet counts
- destination context
- labels
- app/application identifiers

It also derives `dst_novelty` if the raw dataset does not provide it.

PCAP-only datasets need one extra conversion step first. MANTA now includes a `tshark`-based converter:

```bash
python -m ml_pipeline.convert_pcaps_to_flow_csv \
  --profile parrot \
  --input-dir downloads/parrot2025_mitmproxy/unzipped/PARROT2025_mitmproxy \
  --output data/real/parrot-converted.csv \
  --report reports/parrot-converted-report.csv
```

```bash
python -m ml_pipeline.convert_pcaps_to_flow_csv \
  --profile android_spyware \
  --input-dir downloads/android-spyware-unzipped/Android\ Spyware\ Detection\ Using\ Machine\ Learning\ A\ Novel\ Dataset \
  --output data/real/android-spyware-converted.csv \
  --report reports/android-spyware-converted-report.csv
```

This converter requires `tshark` from Wireshark to be installed and available on `PATH`, or passed explicitly with `--tshark`.

4. Merge normalized datasets into one training corpus:

```bash
python -m ml_pipeline.merge_normalized_datasets \
  --inputs data/real/westermo-normalized.csv data/real/android-spyware-normalized.csv \
  --output data/real/manta-real-training.csv
```

5. Train the Android linear model and export the TFLite model:

```bash
python -m ml_pipeline.train_android_model \
  --input data/real/manta-real-training.csv \
  --output-model artifacts/android/anomaly-linear.json \
  --output-report reports/android-model-evaluation.json

python -m ml_pipeline.export_tflite \
  --input data/real/manta-real-training.csv \
  --output artifacts/tflite/anomaly.tflite \
  --output-report reports/tflite-autoencoder-evaluation.json
```

6. Train the backend remote-assisted model as a real sklearn artifact:

```bash
python -m ml_pipeline.train_remote_backend_model \
  --input data/real/manta-real-training.csv \
  --output-model artifacts/backend/remote-assisted-model.json \
  --output-report reports/remote-assisted-model.json

python -m ml_pipeline.compare_model_families \
  --input data/real/manta-real-training.csv \
  --output-dir reports/model-family-matrix
```

7. Run the full experiment suite on the real corpus:

```bash
python -m ml_pipeline.run_experiment_suite \
  --input data/real/manta-real-training.csv \
  --output-dir experiment-runs/real-run-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

8. Deliver the newly trained artifacts:

- Copy `artifacts/android/anomaly-linear.json` to `android-app/app/src/main/assets/models/anomaly-linear.json`
- Copy `artifacts/tflite/anomaly.tflite` to `android-app/app/src/main/assets/models/anomaly.tflite`
- Import `artifacts/backend/remote-assisted-model.json` into the backend dashboard under `Remote model control -> Import trained backend model JSON`

9. Continue improving the remote-assisted model with real device feedback:

- generate alerts from the phone
- triage them as `FALSE_POSITIVE` or `RESOLVED`
- retrain from the dashboard for device-specific adaptation

### Windows quick commands

PowerShell setup:

```powershell
cd <path-to-manta>\ml-pipeline
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

Download what can be automated:

```powershell
python -m ml_pipeline.download_real_datasets --list
python -m ml_pipeline.download_real_datasets --dataset westermo --output-dir downloads
python -m ml_pipeline.download_real_datasets --dataset parrot2025_mitmproxy --output-dir downloads
python -m ml_pipeline.download_real_datasets --dataset android_spyware_mendeley
python -m ml_pipeline.download_real_datasets --dataset sdncampus_flow_statistics
```

Manual datasets:

- Download the Android spyware dataset from the printed Mendeley URL and place the extracted CSV/TSV/Parquet under `downloads/manual/android-spyware/`
- Download the SDNCampus dataset from the printed Mendeley URL and place the extracted CSV/TSV/Parquet under `downloads/manual/sdncampus/`
- If you downloaded the Android Mischief archive (`xbx2j63xfd-2.zip`), do not rely on `Expand-Archive` alone. That package contains nested ZIP files and at least one unsupported compression method for the default PowerShell extractor. Prefer `7z` or `tar`, extract it under `downloads/android-mischief-unzipped/`, then convert the embedded `.pcap` files with the `android_spyware` PCAP converter profile.

Normalize Westermo reduced-flow CSVs after extracting the ZIP archives:

```powershell
Expand-Archive ".\downloads\westermo\westermo-network-traffic-dataset.zip" ".\downloads\westermo\unzipped" -Force
Expand-Archive ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_bottom.zip" ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_bottom" -Force
Expand-Archive ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_left.zip" ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_left" -Force
Expand-Archive ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_right.zip" ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_right" -Force

python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_bottom\output_bottom.csv" `
  --profile westermo `
  --output ".\data\real\westermo-bottom-normalized.csv" `
  --report ".\reports\westermo-bottom-normalized.json"

python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_left\output_left.csv" `
  --profile westermo `
  --output ".\data\real\westermo-left-normalized.csv" `
  --report ".\reports\westermo-left-normalized.json"

python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\westermo\unzipped\network-traffic-dataset-main\data\reduced\flows\output_right\output_right.csv" `
  --profile westermo `
  --output ".\data\real\westermo-right-normalized.csv" `
  --report ".\reports\westermo-right-normalized.json"
```

Normalize the manual datasets once the real filenames are known:

```powershell
python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\manual\android-spyware\<FILE>.csv" `
  --profile generic_flow `
  --output ".\data\real\android-spyware-normalized.csv" `
  --report ".\reports\android-spyware-normalized.json"

python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\manual\sdncampus\<FILE>.csv" `
  --profile sdncampus `
  --output ".\data\real\sdncampus-normalized.csv" `
  --report ".\reports\sdncampus-normalized.json"
```

Merge and train:

```powershell
python -m ml_pipeline.merge_normalized_datasets `
  --inputs ".\data\real\westermo-bottom-normalized.csv" ".\data\real\westermo-left-normalized.csv" ".\data\real\westermo-right-normalized.csv" ".\data\real\android-spyware-normalized.csv" ".\data\real\sdncampus-normalized.csv" `
  --output ".\data\real\manta-real-training.csv"

python -m ml_pipeline.train_android_model `
  --input ".\data\real\manta-real-training.csv" `
  --output-model ".\artifacts\android\anomaly-linear.json" `
  --output-report ".\reports\android-model-evaluation.json"

python -m ml_pipeline.export_tflite `
  --input ".\data\real\manta-real-training.csv" `
  --output ".\artifacts\tflite\anomaly.tflite" `
  --output-report ".\reports\tflite-autoencoder-evaluation.json"

python -m ml_pipeline.train_remote_backend_model `
  --input ".\data\real\manta-real-training.csv" `
  --output-model ".\artifacts\backend\remote-assisted-model.json" `
  --output-report ".\reports\remote-assisted-model.json"

python -m ml_pipeline.compare_model_families `
  --input ".\data\real\manta-real-training.csv" `
  --output-dir ".\reports\model-family-matrix"
```

PCAP conversion on Windows:

```powershell
Expand-Archive ".\downloads\Android Spyware Detection Using Machine Learning A Novel Dataset.zip" ".\downloads\android-spyware-unzipped" -Force
Expand-Archive ".\downloads\SDNCampus Dataset.zip" ".\downloads\sdncampus-unzipped" -Force

python -m ml_pipeline.convert_pcaps_to_flow_csv `
  --profile android_spyware `
  --input-dir ".\downloads\android-spyware-unzipped\Android Spyware Detection Using Machine Learning A Novel Dataset" `
  --output ".\data\real\android-spyware-converted.csv" `
  --report ".\reports\android-spyware-converted-report.csv"

python -m ml_pipeline.convert_pcaps_to_flow_csv `
  --profile parrot `
  --input-dir ".\downloads\parrot2025_mitmproxy\unzipped\PARROT2025_mitmproxy" `
  --output ".\data\real\parrot-converted.csv" `
  --report ".\reports\parrot-converted-report.csv"

python -m ml_pipeline.convert_pcaps_to_flow_csv `
  --profile android_spyware `
  --input-dir ".\downloads\android-mischief-unzipped\AndroidMischiefDataset_v2" `
  --output ".\data\real\android-mischief-converted.csv" `
  --report ".\reports\android-mischief-converted-report.csv"
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
