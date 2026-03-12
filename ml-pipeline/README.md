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

Run the full training workflow into the next numbered run directory automatically:
```bash
python -m ml_pipeline.train_all \
  --input data/real/manta-real-training.csv \
  --runs-root experiment-runs
```

Windows wrapper:
```powershell
.\train_all.ps1 -Input ".\data\real\manta-real-training.csv"
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
- `Android Mischief` (`CC BY 4.0`): Android RAT traffic PCAP corpus with malicious and benign context
  `https://data.mendeley.com/datasets/xbx2j63xfd/2`
- `SDNCampus flow statistics data across 30 applications` (`CC BY 4.0`): benign application-flow coverage with app diversity
  `https://data.mendeley.com/datasets/wvp9tksn72/1`
- `ITC-Net-Blend-60 scenario E` (`CC BY 4.0`): benign Android app traffic across 60 apps, useful for privacy leakage and hard benign negatives
  `https://data.mendeley.com/datasets/gdtnnfyr7s/2`
- `CIC-AndMal2017` (public CIC research dataset): Android malware traffic captures and extracted flow features
  `https://www.unb.ca/cic/datasets/andmal2017.html`
- `Labeled Multi-Stage Android APT Datasets` (`CC BY 4.0`): device-behavior and multi-stage Android attack traces that are useful as an auxiliary suspicious-behavior source
  `https://data.mendeley.com/datasets/bdtn9vj7d7/3`

Practical split for MANTA:

- Use `Westermo` as the strongest open attack/anomaly source.
- Use `SDNCampus` and `ITC-Net-Blend-60` as the primary public benign/app-diversity slices.
- Use `Android Spyware`, `Android Mischief`, and `CIC-AndMal2017` as the primary public Android-malware / suspicious-behavior slices.
- Use only public datasets for the thesis corpus if you do not want to collect private MANTA sessions.

### Public-only thesis corpus
The intended thesis corpus is a public-only merge of:

- `Westermo`
- `Android Spyware`
- `Android Mischief`
- `SDNCampus`
- `ITC-Net-Blend-60 scenario E`
- `CIC-AndMal2017`

Optionally add `Labeled Multi-Stage Android APT Datasets` as an extra suspicious-behavior slice. The pipeline now carries dataset/source/session metadata through normalization, privacy-view derivation, remote training, privacy-student training, and federated simulation so the evaluation split can stay source-aware instead of collapsing to a random row holdout.

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
python -m ml_pipeline.download_real_datasets --dataset android_spyware_mendeley
python -m ml_pipeline.download_real_datasets --dataset android_mischief_rat_traffic
python -m ml_pipeline.download_real_datasets --dataset sdncampus_flow_statistics
python -m ml_pipeline.download_real_datasets --dataset itc_net_blend60_scenario_e
python -m ml_pipeline.download_real_datasets --dataset cicandmal2017_android
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
  --inputs \
    data/real/westermo-bottom-normalized.csv \
    data/real/westermo-left-normalized.csv \
    data/real/westermo-right-normalized.csv \
    data/real/android-spyware-normalized.csv \
    data/real/android-mischief-converted.csv \
    data/real/sdncampus-normalized.csv \
    data/real/itc-net-blend60-converted.csv \
    data/real/cicandmal2017-normalized.csv \
  --output data/real/manta-real-training.csv \
  --manifest-output reports/manta-real-training-manifest.json
```

If your existing `data/real/manta-real-training.csv` was built before the metadata-aware merge path landed, rebuild it. The newer grouped evaluation, privacy, and federated reports depend on the merged corpus carrying `dataset_source`, `dataset_variant`, `environment_id`, `session_id`, and `app_family`.

5. Audit the merged corpus protocol before training:

```bash
python -m ml_pipeline.dataset_manifest \
  --input data/real/manta-real-training.csv \
  --output reports/dataset-manifest.json

python -m ml_pipeline.evaluation_protocol_report \
  --input data/real/manta-real-training.csv \
  --output reports/evaluation-protocol.json
```

6. Train the Android linear model and export the TFLite model:

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

7. Train the backend remote-assisted model as a real sklearn artifact:

```bash
python -m ml_pipeline.train_remote_backend_model \
  --input data/real/manta-real-training.csv \
  --output-model artifacts/backend/remote-assisted-model.json \
  --output-report reports/remote-assisted-model.json \
  --model-family hybrid_dual_channel

python -m ml_pipeline.compare_model_families \
  --input data/real/manta-real-training.csv \
  --output-dir reports/model-family-matrix
```

8. Train the privacy-preserving student and the public-proxy federated variant:

```bash
python -m ml_pipeline.train_privacy_student \
  --input data/real/manta-real-training.csv \
  --output-model artifacts/privacy/privacy-student.json \
  --output-report reports/privacy-student-report.json \
  --student-view medium

python -m ml_pipeline.simulate_federated_rounds \
  --input data/real/manta-real-training.csv \
  --student-model artifacts/privacy/privacy-student.json \
  --output-report reports/federated-report.json \
  --view medium

python -m ml_pipeline.privacy_gate_report \
  --ablation-report reports/privacy-ablation.json \
  --leakage-report reports/privacy-leakage.json \
  --output reports/privacy-gate.json
```

9. Run the full experiment suite on the real corpus:

```bash
python -m ml_pipeline.run_experiment_suite \
  --input data/real/manta-real-training.csv \
  --output-dir experiment-runs/real-run-001 \
  --model-threshold 0.5 \
  --ids-threshold 0.55
```

The suite uses the public-corpus-aware grouped split logic, trains the hybrid remote primary by default, reruns privacy leakage on the derived views, and builds the full comparison matrix.

The suite now also warms reusable caches for:
- feature windows
- remote windows
- privacy views
- full-frame CSV reads

Those caches live under the run cache directory by default and make reruns much faster.

10. Deliver the newly trained artifacts:

- Copy `artifacts/android/anomaly-linear.json` to `android-app/app/src/main/assets/models/anomaly-linear.json`
- Copy `artifacts/tflite/anomaly.tflite` to `android-app/app/src/main/assets/models/anomaly.tflite`
- Import `artifacts/backend/remote-assisted-model.json` into the backend dashboard under `Remote model control -> Import trained backend model JSON`

11. Continue improving the remote-assisted model with real device feedback:

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
- Download the Android Mischief PCAP corpus and place the extracted `.pcap` files under `downloads/manual/android-mischief/`
- Download the SDNCampus dataset from the printed Mendeley URL and place the extracted CSV/TSV/Parquet under `downloads/manual/sdncampus/`
- Download the ITC-Net-Blend-60 scenario E PCAPs and place the extracted `.pcap` files under `downloads/manual/itc-net-blend60/`
- Download CIC-AndMal2017 from the official CIC page and place its extracted CICFlowMeter CSVs or PCAPs under `downloads/manual/cicandmal2017/`
- Download the Android APT behavior dataset and place the extracted CSV/TSV/Parquet under `downloads/manual/android-apt-behavior/`
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

python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\manual\cicandmal2017\<FILE>.csv" `
  --profile cicflowmeter `
  --output ".\data\real\cicandmal2017-normalized.csv" `
  --report ".\reports\cicandmal2017-normalized.json"

python -m ml_pipeline.normalize_real_dataset `
  --input ".\downloads\manual\android-apt-behavior\<FILE>.csv" `
  --profile android_apt_behavior `
  --output ".\data\real\android-apt-behavior-normalized.csv" `
  --report ".\reports\android-apt-behavior-normalized.json"
```

Merge and train:

```powershell
python -m ml_pipeline.merge_normalized_datasets `
  --inputs ".\data\real\westermo-bottom-normalized.csv" ".\data\real\westermo-left-normalized.csv" ".\data\real\westermo-right-normalized.csv" ".\data\real\android-spyware-normalized.csv" ".\data\real\android-mischief-converted.csv" ".\data\real\sdncampus-normalized.csv" ".\data\real\itc-net-blend60-converted.csv" ".\data\real\cicandmal2017-normalized.csv" ".\data\real\android-apt-behavior-normalized.csv" `
  --output ".\data\real\manta-real-training.csv" `
  --manifest-output ".\reports\manta-real-training-manifest.json"

python -m ml_pipeline.dataset_manifest `
  --input ".\data\real\manta-real-training.csv" `
  --output ".\reports\dataset-manifest.json"

python -m ml_pipeline.evaluation_protocol_report `
  --input ".\data\real\manta-real-training.csv" `
  --output ".\reports\evaluation-protocol.json"

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
  --output-report ".\reports\remote-assisted-model.json" `
  --model-family hybrid_dual_channel

python -m ml_pipeline.compare_model_families `
  --input ".\data\real\manta-real-training.csv" `
  --output-dir ".\reports\model-family-matrix"

python -m ml_pipeline.train_privacy_student `
  --input ".\data\real\manta-real-training.csv" `
  --output-model ".\artifacts\privacy\privacy-student.json" `
  --output-report ".\reports\privacy-student-report.json" `
  --student-view medium

python -m ml_pipeline.simulate_federated_rounds `
  --input ".\data\real\manta-real-training.csv" `
  --student-model ".\artifacts\privacy\privacy-student.json" `
  --output-report ".\reports\federated-report.json" `
  --view medium

python -m ml_pipeline.privacy_gate_report `
  --ablation-report ".\reports\privacy-ablation.json" `
  --leakage-report ".\reports\privacy-leakage.json" `
  --output ".\reports\privacy-gate.json"
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
  --profile android_mischief `
  --input-dir ".\downloads\manual\android-mischief" `
  --output ".\data\real\android-mischief-converted.csv" `
  --report ".\reports\android-mischief-converted-report.csv"

python -m ml_pipeline.convert_pcaps_to_flow_csv `
  --profile itc_net_blend `
  --input-dir ".\downloads\manual\itc-net-blend60" `
  --output ".\data\real\itc-net-blend60-converted.csv" `
  --report ".\reports\itc-net-blend60-converted-report.csv"

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
- `dataset-manifest.json` (corpus source/session/app-family inventory and metadata completeness)
- `evaluation-protocol.json` (source/app-family/temporal robustness matrix across grouped holdouts)
- `evaluation.json` (core metrics + policy calibration references)
- `threshold-sweep.csv`, `roc-curve.csv`, `pr-curve.csv`, `confusion-matrix.json`
- `comparison.json` (ML vs IDS baseline)
- `privacy-ablation.json` (privacy/utility deltas by feature set)
- `privacy-gate.json` (combined utility + leakage verdict per privacy tier)
- `drift-report.json`, `drift-series.csv` (concept drift timeline by app)
- `policy-simulation.json`, `policy-simulation-per-app.csv` (policy threshold what-if)
- `android-model-evaluation.json` (metrics for exported Android model)
- `tflite-autoencoder-evaluation.json` (cluster-centered one-class metrics for the exported TFLite model)
- `remote-assisted-model.json` (hybrid remote primary report)
- `model-family-matrix/comparison-summary.json` (logistic vs tree vs mahalanobis vs hybrid comparison)
- `privacy-student-report.json` (adversarial medium-view student report)
- `federated-report.json` (FedProx simulation over public proxy clients)
- `full-model-matrix.json` (ranked cross-family comparison matrix)
- `window-comparison.csv` (per-window scores)
- `manifest.json` (commands, dependency versions, input hash, platform metadata)

Android model delivery:
- Copy `artifacts/android/anomaly-linear.json` to `android-app/app/src/main/assets/models/anomaly-linear.json`
  when updating the bundled on-device model from newly trained data.
