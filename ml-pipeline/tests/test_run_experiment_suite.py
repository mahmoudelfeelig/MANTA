from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path



def test_run_experiment_suite_creates_reports(tmp_path: Path) -> None:
    input_csv = tmp_path / "controlled.csv"
    output_dir = tmp_path / "suite-output"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.generate_controlled_dataset",
            "--output",
            str(input_csv),
            "--rows-per-scenario",
            "60",
            "--seed",
            "11",
        ],
        check=True,
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.run_experiment_suite",
            "--input",
            str(input_csv),
            "--output-dir",
            str(output_dir),
        ],
        check=True,
    )

    eval_report = output_dir / "reports" / "evaluation.json"
    policy_report = output_dir / "reports" / "policy-calibrated.json"
    comparison_report = output_dir / "reports" / "comparison.json"
    privacy_report = output_dir / "reports" / "privacy-ablation.json"
    drift_report = output_dir / "reports" / "drift-report.json"
    policy_sim_report = output_dir / "reports" / "policy-simulation.json"
    threshold_sweep = output_dir / "reports" / "threshold-sweep.csv"
    roc_curve = output_dir / "reports" / "roc-curve.csv"
    pr_curve = output_dir / "reports" / "pr-curve.csv"
    confusion = output_dir / "reports" / "confusion-matrix.json"
    drift_series = output_dir / "reports" / "drift-series.csv"
    policy_sim_per_app = output_dir / "reports" / "policy-simulation-per-app.csv"
    android_model = output_dir / "artifacts" / "android" / "anomaly-local.json"
    remote_report = output_dir / "reports" / "remote-assisted-model.json"
    privacy_student_report = output_dir / "reports" / "privacy-student-report.json"
    federated_report = output_dir / "reports" / "federated-report.json"
    family_summary = output_dir / "reports" / "model-family-matrix" / "comparison-summary.json"
    full_matrix = output_dir / "reports" / "full-model-matrix.json"
    dataset_manifest = output_dir / "reports" / "dataset-manifest.json"
    evaluation_protocol = output_dir / "reports" / "evaluation-protocol.json"
    privacy_gate = output_dir / "reports" / "privacy-gate.json"
    traffic_fingerprint = output_dir / "reports" / "traffic-fingerprint.json"
    manifest = output_dir / "reports" / "manifest.json"

    assert eval_report.exists()
    assert policy_report.exists()
    assert comparison_report.exists()
    assert privacy_report.exists()
    assert drift_report.exists()
    assert policy_sim_report.exists()
    assert threshold_sweep.exists()
    assert roc_curve.exists()
    assert pr_curve.exists()
    assert confusion.exists()
    assert drift_series.exists()
    assert policy_sim_per_app.exists()
    assert android_model.exists()
    assert remote_report.exists()
    assert privacy_student_report.exists()
    assert federated_report.exists()
    assert family_summary.exists()
    assert full_matrix.exists()
    assert dataset_manifest.exists()
    assert evaluation_protocol.exists()
    assert privacy_gate.exists()
    assert traffic_fingerprint.exists()
    assert manifest.exists()

    parsed = json.loads(eval_report.read_text(encoding="utf-8"))
    assert "rows" in parsed
    assert parsed["threshold_source"] in {"fixed", "auto_f1"}

    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert "python_version" in manifest_data
    assert "input_sha256" in manifest_data
    assert "labels_present" in manifest_data
