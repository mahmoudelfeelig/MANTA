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
    manifest = output_dir / "reports" / "manifest.json"

    assert eval_report.exists()
    assert policy_report.exists()
    assert comparison_report.exists()
    assert manifest.exists()

    parsed = json.loads(eval_report.read_text(encoding="utf-8"))
    assert "rows" in parsed

    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert "python_version" in manifest_data
    assert "input_sha256" in manifest_data
