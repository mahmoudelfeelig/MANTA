from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_pipeline_cli_end_to_end(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    artifacts = tmp_path / "artifacts"
    reports = tmp_path / "reports"

    rows = []
    for idx in range(200):
        rows.append(
            {
                "app_id": "com.test" if idx < 120 else "com.alt",
                "timestamp_end": 1_700_000_000_000 + idx * 1000,
                "bytes_out": 100 + idx,
                "bytes_in": 200 + idx,
                "packets_out": 2,
                "packets_in": 2,
                "dst_novelty": 1.0 if idx % 50 == 0 else 0.0,
                "label": 1 if idx % 57 == 0 else 0,
            }
        )
    pd.DataFrame(rows).to_csv(input_csv, index=False)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.train_baseline",
            "--input",
            str(input_csv),
            "--output",
            str(artifacts),
        ],
        check=True,
    )

    report_path = reports / "eval.json"
    explanations_path = reports / "explanations.csv"
    policy_path = reports / "policy.json"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.evaluate",
            "--input",
            str(input_csv),
            "--artifacts",
            str(artifacts),
            "--output",
            str(report_path),
            "--explanations-output",
            str(explanations_path),
            "--policy-output",
            str(policy_path),
        ],
        check=True,
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "rows" in report
    assert report_path.exists()
    assert explanations_path.exists()
    assert policy_path.exists()
