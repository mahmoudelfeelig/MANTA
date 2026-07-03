from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_simulate_policy_generates_distribution(tmp_path: Path) -> None:
    input_csv = tmp_path / "scored.csv"
    policy_json = tmp_path / "policy.json"
    output_json = tmp_path / "reports" / "policy-simulation.json"
    per_app_csv = tmp_path / "reports" / "policy-simulation-per-app.csv"

    pd.DataFrame(
        [
            {"app_id": "com.alpha", "anomaly_score": 0.2},
            {"app_id": "com.alpha", "anomaly_score": 0.7},
            {"app_id": "com.alpha", "anomaly_score": 0.92},
            {"app_id": "com.beta", "anomaly_score": 0.58},
            {"app_id": "com.beta", "anomaly_score": 0.88},
        ]
    ).to_csv(input_csv, index=False)

    policy_payload = {
        "policy_version": 2,
        "default_thresholds": {"medium": 0.6, "high": 0.85},
        "app_threshold_overrides": {"com.beta": {"medium": 0.5, "high": 0.8}},
        "export_enabled": True,
        "retention_days": 7,
    }
    policy_json.write_text(json.dumps(policy_payload, indent=2), encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.simulate_policy",
            "--input",
            str(input_csv),
            "--policy",
            str(policy_json),
            "--output",
            str(output_json),
            "--per-app-output",
            str(per_app_csv),
        ],
        check=True,
    )

    report = json.loads(output_json.read_text(encoding="utf-8"))
    assert report["rows_evaluated"] == 5
    assert set(report["severity_distribution"].keys()) == {"LOW", "MEDIUM", "HIGH"}
    assert per_app_csv.exists()
