from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_drift_report_writes_summary_and_series(tmp_path: Path) -> None:
    input_csv = tmp_path / "windows.csv"
    output_json = tmp_path / "reports" / "drift-report.json"
    output_series = tmp_path / "reports" / "drift-series.csv"

    rows = []
    for idx in range(120):
        rows.append(
            {
                "app_id": "com.test",
                "window_bucket": 1_700_000_000_000 + idx * 60_000,
                "anomaly_score": 0.18 + (0.01 * (idx % 5)) if idx < 80 else 0.75 + (0.02 * (idx % 3)),
                "novelty_score": 0.05 if idx < 80 else 0.8,
                "burstiness": 0.2 if idx < 80 else 0.9,
                "connection_frequency_delta": 1.2 if idx < 80 else 7.5,
                "periodic_beacon_score": 0.1 if idx < 80 else 0.85,
                "data_quality_score": 1.0,
            }
        )
    pd.DataFrame(rows).to_csv(input_csv, index=False)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.drift_report",
            "--input",
            str(input_csv),
            "--output",
            str(output_json),
            "--series-output",
            str(output_series),
        ],
        check=True,
    )

    report = json.loads(output_json.read_text(encoding="utf-8"))
    assert report["rows"] == 120
    assert report["apps"] == 1
    assert "per_app_max_drift" in report
    assert output_series.exists()
