from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_compare_baselines_generates_comparison_report(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    artifacts = tmp_path / "artifacts"
    report_path = tmp_path / "comparison.json"

    rows = []
    for idx in range(240):
        rows.append(
            {
                "app_id": "com.test" if idx < 160 else "com.alt",
                "timestamp_end": 1_700_000_000_000 + idx * 1_000,
                "bytes_out": 100 + idx * 20 if idx % 60 else 120_000 + idx * 500,
                "bytes_in": 200 + idx * 10 if idx % 60 else 2_000,
                "packets_out": 2 + (idx % 3),
                "packets_in": 2 + (idx % 4),
                "dst_novelty": 1.0 if idx % 60 == 0 else 0.0,
                "label": 1 if idx % 60 == 0 else 0,
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

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.compare_baselines",
            "--input",
            str(input_csv),
            "--artifacts",
            str(artifacts),
            "--output",
            str(report_path),
        ],
        check=True,
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "model" in report
    assert "ids_baseline" in report
    assert "rows" in report
