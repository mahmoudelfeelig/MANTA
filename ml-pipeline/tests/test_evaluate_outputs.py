from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_evaluate_writes_curves_confusion_and_sweep(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    artifacts = tmp_path / "artifacts"
    report = tmp_path / "reports" / "eval.json"
    sweep = tmp_path / "reports" / "threshold-sweep.csv"
    roc = tmp_path / "reports" / "roc.csv"
    pr = tmp_path / "reports" / "pr.csv"
    confusion = tmp_path / "reports" / "confusion.json"
    windows = tmp_path / "reports" / "windows.csv"

    rows = []
    for idx in range(250):
        anomalous = idx % 65 == 0
        rows.append(
            {
                "app_id": "com.test",
                "timestamp_end": 1_700_000_000_000 + idx * 1000,
                "bytes_out": 90000 if anomalous else 1200 + idx * 6,
                "bytes_in": 2500 if anomalous else 4000 + idx * 8,
                "packets_out": 2 + (idx % 3),
                "packets_in": 2 + (idx % 2),
                "dst_novelty": 1.0 if anomalous else 0.0,
                "label": 1 if anomalous else 0,
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
            "ml_pipeline.evaluate",
            "--input",
            str(input_csv),
            "--artifacts",
            str(artifacts),
            "--output",
            str(report),
            "--auto-threshold",
            "--threshold-sweep-output",
            str(sweep),
            "--roc-output",
            str(roc),
            "--pr-output",
            str(pr),
            "--confusion-output",
            str(confusion),
            "--window-scores-output",
            str(windows),
        ],
        check=True,
    )

    parsed = json.loads(report.read_text(encoding="utf-8"))
    assert parsed["threshold_source"] in {"fixed", "auto_f1"}
    assert "confusion_matrix" in parsed

    assert sweep.exists()
    assert roc.exists()
    assert pr.exists()
    assert confusion.exists()
    assert windows.exists()
