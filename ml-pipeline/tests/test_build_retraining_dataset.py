from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_build_retraining_dataset_from_backend_samples(tmp_path: Path) -> None:
    input_json = tmp_path / "samples.json"
    output_csv = tmp_path / "artifacts" / "retraining-dataset.csv"
    report_json = tmp_path / "reports" / "retraining-dataset-report.json"

    payload = {
        "status": "ok",
        "device_id_pseudo": "abcd1234",
        "samples": [
            {
                "alert_id": "a1",
                "app_id": "com.alpha",
                "anomaly_score": 0.82,
                "source_model": "ensemble_fusion",
                "triage_status": "RESOLVED",
                "triage_note": "confirmed",
                "confidence": 0.74,
                "uncertainty": 0.26,
                "drift_score": 0.41,
                "beacon_score": 0.35,
                "timestamp": 1_700_000_001,
            },
            {
                "alert_id": "a2",
                "app_id": "com.alpha",
                "anomaly_score": 0.63,
                "source_model": "ensemble_fusion",
                "triage_status": "FALSE_POSITIVE",
                "triage_note": "noise",
                "confidence": 0.61,
                "uncertainty": 0.39,
                "drift_score": 0.12,
                "beacon_score": 0.05,
                "timestamp": 1_700_000_002,
            },
        ],
    }
    input_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.build_retraining_dataset",
            "--input",
            str(input_json),
            "--output",
            str(output_csv),
            "--report",
            str(report_json),
            "--min-per-class",
            "1",
        ],
        check=True,
    )

    frame = pd.read_csv(output_csv)
    report = json.loads(report_json.read_text(encoding="utf-8"))

    assert len(frame) == 2
    assert set(frame["label"].tolist()) == {0, 1}
    assert report["rows_exported"] == 2
    assert report["sufficient_per_class"] is True
