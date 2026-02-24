from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_train_android_model_exports_coefficients_and_report(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    model_json = tmp_path / "artifacts" / "anomaly-linear.json"
    report_json = tmp_path / "reports" / "android-model-eval.json"

    rows = []
    for idx in range(260):
        is_anomaly = idx % 70 == 0
        rows.append(
            {
                "app_id": "com.test" if idx < 180 else "com.alt",
                "timestamp_end": 1_700_100_000_000 + idx * 1_000,
                "bytes_out": 150_000 + idx * 300 if is_anomaly else 1_000 + idx * 8,
                "bytes_in": 2_000 if is_anomaly else 4_000 + idx * 10,
                "packets_out": 3 + (idx % 4),
                "packets_in": 2 + (idx % 3),
                "dst_novelty": 1.0 if is_anomaly else 0.0,
                "label": 1 if is_anomaly else 0,
            }
        )
    pd.DataFrame(rows).to_csv(input_csv, index=False)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.train_android_model",
            "--input",
            str(input_csv),
            "--output-model",
            str(model_json),
            "--output-report",
            str(report_json),
        ],
        check=True,
    )

    exported_model = json.loads(model_json.read_text(encoding="utf-8"))
    exported_report = json.loads(report_json.read_text(encoding="utf-8"))

    assert exported_model["model_type"] == "logistic_regression"
    assert len(exported_model["feature_order"]) == len(exported_model["weights"])
    assert "recommended_threshold" in exported_model
    assert "f1" in exported_report
