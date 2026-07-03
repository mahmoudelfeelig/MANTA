import json
from pathlib import Path

import pandas as pd

from ml_pipeline.feedback_dataset import android_alert_feedback_to_training_csv


def test_feedback_converter_maps_triage_to_labels(tmp_path: Path) -> None:
    input_json = tmp_path / "alerts.json"
    output_csv = tmp_path / "feedback.csv"
    input_json.write_text(
        json.dumps(
            {
                "alerts": [
                    {"id": "a", "app_id": "com.a", "triage_status": "FALSE_POSITIVE", "timestamp": 1},
                    {"id": "b", "app_id": "com.b", "triage_status": "RESOLVED", "timestamp": 2},
                ]
            }
        ),
        encoding="utf-8",
    )

    android_alert_feedback_to_training_csv(input_json, output_csv)
    frame = pd.read_csv(output_csv)

    assert frame["label"].tolist() == [0, 1]
    assert set(frame["dataset_source"]) == {"android_feedback"}
