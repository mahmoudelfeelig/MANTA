from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_privacy_ablation_generates_tradeoff_report(tmp_path: Path) -> None:
    input_csv = tmp_path / "controlled.csv"
    output_json = tmp_path / "privacy-ablation.json"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.generate_controlled_dataset",
            "--output",
            str(input_csv),
            "--rows-per-scenario",
            "40",
            "--seed",
            "9",
        ],
        check=True,
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.privacy_ablation",
            "--input",
            str(input_csv),
            "--output",
            str(output_json),
            "--contamination",
            "0.05",
        ],
        check=True,
    )

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    assert payload["compatibility"]["ignored_contamination"] == 0.05
    assert "results" in payload
    assert "off" in payload["results"]
    assert "medium" in payload["results"]
