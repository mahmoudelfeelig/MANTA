from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_privacy_gate_report_fails_on_non_app_and_observer_leakage(tmp_path: Path) -> None:
    ablation_path = tmp_path / "privacy-ablation.json"
    leakage_path = tmp_path / "privacy-leakage.json"
    traffic_path = tmp_path / "traffic-fingerprint.json"
    output_path = tmp_path / "privacy-gate.json"

    ablation_path.write_text(
        json.dumps(
            {
                "results": {
                    "off": {"f1": 0.60, "pr_auc": 0.60, "roc_auc": 0.70},
                    "medium": {"f1": 0.59, "pr_auc": 0.59, "roc_auc": 0.69},
                    "strict": {"f1": 0.58, "pr_auc": 0.58, "roc_auc": 0.68},
                },
                "deltas": {
                    "off": {"pr_auc_relative_drop_vs_off": 0.0, "roc_auc_relative_drop_vs_off": 0.0},
                    "medium": {"pr_auc_relative_drop_vs_off": 0.01, "roc_auc_relative_drop_vs_off": 0.01},
                    "strict": {"pr_auc_relative_drop_vs_off": 0.02, "roc_auc_relative_drop_vs_off": 0.02},
                },
            }
        ),
        encoding="utf-8",
    )
    leakage_path.write_text(
        json.dumps(
            {
                "results": {
                    "off": {},
                    "medium": {
                        "app_reidentification_accuracy": 0.05,
                        "normalized_app_reidentification": 0.04,
                        "tasks": {
                            "app_family": {"strongest_model": {"normalized_leakage": 0.61}},
                            "destination_behavior": {"strongest_model": {"normalized_leakage": 0.52}},
                        },
                    },
                    "strict": {
                        "app_reidentification_accuracy": 0.03,
                        "normalized_app_reidentification": 0.02,
                        "tasks": {
                            "app_family": {"strongest_model": {"normalized_leakage": 0.31}},
                            "destination_behavior": {"strongest_model": {"normalized_leakage": 0.29}},
                        },
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    traffic_path.write_text(
        json.dumps(
            {
                "benchmark": "encrypted_flow_sequence_fingerprinting",
                "representation": {"type": "metadata_flow_sequence"},
                "results": {
                    "app_id": {"strongest_model": {"normalized_leakage": 0.44}},
                    "app_family": {"strongest_model": {"normalized_leakage": 0.86}},
                },
            }
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.privacy_gate_report",
            "--ablation-report",
            str(ablation_path),
            "--leakage-report",
            str(leakage_path),
            "--traffic-fingerprint-report",
            str(traffic_path),
            "--output",
            str(output_path),
        ],
        check=True,
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["verdicts"]["medium"]["utility_pass"] is True
    assert payload["verdicts"]["medium"]["leakage_pass"] is False
    assert payload["verdicts"]["medium"]["observer_pass"] is False
    assert payload["verdicts"]["medium"]["overall_pass"] is False
    assert payload["verdicts"]["strict"]["leakage_pass"] is False
    assert payload["verdicts"]["strict"]["observer_pass"] is False
