from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_privacy_leakage_benchmark_uses_grouped_app_holdout(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    output_json = tmp_path / "privacy-leakage.json"

    base_ts = 1_700_000_000_000
    rows: list[dict[str, object]] = []
    app_specs = [
        ("com.browser.alpha", 0, "sdncampus_flow_statistics", "campus_wifi", "browser"),
        ("com.browser.beta", 0, "itc_net_blend60_scenario_e", "android_lab", "browser"),
        ("com.spyware.bad", 1, "android_spyware_mendeley", "malware_lab", "malware"),
        ("com.telemetry.noisy", 0, "westermo_public", "campus_wifi", "telemetry"),
    ]
    for app_index, (app_id, label, source, environment, family) in enumerate(app_specs):
        for session_index in range(2):
            for step in range(12):
                rows.append(
                    {
                        "app_id": app_id,
                        "timestamp_end": base_ts + (app_index * 10_000_000) + (session_index * 2_000_000) + (step * 61_000),
                        "bytes_out": 400 + (app_index * 120) + (session_index * 35) + step,
                        "bytes_in": 800 + (app_index * 90) + (session_index * 20) + step,
                        "packets_out": 3 + (step % 2),
                        "packets_in": 4 + (step % 3),
                        "dst_novelty": 0.8 if label else 0.1,
                        "label": label,
                        "dataset_source": source,
                        "dataset_profile": source,
                        "dataset_variant": f"{source}_variant_{session_index}",
                        "environment_id": environment,
                        "session_id": f"{app_id}_session_{session_index}",
                        "app_family": family,
                        "destination_key": f"{app_id}.example:{443 + session_index}",
                        "protocol": "TCP",
                        "dst_port": 443 + session_index,
                    }
                )

    pd.DataFrame(rows).to_csv(input_csv, index=False)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.privacy_leakage_benchmark",
            "--input",
            str(input_csv),
            "--output",
            str(output_json),
            "--min-class-rows",
            "4",
        ],
        check=True,
    )

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    assert payload["results"]["off"]["split_strategy"] == "per_app_group_holdout"
    assert payload["results"]["off"]["rows_train"] > 0
    assert payload["results"]["off"]["rows_test"] > 0
    assert payload["results"]["off"]["tasks"]["app_family"]["strongest_model"]["accuracy"] is not None
    assert payload["results"]["off"]["normalized_app_reidentification"] is not None
    assert payload["results"]["off"]["tasks"]["app_id"]["open_world"] is not None
