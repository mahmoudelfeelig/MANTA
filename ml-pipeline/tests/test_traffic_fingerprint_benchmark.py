from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def test_traffic_fingerprint_benchmark_emits_sequence_attack_report(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    output_json = tmp_path / "traffic-fingerprint.json"

    base_ts = 1_700_000_000_000
    rows: list[dict[str, object]] = []
    app_specs = [
        ("com.browser.alpha", "browser", "sdncampus_flow_statistics", "campus_wifi", 420, 890, 443, "TCP"),
        ("com.browser.beta", "browser", "itc_net_blend60_scenario_e", "android_lab", 540, 740, 8443, "TCP"),
        ("com.spyware.bad", "malware", "android_spyware_mendeley", "malware_lab", 1200, 220, 8080, "UDP"),
        ("com.telemetry.noisy", "telemetry", "westermo_public", "plant_floor", 260, 510, 53, "UDP"),
    ]
    for app_index, (app_id, family, source, environment, bytes_out, bytes_in, port, protocol) in enumerate(app_specs):
        for session_index in range(2):
            for step in range(18):
                rows.append(
                    {
                        "app_id": app_id,
                        "timestamp_end": base_ts + (app_index * 20_000_000) + (session_index * 4_000_000) + (step * 11_000),
                        "bytes_out": bytes_out + (step * (app_index + 1)),
                        "bytes_in": bytes_in + (step * (session_index + 2)),
                        "packets_out": 2 + (step % 3),
                        "packets_in": 3 + (step % 4),
                        "duration_ms": 120 + (step * 5),
                        "dst_novelty": 0.85 if family == "malware" else (0.55 if family == "telemetry" else 0.15),
                        "label": 1 if family == "malware" else 0,
                        "dataset_source": source,
                        "dataset_profile": source,
                        "dataset_variant": f"{source}_variant_{session_index}",
                        "environment_id": environment,
                        "session_id": f"{app_id}_session_{session_index}",
                        "app_family": family,
                        "destination_key": f"{app_id}.example:{port}",
                        "protocol": protocol,
                        "dst_port": port,
                    }
                )

    pd.DataFrame(rows).to_csv(input_csv, index=False)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "ml_pipeline.traffic_fingerprint_benchmark",
            "--input",
            str(input_csv),
            "--output",
            str(output_json),
            "--sequence-length",
            "8",
            "--min-sequence-flows",
            "6",
            "--stride",
            "4",
            "--min-class-rows",
            "6",
        ],
        check=True,
    )

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    assert payload["benchmark"] == "encrypted_flow_sequence_fingerprinting"
    assert payload["corpus"]["rows_sequences"] > 0
    assert payload["results"]["app_id"]["strongest_model"]["accuracy"] is not None
    assert payload["results"]["app_id"]["open_world"] is not None
