from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


SCENARIOS = [
    "normal_browsing",
    "normal_streaming",
    "beaconing",
    "burst_exfiltration",
    "unusual_destination",
]



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate controlled mobile flow traces for experiments")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--rows-per-scenario", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()



def _scenario_label(name: str) -> int:
    return 0 if name in {"normal_browsing", "normal_streaming"} else 1



def _sample_flow(scenario: str, timestamp_end: int, rng: np.random.Generator) -> dict:
    app_pool = {
        "normal_browsing": ["com.browser.alpha", "com.news.beta"],
        "normal_streaming": ["com.stream.video", "com.music.player"],
        "beaconing": ["com.suspicious.beacon"],
        "burst_exfiltration": ["com.suspicious.exfil"],
        "unusual_destination": ["com.mixed.client"],
    }

    app_id = app_pool[scenario][int(rng.integers(0, len(app_pool[scenario])))]

    def _clipped_int(value: float, low: float, high: float) -> int:
        return int(np.clip(value, low, high))

    if scenario == "normal_browsing":
        bytes_out = _clipped_int(rng.normal(loc=4_500, scale=1_500), 300, 20_000)
        bytes_in = _clipped_int(rng.normal(loc=9_000, scale=3_000), 500, 35_000)
        novelty = float(rng.choice([0.0, 0.0, 0.1, 0.2]))
        dst_port = int(rng.choice([80, 443]))
    elif scenario == "normal_streaming":
        bytes_out = _clipped_int(rng.normal(loc=8_000, scale=2_500), 1_000, 30_000)
        bytes_in = _clipped_int(rng.normal(loc=45_000, scale=8_000), 3_000, 120_000)
        novelty = float(rng.choice([0.0, 0.0, 0.1]))
        dst_port = 443
    elif scenario == "beaconing":
        bytes_out = _clipped_int(rng.normal(loc=300, scale=90), 50, 1_000)
        bytes_in = _clipped_int(rng.normal(loc=250, scale=100), 40, 1_200)
        novelty = float(rng.choice([0.0, 0.2]))
        dst_port = int(rng.choice([443, 8080]))
    elif scenario == "burst_exfiltration":
        bytes_out = _clipped_int(rng.normal(loc=280_000, scale=75_000), 40_000, 700_000)
        bytes_in = _clipped_int(rng.normal(loc=4_000, scale=1_200), 200, 15_000)
        novelty = float(rng.choice([0.4, 0.7, 1.0]))
        dst_port = int(rng.choice([443, 8443, 9001]))
    else:  # unusual_destination
        bytes_out = _clipped_int(rng.normal(loc=7_000, scale=2_000), 600, 30_000)
        bytes_in = _clipped_int(rng.normal(loc=7_500, scale=2_000), 600, 35_000)
        novelty = float(rng.choice([0.6, 0.8, 1.0]))
        dst_port = int(rng.choice([443, 5222, 6881, 8443]))

    packets_out = max(1, int(bytes_out / max(80, rng.normal(300, 90))))
    packets_in = max(1, int(bytes_in / max(80, rng.normal(400, 120))))
    duration_ms = _clipped_int(rng.normal(loc=1_200, scale=300), 200, 10_000)

    return {
        "scenario": scenario,
        "label": _scenario_label(scenario),
        "app_id": app_id,
        "timestamp_end": timestamp_end,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "packets_out": packets_out,
        "packets_in": packets_in,
        "dst_novelty": novelty,
        "duration_ms": duration_ms,
        "protocol": "TCP",
        "dst_port": dst_port,
    }



def generate_controlled_dataset(rows_per_scenario: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    base_ts = 1_706_000_000_000

    rows: list[dict] = []
    for scenario in SCENARIOS:
        for idx in range(rows_per_scenario):
            timestamp_end = base_ts + (len(rows) * 1_000) + int(rng.integers(0, 300))
            rows.append(_sample_flow(scenario=scenario, timestamp_end=timestamp_end, rng=rng))

    return pd.DataFrame(rows)



def main() -> None:
    args = parse_args()
    df = generate_controlled_dataset(rows_per_scenario=args.rows_per_scenario, seed=args.seed)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)


if __name__ == "__main__":
    main()
