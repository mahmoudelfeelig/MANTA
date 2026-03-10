from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .features import build_feature_windows, feature_matrix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark MANTA feature extraction/scoring performance with realistic window-sized batches")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--iterations", type=int, default=40)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--mini-batch-windows", type=int, default=8)
    return parser.parse_args()


def percentile(values: list[float], target: float) -> float:
    if not values:
        return 0.0
    return float(np.percentile(np.asarray(values, dtype=float), target))


def _timing_summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
    }


def main() -> None:
    args = parse_args()
    rng = np.random.default_rng(args.random_seed)
    flows = pd.read_csv(args.input)
    windows = build_feature_windows(flows)

    grouped = flows.copy()
    grouped["timestamp_end"] = pd.to_numeric(grouped["timestamp_end"], errors="coerce")
    grouped = grouped.dropna(subset=["timestamp_end"]).copy()
    grouped["timestamp_end"] = grouped["timestamp_end"].astype("int64")
    grouped["window_bucket"] = (grouped["timestamp_end"] // (60 * 1000)).astype("int64")

    grouped_indices = grouped.groupby(["app_id", "window_bucket"], sort=False).groups
    group_keys = list(grouped_indices.keys())
    if not group_keys:
        raise SystemExit("No feature windows available for performance benchmarking.")

    single_window_timings: list[float] = []
    mini_batch_timings: list[float] = []
    single_matrix_timings: list[float] = []
    batch_matrix_timings: list[float] = []

    for _ in range(args.iterations):
        single_key = group_keys[int(rng.integers(0, len(group_keys)))]
        single_group = grouped[(grouped["app_id"] == single_key[0]) & (grouped["window_bucket"] == single_key[1])]

        start = time.perf_counter()
        single_window = build_feature_windows(single_group)
        single_window_timings.append((time.perf_counter() - start) * 1000.0)

        start = time.perf_counter()
        _ = feature_matrix(single_window)
        single_matrix_timings.append((time.perf_counter() - start) * 1000.0)

        batch_size = min(args.mini_batch_windows, len(group_keys))
        batch_indices = rng.choice(len(group_keys), size=batch_size, replace=False)
        row_indices: list[int] = []
        for index in batch_indices.tolist():
            row_indices.extend(grouped_indices[group_keys[int(index)]].tolist())
        batch_frame = grouped.iloc[row_indices]

        start = time.perf_counter()
        batch_windows = build_feature_windows(batch_frame)
        mini_batch_timings.append((time.perf_counter() - start) * 1000.0 / max(1, len(batch_windows)))

        matrix_batch = windows.sample(n=min(32, len(windows)), random_state=int(rng.integers(0, 1_000_000)))
        start = time.perf_counter()
        _ = feature_matrix(matrix_batch)
        batch_matrix_timings.append((time.perf_counter() - start) * 1000.0 / max(1, len(matrix_batch)))

    report = {
        "rows_flows": int(len(flows)),
        "rows_windows": int(len(windows)),
        "window_extraction_single_ms": _timing_summary(single_window_timings),
        "window_extraction_mini_batch_per_window_ms": _timing_summary(mini_batch_timings),
        "feature_matrix_single_window_ms": _timing_summary(single_matrix_timings),
        "feature_matrix_batch_per_window_ms": _timing_summary(batch_matrix_timings),
    }
    report["gates"] = {
        "single_window_build_p95_le_25ms": report["window_extraction_single_ms"]["p95"] <= 25.0,
        "single_window_build_p99_le_40ms": report["window_extraction_single_ms"]["p99"] <= 40.0,
        "mini_batch_build_p95_le_25ms": report["window_extraction_mini_batch_per_window_ms"]["p95"] <= 25.0,
        "feature_matrix_single_p95_le_5ms": report["feature_matrix_single_window_ms"]["p95"] <= 5.0,
        "feature_matrix_batch_p95_le_5ms": report["feature_matrix_batch_per_window_ms"]["p95"] <= 5.0,
    }
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
