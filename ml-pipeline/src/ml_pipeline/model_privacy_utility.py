from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .error_analysis import score_android_model
from .metrics import binary_classification_metrics
from .privacy_views import build_window_privacy_views_from_windows
from .window_builders import add_window_protocol_args, adaptive_cache_name, load_android_windows_for_protocol


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare local and remote model utility under privacy feature views")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--local-model", required=True, help="Android exported local JSON model")
    parser.add_argument("--remote-model", required=True, help="Backend remote JSON model")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--max-report-rows", type=int, default=0, help="Optional stratified row cap for slower remote scoring reports")
    add_window_protocol_args(parser)
    return parser.parse_args()


def _load_backend_remote_modeling():
    module_path = Path(__file__).resolve().parents[3] / "backend-adapter" / "app" / "remote_modeling.py"
    spec = importlib.util.spec_from_file_location("manta_backend_remote_modeling", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load backend remote modeling module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _threshold_from_model(payload: dict[str, Any]) -> float:
    return float(payload.get("recommended_threshold", payload.get("threshold", 0.5)))


def _score_remote_model(remote_module, payload: dict[str, Any], frame: pd.DataFrame) -> np.ndarray:
    scores: list[float] = []
    for row in frame.to_dict(orient="records"):
        if "bytes_out" not in row:
            row["bytes_out"] = row.get("total_bytes_out", 0.0)
        if "bytes_in" not in row:
            row["bytes_in"] = row.get("total_bytes_in", 0.0)
        result = remote_module.score_remote_model(payload, row, row.get("site_hint"))
        scores.append(float(result.get("score", 0.0)))
    return np.asarray(scores, dtype=float)


def _evaluate_scores(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    metrics = binary_classification_metrics(labels, scores, threshold)
    return {"threshold": float(threshold), **metrics}


def _sample_report_windows(windows: pd.DataFrame, max_rows: int, random_seed: int = 42) -> pd.DataFrame:
    if max_rows <= 0 or len(windows) <= max_rows or "label" not in windows.columns:
        return windows
    samples: list[pd.DataFrame] = []
    groups = list(windows.groupby(windows["label"].fillna(0).astype(int), sort=False))
    per_group = max(1, max_rows // max(1, len(groups)))
    for _, group in groups:
        take = min(len(group), per_group)
        samples.append(group.sample(n=take, random_state=random_seed))
    sampled = pd.concat(samples, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=random_seed)
    return sampled.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


def _remote_raw_signal_count(frame: pd.DataFrame) -> int:
    raw_signals = [
        "flow_count",
        "bytes_out",
        "bytes_in",
        "total_bytes_out",
        "total_bytes_in",
        "mean_packet_size",
        "outbound_ratio",
        "burstiness",
        "novelty_score",
        "connection_frequency_delta",
        "bytes_per_flow",
        "destination_diversity",
        "activity_ratio",
        "periodic_beacon_score",
        "byte_rate",
        "packet_rate",
        "mean_duration_ms",
        "duration_jitter",
        "port_diversity",
        "protocol_diversity",
        "packet_imbalance",
        "small_flow_ratio",
        "high_port_ratio",
        "hour_of_day",
        "day_of_week",
        "is_weekend",
        "data_quality_score",
        "ttl_gap",
        "ttl_metrics_present",
        "transport_metrics_present",
        "destination_concentration",
        "destination_transition_rate",
        "dns_flow_ratio",
        "web_flow_ratio",
        "destination_risk_score",
        "lookalike_score",
        "suspicious_destination_ratio",
    ]
    return int(sum(1 for signal in raw_signals if signal in frame.columns))


def main() -> None:
    args = parse_args()
    windows = load_android_windows_for_protocol(args.input, args, cache_prefix="model_privacy_utility")
    original_rows = int(len(windows))
    windows = _sample_report_windows(windows, int(args.max_report_rows))
    if "label" not in windows.columns:
        raise SystemExit("Model privacy utility requires labels.")
    views = build_window_privacy_views_from_windows(windows)
    local_payload = json.loads(Path(args.local_model).expanduser().resolve().read_text(encoding="utf-8"))
    remote_payload = json.loads(Path(args.remote_model).expanduser().resolve().read_text(encoding="utf-8"))
    remote_module = _load_backend_remote_modeling()
    labels = windows["label"].fillna(0).astype(int).to_numpy()
    local_threshold = _threshold_from_model(local_payload)
    remote_threshold = _threshold_from_model(remote_payload)
    local_runtime_scores = score_android_model(local_payload, windows)

    results: dict[str, dict[str, object]] = {}
    for view_name, frame in views.items():
        local_frame = frame.copy()
        for feature in local_payload.get("feature_order", []):
            if feature not in local_frame.columns:
                local_frame[str(feature)] = 0.0
        local_release_view_scores = score_android_model(local_payload, local_frame)
        remote_scores = _score_remote_model(remote_module, remote_payload, frame)
        results[view_name] = {
            "local": _evaluate_scores(labels, local_runtime_scores, local_threshold),
            "local_runtime": _evaluate_scores(labels, local_runtime_scores, local_threshold),
            "local_release_view": _evaluate_scores(labels, local_release_view_scores, local_threshold),
            "remote": _evaluate_scores(labels, remote_scores, remote_threshold),
            "features_present": {
                "local_runtime_exported_order": int(sum(1 for feature in local_payload.get("feature_order", []) if feature in windows.columns)),
                "local_release_view_exported_order": int(sum(1 for feature in local_payload.get("feature_order", []) if feature in frame.columns)),
                "remote_raw_signals": _remote_raw_signal_count(frame),
                "remote_transformed_order_direct": int(sum(1 for feature in remote_payload.get("feature_order", []) if feature in frame.columns)),
            },
        }

    payload = {
        "input": str(Path(args.input).expanduser().resolve()),
        "rows": int(len(windows)),
        "original_rows": original_rows,
        "max_report_rows": int(args.max_report_rows),
        "label_counts": windows["label"].value_counts().to_dict(),
        "local_model": str(Path(args.local_model).expanduser().resolve()),
        "remote_model": str(Path(args.remote_model).expanduser().resolve()),
        "window_protocol": {
            "window_mode": args.window_mode,
            "window_seconds": int(args.window_seconds),
            "label_strategy": args.label_strategy,
            "max_adaptive_windows": int(args.max_adaptive_windows),
            "max_flow_rows": int(args.max_flow_rows),
            "multi_horizon_training": bool(args.multi_horizon_training),
            "cache_name": adaptive_cache_name(args, "model_privacy_utility"),
        },
        "results": results,
    }
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
