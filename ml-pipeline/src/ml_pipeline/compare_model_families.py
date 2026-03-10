from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pandas as pd

from .train_remote_backend_model import build_remote_windows
from .progress import PhaseProgress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train and compare multiple MANTA remote model families on one corpus")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-dir", required=True, help="Directory for model-family benchmark outputs")
    parser.add_argument("--window-seconds", type=int, default=60, help="Feature window size in seconds")
    parser.add_argument(
        "--families",
        nargs="+",
        default=["logistic_regression", "mahalanobis_covariance", "hybrid_dual_channel"],
        choices=["logistic_regression", "mahalanobis_covariance", "hybrid_dual_channel"],
        help="Remote model families to compare",
    )
    return parser.parse_args()


def _load_remote_modeling_module():
    module_path = Path(__file__).resolve().parents[3] / "backend-adapter" / "app" / "remote_modeling.py"
    spec = importlib.util.spec_from_file_location("manta_backend_remote_modeling", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load backend remote modeling module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Remote family comparison")
    input_path = Path(args.input).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    progress.update(5, "Loading flow CSV")
    flows = pd.read_csv(input_path)
    progress.update(18, "Building feature windows")
    windows = build_remote_windows(flows, window_seconds=args.window_seconds)
    samples = [
        {
            "window_features": {
                "flow_count": int(row.flow_count),
                "bytes_out": int(row.bytes_out),
                "bytes_in": int(row.bytes_in),
                "mean_packet_size": float(row.mean_packet_size),
                "outbound_ratio": float(row.outbound_ratio),
                "burstiness": float(row.burstiness),
                "novelty_score": float(row.novelty_score),
                "connection_frequency_delta": float(row.connection_frequency_delta),
                "bytes_per_flow": float(row.bytes_per_flow),
                "destination_diversity": float(row.destination_diversity),
                "activity_ratio": float(row.activity_ratio),
                "periodic_beacon_score": float(row.periodic_beacon_score),
                "byte_rate": float(row.byte_rate),
                "packet_rate": float(row.packet_rate),
                "mean_duration_ms": float(row.mean_duration_ms),
                "duration_jitter": float(row.duration_jitter),
                "port_diversity": float(row.port_diversity),
                "protocol_diversity": float(row.protocol_diversity),
                "packet_imbalance": float(row.packet_imbalance),
                "small_flow_ratio": float(row.small_flow_ratio),
                "high_port_ratio": float(row.high_port_ratio),
                "hour_of_day": int(row.hour_of_day),
                "is_weekend": bool(row.is_weekend),
                "data_quality_score": float(row.data_quality_score),
                "ttl_gap": float(row.ttl_gap),
                "ttl_metrics_present": float(row.ttl_metrics_present),
                "syn_rate_total": float(row.syn_rate_total),
                "rst_rate_total": float(row.rst_rate_total),
                "ack_rate_total": float(row.ack_rate_total),
                "fin_rate_total": float(row.fin_rate_total),
                "psh_rate_total": float(row.psh_rate_total),
                "fragment_rate_total": float(row.fragment_rate_total),
                "tcp_window_mean": float(row.tcp_window_mean),
                "ack_delay_mean": float(row.ack_delay_mean),
                "inter_packet_gap_mean": float(row.inter_packet_gap_mean),
                "payload_mean": float(row.payload_mean),
                "load_mean": float(row.load_mean),
                "transport_metrics_present": float(row.transport_metrics_present),
            },
            "site_hint": None,
            "label": int(row.label),
        }
        for row in windows.itertuples(index=False)
    ]

    module = _load_remote_modeling_module()
    matrix: list[dict[str, object]] = []
    total = max(1, len(args.families))
    for index, family in enumerate(args.families, start=1):
        progress.update(20 + ((index - 1) / total) * 60, f"Training {family}")
        model, report = module.train_remote_model(samples=samples, model_type=family)
        (output_dir / f"{family}.model.json").write_text(json.dumps(model, indent=2), encoding="utf-8")
        (output_dir / f"{family}.report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        metrics = report.get("metrics") or {}
        matrix.append(
            {
                "family": family,
                "sample_count": int(report.get("sample_count", 0)),
                "precision": metrics.get("precision"),
                "recall": metrics.get("recall"),
                "f1": metrics.get("f1"),
                "pr_auc": metrics.get("pr_auc"),
                "roc_auc": metrics.get("roc_auc"),
            }
        )

    summary = {
        "input": str(input_path),
        "window_seconds": args.window_seconds,
        "families": matrix,
        "label_counts": windows["label"].value_counts().to_dict() if "label" in windows.columns else {},
    }
    (output_dir / "comparison-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
