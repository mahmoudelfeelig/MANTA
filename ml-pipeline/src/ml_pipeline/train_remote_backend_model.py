from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .features import build_feature_windows, validate_flow_df
from .progress import PhaseProgress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train backend remote-assisted model from canonical real flow data")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-model", required=True, help="Output JSON model path")
    parser.add_argument("--output-report", required=True, help="Output JSON report path")
    parser.add_argument("--window-seconds", type=int, default=60, help="Feature window size in seconds")
    parser.add_argument(
        "--model-family",
        default="logistic_regression",
        choices=["logistic_regression", "mahalanobis_covariance", "hybrid_dual_channel"],
        help="Remote model family to train",
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


def _numeric_series(frame: pd.DataFrame, column: str, default: float = 0.0) -> pd.Series:
    if column in frame.columns:
        return pd.to_numeric(frame[column], errors="coerce").fillna(default)
    return pd.Series(np.full(len(frame), default, dtype=float), index=frame.index)


def build_remote_windows(df: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    validate_flow_df(df)
    working = df.copy()
    working["timestamp_end"] = pd.to_numeric(working["timestamp_end"], errors="coerce")
    working = working.dropna(subset=["timestamp_end"]).copy()
    working["timestamp_end"] = working["timestamp_end"].astype("int64")
    working["window_bucket"] = (working["timestamp_end"] // (window_seconds * 1000)).astype("int64")
    portable = build_feature_windows(working, window_seconds=window_seconds)

    optional_numeric = [
        "s_load",
        "r_load",
        "s_payload_avg",
        "r_payload_avg",
        "s_inter_packet_avg",
        "r_inter_packet_avg",
        "sttl",
        "rttl",
        "s_ack_rate",
        "r_ack_rate",
        "s_fin_rate",
        "r_fin_rate",
        "s_psh_rate",
        "r_psh_rate",
        "s_syn_rate",
        "r_syn_rate",
        "s_rst_rate",
        "r_rst_rate",
        "s_fragment_rate",
        "r_fragment_rate",
        "s_win_tcp",
        "r_win_tcp",
        "s_ack_delay_avg",
        "r_ack_delay_avg",
    ]
    availability_flags = [
        "has_duration_ms",
        "has_load_metrics",
        "has_payload_metrics",
        "has_inter_packet_metrics",
        "has_ttl_metrics",
        "has_tcp_flag_metrics",
        "has_fragment_metrics",
        "has_window_metrics",
        "has_ack_delay_metrics",
    ]

    for column in optional_numeric:
        working[column] = _numeric_series(working, column)
    for column in availability_flags:
        working[column] = _numeric_series(working, column).clip(lower=0.0, upper=1.0)

    rows: list[dict[str, float | int | str | bool]] = []
    grouped = working.groupby(["app_id", "window_bucket"], sort=True)
    portable_indexed = portable.set_index(["app_id", "window_bucket"], drop=False)

    for (app_id, bucket), group in grouped:
        base = portable_indexed.loc[(str(app_id), int(bucket))]
        if isinstance(base, pd.DataFrame):
            base_row = base.iloc[0]
        else:
            base_row = base

        bucket_end = int(group["timestamp_end"].max())
        bucket_dt = pd.to_datetime(bucket_end, unit="ms", utc=True)

        ttl_present = float(group["has_ttl_metrics"].mean())
        tcp_flags_present = float(group["has_tcp_flag_metrics"].mean())
        fragment_present = float(group["has_fragment_metrics"].mean())
        window_present = float(group["has_window_metrics"].mean())
        ack_delay_present = float(group["has_ack_delay_metrics"].mean())
        load_present = float(group["has_load_metrics"].mean())
        payload_present = float(group["has_payload_metrics"].mean())
        inter_packet_present = float(group["has_inter_packet_metrics"].mean())

        ttl_gap = (group["sttl"] - group["rttl"]).abs()
        load_mean = (group["s_load"] + group["r_load"]) * 0.5
        payload_mean = (group["s_payload_avg"] + group["r_payload_avg"]) * 0.5
        inter_packet_mean = (group["s_inter_packet_avg"] + group["r_inter_packet_avg"]) * 0.5
        tcp_window_mean = (group["s_win_tcp"] + group["r_win_tcp"]) * 0.5
        ack_delay_mean = (group["s_ack_delay_avg"] + group["r_ack_delay_avg"]) * 0.5

        rows.append(
            {
                "app_id": str(app_id),
                "window_bucket": int(bucket),
                "flow_count": int(base_row["flow_count"]),
                "bytes_out": float(base_row["total_bytes_out"]),
                "bytes_in": float(base_row["total_bytes_in"]),
                "mean_packet_size": float(base_row["mean_packet_size"]),
                "outbound_ratio": float(base_row["outbound_ratio"]),
                "burstiness": float(base_row["burstiness"]),
                "novelty_score": float(base_row["novelty_score"]),
                "connection_frequency_delta": float(base_row["connection_frequency_delta"]),
                "bytes_per_flow": float(base_row["bytes_per_flow"]),
                "destination_diversity": float(base_row["destination_diversity"]),
                "activity_ratio": float(base_row["activity_ratio"]),
                "periodic_beacon_score": float(base_row["periodic_beacon_score"]),
                "byte_rate": float(base_row["byte_rate"]),
                "packet_rate": float(base_row["packet_rate"]),
                "mean_duration_ms": float(base_row["mean_duration_ms"]),
                "duration_jitter": float(base_row["duration_jitter"]),
                "port_diversity": float(base_row["port_diversity"]),
                "protocol_diversity": float(base_row["protocol_diversity"]),
                "packet_imbalance": float(base_row["packet_imbalance"]),
                "small_flow_ratio": float(base_row["small_flow_ratio"]),
                "high_port_ratio": float(base_row["high_port_ratio"]),
                "hour_of_day": int(bucket_dt.hour),
                "is_weekend": bool(bucket_dt.dayofweek >= 5),
                "data_quality_score": 1.0,
                "ttl_gap": float(ttl_gap.mean() / 255.0) if ttl_present else 0.0,
                "ttl_metrics_present": ttl_present,
                "syn_rate_total": float((group["s_syn_rate"] + group["r_syn_rate"]).mean()) if tcp_flags_present else 0.0,
                "rst_rate_total": float((group["s_rst_rate"] + group["r_rst_rate"]).mean()) if tcp_flags_present else 0.0,
                "ack_rate_total": float((group["s_ack_rate"] + group["r_ack_rate"]).mean()) if tcp_flags_present else 0.0,
                "fin_rate_total": float((group["s_fin_rate"] + group["r_fin_rate"]).mean()) if tcp_flags_present else 0.0,
                "psh_rate_total": float((group["s_psh_rate"] + group["r_psh_rate"]).mean()) if tcp_flags_present else 0.0,
                "fragment_rate_total": float((group["s_fragment_rate"] + group["r_fragment_rate"]).mean()) if fragment_present else 0.0,
                "tcp_window_mean": float(tcp_window_mean.mean()) if window_present else 0.0,
                "ack_delay_mean": float(ack_delay_mean.mean()) if ack_delay_present else 0.0,
                "inter_packet_gap_mean": float(inter_packet_mean.mean()) if inter_packet_present else 0.0,
                "payload_mean": float(payload_mean.mean()) if payload_present else 0.0,
                "load_mean": float(load_mean.mean()) if load_present else 0.0,
                "transport_metrics_present": max(
                    ttl_present,
                    tcp_flags_present,
                    fragment_present,
                    window_present,
                    ack_delay_present,
                    load_present,
                    payload_present,
                    inter_packet_present,
                ),
                "label": int(pd.to_numeric(group["label"], errors="coerce").fillna(0).astype(int).max()) if "label" in group.columns else 0,
            }
        )

    return pd.DataFrame(rows)


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Remote model training")
    input_path = Path(args.input).expanduser().resolve()
    output_model_path = Path(args.output_model).expanduser().resolve()
    output_report_path = Path(args.output_report).expanduser().resolve()

    progress.update(5, "Loading flow CSV")
    flows = pd.read_csv(input_path)
    progress.update(18, "Building remote feature windows")
    windows = build_remote_windows(flows, window_seconds=args.window_seconds)
    if "label" not in windows.columns or windows["label"].nunique() < 2:
        raise ValueError("Remote backend training requires both benign and anomalous labels in the normalized dataset.")

    progress.update(34, f"Loading backend modeling family {args.model_family}")
    module = _load_remote_modeling_module()
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
    progress.update(56, "Training model")
    model, report = module.train_remote_model(samples=samples, model_type=args.model_family)
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    progress.update(88, "Writing model and report")
    output_model_path.write_text(json.dumps(model, indent=2), encoding="utf-8")
    output_report_path.write_text(
        json.dumps(
            {
                "input": str(input_path),
                "rows": int(len(flows)),
                "windows": int(len(windows)),
                "window_seconds": args.window_seconds,
                "label_counts": windows["label"].value_counts().to_dict(),
                "training_report": report,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    progress.update(100, "Completed")
    print(f"Remote backend model written to {output_model_path}")
    print(f"Training report written to {output_report_path}")


if __name__ == "__main__":
    main()
