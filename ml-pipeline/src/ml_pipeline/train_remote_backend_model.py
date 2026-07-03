from __future__ import annotations

import argparse
import importlib.util
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .cache_utils import _sample_by_source, load_feature_windows_cached, load_remote_windows_cached
from .features import (
    build_android_feature_windows,
    build_android_sliding_feature_windows,
    build_feature_windows,
    validate_flow_df,
)
from .io_utils import read_csv_resilient
from .progress import PhaseProgress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train backend remote-assisted model from canonical real flow data")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-model", required=True, help="Output JSON model path")
    parser.add_argument("--output-report", required=True, help="Output JSON report path")
    parser.add_argument("--window-seconds", type=int, default=60, help="Feature window size in seconds")
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument(
        "--max-adaptive-windows",
        type=int,
        default=250000,
        help="Emit at most a bounded stride of adaptive windows while preserving positive windows.",
    )
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
    parser.add_argument(
        "--max-flow-rows",
        type=int,
        default=0,
        help="Source-balanced raw-flow cap applied before feature-window construction; positives are preserved where possible.",
    )
    parser.add_argument(
        "--model-family",
        default="hybrid_dual_channel",
        choices=["logistic_regression", "gradient_boosted_tree", "mahalanobis_covariance", "hybrid_dual_channel"],
        help="Remote model family to train; hybrid_dual_channel is the default thesis primary",
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
                "dataset_source": str(base_row.get("dataset_source", "unknown_source")),
                "dataset_profile": str(base_row.get("dataset_profile", "unknown_profile")),
                "dataset_variant": str(base_row.get("dataset_variant", "unknown_variant")),
                "environment_id": str(base_row.get("environment_id", "unknown_environment")),
                "session_id": str(base_row.get("session_id", "unknown_session")),
                "app_family": str(base_row.get("app_family", "other_app")),
                "label": int(pd.to_numeric(group["label"], errors="coerce").fillna(0).astype(int).max()) if "label" in group.columns else 0,
            }
        )

    return pd.DataFrame(rows)


def _sample_flow_rows(frame: pd.DataFrame, max_flow_rows: int, random_seed: int = 42) -> pd.DataFrame:
    if max_flow_rows <= 0 or len(frame) <= max_flow_rows:
        return frame.reset_index(drop=True)
    label_column = "label" if "label" in frame.columns else ("is_anomaly" if "is_anomaly" in frame.columns else None)
    if label_column is None:
        return _sample_by_source(frame, max_flow_rows, random_seed=random_seed)
    labels = pd.to_numeric(frame[label_column], errors="coerce").fillna(0).astype(int)
    positives = frame[labels > 0]
    negatives = frame[labels <= 0]
    positive_limit = min(len(positives), max(1, max_flow_rows // 2)) if not positives.empty and not negatives.empty else min(len(positives), max_flow_rows)
    sampled_positives = _sample_by_source(positives, positive_limit, random_seed=random_seed) if positive_limit < len(positives) else positives
    negative_limit = max(0, max_flow_rows - len(sampled_positives))
    if negative_limit <= 0:
        return sampled_positives.reset_index(drop=True)
    sampled_negatives = _sample_by_source(negatives, negative_limit, random_seed=random_seed)
    return pd.concat([sampled_positives, sampled_negatives], ignore_index=True, sort=False).sort_values(
        ["app_id", "timestamp_end"] if {"app_id", "timestamp_end"}.issubset(frame.columns) else frame.columns[0],
        kind="mergesort",
    ).reset_index(drop=True)


def _load_training_windows(args: argparse.Namespace, input_path: Path) -> tuple[pd.DataFrame, str]:
    if int(args.max_flow_rows) > 0:
        frame = _sample_flow_rows(read_csv_resilient(input_path), int(args.max_flow_rows))
        if args.window_mode == "bucket":
            return build_remote_windows(frame, args.window_seconds), f"direct_sampled_bucket_maxflow{int(args.max_flow_rows)}"
        builder = (
            (lambda raw, seconds: build_android_sliding_feature_windows(
                raw,
                seconds,
                adaptive=False,
                label_strategy=args.label_strategy,
                emit_all_horizons=args.multi_horizon_training,
            ))
            if args.window_mode == "sliding"
            else (lambda raw, seconds: build_android_sliding_feature_windows(
                raw,
                seconds,
                adaptive=True,
                max_windows=args.max_adaptive_windows,
                label_strategy=args.label_strategy,
                emit_all_horizons=args.multi_horizon_training,
            ))
        )
        return builder(frame, args.window_seconds), f"direct_sampled_{args.window_mode}_maxflow{int(args.max_flow_rows)}"
    if args.window_mode == "bucket":
        windows = load_remote_windows_cached(
            input_path,
            build_remote_windows_fn=build_remote_windows,
            read_frame_fn=read_csv_resilient,
            window_seconds=args.window_seconds,
        )
        return windows, "remote_bucket"
    if args.window_mode == "sliding":
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=False,
            label_strategy=args.label_strategy,
            emit_all_horizons=args.multi_horizon_training,
        )
        cache_name = "android_sliding_feature_windows"
    else:
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=True,
            max_windows=args.max_adaptive_windows,
            label_strategy=args.label_strategy,
                emit_all_horizons=args.multi_horizon_training,
        )
        cache_name = "android_adaptive_feature_windows"
        if args.max_adaptive_windows > 0:
            cache_name = f"{cache_name}_max{args.max_adaptive_windows}"
    if args.label_strategy != "window":
        cache_name = f"{cache_name}_{args.label_strategy}"
    if args.multi_horizon_training:
        cache_name = f"{cache_name}_multihorizon"
    windows = load_feature_windows_cached(
        input_path,
        build_windows_fn=build_windows_fn if args.window_mode != "bucket" else build_android_feature_windows,
        read_frame_fn=read_csv_resilient,
        window_seconds=args.window_seconds,
        cache_name=cache_name,
    )
    return windows, cache_name


def _feature_window_from_row(row: dict[str, object]) -> dict[str, object]:
    feature_window = dict(row)
    if "bytes_out" not in feature_window:
        feature_window["bytes_out"] = feature_window.get("total_bytes_out", 0.0)
    if "bytes_in" not in feature_window:
        feature_window["bytes_in"] = feature_window.get("total_bytes_in", 0.0)
    if "data_quality_score" not in feature_window:
        feature_window["data_quality_score"] = 1.0
    if "hour_of_day" in feature_window:
        feature_window["hour_of_day"] = int(float(feature_window.get("hour_of_day") or 0)) % 24
    if "is_weekend" in feature_window:
        feature_window["is_weekend"] = bool(feature_window.get("is_weekend"))
    return feature_window


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Remote model training")
    input_path = Path(args.input).expanduser().resolve()
    output_model_path = Path(args.output_model).expanduser().resolve()
    output_report_path = Path(args.output_report).expanduser().resolve()

    progress.update(5, "Loading flow CSV")
    progress.update(18, "Building remote feature windows")
    windows, window_cache_name = _load_training_windows(args, input_path)
    if "label" not in windows.columns or windows["label"].nunique() < 2:
        raise ValueError("Remote backend training requires both benign and anomalous labels in the normalized dataset.")

    progress.update(34, f"Loading backend modeling family {args.model_family}")
    module = _load_remote_modeling_module()
    samples = []
    for row in windows.to_dict(orient="records"):
        samples.append(
            {
                "window_features": _feature_window_from_row(row),
                "site_hint": row.get("site_hint"),
                "label": int(row.get("label") or 0),
                "dataset_source": str(row.get("dataset_source") or "unknown_source"),
                "dataset_profile": str(row.get("dataset_profile") or "unknown_profile"),
                "dataset_variant": str(row.get("dataset_variant") or "unknown_variant"),
                "environment_id": str(row.get("environment_id") or "unknown_environment"),
                "session_id": str(row.get("session_id") or "unknown_session"),
                "app_family": str(row.get("app_family") or "other_app"),
                "window_bucket": int(row.get("window_bucket") or 0),
            }
        )
    progress.update(56, "Training model")
    fit_start = time.perf_counter()
    model, report = module.train_remote_model(samples=samples, model_type=args.model_family)
    training_seconds = float(time.perf_counter() - fit_start)
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    progress.update(88, "Writing model and report")
    output_model_path.write_text(json.dumps(model, indent=2), encoding="utf-8")
    output_report_path.write_text(
        json.dumps(
            {
                "input": str(input_path),
                "model_family": args.model_family,
                "rows": int(len(read_csv_resilient(input_path))),
                "windows": int(len(windows)),
                "window_seconds": args.window_seconds,
                "window_mode": args.window_mode,
                "window_cache_name": window_cache_name,
                "label_strategy": args.label_strategy,
                "max_adaptive_windows": int(args.max_adaptive_windows),
                "multi_horizon_training": bool(args.multi_horizon_training),
                "training_seconds": training_seconds,
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
