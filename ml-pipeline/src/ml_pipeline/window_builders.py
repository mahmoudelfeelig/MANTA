from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import Callable

import pandas as pd

from .cache_utils import _sample_by_source, load_feature_windows_cached
from .features import build_android_feature_windows, build_android_sliding_feature_windows
from .io_utils import read_csv_resilient


def add_window_protocol_args(parser) -> None:
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=250000)
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
    parser.add_argument("--max-flow-rows", type=int, default=0)


def adaptive_cache_name(args: Namespace, prefix: str) -> str:
    if args.window_mode == "bucket":
        cache_name = f"{prefix}_bucket_feature_windows"
    elif args.window_mode == "sliding":
        cache_name = f"{prefix}_sliding_feature_windows"
    else:
        cache_name = f"{prefix}_adaptive_feature_windows"
        if int(args.max_adaptive_windows) > 0:
            cache_name = f"{cache_name}_max{int(args.max_adaptive_windows)}"
    if args.label_strategy != "window":
        cache_name = f"{cache_name}_{args.label_strategy}"
    if bool(args.multi_horizon_training):
        cache_name = f"{cache_name}_multihorizon"
    return cache_name


def android_window_builder(args: Namespace) -> Callable[[pd.DataFrame, int], pd.DataFrame]:
    if args.window_mode == "bucket":
        return build_android_feature_windows
    if args.window_mode == "sliding":
        return lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=False,
            label_strategy=args.label_strategy,
            emit_all_horizons=args.multi_horizon_training,
        )
    return lambda frame, seconds: build_android_sliding_feature_windows(
        frame,
        seconds,
        adaptive=True,
        max_windows=int(args.max_adaptive_windows),
        label_strategy=args.label_strategy,
        emit_all_horizons=args.multi_horizon_training,
    )


def load_android_windows_for_protocol(input_path: str | Path, args: Namespace, *, cache_prefix: str) -> pd.DataFrame:
    if int(getattr(args, "max_flow_rows", 0) or 0) > 0:
        frame = read_csv_resilient(input_path)
        frame = _sample_flow_rows(frame, int(args.max_flow_rows))
        return android_window_builder(args)(frame, int(args.window_seconds)).reset_index(drop=True)
    return load_feature_windows_cached(
        input_path,
        build_windows_fn=android_window_builder(args),
        read_frame_fn=read_csv_resilient,
        window_seconds=int(args.window_seconds),
        cache_name=adaptive_cache_name(args, cache_prefix),
    )


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
    sort_columns = ["app_id", "timestamp_end"] if {"app_id", "timestamp_end"}.issubset(frame.columns) else [frame.columns[0]]
    return pd.concat([sampled_positives, sampled_negatives], ignore_index=True, sort=False).sort_values(
        sort_columns,
        kind="mergesort",
    ).reset_index(drop=True)
