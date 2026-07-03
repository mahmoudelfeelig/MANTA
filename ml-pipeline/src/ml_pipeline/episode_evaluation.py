from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .cache_utils import load_feature_windows_cached
from .error_analysis import score_android_model
from .features import build_android_feature_windows, build_android_sliding_feature_windows
from .io_utils import read_csv_resilient
from .metrics import operational_binary_metrics
from .splits import source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Android detections as correlated alert episodes")
    parser.add_argument("--input", required=True, help="Flow CSV used for training/evaluation")
    parser.add_argument("--model", required=True, help="Android JSON model artifact")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0)
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
    parser.add_argument("--episode-gap-seconds", type=int, default=300)
    return parser.parse_args()


def _load_windows(
    input_path: str | Path,
    *,
    window_mode: str,
    max_adaptive_windows: int,
    label_strategy: str,
    multi_horizon_training: bool,
) -> pd.DataFrame:
    if window_mode == "bucket":
        build_windows_fn = build_android_feature_windows
        cache_name = "android_feature_windows"
    elif window_mode == "sliding":
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=False,
            label_strategy=label_strategy,
            emit_all_horizons=multi_horizon_training,
        )
        cache_name = "android_sliding_feature_windows"
    else:
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=True,
            max_windows=max_adaptive_windows,
            label_strategy=label_strategy,
            emit_all_horizons=multi_horizon_training,
        )
        cache_name = "android_adaptive_feature_windows"
        if max_adaptive_windows > 0:
            cache_name = f"{cache_name}_max{max_adaptive_windows}"
    if label_strategy != "window":
        cache_name = f"{cache_name}_{label_strategy}"
    if multi_horizon_training:
        cache_name = f"{cache_name}_multihorizon"
    return load_feature_windows_cached(
        input_path,
        build_windows_fn=build_windows_fn,
        read_frame_fn=read_csv_resilient,
        cache_name=cache_name,
    )


def _episode_frame(windows: pd.DataFrame, scores: np.ndarray, threshold: float, gap_seconds: int) -> pd.DataFrame:
    working = windows.copy()
    working["_score"] = np.asarray(scores, dtype=float)
    working["_prediction"] = (working["_score"] >= float(threshold)).astype(int)
    working["label"] = pd.to_numeric(working["label"], errors="coerce").fillna(0).astype(int)
    if "session_id" not in working.columns:
        working["session_id"] = "unknown_session"
    if "window_end_ms" not in working.columns:
        working["window_end_ms"] = pd.to_numeric(working.get("window_bucket", 0), errors="coerce").fillna(0).astype("int64") * 1000
    sort_keys = ["app_id", "session_id", "window_end_ms"]
    working = working.sort_values(sort_keys, kind="mergesort").reset_index(drop=True)
    previous_app = working["app_id"].astype(str).shift()
    previous_session = working["session_id"].astype(str).shift()
    previous_end = pd.to_numeric(working["window_end_ms"], errors="coerce").fillna(0).shift()
    gap_ms = pd.to_numeric(working["window_end_ms"], errors="coerce").fillna(0) - previous_end.fillna(0)
    starts_new = (
        (working["app_id"].astype(str) != previous_app.fillna("")) |
        (working["session_id"].astype(str) != previous_session.fillna("")) |
        (gap_ms > int(gap_seconds) * 1000)
    )
    working["_episode_id"] = starts_new.astype(int).cumsum()
    return (
        working.groupby("_episode_id", sort=False)
        .agg(
            app_id=("app_id", "first"),
            app_family=("app_family", "first"),
            dataset_source=("dataset_source", "first"),
            session_id=("session_id", "first"),
            start_ms=("window_end_ms", "min"),
            end_ms=("window_end_ms", "max"),
            windows=("label", "size"),
            label=("label", "max"),
            score=("_score", "max"),
            prediction=("_prediction", "max"),
        )
        .reset_index(drop=True)
    )


def build_episode_report(
    input_path: str | Path,
    model_path: str | Path,
    *,
    random_seed: int = 42,
    test_ratio: float = 0.3,
    window_mode: str = "adaptive",
    max_adaptive_windows: int = 0,
    label_strategy: str = "window",
    multi_horizon_training: bool = False,
    episode_gap_seconds: int = 300,
) -> dict[str, object]:
    payload = json.loads(Path(model_path).read_text(encoding="utf-8"))
    windows = _load_windows(
        input_path,
        window_mode=window_mode,
        max_adaptive_windows=max_adaptive_windows,
        label_strategy=label_strategy,
        multi_horizon_training=multi_horizon_training,
    )
    split = source_aware_train_test_split(
        windows,
        label_column="label",
        test_size=test_ratio,
        random_seed=random_seed,
    )
    test_df = windows.iloc[split.test_idx].reset_index(drop=True)
    scores = score_android_model(payload, test_df)
    threshold = float(payload.get("recommended_threshold", 0.5))
    y_true = test_df["label"].fillna(0).astype(int).to_numpy()
    window_metrics = operational_binary_metrics(y_true, scores, threshold)
    episodes = _episode_frame(test_df, scores, threshold, episode_gap_seconds)
    episode_metrics = operational_binary_metrics(
        episodes["label"].to_numpy(dtype=int),
        episodes["score"].to_numpy(dtype=float),
        threshold,
    )
    return {
        "threshold": threshold,
        "episode_gap_seconds": int(episode_gap_seconds),
        "windows": int(len(test_df)),
        "episodes": int(len(episodes)),
        "positive_episodes": int((episodes["label"] == 1).sum()),
        "window_metrics": window_metrics,
        "episode_metrics": episode_metrics,
        "per_episode_family_counts": episodes["app_family"].astype(str).value_counts().to_dict(),
        "per_episode_source_counts": episodes["dataset_source"].astype(str).value_counts().to_dict(),
    }


def main() -> None:
    args = parse_args()
    report = build_episode_report(
        args.input,
        args.model,
        random_seed=args.random_seed,
        test_ratio=args.test_ratio,
        window_mode=args.window_mode,
        max_adaptive_windows=args.max_adaptive_windows,
        label_strategy=args.label_strategy,
        multi_horizon_training=args.multi_horizon_training,
        episode_gap_seconds=args.episode_gap_seconds,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
