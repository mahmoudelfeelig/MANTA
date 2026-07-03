from __future__ import annotations

import argparse
from collections import defaultdict, deque
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .cache_utils import load_feature_windows_cached
from .episode_evaluation import _episode_frame
from .error_analysis import score_android_model
from .features import build_android_feature_windows, build_android_sliding_feature_windows
from .io_utils import read_csv_resilient
from .metrics import operational_binary_metrics
from .splits import source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate persistence/evidence alert policies over Android model scores")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0)
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--episode-gap-seconds", type=int, default=300)
    return parser.parse_args()


def _load_windows(
    input_path: str | Path,
    *,
    window_mode: str,
    max_adaptive_windows: int,
    label_strategy: str,
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
        )
        cache_name = "android_sliding_feature_windows"
    else:
        build_windows_fn = lambda frame, seconds: build_android_sliding_feature_windows(
            frame,
            seconds,
            adaptive=True,
            max_windows=max_adaptive_windows,
            label_strategy=label_strategy,
        )
        cache_name = "android_adaptive_feature_windows"
        if max_adaptive_windows > 0:
            cache_name = f"{cache_name}_max{max_adaptive_windows}"
    if label_strategy != "window":
        cache_name = f"{cache_name}_{label_strategy}"
    return load_feature_windows_cached(
        input_path,
        build_windows_fn=build_windows_fn,
        read_frame_fn=read_csv_resilient,
        cache_name=cache_name,
    )


def _numeric_array(frame: pd.DataFrame, column: str) -> np.ndarray:
    if column not in frame.columns:
        return np.zeros(len(frame), dtype=float)
    return pd.to_numeric(frame[column], errors="coerce").fillna(0.0).to_numpy(dtype=float)


def _evidence_strength_values(frame: pd.DataFrame) -> np.ndarray:
    strength = np.zeros(len(frame), dtype=np.int16)
    strength += ((_numeric_array(frame, "novelty_score") >= 0.35) | (_numeric_array(frame, "novelty_shift") >= 0.18)).astype(np.int16)
    strength += ((_numeric_array(frame, "destination_diversity") >= 0.35) | (_numeric_array(frame, "destination_transition_rate") >= 0.25)).astype(np.int16)
    strength += ((_numeric_array(frame, "port_diversity") >= 0.20) | (_numeric_array(frame, "protocol_diversity") >= 0.20)).astype(np.int16)
    strength += ((_numeric_array(frame, "byte_rate_deviation") >= 0.40) | (_numeric_array(frame, "flow_count_deviation") >= 0.40)).astype(np.int16)
    strength += (_numeric_array(frame, "periodic_beacon_score") >= 0.55).astype(np.int16)
    strength += (_numeric_array(frame, "low_volume_periodic_score") >= 0.35).astype(np.int16)
    strength += ((_numeric_array(frame, "destination_risk_score") >= 0.35) | (_numeric_array(frame, "suspicious_destination_ratio") >= 0.20)).astype(np.int16)
    strength += (
        (_numeric_array(frame, "transport_metrics_present") >= 0.5) &
        (
            (_numeric_array(frame, "syn_rate_total") >= 0.15) |
            (_numeric_array(frame, "rst_rate_total") >= 0.15) |
            (_numeric_array(frame, "fragment_rate_total") >= 0.05)
        )
    ).astype(np.int16)
    return strength


def _simulate_policy(
    frame: pd.DataFrame,
    scores: np.ndarray,
    *,
    threshold: float,
    high_bypass: float,
    service_count: int,
    default_count: int,
    min_evidence: int,
    window_seconds: int,
    trend_slack: float,
) -> np.ndarray:
    working = frame[["app_id", "session_id", "app_family"]].copy()
    working["_position"] = np.arange(len(frame), dtype=np.int64)
    working["_score"] = scores
    if "window_end_ms" in frame.columns:
        working["window_end_ms"] = pd.to_numeric(frame["window_end_ms"], errors="coerce").fillna(0).astype("int64")
    else:
        if "window_bucket" in frame.columns:
            window_bucket = pd.to_numeric(frame["window_bucket"], errors="coerce").fillna(0)
        else:
            window_bucket = pd.Series(np.zeros(len(frame), dtype=np.int64), index=frame.index)
        working["window_end_ms"] = window_bucket.astype("int64") * 1000
    working["_evidence"] = _evidence_strength_values(frame)
    working = working.sort_values(["app_id", "session_id", "window_end_ms"], kind="mergesort")
    emitted = np.zeros(len(frame), dtype=int)
    recent: dict[tuple[str, str], deque[tuple[int, float, int]]] = defaultdict(deque)
    cutoff_ms = int(window_seconds * 1000)
    for app_id, session_id, app_family, position, score, now, evidence in working[
        ["app_id", "session_id", "app_family", "_position", "_score", "window_end_ms", "_evidence"]
    ].itertuples(index=False, name=None):
        score = float(score)
        if score < threshold:
            continue
        key = (str(app_id), str(session_id))
        now = int(now)
        queue = recent[key]
        while queue and queue[0][0] < now - cutoff_ms:
            queue.popleft()
        evidence = int(evidence)
        queue.append((now, score, evidence))
        count = len(queue)
        first_score = queue[0][1]
        max_evidence = max(item[2] for item in queue)
        family = str(app_family)
        required_count = service_count if family in {"service", "system", "other_app"} else default_count
        persistent = count >= required_count and score >= first_score - trend_slack
        strong_single = score >= high_bypass and evidence >= min_evidence
        enough_evidence = max_evidence >= min_evidence
        if (persistent and enough_evidence) or strong_single:
            emitted[int(position)] = 1
    return emitted


def build_alert_policy_report(
    input_path: str | Path,
    model_path: str | Path,
    *,
    random_seed: int = 42,
    test_ratio: float = 0.3,
    window_mode: str = "adaptive",
    max_adaptive_windows: int = 0,
    label_strategy: str = "window",
    episode_gap_seconds: int = 300,
) -> dict[str, object]:
    payload = json.loads(Path(model_path).read_text(encoding="utf-8"))
    windows = _load_windows(
        input_path,
        window_mode=window_mode,
        max_adaptive_windows=max_adaptive_windows,
        label_strategy=label_strategy,
    )
    split = source_aware_train_test_split(windows, label_column="label", test_size=test_ratio, random_seed=random_seed)
    test_df = windows.iloc[split.test_idx].reset_index(drop=True)
    y_true = test_df["label"].fillna(0).astype(int).to_numpy()
    scores = score_android_model(payload, test_df)
    threshold = float(payload.get("recommended_threshold", 0.5))
    baseline_window_metrics = operational_binary_metrics(y_true, scores, threshold)
    baseline_episodes = _episode_frame(test_df, scores, threshold, episode_gap_seconds)
    baseline_episode_metrics = operational_binary_metrics(
        baseline_episodes["label"].to_numpy(dtype=int),
        baseline_episodes["score"].to_numpy(dtype=float),
        threshold,
    )
    candidates = []
    for service_count in (2, 3, 4):
        for default_count in (1, 2):
            for min_evidence in (1, 2, 3):
                for high_bypass in (0.94, 0.97, 0.99):
                    predictions = _simulate_policy(
                        test_df,
                        scores,
                        threshold=threshold,
                        high_bypass=high_bypass,
                        service_count=service_count,
                        default_count=default_count,
                        min_evidence=min_evidence,
                        window_seconds=episode_gap_seconds,
                        trend_slack=0.08,
                    )
                    policy_scores = predictions.astype(float)
                    window_metrics = operational_binary_metrics(y_true, policy_scores, 0.5)
                    episode_frame = _episode_frame(test_df, policy_scores, 0.5, episode_gap_seconds)
                    episode_metrics = operational_binary_metrics(
                        episode_frame["label"].to_numpy(dtype=int),
                        episode_frame["score"].to_numpy(dtype=float),
                        0.5,
                    )
                    candidates.append(
                        {
                            "policy": {
                                "service_count": service_count,
                                "default_count": default_count,
                                "min_evidence": min_evidence,
                                "high_bypass": high_bypass,
                                "window_seconds": episode_gap_seconds,
                                "trend_slack": 0.08,
                            },
                            "window_metrics": window_metrics,
                            "episode_metrics": episode_metrics,
                        }
                    )
    candidates.sort(
        key=lambda row: (
            float(row["episode_metrics"].get("f1", 0.0)),
            float(row["episode_metrics"].get("precision", 0.0)),
            float(row["episode_metrics"].get("recall", 0.0)),
        ),
        reverse=True,
    )
    family_best: dict[str, object] = {}
    for family, family_rows in test_df.groupby("app_family", sort=False):
        if len(family_rows) < 100:
            continue
        family_idx = family_rows.index.to_numpy(dtype=int)
        family_y = y_true[family_idx]
        if len(np.unique(family_y)) < 2:
            continue
        family_candidates = []
        for service_count in (1, 2, 3, 4):
            for default_count in (1, 2, 3):
                for min_evidence in (1, 2, 3):
                    for high_bypass in (0.90, 0.94, 0.97, 0.99):
                        predictions = _simulate_policy(
                            family_rows.reset_index(drop=True),
                            scores[family_idx],
                            threshold=threshold,
                            high_bypass=high_bypass,
                            service_count=service_count,
                            default_count=default_count,
                            min_evidence=min_evidence,
                            window_seconds=episode_gap_seconds,
                            trend_slack=0.08,
                        )
                        policy_scores = predictions.astype(float)
                        episode_frame = _episode_frame(family_rows.reset_index(drop=True), policy_scores, 0.5, episode_gap_seconds)
                        episode_metrics = operational_binary_metrics(
                            episode_frame["label"].to_numpy(dtype=int),
                            episode_frame["score"].to_numpy(dtype=float),
                            0.5,
                        )
                        family_candidates.append(
                            {
                                "policy": {
                                    "service_count": service_count,
                                    "default_count": default_count,
                                    "min_evidence": min_evidence,
                                    "high_bypass": high_bypass,
                                    "window_seconds": episode_gap_seconds,
                                    "trend_slack": 0.08,
                                },
                                "episode_metrics": episode_metrics,
                            }
                        )
        if str(family) == "service":
            sort_key = lambda row: (
                float(row["episode_metrics"].get("precision", 0.0)),
                -float(row["episode_metrics"].get("false_positive_rate", 1.0)),
                float(row["episode_metrics"].get("recall", 0.0)),
            )
        elif str(family) == "malware":
            sort_key = lambda row: (
                float(row["episode_metrics"].get("recall", 0.0)),
                float(row["episode_metrics"].get("precision", 0.0)),
                float(row["episode_metrics"].get("f1", 0.0)),
            )
        else:
            sort_key = lambda row: (
                float(row["episode_metrics"].get("f1", 0.0)),
                float(row["episode_metrics"].get("precision", 0.0)),
                float(row["episode_metrics"].get("recall", 0.0)),
            )
        family_candidates.sort(key=sort_key, reverse=True)
        family_best[str(family)] = family_candidates[0]
    return {
        "threshold": threshold,
        "baseline_window_metrics": baseline_window_metrics,
        "baseline_episode_metrics": baseline_episode_metrics,
        "best_policy": candidates[0] if candidates else None,
        "family_best_policies": family_best,
        "candidates": candidates[:20],
    }


def main() -> None:
    args = parse_args()
    report = build_alert_policy_report(
        args.input,
        args.model,
        random_seed=args.random_seed,
        test_ratio=args.test_ratio,
        window_mode=args.window_mode,
        max_adaptive_windows=args.max_adaptive_windows,
        label_strategy=args.label_strategy,
        episode_gap_seconds=args.episode_gap_seconds,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
