from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .cache_utils import load_feature_windows_cached
from .dataset_metadata import derive_app_family
from .episode_evaluation import _episode_frame
from .error_analysis import score_android_model
from .features import build_android_feature_windows, build_android_sliding_feature_windows
from .io_utils import read_csv_resilient
from .metrics import operational_binary_metrics, per_group_binary_metrics, threshold_sweep_metrics
from .splits import source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate hybrid v13/v14 Android scoring policies")
    parser.add_argument("--input", required=True, help="Flow CSV used for training/evaluation")
    parser.add_argument("--model-v13", required=True, help="Recall-oriented Android JSON model")
    parser.add_argument("--model-v14", required=True, help="Quiet Android JSON model")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0)
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
    parser.add_argument("--episode-gap-seconds", type=int, default=300)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--sample-test-windows", type=int, default=0, help="Optional bounded holdout sample for fast hybrid sweeps")
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


def _family_values(frame: pd.DataFrame) -> np.ndarray:
    if "app_family" in frame.columns:
        return frame["app_family"].astype(str).fillna("other_app").to_numpy(dtype=str)
    return frame["app_id"].astype(str).map(derive_app_family).to_numpy(dtype=str)


def _blend_scores(
    frame: pd.DataFrame,
    v13_scores: np.ndarray,
    v14_scores: np.ndarray,
    *,
    service_weight: float,
    service_cap: float,
    malware_mode: str,
    other_weight: float,
) -> np.ndarray:
    families = _family_values(frame)
    blended = (other_weight * v13_scores) + ((1.0 - other_weight) * v14_scores)

    service_mask = np.isin(families, ["service", "system", "other_app"])
    service_blend = (service_weight * v13_scores) + ((1.0 - service_weight) * v14_scores)
    blended[service_mask] = np.minimum(service_blend[service_mask], v14_scores[service_mask] + service_cap)

    malware_mask = np.isin(families, ["malware", "remote_access"])
    if malware_mode == "max":
        blended[malware_mask] = np.maximum(v13_scores[malware_mask], v14_scores[malware_mask])
    elif malware_mode == "v14":
        blended[malware_mask] = v14_scores[malware_mask]
    else:
        blended[malware_mask] = (0.35 * v13_scores[malware_mask]) + (0.65 * v14_scores[malware_mask])
    return np.clip(blended, 0.0, 1.0)


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> dict[str, object]:
    sweep = threshold_sweep_metrics(y_true, scores, steps=201)
    best_f1 = sweep.sort_values(["f1", "precision", "recall"], ascending=False).iloc[0].to_dict()
    return {str(key): float(value) for key, value in best_f1.items()}


def _best_constrained_threshold(y_true: np.ndarray, scores: np.ndarray, *, max_fpr: float) -> dict[str, object]:
    sweep = threshold_sweep_metrics(y_true, scores, steps=201)
    eligible = sweep[sweep["false_positive_rate"] <= max_fpr]
    if eligible.empty:
        eligible = sweep
    best = eligible.sort_values(["recall", "f1", "precision"], ascending=False).iloc[0].to_dict()
    return {str(key): float(value) for key, value in best.items()}


def _false_error_counts(frame: pd.DataFrame, y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    predictions = (scores >= threshold).astype(int)
    fp_mask = (predictions == 1) & (y_true == 0)
    fn_mask = (predictions == 0) & (y_true == 1)
    payload: dict[str, object] = {}
    for column in ("app_family", "dataset_source", "dataset_profile"):
        if column not in frame.columns:
            continue
        payload[column] = {
            "false_positives": frame.loc[fp_mask, column].astype(str).value_counts().head(10).to_dict(),
            "false_negatives": frame.loc[fn_mask, column].astype(str).value_counts().head(10).to_dict(),
        }
    return payload


def _evaluate_score_set(
    name: str,
    frame: pd.DataFrame,
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    threshold: float,
    episode_gap_seconds: int,
    max_fpr: float,
    policy: dict[str, object] | None = None,
    include_episode_details: bool = True,
) -> dict[str, object]:
    best_f1_threshold = _best_threshold(y_true, scores)
    constrained_threshold = _best_constrained_threshold(y_true, scores, max_fpr=max_fpr)
    payload: dict[str, object] = {
        "name": name,
        "policy": policy or {},
        "operational_threshold": float(threshold),
        "window_metrics": operational_binary_metrics(y_true, scores, threshold),
        "best_f1_threshold": best_f1_threshold,
        "best_constrained_threshold": constrained_threshold,
    }
    if include_episode_details:
        episodes = _episode_frame(frame, scores, threshold, episode_gap_seconds)
        payload.update(
            {
                "episode_metrics": operational_binary_metrics(
                    episodes["label"].to_numpy(dtype=int),
                    episodes["score"].to_numpy(dtype=float),
                    threshold,
                ),
                "app_family_metrics": per_group_binary_metrics(y_true, scores, frame["app_family"], threshold, min_rows=24)
                if "app_family" in frame.columns
                else {},
                "error_counts": _false_error_counts(frame, y_true, scores, threshold),
            }
        )
    return payload


def build_hybrid_report(
    input_path: str | Path,
    model_v13_path: str | Path,
    model_v14_path: str | Path,
    *,
    random_seed: int = 42,
    test_ratio: float = 0.3,
    window_mode: str = "adaptive",
    max_adaptive_windows: int = 0,
    label_strategy: str = "window",
    multi_horizon_training: bool = False,
    episode_gap_seconds: int = 300,
    max_fpr: float = 0.05,
    sample_test_windows: int = 0,
) -> dict[str, object]:
    payload_v13 = json.loads(Path(model_v13_path).read_text(encoding="utf-8"))
    payload_v14 = json.loads(Path(model_v14_path).read_text(encoding="utf-8"))
    windows = _load_windows(
        input_path,
        window_mode=window_mode,
        max_adaptive_windows=max_adaptive_windows,
        label_strategy=label_strategy,
        multi_horizon_training=multi_horizon_training,
    )
    split = source_aware_train_test_split(windows, label_column="label", test_size=test_ratio, random_seed=random_seed)
    test_df = windows.iloc[split.test_idx].reset_index(drop=True)
    if sample_test_windows > 0 and len(test_df) > sample_test_windows:
        test_df = test_df.sample(n=int(sample_test_windows), random_state=random_seed).sort_index().reset_index(drop=True)
    y_true = test_df["label"].fillna(0).astype(int).to_numpy()
    v13_scores = score_android_model(payload_v13, test_df)
    v14_scores = score_android_model(payload_v14, test_df)
    threshold_v13 = float(payload_v13.get("recommended_threshold", 0.5))
    threshold_v14 = float(payload_v14.get("recommended_threshold", 0.5))

    candidates = []
    policies = [
        {"name": "android_runtime_v15", "service_weight": 0.25, "service_cap": 0.12, "malware_mode": "max", "other_weight": 0.45},
    ]
    for service_weight in (0.0, 0.15, 0.25, 0.40, 0.55):
        for service_cap in (0.06, 0.12, 0.18, 0.30):
            for malware_mode in ("max", "blend", "v14"):
                for other_weight in (0.25, 0.45, 0.65):
                    policies.append(
                        {
                            "name": f"grid_sw{service_weight:.2f}_cap{service_cap:.2f}_{malware_mode}_ow{other_weight:.2f}",
                            "service_weight": service_weight,
                            "service_cap": service_cap,
                            "malware_mode": malware_mode,
                            "other_weight": other_weight,
                        }
                    )

    seen: set[tuple[float, float, str, float]] = set()
    for policy in policies:
        key = (
            float(policy["service_weight"]),
            float(policy["service_cap"]),
            str(policy["malware_mode"]),
            float(policy["other_weight"]),
        )
        if key in seen:
            continue
        seen.add(key)
        scores = _blend_scores(
            test_df,
            v13_scores,
            v14_scores,
            service_weight=float(policy["service_weight"]),
            service_cap=float(policy["service_cap"]),
            malware_mode=str(policy["malware_mode"]),
            other_weight=float(policy["other_weight"]),
        )
        candidates.append(
            _evaluate_score_set(
                str(policy["name"]),
                test_df,
                y_true,
                scores,
                threshold=threshold_v14,
                episode_gap_seconds=episode_gap_seconds,
                max_fpr=max_fpr,
                policy=policy,
                include_episode_details=False,
            )
        )

    candidates.sort(
        key=lambda row: (
            float(row["best_constrained_threshold"].get("recall", 0.0)),
            float(row["best_constrained_threshold"].get("f1", 0.0)),
            float(row["best_constrained_threshold"].get("precision", 0.0)),
        ),
        reverse=True,
    )
    best_f1_candidates = sorted(
        candidates,
        key=lambda row: (
            float(row["best_f1_threshold"].get("f1", 0.0)),
            float(row["best_f1_threshold"].get("precision", 0.0)),
            float(row["best_f1_threshold"].get("recall", 0.0)),
        ),
        reverse=True,
    )

    def detailed_candidate(candidate: dict[str, object]) -> dict[str, object]:
        policy = candidate["policy"]
        assert isinstance(policy, dict)
        scores = _blend_scores(
            test_df,
            v13_scores,
            v14_scores,
            service_weight=float(policy["service_weight"]),
            service_cap=float(policy["service_cap"]),
            malware_mode=str(policy["malware_mode"]),
            other_weight=float(policy["other_weight"]),
        )
        return _evaluate_score_set(
            str(candidate["name"]),
            test_df,
            y_true,
            scores,
            threshold=threshold_v14,
            episode_gap_seconds=episode_gap_seconds,
            max_fpr=max_fpr,
            policy=policy,
            include_episode_details=True,
        )

    return {
        "protocol": {
            "random_seed": int(random_seed),
            "test_ratio": float(test_ratio),
            "window_mode": window_mode,
            "max_adaptive_windows": int(max_adaptive_windows),
            "label_strategy": label_strategy,
            "multi_horizon_training": bool(multi_horizon_training),
            "episode_gap_seconds": int(episode_gap_seconds),
            "max_fpr": float(max_fpr),
            "sample_test_windows": int(sample_test_windows),
        },
        "rows": int(len(test_df)),
        "positives": int((y_true == 1).sum()),
        "thresholds": {"v13": threshold_v13, "v14": threshold_v14, "v15_operational": threshold_v14},
        "baselines": {
            "v13_recall": _evaluate_score_set(
                "v13_recall",
                test_df,
                y_true,
                v13_scores,
                threshold=threshold_v13,
                episode_gap_seconds=episode_gap_seconds,
                max_fpr=max_fpr,
            ),
            "v14_quiet": _evaluate_score_set(
                "v14_quiet",
                test_df,
                y_true,
                v14_scores,
                threshold=threshold_v14,
                episode_gap_seconds=episode_gap_seconds,
                max_fpr=max_fpr,
            ),
        },
        "android_runtime_v15": detailed_candidate(next(row for row in candidates if row["name"] == "android_runtime_v15")),
        "best_constrained_candidates": [detailed_candidate(row) for row in candidates[:10]],
        "best_f1_candidates": [detailed_candidate(row) for row in best_f1_candidates[:10]],
    }


def main() -> None:
    args = parse_args()
    report = build_hybrid_report(
        args.input,
        args.model_v13,
        args.model_v14,
        random_seed=args.random_seed,
        test_ratio=args.test_ratio,
        window_mode=args.window_mode,
        max_adaptive_windows=args.max_adaptive_windows,
        label_strategy=args.label_strategy,
        multi_horizon_training=args.multi_horizon_training,
        episode_gap_seconds=args.episode_gap_seconds,
        max_fpr=args.max_fpr,
        sample_test_windows=args.sample_test_windows,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
