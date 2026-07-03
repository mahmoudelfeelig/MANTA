from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .cache_utils import load_feature_windows_cached
from .dataset_metadata import derive_app_family
from .features import FEATURE_COLUMNS, build_android_feature_windows, build_android_sliding_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import per_group_binary_metrics
from .splits import source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Android model false-positive and false-negative contributors")
    parser.add_argument("--input", required=True, help="Flow CSV used for training/evaluation")
    parser.add_argument("--model", required=True, help="Android JSON model artifact")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--top-groups", type=int, default=20)
    parser.add_argument("--window-mode", choices=["bucket", "sliding", "adaptive"], default="adaptive")
    parser.add_argument("--max-adaptive-windows", type=int, default=0, help="Use the bounded adaptive-window cache produced for training")
    parser.add_argument("--label-strategy", choices=["focal", "window"], default="window")
    parser.add_argument("--multi-horizon-training", action="store_true")
    return parser.parse_args()


def _sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-values))


def _score_logistic(payload: dict[str, object], features: pd.DataFrame) -> np.ndarray:
    means = np.asarray(payload["means"], dtype=float)
    scales = np.asarray(payload["scales"], dtype=float)
    weights = np.asarray(payload["weights"], dtype=float)
    values = features[list(payload["feature_order"])].to_numpy(dtype=float)
    normalized = (values - means) / np.where(scales == 0.0, 1.0, scales)
    return _sigmoid(normalized @ weights + float(payload.get("bias", 0.0)))


def _score_tree(tree: dict[str, object], values: np.ndarray) -> np.ndarray:
    nodes = list(tree["nodes"])
    if not nodes:
        return np.zeros(values.shape[0], dtype=float)
    feature_indices = np.asarray([int(node["feature_index"]) for node in nodes], dtype=int)
    thresholds = np.asarray([float(node["threshold"]) for node in nodes], dtype=float)
    left_children = np.asarray([int(node["left"]) for node in nodes], dtype=int)
    right_children = np.asarray([int(node["right"]) for node in nodes], dtype=int)
    node_values = np.asarray([float(node["value"]) for node in nodes], dtype=float)
    scores = np.zeros(values.shape[0], dtype=float)
    current_nodes = np.zeros(values.shape[0], dtype=int)
    active = np.ones(values.shape[0], dtype=bool)
    for _ in range(64):
        active_rows = np.flatnonzero(active)
        if len(active_rows) == 0:
            break
        node_indices = current_nodes[active_rows]
        valid_nodes = (node_indices >= 0) & (node_indices < len(nodes))
        if not bool(valid_nodes.all()):
            invalid_rows = active_rows[~valid_nodes]
            active[invalid_rows] = False
            active_rows = active_rows[valid_nodes]
            node_indices = node_indices[valid_nodes]
            if len(active_rows) == 0:
                break
        leaf_mask = (
            (left_children[node_indices] < 0) |
            (right_children[node_indices] < 0) |
            (feature_indices[node_indices] < 0)
        )
        if bool(leaf_mask.any()):
            leaf_rows = active_rows[leaf_mask]
            scores[leaf_rows] = node_values[node_indices[leaf_mask]]
            active[leaf_rows] = False
        branch_rows = active_rows[~leaf_mask]
        if len(branch_rows) == 0:
            continue
        branch_nodes = node_indices[~leaf_mask]
        branch_features = feature_indices[branch_nodes]
        go_left = values[branch_rows, branch_features] <= thresholds[branch_nodes]
        current_nodes[branch_rows] = np.where(go_left, left_children[branch_nodes], right_children[branch_nodes])
    return scores


def _score_random_forest(payload: dict[str, object], features: pd.DataFrame) -> np.ndarray:
    values = features[list(payload["feature_order"])].to_numpy(dtype=float)
    trees = list(payload["trees"])
    total = np.zeros(values.shape[0], dtype=float)
    for tree in trees:
        total += _score_tree(tree, values)
    return total / max(1, len(trees))


def _score_boosted_tree(payload: dict[str, object], features: pd.DataFrame) -> np.ndarray:
    values = features[list(payload["feature_order"])].to_numpy(dtype=float)
    trees = list(payload["trees"])
    raw = np.full(values.shape[0], float(payload.get("initial_score", 0.0)), dtype=float)
    learning_rate = float(payload.get("learning_rate", 1.0))
    for tree in trees:
        raw += learning_rate * _score_tree(tree, values)
    return _sigmoid(raw)


def _score_single_model_payload(payload: dict[str, object], windows: pd.DataFrame) -> np.ndarray:
    transformed_windows = _apply_payload_input_transform(payload, windows)
    features = feature_matrix(transformed_windows, list(payload["feature_order"]))
    model_type = payload.get("model_type")
    if model_type == "logistic_regression":
        scores = _score_logistic(payload, features)
    elif model_type == "random_forest_classifier":
        scores = _score_random_forest(payload, features)
    elif model_type == "boosted_tree_classifier":
        scores = _score_boosted_tree(payload, features)
    else:
        raise ValueError(f"Unsupported model_type: {model_type}")
    score_scale = float(payload.get("score_scale", 1.0))
    if score_scale != 1.0:
        scores = np.clip(scores * score_scale, 0.0, 1.0)
    return scores


def _apply_payload_input_transform(payload: dict[str, object], windows: pd.DataFrame) -> pd.DataFrame:
    transform = str(payload.get("input_transform") or "")
    if not transform:
        return windows
    from .train_android_model import _android_privacy_medium_plus_transform, _android_privacy_medium_transform

    if transform == "android_privacy_medium_reduced":
        return _android_privacy_medium_transform(windows)
    if transform == "android_privacy_medium_plus_reduced":
        return _android_privacy_medium_plus_transform(windows)
    return windows


def score_android_model(payload: dict[str, object], windows: pd.DataFrame) -> np.ndarray:
    scores = _score_single_model_payload(payload, windows)
    specialists = payload.get("specialists", {})
    app_family_specialists = specialists.get("app_family", {}) if isinstance(specialists, dict) else {}
    if isinstance(app_family_specialists, dict) and app_family_specialists:
        families = windows["app_id"].astype(str).map(derive_app_family).to_numpy()
        for family, specialist_payload in app_family_specialists.items():
            if not isinstance(specialist_payload, dict):
                continue
            mask = families == str(family)
            if not bool(mask.any()):
                continue
            scores[mask] = _score_single_model_payload(specialist_payload, windows.loc[mask])
    overrides_root = payload.get("threshold_overrides", {})
    default_threshold = float(payload.get("recommended_threshold", 0.5))
    if isinstance(overrides_root, dict) and overrides_root:
        effective_thresholds = np.full(len(windows), default_threshold, dtype=float)
        family_overrides = overrides_root.get("app_family", {})
        if isinstance(family_overrides, dict) and family_overrides:
            families = windows["app_id"].astype(str).map(derive_app_family).to_numpy()
            for family, threshold in family_overrides.items():
                effective_thresholds[families == str(family)] = max(0.05, float(threshold))
        app_overrides = overrides_root.get("app_id", {})
        if isinstance(app_overrides, dict) and app_overrides:
            app_ids = windows["app_id"].astype(str).to_numpy()
            for app_id, threshold in app_overrides.items():
                effective_thresholds[app_ids == str(app_id)] = max(0.05, float(threshold))
        calibrated = np.asarray(scores, dtype=float).copy()
        calibrated = calibrated * (default_threshold / np.clip(effective_thresholds, 0.05, 1.0))
        scores = np.clip(calibrated, 0.0, 1.0)
    return scores


def _top_error_groups(frame: pd.DataFrame, mask: np.ndarray, column: str, top_n: int) -> list[dict[str, object]]:
    if column not in frame.columns or not bool(mask.any()):
        return []
    total_by_group = frame[column].astype(str).value_counts(dropna=False)
    errors = frame.loc[mask, column].astype(str).value_counts(dropna=False)
    rows: list[dict[str, object]] = []
    for group, count in errors.head(top_n).items():
        total = int(total_by_group.get(group, 0))
        rows.append(
            {
                "group": str(group),
                "errors": int(count),
                "rows": total,
                "error_rate": float(count / max(1, total)),
                "share_of_error_type": float(count / max(1, int(mask.sum()))),
            }
        )
    return rows


def _feature_shifts(frame: pd.DataFrame, mask: np.ndarray, reference_mask: np.ndarray, top_n: int) -> list[dict[str, object]]:
    if not bool(mask.any()) or not bool(reference_mask.any()):
        return []
    rows: list[dict[str, object]] = []
    for column in FEATURE_COLUMNS:
        error_values = pd.to_numeric(frame.loc[mask, column], errors="coerce").fillna(0.0)
        reference_values = pd.to_numeric(frame.loc[reference_mask, column], errors="coerce").fillna(0.0)
        reference_std = float(reference_values.std(ddof=0))
        delta = float(error_values.mean() - reference_values.mean())
        rows.append(
            {
                "feature": column,
                "error_mean": float(error_values.mean()),
                "reference_mean": float(reference_values.mean()),
                "delta": delta,
                "standardized_delta": float(delta / (reference_std + 1e-9)),
            }
        )
    rows.sort(key=lambda row: abs(float(row["standardized_delta"])), reverse=True)
    return rows[:top_n]


def build_error_report(
    input_path: str | Path,
    model_path: str | Path,
    *,
    random_seed: int = 42,
    test_ratio: float = 0.3,
    top_groups: int = 20,
    window_mode: str = "adaptive",
    max_adaptive_windows: int = 0,
    label_strategy: str = "window",
    multi_horizon_training: bool = False,
) -> dict[str, object]:
    payload = json.loads(Path(model_path).read_text(encoding="utf-8"))
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
    windows = load_feature_windows_cached(
        input_path,
        build_windows_fn=build_windows_fn,
        read_frame_fn=read_csv_resilient,
        cache_name=cache_name,
    )
    split = source_aware_train_test_split(
        windows,
        label_column="label",
        test_size=test_ratio,
        random_seed=random_seed,
    )
    test_df = windows.iloc[split.test_idx].reset_index(drop=True)
    y_true = test_df["label"].fillna(0).astype(int).to_numpy()
    scores = score_android_model(payload, test_df)
    threshold = float(payload.get("recommended_threshold", 0.5))
    predictions = (scores >= threshold).astype(int)
    false_positive = (predictions == 1) & (y_true == 0)
    false_negative = (predictions == 0) & (y_true == 1)
    true_positive = (predictions == 1) & (y_true == 1)
    true_negative = (predictions == 0) & (y_true == 0)
    return {
        "model_type": payload.get("model_type"),
        "threshold": threshold,
        "rows": int(len(test_df)),
        "positives": int((y_true == 1).sum()),
        "false_positives": int(false_positive.sum()),
        "false_negatives": int(false_negative.sum()),
        "true_positives": int(true_positive.sum()),
        "true_negatives": int(true_negative.sum()),
        "group_metrics": {
            "dataset_source": per_group_binary_metrics(y_true, scores, test_df["dataset_source"], threshold, min_rows=24),
            "dataset_profile": per_group_binary_metrics(y_true, scores, test_df["dataset_profile"], threshold, min_rows=24),
            "app_family": per_group_binary_metrics(y_true, scores, test_df["app_family"], threshold, min_rows=24),
        },
        "false_positive_contributors": {
            column: _top_error_groups(test_df, false_positive, column, top_groups)
            for column in ("dataset_source", "dataset_profile", "app_family")
        },
        "false_negative_contributors": {
            column: _top_error_groups(test_df, false_negative, column, top_groups)
            for column in ("dataset_source", "dataset_profile", "app_family")
        },
        "false_positive_feature_shifts": _feature_shifts(test_df, false_positive, true_negative, top_groups),
        "false_negative_feature_shifts": _feature_shifts(test_df, false_negative, true_positive, top_groups),
    }


def main() -> None:
    args = parse_args()
    report = build_error_report(
        args.input,
        args.model,
        random_seed=args.random_seed,
        test_ratio=args.test_ratio,
        top_groups=args.top_groups,
        window_mode=args.window_mode,
        max_adaptive_windows=args.max_adaptive_windows,
        label_strategy=args.label_strategy,
        multi_horizon_training=args.multi_horizon_training,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
