from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.preprocessing import LabelEncoder

from .privacy_attack_utils import (
    ATTACK_MODEL_CHOICES,
    build_context_bucket,
    build_destination_behavior_bucket,
    evaluate_feature_group_attacks,
    evaluate_multiclass_models,
    evaluate_open_world_unknown_detection,
    grouped_label_holdout_split,
    parse_attack_model_names,
)
from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_GROUPS, PRIVACY_FEATURE_SETS, build_window_privacy_views_from_windows
from .splits import add_split_metadata
from .window_builders import add_window_protocol_args, adaptive_cache_name, load_android_windows_for_protocol


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark privacy leakage by re-identification and context inference from exported features")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--min-class-rows", type=int, default=20)
    parser.add_argument("--max-class-rows", type=int, default=400)
    parser.add_argument("--destination-buckets", type=int, default=3)
    parser.add_argument("--open-world-ratio", type=float, default=0.25)
    parser.add_argument("--attack-models", default=",".join(ATTACK_MODEL_CHOICES))
    parser.add_argument("--random-seed", type=int, default=42)
    add_window_protocol_args(parser)
    return parser.parse_args()


def _prepare_task_frame(
    frame: pd.DataFrame,
    *,
    target_column: str,
    min_class_rows: int,
    max_class_rows: int,
) -> pd.DataFrame:
    counts = frame[target_column].astype(str).value_counts()
    keep = counts[counts >= min_class_rows].index if min_class_rows > 0 else counts.index
    filtered = frame[frame[target_column].astype(str).isin(keep)].copy()
    if max_class_rows > 0 and not filtered.empty:
        filtered = (
            filtered.groupby(filtered[target_column].astype(str), sort=False, group_keys=False)
            .head(max_class_rows)
            .reset_index(drop=True)
        )
    return filtered


def _task_payload(
    frame: pd.DataFrame,
    *,
    target_column: str,
    task_name: str,
    feature_columns: list[str],
    group_columns: tuple[str, ...],
    attack_models: tuple[str, ...],
    random_seed: int,
    min_class_rows: int,
    max_class_rows: int,
    include_open_world: bool,
    open_world_ratio: float,
) -> dict[str, object] | None:
    filtered = _prepare_task_frame(
        frame,
        target_column=target_column,
        min_class_rows=min_class_rows,
        max_class_rows=max_class_rows,
    )
    if filtered[target_column].astype(str).nunique() < 2 or len(filtered) < max(16, min_class_rows * 2):
        return None

    split = grouped_label_holdout_split(
        filtered,
        target=filtered[target_column].astype(str),
        label_name=task_name,
        group_columns=group_columns,
        test_size=0.3,
        random_seed=random_seed,
    )
    encoder = LabelEncoder()
    labels = encoder.fit_transform(filtered[target_column].astype(str))
    train_x = filtered.iloc[split.train_idx][feature_columns].fillna(0.0)
    test_x = filtered.iloc[split.test_idx][feature_columns].fillna(0.0)
    train_y = labels[split.train_idx]
    test_y = labels[split.test_idx]
    model_results, strongest = evaluate_multiclass_models(
        train_x,
        test_x,
        train_y,
        test_y,
        model_names=attack_models,
        random_seed=random_seed,
    )
    if strongest is None:
        return {
            "target_column": target_column,
            "rows_train": int(len(train_x)),
            "rows_test": int(len(test_x)),
            "class_count": int(len(encoder.classes_)),
            "split_strategy": split.strategy,
            "split_summary": split.summary,
            "models": model_results,
        }

    payload: dict[str, object] = {
        "target_column": target_column,
        "rows_train": int(len(train_x)),
        "rows_test": int(len(test_x)),
        "class_count": int(len(encoder.classes_)),
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "strongest_model": strongest,
        "models": model_results,
    }
    if task_name == "app_id":
        payload["feature_group_results"] = evaluate_feature_group_attacks(
            filtered,
            feature_groups=PRIVACY_FEATURE_GROUPS,
            train_idx=split.train_idx,
            test_idx=split.test_idx,
            labels=labels,
            random_seed=random_seed,
        )
        if include_open_world:
            payload["open_world"] = evaluate_open_world_unknown_detection(
                filtered,
                feature_columns=feature_columns,
                target_column=target_column,
                group_columns=group_columns,
                model_names=attack_models,
                random_seed=random_seed + 101,
                unknown_ratio=open_world_ratio,
            )
    return payload


def main() -> None:
    args = parse_args()
    attack_models = parse_attack_model_names(args.attack_models)
    progress = PhaseProgress("Privacy leakage benchmark")
    progress.update(5, "Loading flow CSV")
    progress.update(15, "Building privacy views")
    windows = load_android_windows_for_protocol(args.input, args, cache_prefix="privacy_leakage")
    views = build_window_privacy_views_from_windows(windows)
    reference = add_split_metadata(views["off"]).reset_index(drop=True)
    context_bucket = build_context_bucket(reference).astype(str)
    destination_behavior = build_destination_behavior_bucket(reference, args.destination_buckets).astype(str)

    results: dict[str, dict[str, object]] = {}
    total_views = max(1, len(views))
    for index, (view_name, raw_view) in enumerate(views.items(), start=1):
        progress.update(20 + (60 * (index - 1) / total_views), f"Evaluating {view_name}")
        frame = add_split_metadata(raw_view).reset_index(drop=True)
        if len(frame) != len(reference):
            raise SystemExit(f"Privacy view '{view_name}' is misaligned with the reference off-view rows.")
        feature_columns = [column for column in PRIVACY_FEATURE_SETS[view_name] if column in frame.columns]
        if not feature_columns:
            raise SystemExit(f"Privacy view '{view_name}' has no usable feature columns. Delete stale privacy caches or rerun with the patched cache validation.")

        frame["_target_app_id"] = reference["app_id"].astype(str).to_numpy()
        frame["_target_app_family"] = reference["app_family"].astype(str).to_numpy()
        frame["_target_dataset_source"] = reference["dataset_source"].astype(str).to_numpy()
        frame["_target_context_bucket"] = context_bucket.to_numpy()
        frame["_target_destination_behavior"] = destination_behavior.to_numpy()

        task_specs = {
            "app_id": {
                "target_column": "_target_app_id",
                "group_columns": ("dataset_source", "environment_id", "session_id", "time_fold"),
                "include_open_world": True,
            },
            "app_family": {
                "target_column": "_target_app_family",
                "group_columns": ("dataset_source", "environment_id", "session_id", "time_fold"),
                "include_open_world": False,
            },
            "dataset_source": {
                "target_column": "_target_dataset_source",
                "group_columns": ("environment_id", "session_id", "app_family", "time_fold"),
                "include_open_world": False,
            },
            "context_bucket": {
                "target_column": "_target_context_bucket",
                "group_columns": ("dataset_source", "session_id", "app_family"),
                "include_open_world": False,
            },
            "destination_behavior": {
                "target_column": "_target_destination_behavior",
                "group_columns": ("dataset_source", "environment_id", "session_id", "time_fold"),
                "include_open_world": False,
            },
        }

        task_results: dict[str, dict[str, object]] = {}
        for task_name, spec in task_specs.items():
            payload = _task_payload(
                frame,
                target_column=str(spec["target_column"]),
                task_name=task_name,
                feature_columns=feature_columns,
                group_columns=tuple(spec["group_columns"]),
                attack_models=attack_models,
                random_seed=args.random_seed + (index * 37),
                min_class_rows=args.min_class_rows,
                max_class_rows=args.max_class_rows,
                include_open_world=bool(spec["include_open_world"]),
                open_world_ratio=args.open_world_ratio,
            )
            if payload is not None:
                task_results[task_name] = payload

        app_task = task_results.get("app_id", {})
        app_strongest = app_task.get("strongest_model") if isinstance(app_task, dict) else None
        strongest_task = max(
            [
                {"task_name": task_name, **payload["strongest_model"]}
                for task_name, payload in task_results.items()
                if isinstance(payload.get("strongest_model"), dict)
            ],
            key=lambda row: (
                float(row.get("normalized_leakage") or 0.0),
                float(row.get("macro_f1") or 0.0),
                float(row.get("accuracy") or 0.0),
            ),
            default=None,
        )
        results[view_name] = {
            "rows_train": app_task.get("rows_train"),
            "rows_test": app_task.get("rows_test"),
            "split_strategy": app_task.get("split_strategy"),
            "split_summary": app_task.get("split_summary"),
            "class_count": app_task.get("class_count"),
            "app_reidentification_accuracy": (app_strongest or {}).get("accuracy") if isinstance(app_strongest, dict) else None,
            "macro_f1": (app_strongest or {}).get("macro_f1") if isinstance(app_strongest, dict) else None,
            "normalized_app_reidentification": (app_strongest or {}).get("normalized_leakage") if isinstance(app_strongest, dict) else None,
            "strongest_app_reidentification_model": (app_strongest or {}).get("model_name") if isinstance(app_strongest, dict) else None,
            "feature_group_results": app_task.get("feature_group_results", {}) if isinstance(app_task, dict) else {},
            "tasks": task_results,
            "strongest_task": strongest_task,
        }

    payload = {
        "benchmark": "privacy_inference_attack_suite",
        "attack_models": list(attack_models),
        "window_protocol": {
            "window_mode": args.window_mode,
            "window_seconds": int(args.window_seconds),
            "label_strategy": args.label_strategy,
            "max_adaptive_windows": int(args.max_adaptive_windows),
            "max_flow_rows": int(args.max_flow_rows),
            "multi_horizon_training": bool(args.multi_horizon_training),
            "cache_name": adaptive_cache_name(args, "privacy_leakage"),
        },
        "results": results,
    }
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
