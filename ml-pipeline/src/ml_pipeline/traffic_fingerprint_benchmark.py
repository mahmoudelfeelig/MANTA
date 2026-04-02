from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from .io_utils import read_csv_resilient
from .privacy_attack_utils import (
    ATTACK_MODEL_CHOICES,
    build_context_bucket,
    evaluate_multiclass_models,
    evaluate_open_world_unknown_detection,
    grouped_label_holdout_split,
    parse_attack_model_names,
)
from .progress import PhaseProgress
from .splits import add_split_metadata


STEP_FEATURES: tuple[str, ...] = (
    "log_total_bytes",
    "signed_byte_delta",
    "log_duration_ms",
    "log_interarrival_ms",
    "novelty_score",
    "dst_port_bucket",
    "protocol_code",
)

SUMMARY_FEATURES: tuple[str, ...] = (
    "seq_flow_fraction",
    "seq_log_total_bytes",
    "seq_log_mean_duration_ms",
    "seq_log_mean_interarrival_ms",
    "seq_novelty_mean",
    "seq_outbound_ratio_mean",
    "seq_high_port_ratio",
    "seq_protocol_diversity",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark encrypted-flow sequence fingerprinting over canonical MANTA flow traces")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--sequence-length", type=int, default=24)
    parser.add_argument("--min-sequence-flows", type=int, default=8)
    parser.add_argument("--stride", type=int, default=12)
    parser.add_argument("--max-sequences-per-app", type=int, default=120)
    parser.add_argument("--min-class-rows", type=int, default=12)
    parser.add_argument("--attack-models", default=",".join(ATTACK_MODEL_CHOICES))
    parser.add_argument("--open-world-ratio", type=float, default=0.25)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _port_bucket(series: pd.Series) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0)
    return pd.Series(
        np.select(
            [values <= 1023, values <= 49151],
            [0.0, 0.5],
            default=1.0,
        ),
        index=series.index,
        dtype=float,
    )


def _protocol_code(series: pd.Series) -> pd.Series:
    values = series.astype(str).str.upper()
    return pd.Series(
        np.select(
            [values.str.contains("TCP", na=False), values.str.contains("UDP", na=False)],
            [1.0, 0.5],
            default=0.0,
        ),
        index=series.index,
        dtype=float,
    )


def _build_sequence_rows(
    flows: pd.DataFrame,
    *,
    sequence_length: int,
    min_sequence_flows: int,
    stride: int,
    max_sequences_per_app: int,
) -> pd.DataFrame:
    working = add_split_metadata(flows).copy()
    duration_series = working["duration_ms"] if "duration_ms" in working.columns else pd.Series(np.zeros(len(working)), index=working.index)
    dst_port_series = working["dst_port"] if "dst_port" in working.columns else pd.Series(np.zeros(len(working)), index=working.index)
    protocol_series = working["protocol"] if "protocol" in working.columns else pd.Series(["UNKNOWN"] * len(working), index=working.index)
    working["timestamp_end"] = pd.to_numeric(working["timestamp_end"], errors="coerce").fillna(0).astype("int64")
    working["bytes_out"] = pd.to_numeric(working["bytes_out"], errors="coerce").fillna(0.0)
    working["bytes_in"] = pd.to_numeric(working["bytes_in"], errors="coerce").fillna(0.0)
    working["duration_ms"] = pd.to_numeric(duration_series, errors="coerce").fillna(0.0).clip(lower=0.0)
    working["dst_novelty"] = pd.to_numeric(working["dst_novelty"], errors="coerce").fillna(0.0).clip(lower=0.0, upper=1.0)
    working["dst_port_bucket"] = _port_bucket(dst_port_series)
    working["protocol_code"] = _protocol_code(protocol_series)
    working["total_bytes"] = working["bytes_out"] + working["bytes_in"]
    working["log_total_bytes"] = np.log1p(working["total_bytes"].clip(lower=0.0))
    working["signed_byte_delta"] = np.log1p(working["bytes_out"].clip(lower=0.0)) - np.log1p(working["bytes_in"].clip(lower=0.0))
    working["log_duration_ms"] = np.log1p(working["duration_ms"])
    working["outbound_ratio"] = working["bytes_out"] / (working["total_bytes"] + 1.0)
    working["high_port_flag"] = (pd.to_numeric(dst_port_series, errors="coerce").fillna(0) >= 1024).astype(float)
    working["flow_order_group"] = (
        working["app_id"].astype(str) + "|" +
        working["dataset_source"].astype(str) + "|" +
        working["environment_id"].astype(str) + "|" +
        working["session_id"].astype(str)
    )

    rows: list[dict[str, object]] = []
    effective_stride = max(1, int(stride) if stride > 0 else int(sequence_length))
    for group_key, group in working.groupby("flow_order_group", sort=False):
        ordered = group.sort_values("timestamp_end").reset_index(drop=True)
        if len(ordered) < min_sequence_flows:
            continue
        ordered["interarrival_ms"] = ordered["timestamp_end"].diff().fillna(0).clip(lower=0.0)
        ordered["log_interarrival_ms"] = np.log1p(ordered["interarrival_ms"])
        emitted = 0
        for start in range(0, len(ordered), effective_stride):
            chunk = ordered.iloc[start : start + sequence_length].reset_index(drop=True)
            if len(chunk) < min_sequence_flows:
                continue
            if max_sequences_per_app > 0 and emitted >= max_sequences_per_app:
                break
            row: dict[str, object] = {
                "sequence_id": f"{group_key}|{start}",
                "app_id": str(chunk["app_id"].iloc[0]),
                "app_family": str(chunk["app_family"].iloc[0]),
                "dataset_source": str(chunk["dataset_source"].iloc[0]),
                "environment_id": str(chunk["environment_id"].iloc[0]),
                "session_id": str(chunk["session_id"].iloc[0]),
                "time_fold": str(chunk["time_fold"].iloc[0]),
                "capture_group": str(chunk["dataset_source"].iloc[0]) + "|" + str(chunk["environment_id"].iloc[0]) + "|" + str(chunk["session_id"].iloc[0]),
                "seq_flow_fraction": float(len(chunk) / max(1, sequence_length)),
                "seq_log_total_bytes": float(np.log1p(chunk["total_bytes"].sum())),
                "seq_log_mean_duration_ms": float(np.log1p(chunk["duration_ms"].mean())),
                "seq_log_mean_interarrival_ms": float(np.log1p(chunk["interarrival_ms"].mean())),
                "seq_novelty_mean": float(chunk["dst_novelty"].mean()),
                "seq_outbound_ratio_mean": float(chunk["outbound_ratio"].mean()),
                "seq_high_port_ratio": float(chunk["high_port_flag"].mean()),
                "seq_protocol_diversity": float(chunk["protocol_code"].nunique() / max(1, len(chunk))),
            }
            for step_index in range(sequence_length):
                if step_index < len(chunk):
                    sample = chunk.iloc[step_index]
                    row[f"s{step_index:02d}_log_total_bytes"] = float(sample["log_total_bytes"])
                    row[f"s{step_index:02d}_signed_byte_delta"] = float(sample["signed_byte_delta"])
                    row[f"s{step_index:02d}_log_duration_ms"] = float(sample["log_duration_ms"])
                    row[f"s{step_index:02d}_log_interarrival_ms"] = float(sample["log_interarrival_ms"])
                    row[f"s{step_index:02d}_novelty_score"] = float(sample["dst_novelty"])
                    row[f"s{step_index:02d}_dst_port_bucket"] = float(sample["dst_port_bucket"])
                    row[f"s{step_index:02d}_protocol_code"] = float(sample["protocol_code"])
                else:
                    row[f"s{step_index:02d}_log_total_bytes"] = 0.0
                    row[f"s{step_index:02d}_signed_byte_delta"] = 0.0
                    row[f"s{step_index:02d}_log_duration_ms"] = 0.0
                    row[f"s{step_index:02d}_log_interarrival_ms"] = 0.0
                    row[f"s{step_index:02d}_novelty_score"] = 0.0
                    row[f"s{step_index:02d}_dst_port_bucket"] = 0.0
                    row[f"s{step_index:02d}_protocol_code"] = 0.0
            rows.append(row)
            emitted += 1
    return pd.DataFrame(rows)


def _prepare_task_frame(frame: pd.DataFrame, *, target_column: str, min_class_rows: int) -> pd.DataFrame:
    counts = frame[target_column].astype(str).value_counts()
    keep = counts[counts >= min_class_rows].index
    return frame[frame[target_column].astype(str).isin(keep)].copy().reset_index(drop=True)


def _evaluate_task(
    frame: pd.DataFrame,
    *,
    target_column: str,
    task_name: str,
    feature_columns: list[str],
    group_columns: tuple[str, ...],
    attack_models: tuple[str, ...],
    random_seed: int,
    min_class_rows: int,
    open_world_ratio: float,
) -> dict[str, object] | None:
    filtered = _prepare_task_frame(frame, target_column=target_column, min_class_rows=min_class_rows)
    if filtered[target_column].astype(str).nunique() < 2 or len(filtered) < max(12, min_class_rows * 2):
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
    payload: dict[str, object] = {
        "target_column": target_column,
        "rows_train": int(len(train_x)),
        "rows_test": int(len(test_x)),
        "class_count": int(len(encoder.classes_)),
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "models": model_results,
    }
    if strongest is not None:
        payload["strongest_model"] = strongest
    if task_name == "app_id":
        payload["open_world"] = evaluate_open_world_unknown_detection(
            filtered,
            feature_columns=feature_columns,
            target_column=target_column,
            group_columns=group_columns,
            model_names=attack_models,
            random_seed=random_seed + 97,
            unknown_ratio=open_world_ratio,
        )
    return payload


def main() -> None:
    args = parse_args()
    attack_models = parse_attack_model_names(args.attack_models)
    progress = PhaseProgress("Traffic fingerprint benchmark")
    progress.update(5, "Loading flow CSV")
    flows = read_csv_resilient(args.input)
    if "app_id" not in flows.columns:
        raise SystemExit("Traffic fingerprint benchmark requires canonical flow data with app_id.")

    progress.update(15, "Building encrypted-flow sequences")
    sequences = _build_sequence_rows(
        flows,
        sequence_length=args.sequence_length,
        min_sequence_flows=args.min_sequence_flows,
        stride=args.stride,
        max_sequences_per_app=args.max_sequences_per_app,
    )
    if sequences.empty:
        raise SystemExit("Could not derive any flow sequences. Check the corpus and sequence-length settings.")

    sequences["_target_context_bucket"] = build_context_bucket(sequences).astype(str)
    feature_columns = [
        *(f"s{step_index:02d}_{feature_name}" for step_index in range(args.sequence_length) for feature_name in STEP_FEATURES),
        *SUMMARY_FEATURES,
    ]
    feature_columns = [column for column in feature_columns if column in sequences.columns]

    task_specs = {
        "app_id": {
            "target_column": "app_id",
            "group_columns": ("dataset_source", "environment_id", "session_id"),
        },
        "app_family": {
            "target_column": "app_family",
            "group_columns": ("dataset_source", "environment_id", "session_id"),
        },
        "dataset_source": {
            "target_column": "dataset_source",
            "group_columns": ("environment_id", "session_id", "app_family"),
        },
        "context_bucket": {
            "target_column": "_target_context_bucket",
            "group_columns": ("dataset_source", "session_id", "app_family"),
        },
    }

    results: dict[str, dict[str, object]] = {}
    total_tasks = max(1, len(task_specs))
    for index, (task_name, spec) in enumerate(task_specs.items(), start=1):
        progress.update(25 + (55 * (index - 1) / total_tasks), f"Evaluating {task_name}")
        payload = _evaluate_task(
            sequences,
            target_column=str(spec["target_column"]),
            task_name=task_name,
            feature_columns=feature_columns,
            group_columns=tuple(spec["group_columns"]),
            attack_models=attack_models,
            random_seed=args.random_seed + (index * 29),
            min_class_rows=args.min_class_rows,
            open_world_ratio=args.open_world_ratio,
        )
        if payload is not None:
            results[task_name] = payload

    strongest_task = max(
        [
            {"task_name": task_name, **payload["strongest_model"]}
            for task_name, payload in results.items()
            if isinstance(payload.get("strongest_model"), dict)
        ],
        key=lambda row: (
            float(row.get("normalized_leakage") or 0.0),
            float(row.get("macro_f1") or 0.0),
            float(row.get("accuracy") or 0.0),
        ),
        default=None,
    )
    output = {
        "benchmark": "encrypted_flow_sequence_fingerprinting",
        "attack_models": list(attack_models),
        "representation": {
            "type": "metadata_flow_sequence",
            "sequence_length": int(args.sequence_length),
            "min_sequence_flows": int(args.min_sequence_flows),
            "stride": int(args.stride),
            "step_features": list(STEP_FEATURES),
            "summary_features": list(SUMMARY_FEATURES),
        },
        "corpus": {
            "rows_flows": int(len(flows)),
            "rows_sequences": int(len(sequences)),
            "unique_apps": int(sequences["app_id"].astype(str).nunique()),
            "unique_app_families": int(sequences["app_family"].astype(str).nunique()),
            "dataset_sources": sorted(sequences["dataset_source"].astype(str).unique().tolist()),
        },
        "results": results,
        "strongest_task": strongest_task,
    }
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
