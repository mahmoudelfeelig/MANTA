from __future__ import annotations

import numpy as np
import pandas as pd

from .dataset_metadata import derive_app_family


PORTABLE_FEATURE_COLUMNS = [
    "flow_count",
    "total_bytes_out",
    "total_bytes_in",
    "mean_packet_size",
    "outbound_ratio",
    "burstiness",
    "novelty_score",
    "connection_frequency_delta",
    "bytes_per_flow",
    "destination_diversity",
    "activity_ratio",
    "periodic_beacon_score",
    "byte_rate",
    "packet_rate",
    "mean_duration_ms",
    "duration_jitter",
    "port_diversity",
    "protocol_diversity",
    "packet_imbalance",
    "small_flow_ratio",
    "high_port_ratio",
    "destination_concentration",
    "destination_transition_rate",
    "destination_transition_entropy",
    "protocol_port_profile_diversity",
    "flow_size_iqr",
    "flow_count_deviation",
    "byte_rate_deviation",
    "destination_diversity_shift",
    "novelty_shift",
]

# Backwards-compatible alias used by the existing training scripts.
FEATURE_COLUMNS = PORTABLE_FEATURE_COLUMNS


REQUIRED_FLOW_COLUMNS = {
    "app_id",
    "timestamp_end",
    "bytes_out",
    "bytes_in",
    "packets_out",
    "packets_in",
    "dst_novelty",
}


def validate_flow_df(df: pd.DataFrame) -> None:
    missing = REQUIRED_FLOW_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Missing required flow columns: {sorted(missing)}")


def _periodic_beacon_score(values_ms: pd.Series) -> float:
    timestamps = np.sort(pd.to_numeric(values_ms, errors="coerce").dropna().to_numpy(dtype=float))
    if len(timestamps) < 4:
        return 0.0
    diffs = np.diff(timestamps) / 1000.0
    mean = float(np.mean(diffs))
    if mean <= 0:
        return 0.0
    std = float(np.std(diffs))
    coefficient = std / mean if mean else 0.0
    return float(max(0.0, min(1.0, 1.0 - coefficient)))


def _numeric_series(frame: pd.DataFrame, column: str, default: float = 0.0) -> pd.Series:
    if column in frame.columns:
        return pd.to_numeric(frame[column], errors="coerce").fillna(default)
    return pd.Series(np.full(len(frame), default, dtype=float), index=frame.index)


def _text_series(frame: pd.DataFrame, column: str, default: str) -> pd.Series:
    if column in frame.columns:
        return frame[column].astype(str).fillna(default)
    return pd.Series([default] * len(frame), index=frame.index, dtype="object")


def _dominant_text(group: pd.DataFrame, column: str, default: str) -> str:
    if column not in group.columns:
        return default
    values = group[column].astype(str).replace({"": default}).fillna(default)
    if values.empty:
        return default
    counts = values.value_counts()
    return str(counts.index[0]) if not counts.empty else default


def _normalized_entropy(values: list[str]) -> float:
    if len(values) <= 1:
        return 0.0
    counts = pd.Series(values, dtype="object").value_counts(normalize=True)
    if len(counts) <= 1:
        return 0.0
    entropy = float(-(counts * np.log(counts.clip(lower=1e-12))).sum())
    return float(entropy / np.log(max(2, len(counts))))


def build_feature_windows(df: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    validate_flow_df(df)

    working = df.copy()
    working["timestamp_end"] = pd.to_numeric(working["timestamp_end"], errors="coerce")
    working = working.dropna(subset=["timestamp_end"]).copy()
    working["timestamp_end"] = working["timestamp_end"].astype("int64")
    working["window_bucket"] = (working["timestamp_end"] // (window_seconds * 1000)).astype("int64")

    working["bytes_out"] = _numeric_series(working, "bytes_out")
    working["bytes_in"] = _numeric_series(working, "bytes_in")
    working["packets_out"] = _numeric_series(working, "packets_out")
    working["packets_in"] = _numeric_series(working, "packets_in")
    working["dst_novelty"] = _numeric_series(working, "dst_novelty").clip(lower=0.0, upper=1.0)
    working["duration_ms"] = _numeric_series(working, "duration_ms").clip(lower=0.0)
    working["dst_port"] = _numeric_series(working, "dst_port").fillna(0).astype("int64")
    working["protocol"] = _text_series(working, "protocol", "UNKNOWN").str.upper().replace({"": "UNKNOWN"})
    working["destination_key"] = _text_series(working, "destination_key", "unknown:0")

    working["total_bytes"] = working["bytes_out"] + working["bytes_in"]
    working["total_packets"] = (working["packets_out"] + working["packets_in"]).clip(lower=1.0)
    working["packet_size"] = working["total_bytes"] / working["total_packets"]
    working["second_bucket"] = (working["timestamp_end"] // 1000).astype("int64")
    working["small_flow"] = (working["total_bytes"] <= 256.0).astype(float)
    working["high_port"] = (working["dst_port"] >= 1024).astype(float)

    rows: list[dict[str, float | int | str]] = []
    grouped = working.groupby(["app_id", "window_bucket"], sort=True)
    for (app_id, bucket), group in grouped:
        ordered = group.sort_values("timestamp_end", kind="mergesort")
        flow_count = int(len(group))
        window_duration_seconds = max(1.0, float(window_seconds))
        total_bytes_out = float(group["bytes_out"].sum())
        total_bytes_in = float(group["bytes_in"].sum())
        total_packets_out = float(group["packets_out"].sum())
        total_packets_in = float(group["packets_in"].sum())
        total_packets = total_packets_out + total_packets_in
        duration_values = group["duration_ms"].astype(float)
        packet_imbalance = abs(total_packets_out - total_packets_in) / (total_packets + 1.0)
        destination_distribution = ordered["destination_key"].astype(str).value_counts(normalize=True)
        destination_sequence = ordered["destination_key"].astype(str).tolist()
        destination_switches = sum(
            int(previous != current)
            for previous, current in zip(destination_sequence[:-1], destination_sequence[1:], strict=False)
        )
        transition_values = [
            f"{previous}->{current}"
            for previous, current in zip(destination_sequence[:-1], destination_sequence[1:], strict=False)
        ]
        protocol_port_sequence = (
            ordered["protocol"].astype(str) + ":" + ordered["dst_port"].astype(str)
        )

        row: dict[str, float | int | str] = {
            "app_id": str(app_id),
            "app_family": derive_app_family(str(app_id)),
            "window_bucket": int(bucket),
            "flow_count": flow_count,
            "total_bytes_out": total_bytes_out,
            "total_bytes_in": total_bytes_in,
            "mean_packet_size": float(group["packet_size"].mean()),
            "outbound_ratio": float(total_bytes_out / (total_bytes_out + total_bytes_in + 1.0)),
            "burstiness": float(group["total_bytes"].std(ddof=0)) if flow_count > 1 else 0.0,
            "novelty_score": float(group["dst_novelty"].mean()),
            "connection_frequency_delta": float(flow_count / window_duration_seconds),
            "bytes_per_flow": float(group["total_bytes"].sum() / max(1, flow_count)),
            "destination_diversity": float(group["destination_key"].nunique() / max(1, flow_count)),
            "activity_ratio": float(
                min(1.0, duration_values.sum() / max(1.0, window_duration_seconds * 1000.0))
            ),
            "periodic_beacon_score": _periodic_beacon_score(group["timestamp_end"]),
            "byte_rate": float(group["total_bytes"].sum() / window_duration_seconds),
            "packet_rate": float(total_packets / window_duration_seconds),
            "mean_duration_ms": float(duration_values.mean()) if flow_count else 0.0,
            "duration_jitter": float(duration_values.std(ddof=0)) if flow_count > 1 else 0.0,
            "port_diversity": float(group["dst_port"].nunique() / max(1, flow_count)),
            "protocol_diversity": float(group["protocol"].nunique() / max(1, flow_count)),
            "packet_imbalance": float(packet_imbalance),
            "small_flow_ratio": float(group["small_flow"].mean()),
            "high_port_ratio": float(group["high_port"].mean()),
            "destination_concentration": float(destination_distribution.iloc[0]) if not destination_distribution.empty else 0.0,
            "destination_transition_rate": float(destination_switches / max(1, flow_count - 1)),
            "destination_transition_entropy": _normalized_entropy(transition_values),
            "protocol_port_profile_diversity": float(protocol_port_sequence.nunique() / max(1, flow_count)),
            "flow_size_iqr": float(group["total_bytes"].quantile(0.75) - group["total_bytes"].quantile(0.25)) if flow_count > 1 else 0.0,
            "dataset_source": _dominant_text(group, "dataset_source", "unknown_source"),
            "dataset_profile": _dominant_text(group, "dataset_profile", "unknown_profile"),
            "dataset_variant": _dominant_text(group, "dataset_variant", "unknown_variant"),
            "environment_id": _dominant_text(group, "environment_id", "unknown_environment"),
            "session_id": _dominant_text(group, "session_id", "unknown_session"),
        }

        label_cols = [col for col in ["label", "is_anomaly"] if col in group.columns]
        if label_cols:
            row["label"] = int(pd.to_numeric(group[label_cols[0]], errors="coerce").fillna(0).astype(int).max())
        rows.append(row)
    windows = pd.DataFrame(rows)
    if windows.empty:
        return windows
    windows = windows.sort_values(["app_id", "window_bucket"], kind="mergesort").reset_index(drop=True)
    app_groups = windows.groupby("app_id", sort=False, dropna=False)

    def _rolling_reference(series: pd.Series) -> pd.Series:
        shifted = series.shift(1)
        return shifted.rolling(3, min_periods=1).mean()

    rolling_flow_count = app_groups["flow_count"].transform(_rolling_reference)
    rolling_byte_rate = app_groups["byte_rate"].transform(_rolling_reference)
    rolling_destination_diversity = app_groups["destination_diversity"].transform(_rolling_reference)
    rolling_novelty = app_groups["novelty_score"].transform(_rolling_reference)
    windows["flow_count_deviation"] = (
        (windows["flow_count"] - rolling_flow_count).abs() / (rolling_flow_count.abs() + 1.0)
    ).fillna(0.0)
    windows["byte_rate_deviation"] = (
        (windows["byte_rate"] - rolling_byte_rate).abs() / (rolling_byte_rate.abs() + 1.0)
    ).fillna(0.0)
    windows["destination_diversity_shift"] = (
        (windows["destination_diversity"] - rolling_destination_diversity).abs()
    ).fillna(0.0)
    windows["novelty_shift"] = (
        (windows["novelty_score"] - rolling_novelty).abs()
    ).fillna(0.0)
    return windows


def feature_matrix(feature_windows: pd.DataFrame, feature_columns: list[str] | None = None) -> pd.DataFrame:
    columns = feature_columns or FEATURE_COLUMNS
    missing = [column for column in columns if column not in feature_windows.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    return feature_windows[columns].fillna(0.0)
