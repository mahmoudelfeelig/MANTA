from __future__ import annotations

import pandas as pd


FEATURE_COLUMNS = [
    "flow_count",
    "total_bytes_out",
    "total_bytes_in",
    "mean_packet_size",
    "outbound_ratio",
    "burstiness",
    "novelty_score",
    "connection_frequency_delta",
]


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



def build_feature_windows(df: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    validate_flow_df(df)

    working = df.copy()
    working["timestamp_end"] = pd.to_numeric(working["timestamp_end"], errors="coerce")
    working = working.dropna(subset=["timestamp_end"])
    working["window_bucket"] = (working["timestamp_end"] // (window_seconds * 1000)).astype("int64")
    working["total_bytes"] = working["bytes_out"].astype(float) + working["bytes_in"].astype(float)
    working["total_packets"] = (
        working["packets_out"].fillna(0).astype(float) +
        working["packets_in"].fillna(0).astype(float)
    ).clip(lower=1)

    grouped = working.groupby(["app_id", "window_bucket"], as_index=False).agg(
        flow_count=("app_id", "count"),
        total_bytes_out=("bytes_out", "sum"),
        total_bytes_in=("bytes_in", "sum"),
        mean_packet_size=("total_bytes", "mean"),
        burstiness=("total_bytes", "std"),
        novelty_score=("dst_novelty", "mean"),
    )

    grouped["burstiness"] = grouped["burstiness"].fillna(0.0)
    grouped["outbound_ratio"] = grouped["total_bytes_out"] / (
        grouped["total_bytes_out"] + grouped["total_bytes_in"] + 1.0
    )
    grouped["connection_frequency_delta"] = grouped["flow_count"] / float(window_seconds)

    label_cols = [col for col in ["label", "is_anomaly"] if col in working.columns]
    if label_cols:
        label_col = label_cols[0]
        labels = working.groupby(["app_id", "window_bucket"], as_index=False).agg(
            label=(label_col, "max")
        )
        grouped = grouped.merge(labels, on=["app_id", "window_bucket"], how="left")

    return grouped



def feature_matrix(feature_windows: pd.DataFrame) -> pd.DataFrame:
    missing = [column for column in FEATURE_COLUMNS if column not in feature_windows.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    return feature_windows[FEATURE_COLUMNS].fillna(0.0)
