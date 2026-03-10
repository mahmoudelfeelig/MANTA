from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from .features import FEATURE_COLUMNS, build_feature_windows


PRIVACY_FEATURE_SETS: dict[str, list[str]] = {
    "full": list(FEATURE_COLUMNS),
    "pseudonymous": list(FEATURE_COLUMNS),
    "semantic_private": [
        "activity_level_bucket",
        "volume_level_bucket",
        "balance_bucket",
        "burst_bucket",
        "novelty_bucket",
        "change_bucket",
        "diversity_bucket",
        "beacon_bucket",
        "packet_imbalance_bucket",
        "small_flow_bucket",
        "high_port_bucket",
        "hour_period",
        "is_weekend",
    ],
    "strict": [
        "activity_level_bucket",
        "balance_bucket",
        "novelty_bucket",
        "beacon_bucket",
        "small_flow_bucket",
        "hour_period",
        "is_weekend",
    ],
}


def stable_hash(value: object, salt: str = "manta") -> str:
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()


def _coarse_quantize(series: pd.Series, buckets: int, *, log_scale: bool = False) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0).astype(float)
    if log_scale:
        values = np.log1p(values.clip(lower=0.0))
    if values.nunique(dropna=False) <= 1:
        return pd.Series(np.zeros(len(values), dtype=float), index=series.index)
    ranks = values.rank(method="average", pct=True).fillna(0.0)
    bucket_ids = np.floor(np.clip(ranks.to_numpy(dtype=float), 0.0, 0.999999) * buckets).astype(int)
    if buckets <= 1:
        normalized = np.zeros(len(bucket_ids), dtype=float)
    else:
        normalized = bucket_ids / float(buckets - 1)
    return pd.Series(normalized, index=series.index, dtype=float)


def _derive_privacy_window_columns(windows: pd.DataFrame) -> pd.DataFrame:
    derived = windows.copy()
    bucket_seconds = pd.to_numeric(derived["window_bucket"], errors="coerce").fillna(0).astype("int64") * 60
    timestamps = pd.to_datetime(bucket_seconds, unit="s", utc=True)
    hours = timestamps.dt.hour.fillna(0).astype(int)
    derived["hour_period"] = pd.Series(
        np.select(
            [
                (hours >= 0) & (hours < 6),
                (hours >= 6) & (hours < 12),
                (hours >= 12) & (hours < 18),
            ],
            [0.0, 1.0 / 3.0, 2.0 / 3.0],
            default=1.0,
        ),
        index=derived.index,
        dtype=float,
    )
    derived["is_weekend"] = timestamps.dt.dayofweek.isin([5, 6]).astype(float)
    derived["activity_level_bucket"] = _coarse_quantize(derived["flow_count"], 5)
    derived["volume_level_bucket"] = _coarse_quantize(
        derived["total_bytes_out"] + derived["total_bytes_in"],
        5,
        log_scale=True,
    )
    derived["balance_bucket"] = np.round(pd.to_numeric(derived["outbound_ratio"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["burst_bucket"] = _coarse_quantize(derived["burstiness"], 5, log_scale=True)
    derived["novelty_bucket"] = np.round(pd.to_numeric(derived["novelty_score"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["change_bucket"] = _coarse_quantize(derived["connection_frequency_delta"], 5, log_scale=True)
    derived["diversity_bucket"] = np.round(pd.to_numeric(derived["destination_diversity"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["beacon_bucket"] = np.round(pd.to_numeric(derived["periodic_beacon_score"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["packet_imbalance_bucket"] = np.round(pd.to_numeric(derived["packet_imbalance"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["small_flow_bucket"] = np.round(pd.to_numeric(derived["small_flow_ratio"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["high_port_bucket"] = np.round(pd.to_numeric(derived["high_port_ratio"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    return derived


def derive_flow_privacy_view(flows: pd.DataFrame, view: str, salt: str = "manta") -> pd.DataFrame:
    working = flows.copy()
    if view == "full":
        return working
    if "app_id" in working.columns:
        working["app_id"] = working["app_id"].astype(str).map(lambda value: stable_hash(value, salt=salt))
    for column in ("src_ip", "dst_ip", "destination_key"):
        if column in working.columns:
            if view == "pseudonymous":
                working[column] = working[column].astype(str).map(lambda value: stable_hash(value, salt=salt))
            else:
                working[column] = ""
    if "dst_port" in working.columns and view in {"semantic_private", "strict"}:
        bins = pd.cut(pd.to_numeric(working["dst_port"], errors="coerce").fillna(0), bins=[-1, 1023, 49151, 65535], labels=["system", "registered", "dynamic"])
        working["dst_port"] = bins.astype(str)
    if "protocol" in working.columns and view == "strict":
        working["protocol"] = working["protocol"].astype(str).str.upper().map(
            lambda value: "TCP_LIKE" if "TCP" in value else ("UDP_LIKE" if "UDP" in value else "OTHER")
        )
    if view in {"semantic_private", "strict"}:
        for column in ("site_hint", "dst_host", "dst_host_hash"):
            if column in working.columns:
                working[column] = ""
    return working


def build_window_privacy_views(flows: pd.DataFrame) -> dict[str, pd.DataFrame]:
    windows = _derive_privacy_window_columns(build_feature_windows(flows))
    views: dict[str, pd.DataFrame] = {}
    for view_name, columns in PRIVACY_FEATURE_SETS.items():
        present = [column for column in columns if column in windows.columns]
        base = windows.copy()
        keep = ["app_id", "window_bucket"]
        if "label" in base.columns:
            keep.append("label")
        keep.extend(present)
        views[view_name] = base[keep].copy()
    return views


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
