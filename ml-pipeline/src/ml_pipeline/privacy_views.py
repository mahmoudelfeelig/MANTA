from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from .features import FEATURE_COLUMNS, build_feature_windows


PRIVACY_FEATURE_SETS: dict[str, list[str]] = {
    "off": list(FEATURE_COLUMNS),
    "low": list(FEATURE_COLUMNS),
    "medium": [
        "activity_dp_bucket",
        "volume_dp_bucket",
        "duration_dp_bucket",
        "rate_dp_bucket",
        "burst_dp_bucket",
        "balance_super_bucket",
        "small_flow_super_bucket",
        "packet_imbalance_super_bucket",
        "temporal_regime",
        "is_weekend",
        "stability_dp_bucket",
        "shape_profile_bucket",
    ],
    "strict": [
        "activity_dp_bucket",
        "volume_dp_bucket",
        "duration_dp_bucket",
        "balance_super_bucket",
        "small_flow_super_bucket",
        "packet_imbalance_super_bucket",
        "temporal_regime",
        "stability_dp_bucket",
        "is_weekend",
    ],
}

PRIVACY_FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "volume_shape": (
        "activity_dp_bucket",
        "volume_dp_bucket",
        "duration_dp_bucket",
        "rate_dp_bucket",
        "burst_dp_bucket",
    ),
    "temporal_context": (
        "temporal_regime",
        "is_weekend",
        "stability_dp_bucket",
    ),
    "traffic_balance": (
        "balance_super_bucket",
        "packet_imbalance_super_bucket",
        "small_flow_super_bucket",
        "shape_profile_bucket",
    ),
}

PRIVACY_VIEW_ALIASES: dict[str, str] = {
    "full": "off",
    "pseudonymous": "low",
    "semantic_private": "medium",
    "semantic-private": "medium",
}

PRIVACY_VIEW_CHOICES: tuple[str, ...] = tuple(sorted(set(PRIVACY_FEATURE_SETS) | set(PRIVACY_VIEW_ALIASES)))
PRIVACY_METADATA_COLUMNS: tuple[str, ...] = (
    "app_id",
    "window_bucket",
    "label",
    "dataset_source",
    "dataset_profile",
    "dataset_variant",
    "environment_id",
    "session_id",
    "app_family",
)


def canonical_privacy_view_name(name: str) -> str:
    normalized = name.strip().lower()
    return PRIVACY_VIEW_ALIASES.get(normalized, normalized)


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


def _group_distribution_quantize(
    series: pd.Series,
    groups: pd.Series,
    buckets: int,
    *,
    log_scale: bool = False,
) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0).astype(float)
    if log_scale:
        values = np.log1p(values.clip(lower=0.0))
    normalized_groups = groups.astype(str).fillna("global").replace({"": "global", "nan": "global", "None": "global"})
    result = pd.Series(np.zeros(len(values), dtype=float), index=series.index)
    for group_name, group_index in normalized_groups.groupby(normalized_groups, sort=False).groups.items():
        group_values = values.loc[group_index]
        if group_values.nunique(dropna=False) <= 1:
            result.loc[group_index] = 0.0
            continue
        ranks = group_values.rank(method="average", pct=True).fillna(0.0).to_numpy(dtype=float)
        bucket_ids = np.floor(np.clip(ranks, 0.0, 0.999999) * buckets).astype(int)
        if buckets <= 1:
            normalized = np.zeros(len(bucket_ids), dtype=float)
        else:
            normalized = bucket_ids / float(buckets - 1)
        result.loc[group_index] = normalized
    return result.astype(float)


def _super_bucket(series: pd.Series, steps: int) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0).clip(lower=0.0, upper=1.0)
    scaled = np.round(values.to_numpy(dtype=float) * float(steps)) / float(max(1, steps))
    return pd.Series(np.clip(scaled, 0.0, 1.0), index=series.index, dtype=float)


def _derive_privacy_window_columns(windows: pd.DataFrame) -> pd.DataFrame:
    derived = windows.copy()
    def optional_numeric(column: str, default: float = 0.0) -> pd.Series:
        if column in derived.columns:
            return pd.to_numeric(derived[column], errors="coerce").fillna(default)
        return pd.Series(np.full(len(derived), default, dtype=float), index=derived.index)

    source_groups = derived["dataset_source"] if "dataset_source" in derived.columns else pd.Series(["global"] * len(derived), index=derived.index)
    if "window_end_ms" in derived.columns:
        timestamps = pd.Series(
            pd.to_datetime(pd.to_numeric(derived["window_end_ms"], errors="coerce").fillna(0), unit="ms", utc=True),
            index=derived.index,
        )
    else:
        raw_bucket = pd.to_numeric(derived["window_bucket"], errors="coerce").fillna(0).astype("int64")
        bucket_seconds = np.where(raw_bucket > 100_000_000, raw_bucket, raw_bucket * 60)
        timestamps = pd.Series(pd.to_datetime(bucket_seconds, unit="s", utc=True), index=derived.index)
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
    derived["temporal_regime"] = pd.Series(
        np.select(
            [
                (hours >= 0) & (hours < 7),
                (hours >= 7) & (hours < 19),
            ],
            [0.0, 0.5],
            default=1.0,
        ),
        index=derived.index,
        dtype=float,
    )
    derived["activity_level_bucket"] = _coarse_quantize(derived["flow_count"], 5)
    derived["volume_level_bucket"] = _coarse_quantize(
        derived["total_bytes_out"] + derived["total_bytes_in"],
        5,
        log_scale=True,
    )
    derived["duration_bucket"] = _coarse_quantize(derived["mean_duration_ms"], 5, log_scale=True)
    derived["byte_rate_bucket"] = _coarse_quantize(derived["byte_rate"], 5, log_scale=True)
    derived["packet_rate_bucket"] = _coarse_quantize(derived["packet_rate"], 5, log_scale=True)
    derived["balance_bucket"] = np.round(pd.to_numeric(derived["outbound_ratio"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["burst_bucket"] = _coarse_quantize(derived["burstiness"], 5, log_scale=True)
    derived["novelty_bucket"] = np.round(pd.to_numeric(derived["novelty_score"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["change_bucket"] = _coarse_quantize(derived["connection_frequency_delta"], 5, log_scale=True)
    derived["diversity_bucket"] = np.round(pd.to_numeric(derived["destination_diversity"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["beacon_bucket"] = np.round(pd.to_numeric(derived["periodic_beacon_score"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["packet_imbalance_bucket"] = np.round(pd.to_numeric(derived["packet_imbalance"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["small_flow_bucket"] = np.round(pd.to_numeric(derived["small_flow_ratio"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["high_port_bucket"] = np.round(pd.to_numeric(derived["high_port_ratio"], errors="coerce").fillna(0.0) * 4.0) / 4.0
    derived["activity_dp_bucket"] = _group_distribution_quantize(derived["flow_count"], source_groups, 4, log_scale=True)
    derived["volume_dp_bucket"] = _group_distribution_quantize(
        derived["total_bytes_out"] + derived["total_bytes_in"],
        source_groups,
        4,
        log_scale=True,
    )
    derived["duration_dp_bucket"] = _group_distribution_quantize(derived["mean_duration_ms"], source_groups, 4, log_scale=True)
    byte_rate_dp = _group_distribution_quantize(derived["byte_rate"], source_groups, 4, log_scale=True)
    packet_rate_dp = _group_distribution_quantize(derived["packet_rate"], source_groups, 4, log_scale=True)
    derived["rate_dp_bucket"] = np.round(((byte_rate_dp + packet_rate_dp) * 0.5) * 4.0) / 4.0
    derived["burst_dp_bucket"] = _group_distribution_quantize(derived["burstiness"], source_groups, 4, log_scale=True)
    stability_signal = (
        optional_numeric("flow_count_deviation") +
        optional_numeric("byte_rate_deviation") +
        optional_numeric("duration_jitter").clip(lower=0.0).map(np.log1p)
    ) / 3.0
    derived["stability_dp_bucket"] = _group_distribution_quantize(stability_signal, source_groups, 4, log_scale=False)
    derived["balance_super_bucket"] = _super_bucket(derived["outbound_ratio"], 2)
    derived["small_flow_super_bucket"] = _super_bucket(derived["small_flow_ratio"], 2)
    derived["packet_imbalance_super_bucket"] = _super_bucket(derived["packet_imbalance"], 2)
    shape_signal = (
        pd.to_numeric(derived["small_flow_ratio"], errors="coerce").fillna(0.0) +
        pd.to_numeric(derived["packet_imbalance"], errors="coerce").fillna(0.0) +
        optional_numeric("flow_size_iqr").clip(lower=0.0).map(np.log1p)
    ) / 3.0
    derived["shape_profile_bucket"] = _group_distribution_quantize(shape_signal, source_groups, 4, log_scale=False)
    return derived


def derive_flow_privacy_view(flows: pd.DataFrame, view: str, salt: str = "manta") -> pd.DataFrame:
    view = canonical_privacy_view_name(view)
    working = flows.copy()
    if view == "off":
        return working
    if "app_id" in working.columns:
        working["app_id"] = working["app_id"].astype(str).map(lambda value: stable_hash(value, salt=salt))
    for column in ("src_ip", "dst_ip", "destination_key"):
        if column in working.columns:
            if view == "low":
                working[column] = working[column].astype(str).map(lambda value: stable_hash(value, salt=salt))
            else:
                working[column] = ""
    if "dst_port" in working.columns and view in {"medium", "strict"}:
        bins = pd.cut(pd.to_numeric(working["dst_port"], errors="coerce").fillna(0), bins=[-1, 1023, 49151, 65535], labels=["system", "registered", "dynamic"])
        working["dst_port"] = bins.astype(str)
    if "protocol" in working.columns and view == "strict":
        working["protocol"] = working["protocol"].astype(str).str.upper().map(
            lambda value: "TCP_LIKE" if "TCP" in value else ("UDP_LIKE" if "UDP" in value else "OTHER")
        )
    if view in {"medium", "strict"}:
        for column in ("site_hint", "dst_host", "dst_host_hash"):
            if column in working.columns:
                working[column] = ""
    return working


def build_window_privacy_views(flows: pd.DataFrame) -> dict[str, pd.DataFrame]:
    windows = _derive_privacy_window_columns(build_feature_windows(flows))
    return build_window_privacy_views_from_windows(windows)


def build_window_privacy_views_from_windows(windows: pd.DataFrame) -> dict[str, pd.DataFrame]:
    windows = _derive_privacy_window_columns(windows)
    views: dict[str, pd.DataFrame] = {}
    for view_name, columns in PRIVACY_FEATURE_SETS.items():
        present = [column for column in columns if column in windows.columns]
        base = windows.copy()
        keep = [column for column in PRIVACY_METADATA_COLUMNS if column in base.columns]
        keep.extend(column for column in present if column not in keep)
        views[view_name] = base[keep].copy()
    return views


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
