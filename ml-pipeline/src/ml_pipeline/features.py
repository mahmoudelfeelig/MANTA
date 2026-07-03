from __future__ import annotations

from bisect import bisect_right, insort
from collections import Counter, deque
from datetime import UTC, datetime
import re

import numpy as np
import pandas as pd

from .android_feature_contract import ANDROID_FEATURE_COLUMNS
from .dataset_metadata import derive_app_family


PORTABLE_FEATURE_COLUMNS = list(ANDROID_FEATURE_COLUMNS)

SERVER_ONLY_ENGINEERED_COLUMNS = [
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

# Backwards-compatible alias used by the existing training scripts. This is now
# intentionally the Android runtime feature contract, not every engineered column.
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


def _periodic_beacon_score_from_rows(rows: deque[dict[str, object]]) -> float:
    if len(rows) < 4:
        return 0.0
    previous: int | None = None
    count = 0
    delta_sum = 0.0
    delta_sq_sum = 0.0
    for row in rows:
        timestamp = int(row["timestamp_end"])
        if previous is not None:
            delta = (timestamp - previous) / 1000.0
            delta_sum += delta
            delta_sq_sum += delta * delta
            count += 1
        previous = timestamp
    if count < 3:
        return 0.0
    mean = delta_sum / count
    if mean <= 0.0:
        return 0.0
    variance = max(0.0, (delta_sq_sum / count) - (mean * mean))
    coefficient = float(np.sqrt(variance) / mean)
    return float(max(0.0, min(1.0, 1.0 - coefficient)))


def _numeric_series(frame: pd.DataFrame, column: str, default: float = 0.0) -> pd.Series:
    if column in frame.columns:
        return pd.to_numeric(frame[column], errors="coerce").fillna(default)
    return pd.Series(np.full(len(frame), default, dtype=float), index=frame.index)


def _optional_numeric(frame: pd.DataFrame, column: str, default: float = 0.0) -> pd.Series:
    return _numeric_series(frame, column, default=default)


def _text_series(frame: pd.DataFrame, column: str, default: str) -> pd.Series:
    if column in frame.columns:
        return frame[column].astype(str).fillna(default)
    return pd.Series([default] * len(frame), index=frame.index, dtype="object")


def _destination_host_series(frame: pd.DataFrame) -> pd.Series:
    if "dst_ip" in frame.columns:
        return frame["dst_ip"].astype(str).fillna("")
    if "destination_ip" in frame.columns:
        return frame["destination_ip"].astype(str).fillna("")
    destination = _text_series(frame, "destination_key", "unknown:0")
    return destination.astype(str).str.split(":", n=1).str[0].fillna("")


def _is_private_destination(hosts: pd.Series) -> pd.Series:
    values = hosts.astype(str).str.lower()
    return (
        values.str.startswith("10.") |
        values.str.startswith("192.168.") |
        values.str.match(r"^172\.(1[6-9]|2\d|3[0-1])\.") |
        values.isin({"127.0.0.1", "::1"}) |
        values.str.startswith("fc") |
        values.str.startswith("fd")
    )


def _is_multicast_destination(hosts: pd.Series) -> pd.Series:
    values = hosts.astype(str).str.lower()
    first_octet = pd.to_numeric(values.str.split(".", n=1).str[0], errors="coerce")
    return first_octet.between(224, 239).fillna(False) | values.str.startswith("ff")


def _destination_intelligence_columns(hosts: pd.Series, frame: pd.DataFrame) -> pd.DataFrame:
    values = hosts.astype(str).str.lower().fillna("")
    has_alpha = values.str.contains(r"[a-z]", regex=True)
    suspicious_tld = values.str.endswith((".xyz", ".top", ".club", ".click", ".work", ".icu", ".tk", ".gq", ".ml", ".cf"))
    punycode = values.str.contains("xn--", regex=False)
    digit_substitution = values.str.contains(r"[a-z][0-9][a-z]|[0-9][a-z][0-9]", regex=True)
    long_host = values.str.len() >= 32
    many_labels = values.str.count(r"\.") >= 4
    lookalike_score = _optional_numeric(frame, "lookalike_score").clip(lower=0.0, upper=1.0)
    if (lookalike_score == 0.0).all():
        lookalike_score = (digit_substitution.astype(float) * 0.45 + punycode.astype(float) * 0.35).clip(upper=1.0)
    threat_tag = (
        _optional_numeric(frame, "has_threat_tags").clip(lower=0.0, upper=1.0)
        if "has_threat_tags" in frame.columns
        else pd.Series(np.zeros(len(frame), dtype=float), index=frame.index)
    )
    mitre = (
        _optional_numeric(frame, "has_mitre_techniques").clip(lower=0.0, upper=1.0)
        if "has_mitre_techniques" in frame.columns
        else pd.Series(np.zeros(len(frame), dtype=float), index=frame.index)
    )
    suspicious = (suspicious_tld | punycode | digit_substitution | long_host | many_labels).astype(float).clip(upper=1.0)
    risk = pd.concat(
        [
            lookalike_score,
            threat_tag * 0.85,
            suspicious_tld.astype(float) * 0.65,
            punycode.astype(float) * 0.55,
            digit_substitution.astype(float) * 0.45,
            long_host.astype(float) * 0.30,
            many_labels.astype(float) * 0.25,
        ],
        axis=1,
    ).max(axis=1).fillna(0.0)
    return pd.DataFrame(
        {
            "destination_risk": risk.clip(lower=0.0, upper=1.0),
            "lookalike_score_flow": lookalike_score,
            "suspicious_destination": suspicious,
            "known_identity": has_alpha.astype(float),
            "mitre_technique_flow": mitre,
            "threat_tag_flow": threat_tag,
        },
        index=frame.index,
    )


def _is_private_destination_value(host: object) -> bool:
    value = str(host or "").lower()
    return (
        value.startswith("10.") or
        value.startswith("192.168.") or
        bool(re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", value)) or
        value in {"127.0.0.1", "::1"} or
        value.startswith("fc") or
        value.startswith("fd")
    )


def _is_multicast_destination_value(host: object) -> bool:
    value = str(host or "").lower()
    first_octet = value.split(".", 1)[0]
    try:
        return 224 <= int(first_octet) <= 239
    except ValueError:
        return value.startswith("ff")


def _row_float(row: dict[str, object], column: str, default: float = 0.0) -> float:
    try:
        value = row.get(column, default)
        if value is None or pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _add_android_expanded_row_values(row: dict[str, object]) -> None:
    timestamp_ms = int(_row_float(row, "timestamp_end", 0.0))
    instant = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=UTC)
    row["hour_of_day"] = float(instant.hour)
    row["day_of_week"] = float(instant.isoweekday())
    row["is_weekend"] = 1.0 if instant.isoweekday() >= 6 else 0.0
    row["data_quality_score"] = 1.0

    sttl = _row_float(row, "sttl")
    rttl = _row_float(row, "rttl")
    has_ttl = max(0.0, min(1.0, _row_float(row, "has_ttl_metrics")))
    row["ttl_gap"] = max(0.0, min(1.0, abs(sttl - rttl) / 255.0)) if has_ttl > 0.0 else 0.0
    row["ttl_metrics_present"] = has_ttl
    row["syn_rate_total"] = max(0.0, _row_float(row, "s_syn_rate") + _row_float(row, "r_syn_rate"))
    row["rst_rate_total"] = max(0.0, _row_float(row, "s_rst_rate") + _row_float(row, "r_rst_rate"))
    row["ack_rate_total"] = max(0.0, _row_float(row, "s_ack_rate") + _row_float(row, "r_ack_rate"))
    row["fin_rate_total"] = max(0.0, _row_float(row, "s_fin_rate") + _row_float(row, "r_fin_rate"))
    row["psh_rate_total"] = max(0.0, _row_float(row, "s_psh_rate") + _row_float(row, "r_psh_rate"))
    row["fragment_rate_total"] = max(0.0, _row_float(row, "s_fragment_rate") + _row_float(row, "r_fragment_rate"))
    row["tcp_window_mean"] = max(0.0, 0.5 * (_row_float(row, "s_win_tcp") + _row_float(row, "r_win_tcp")))
    row["ack_delay_mean"] = max(0.0, 0.5 * (_row_float(row, "s_ack_delay_avg") + _row_float(row, "r_ack_delay_avg")))
    row["inter_packet_gap_mean"] = max(0.0, 0.5 * (_row_float(row, "s_inter_packet_avg") + _row_float(row, "r_inter_packet_avg")))
    row["payload_mean"] = max(0.0, 0.5 * (_row_float(row, "s_payload_avg") + _row_float(row, "r_payload_avg")))
    row["load_mean"] = max(0.0, 0.5 * (_row_float(row, "s_load") + _row_float(row, "r_load")))
    availability_columns = [
        "has_ttl_metrics",
        "has_tcp_flag_metrics",
        "has_fragment_metrics",
        "has_window_metrics",
        "has_ack_delay_metrics",
        "has_inter_packet_metrics",
        "has_payload_metrics",
        "has_load_metrics",
        "lookalike_score",
        "has_threat_tags",
        "has_mitre_techniques",
    ]
    row["transport_metrics_present"] = max(max(0.0, min(1.0, _row_float(row, column))) for column in availability_columns)
    dst_port = int(_row_float(row, "dst_port"))
    row["dns_flow"] = 1.0 if dst_port in {53, 853} else 0.0
    row["web_flow"] = 1.0 if dst_port in {80, 443, 8000, 8080, 8443} else 0.0
    host = row.get("dst_ip") or row.get("destination_ip") or str(row.get("destination_key", "unknown:0")).split(":", 1)[0]
    row["private_destination"] = 1.0 if _is_private_destination_value(host) else 0.0
    row["multicast_destination"] = 1.0 if _is_multicast_destination_value(host) else 0.0
    host_value = str(host or "").lower()
    suspicious_tld = host_value.endswith((".xyz", ".top", ".club", ".click", ".work", ".icu", ".tk", ".gq", ".ml", ".cf"))
    punycode = "xn--" in host_value
    digit_substitution = bool(re.search(r"[a-z][0-9][a-z]|[0-9][a-z][0-9]", host_value))
    long_host = len(host_value) >= 32
    many_labels = host_value.count(".") >= 4
    lookalike = max(0.0, min(1.0, _row_float(row, "lookalike_score")))
    if lookalike == 0.0:
        lookalike = min(1.0, (0.45 if digit_substitution else 0.0) + (0.35 if punycode else 0.0))
    threat_tag = max(0.0, min(1.0, _row_float(row, "has_threat_tags")))
    mitre = max(0.0, min(1.0, _row_float(row, "has_mitre_techniques")))
    row["lookalike_score_flow"] = lookalike
    row["suspicious_destination"] = 1.0 if suspicious_tld or punycode or digit_substitution or long_host or many_labels else 0.0
    row["known_identity"] = 1.0 if re.search(r"[a-z]", host_value) else 0.0
    row["mitre_technique_flow"] = mitre
    row["threat_tag_flow"] = threat_tag
    row["destination_risk"] = max(
        lookalike,
        threat_tag * 0.85,
        0.65 if suspicious_tld else 0.0,
        0.55 if punycode else 0.0,
        0.45 if digit_substitution else 0.0,
        0.30 if long_host else 0.0,
        0.25 if many_labels else 0.0,
    )


def _prepare_android_expanded_flow_columns(working: pd.DataFrame) -> pd.DataFrame:
    timestamps = pd.to_datetime(pd.to_numeric(working["timestamp_end"], errors="coerce").fillna(0).astype("int64"), unit="ms", utc=True)
    working["hour_of_day"] = timestamps.dt.hour.astype(float)
    working["day_of_week"] = (timestamps.dt.dayofweek + 1).astype(float)
    working["is_weekend"] = (timestamps.dt.dayofweek >= 5).astype(float)
    working["data_quality_score"] = 1.0

    sttl = _optional_numeric(working, "sttl")
    rttl = _optional_numeric(working, "rttl")
    has_ttl = _optional_numeric(working, "has_ttl_metrics")
    if "ttl_gap" not in working.columns:
        working["ttl_gap"] = ((sttl - rttl).abs() / 255.0).where(has_ttl > 0, 0.0).clip(lower=0.0, upper=1.0)
    else:
        working["ttl_gap"] = _optional_numeric(working, "ttl_gap").clip(lower=0.0, upper=1.0)
    working["ttl_metrics_present"] = has_ttl.clip(lower=0.0, upper=1.0)
    working["syn_rate_total"] = (_optional_numeric(working, "s_syn_rate") + _optional_numeric(working, "r_syn_rate")).clip(lower=0.0)
    working["rst_rate_total"] = (_optional_numeric(working, "s_rst_rate") + _optional_numeric(working, "r_rst_rate")).clip(lower=0.0)
    working["ack_rate_total"] = (_optional_numeric(working, "s_ack_rate") + _optional_numeric(working, "r_ack_rate")).clip(lower=0.0)
    working["fin_rate_total"] = (_optional_numeric(working, "s_fin_rate") + _optional_numeric(working, "r_fin_rate")).clip(lower=0.0)
    working["psh_rate_total"] = (_optional_numeric(working, "s_psh_rate") + _optional_numeric(working, "r_psh_rate")).clip(lower=0.0)
    working["fragment_rate_total"] = (_optional_numeric(working, "s_fragment_rate") + _optional_numeric(working, "r_fragment_rate")).clip(lower=0.0)
    working["tcp_window_mean"] = ((_optional_numeric(working, "s_win_tcp") + _optional_numeric(working, "r_win_tcp")) * 0.5).clip(lower=0.0)
    working["ack_delay_mean"] = ((_optional_numeric(working, "s_ack_delay_avg") + _optional_numeric(working, "r_ack_delay_avg")) * 0.5).clip(lower=0.0)
    working["inter_packet_gap_mean"] = ((_optional_numeric(working, "s_inter_packet_avg") + _optional_numeric(working, "r_inter_packet_avg")) * 0.5).clip(lower=0.0)
    working["payload_mean"] = ((_optional_numeric(working, "s_payload_avg") + _optional_numeric(working, "r_payload_avg")) * 0.5).clip(lower=0.0)
    working["load_mean"] = ((_optional_numeric(working, "s_load") + _optional_numeric(working, "r_load")) * 0.5).clip(lower=0.0)
    availability_columns = [
        "has_ttl_metrics",
        "has_tcp_flag_metrics",
        "has_fragment_metrics",
        "has_window_metrics",
        "has_ack_delay_metrics",
        "has_inter_packet_metrics",
        "has_payload_metrics",
        "has_load_metrics",
    ]
    transport_present = pd.Series(np.zeros(len(working), dtype=float), index=working.index)
    for column in availability_columns:
        transport_present = pd.Series(
            np.maximum(
                transport_present.to_numpy(dtype=float, copy=False),
                _optional_numeric(working, column).clip(lower=0.0, upper=1.0).to_numpy(dtype=float, copy=False),
            ),
            index=working.index,
        )
    working["transport_metrics_present"] = transport_present.fillna(0.0)
    working["dns_flow"] = working["dst_port"].isin([53, 853]).astype(float)
    working["web_flow"] = working["dst_port"].isin([80, 443, 8000, 8080, 8443]).astype(float)
    hosts = _destination_host_series(working)
    working["private_destination"] = _is_private_destination(hosts).astype(float)
    working["multicast_destination"] = _is_multicast_destination(hosts).astype(float)
    intelligence = _destination_intelligence_columns(hosts, working)
    for column in intelligence.columns:
        working[column] = intelligence[column]
    return working


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


def _dominant_text_by_group(
    frame: pd.DataFrame,
    keys: list[str],
    column: str,
    default: str,
) -> pd.Series:
    if column not in frame.columns:
        group_index = frame.groupby(keys, sort=False, dropna=False).size().index
        return pd.Series(default, index=group_index, dtype="object")
    value_column = f"__{column}_value"
    working = frame[keys].copy()
    working[value_column] = frame[column].astype(str).replace({"": default}).fillna(default)
    counts = (
        working.groupby(keys + [value_column], sort=False, dropna=False)
        .size()
        .rename("__count")
        .reset_index()
        .sort_values(keys + ["__count"], ascending=[True] * len(keys) + [False], kind="mergesort")
        .drop_duplicates(keys, keep="first")
        .set_index(keys)[value_column]
    )
    return counts.astype(str)


def _normalized_group_entropy(counts: pd.DataFrame, keys: list[str], count_column: str) -> pd.Series:
    if counts.empty:
        return pd.Series(dtype=float)
    total = counts.groupby(keys, sort=False, dropna=False)[count_column].transform("sum")
    probabilities = counts[count_column].astype(float) / total.clip(lower=1)
    weighted = -(probabilities * np.log(probabilities.clip(lower=1e-12)))
    entropy = weighted.groupby([counts[key] for key in keys], sort=False).sum()
    unique_counts = counts.groupby(keys, sort=False, dropna=False).size()
    denominator = np.log(unique_counts.clip(lower=2).astype(float))
    return (entropy / denominator).fillna(0.0)


def _add_rolling_baseline_features(windows: pd.DataFrame) -> pd.DataFrame:
    if windows.empty:
        return windows
    ordered = windows.sort_values(["app_id", "window_end_ms" if "window_end_ms" in windows.columns else "window_bucket"], kind="mergesort").reset_index(drop=True)
    app_groups = ordered.groupby("app_id", sort=False, dropna=False)

    def _rolling_reference(series: pd.Series) -> pd.Series:
        shifted = series.shift(1)
        return shifted.rolling(3, min_periods=1).mean()

    rolling_flow_count = app_groups["flow_count"].transform(_rolling_reference)
    rolling_byte_rate = app_groups["byte_rate"].transform(_rolling_reference)
    rolling_destination_diversity = app_groups["destination_diversity"].transform(_rolling_reference)
    rolling_novelty = app_groups["novelty_score"].transform(_rolling_reference)
    ordered["flow_count_deviation"] = (
        (ordered["flow_count"] - rolling_flow_count).abs() / (rolling_flow_count.abs() + 1.0)
    ).fillna(0.0)
    ordered["byte_rate_deviation"] = (
        (ordered["byte_rate"] - rolling_byte_rate).abs() / (rolling_byte_rate.abs() + 1.0)
    ).fillna(0.0)
    ordered["destination_diversity_shift"] = (
        (ordered["destination_diversity"] - rolling_destination_diversity).abs()
    ).fillna(0.0)
    ordered["novelty_shift"] = (
        (ordered["novelty_score"] - rolling_novelty).abs()
    ).fillna(0.0)
    ordered["recent_flow_count_mean"] = rolling_flow_count.fillna(0.0)
    ordered["recent_byte_rate_mean"] = rolling_byte_rate.fillna(0.0)
    ordered["recent_novelty_mean"] = rolling_novelty.fillna(0.0)

    def _trend(series: pd.Series) -> pd.Series:
        previous = series.shift(3)
        return ((series - previous) / (previous.abs() + 1.0)).fillna(0.0)

    ordered["flow_count_trend"] = app_groups["flow_count"].transform(_trend).clip(lower=-10.0, upper=10.0)
    ordered["byte_rate_trend"] = app_groups["byte_rate"].transform(_trend).clip(lower=-10.0, upper=10.0)
    ordered["novelty_trend"] = app_groups["novelty_score"].transform(lambda s: (s - s.shift(3)).fillna(0.0)).clip(lower=-1.0, upper=1.0)
    ordered["destination_diversity_trend"] = app_groups["destination_diversity"].transform(lambda s: (s - s.shift(3)).fillna(0.0)).clip(lower=-1.0, upper=1.0)
    burst_flag = ((ordered["flow_count_deviation"] >= 0.40) | (ordered["byte_rate_deviation"] >= 0.40)).astype(float)
    ordered["consecutive_burst_windows"] = (
        burst_flag.groupby(ordered["app_id"], sort=False)
        .transform(lambda s: s.rolling(3, min_periods=1).sum())
        .fillna(0.0)
        .clip(upper=5.0)
    )
    ordered["low_volume_periodic_score"] = ordered["periodic_beacon_score"].where(ordered["byte_rate"] <= 128.0, 0.0).fillna(0.0)
    return ordered


def build_feature_windows(
    df: pd.DataFrame,
    window_seconds: int = 60,
    *,
    include_server_features: bool = True,
) -> pd.DataFrame:
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
    working = _prepare_android_expanded_flow_columns(working)

    working["total_bytes"] = working["bytes_out"] + working["bytes_in"]
    working["total_packets"] = (working["packets_out"] + working["packets_in"]).clip(lower=1.0)
    working["total_bytes_sq"] = working["total_bytes"] * working["total_bytes"]
    working["duration_ms_sq"] = working["duration_ms"] * working["duration_ms"]
    working["second_bucket"] = (working["timestamp_end"] // 1000).astype("int64")
    working["small_flow"] = (working["total_bytes"] <= 256.0).astype(float)
    working["high_port"] = (working["dst_port"] >= 1024).astype(float)

    keys = ["app_id", "window_bucket"]
    grouped = working.groupby(keys, sort=True, dropna=False)
    working["total_bytes_abs_deviation"] = (
        working["total_bytes"] - grouped["total_bytes"].transform("mean")
    ).abs()
    window_duration_seconds = max(1.0, float(window_seconds))
    windows = grouped.agg(
        flow_count=("timestamp_end", "size"),
        total_bytes_out=("bytes_out", "sum"),
        total_bytes_in=("bytes_in", "sum"),
        total_packets_out=("packets_out", "sum"),
        total_packets_in=("packets_in", "sum"),
        total_bytes=("total_bytes", "sum"),
        total_bytes_sq=("total_bytes_sq", "sum"),
        total_bytes_abs_deviation=("total_bytes_abs_deviation", "sum"),
        novelty_score=("dst_novelty", "mean"),
        duration_sum=("duration_ms", "sum"),
        duration_sq_sum=("duration_ms_sq", "sum"),
        mean_duration_ms=("duration_ms", "mean"),
        destination_unique=("destination_key", "nunique"),
        port_unique=("dst_port", "nunique"),
        protocol_unique=("protocol", "nunique"),
        small_flow_ratio=("small_flow", "mean"),
        high_port_ratio=("high_port", "mean"),
    )
    if windows.empty:
        return windows.reset_index()

    flow_count = windows["flow_count"].clip(lower=1)
    total_packets = windows["total_packets_out"] + windows["total_packets_in"]
    windows["mean_packet_size"] = windows["total_bytes"] / total_packets.clip(lower=1.0)
    windows["outbound_ratio"] = windows["total_bytes_out"] / (windows["total_bytes"] + 1.0)
    total_bytes_mean = windows["total_bytes"] / flow_count
    duration_mean = windows["duration_sum"] / flow_count
    windows["burstiness"] = ((windows["total_bytes_abs_deviation"] / flow_count) / total_bytes_mean.replace(0.0, np.nan)).clip(
        lower=0.0,
        upper=4.0,
    ).fillna(0.0)
    windows["duration_jitter"] = np.sqrt(
        ((windows["duration_sq_sum"] / flow_count) - (duration_mean * duration_mean)).clip(lower=0.0)
    )
    windows["connection_frequency_delta"] = np.log1p(windows["flow_count"] / window_duration_seconds)
    windows["bytes_per_flow"] = windows["total_bytes"] / flow_count
    windows["destination_diversity"] = windows["destination_unique"] / flow_count
    windows["activity_ratio"] = (windows["duration_sum"] / max(1.0, window_duration_seconds * 1000.0)).clip(upper=1.0)
    windows["byte_rate"] = windows["total_bytes"] / window_duration_seconds
    windows["packet_rate"] = total_packets / window_duration_seconds
    windows["port_diversity"] = windows["port_unique"] / flow_count
    windows["protocol_diversity"] = windows["protocol_unique"] / flow_count
    windows["packet_imbalance"] = (windows["total_packets_out"] - windows["total_packets_in"]).abs() / (total_packets + 1.0)
    windows["dns_flow_ratio"] = grouped["dns_flow"].mean()
    windows["web_flow_ratio"] = grouped["web_flow"].mean()
    windows["private_destination_ratio"] = grouped["private_destination"].mean()
    windows["multicast_destination_ratio"] = grouped["multicast_destination"].mean()
    windows["destination_risk_score"] = grouped["destination_risk"].mean()
    windows["lookalike_score"] = grouped["lookalike_score_flow"].mean()
    windows["suspicious_destination_ratio"] = grouped["suspicious_destination"].mean()
    windows["known_identity_ratio"] = grouped["known_identity"].mean()
    windows["mitre_technique_ratio"] = grouped["mitre_technique_flow"].mean()
    windows["threat_tag_ratio"] = grouped["threat_tag_flow"].mean()
    for column in (
        "hour_of_day",
        "day_of_week",
        "is_weekend",
        "data_quality_score",
        "ttl_gap",
        "ttl_metrics_present",
        "syn_rate_total",
        "rst_rate_total",
        "ack_rate_total",
        "fin_rate_total",
        "psh_rate_total",
        "fragment_rate_total",
        "tcp_window_mean",
        "ack_delay_mean",
        "inter_packet_gap_mean",
        "payload_mean",
        "load_mean",
        "transport_metrics_present",
    ):
        windows[column] = grouped[column].mean()

    sorted_working = working.sort_values(keys + ["timestamp_end"], kind="mergesort")
    group_ids = sorted_working.groupby(keys, sort=False, dropna=False).ngroup()
    deltas = sorted_working["timestamp_end"].diff() / 1000.0
    deltas[group_ids != group_ids.shift()] = np.nan
    delta_frame = pd.DataFrame(
        {
            "app_id": sorted_working["app_id"],
            "window_bucket": sorted_working["window_bucket"],
            "delta": deltas,
        }
    ).dropna(subset=["delta"])
    delta_frame["delta_sq"] = delta_frame["delta"] * delta_frame["delta"]
    beacon_stats = (
        delta_frame.groupby(keys, sort=False, dropna=False)
        .agg(delta_count=("delta", "size"), delta_sum=("delta", "sum"), delta_sq_sum=("delta_sq", "sum"))
    )
    beacon_stats["delta_mean"] = beacon_stats["delta_sum"] / beacon_stats["delta_count"].clip(lower=1)
    beacon_stats["delta_std"] = np.sqrt(
        ((beacon_stats["delta_sq_sum"] / beacon_stats["delta_count"].clip(lower=1)) - (beacon_stats["delta_mean"] ** 2)).clip(lower=0.0)
    )
    beacon_score = 1.0 - (beacon_stats["delta_std"] / beacon_stats["delta_mean"].replace(0.0, np.nan))
    beacon_score = beacon_score.where(beacon_stats["delta_count"] >= 3, 0.0).clip(lower=0.0, upper=1.0).fillna(0.0)
    windows["periodic_beacon_score"] = beacon_score.reindex(windows.index, fill_value=0.0)
    destination_counts = working.groupby(keys + ["destination_key"], sort=False, dropna=False).size().rename("count")
    windows["destination_concentration"] = (
        destination_counts.groupby(level=[0, 1], sort=False).max() / flow_count
    ).reindex(windows.index, fill_value=0.0)

    previous_destination = sorted_working.groupby(keys, sort=False, dropna=False)["destination_key"].shift()
    transition_frame = sorted_working[keys].copy()
    transition_frame["previous"] = previous_destination
    transition_frame["current"] = sorted_working["destination_key"]
    transition_frame = transition_frame.dropna(subset=["previous"])
    transition_frame["is_switch"] = (transition_frame["previous"] != transition_frame["current"]).astype(float)
    switch_counts = transition_frame.groupby(keys, sort=False, dropna=False)["is_switch"].sum()
    windows["destination_transition_rate"] = (
        switch_counts / (flow_count - 1).clip(lower=1)
    ).reindex(windows.index, fill_value=0.0)

    if include_server_features:
        transition_frame["transition"] = transition_frame["previous"].astype(str) + "->" + transition_frame["current"].astype(str)
        transition_counts = (
            transition_frame.groupby(keys + ["transition"], sort=False, dropna=False)
            .size()
            .rename("count")
            .reset_index()
        )
        windows["destination_transition_entropy"] = _normalized_group_entropy(
            transition_counts,
            keys,
            "count",
        ).reindex(windows.index, fill_value=0.0)

        protocol_port = working[keys].copy()
        protocol_port["profile"] = working["protocol"].astype(str) + ":" + working["dst_port"].astype(str)
        profile_unique = protocol_port.groupby(keys, sort=False, dropna=False)["profile"].nunique()
        windows["protocol_port_profile_diversity"] = (profile_unique / flow_count).reindex(windows.index, fill_value=0.0)
        flow_q75 = working.groupby(keys, sort=False, dropna=False)["total_bytes"].quantile(0.75)
        flow_q25 = working.groupby(keys, sort=False, dropna=False)["total_bytes"].quantile(0.25)
        windows["flow_size_iqr"] = (flow_q75 - flow_q25).reindex(windows.index, fill_value=0.0)

    for column, default in {
        "dataset_source": "unknown_source",
        "dataset_profile": "unknown_profile",
        "dataset_variant": "unknown_variant",
        "environment_id": "unknown_environment",
        "session_id": "unknown_session",
    }.items():
        windows[column] = _dominant_text_by_group(working, keys, column, default).reindex(windows.index, fill_value=default)

    label_cols = [col for col in ["label", "is_anomaly"] if col in working.columns]
    if label_cols:
        labels = pd.to_numeric(working[label_cols[0]], errors="coerce").fillna(0).astype(int)
        label_frame = working[keys].copy()
        label_frame["label"] = labels
        windows["label"] = label_frame.groupby(keys, sort=False, dropna=False)["label"].max().reindex(windows.index, fill_value=0).astype(int)

    windows = windows.reset_index()
    windows["app_id"] = windows["app_id"].astype(str)
    windows["app_family"] = windows["app_id"].map(derive_app_family)
    windows["window_bucket"] = windows["window_bucket"].astype("int64")
    windows = windows.drop(
        columns=[
            "total_packets_out",
            "total_packets_in",
            "total_bytes",
            "total_bytes_sq",
            "total_bytes_abs_deviation",
            "duration_sum",
            "duration_sq_sum",
            "destination_unique",
            "port_unique",
            "protocol_unique",
        ],
        errors="ignore",
    )
    if windows.empty:
        return windows
    return _add_rolling_baseline_features(windows)


def build_android_feature_windows(df: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    return build_feature_windows(df, window_seconds=window_seconds, include_server_features=False)


def _adaptive_window_seconds(app_id: str, recent_60_count: int) -> int:
    family = derive_app_family(str(app_id))
    if family in {"service", "system", "background"} or recent_60_count < 10:
        return 300
    if recent_60_count > 100:
        return 30
    return 60


class _SlidingWindowState:
    def __init__(self, horizon_seconds: int, row_limit: int = 240) -> None:
        self.horizon_ms = int(horizon_seconds * 1000)
        self.row_limit = int(row_limit)
        self.rows: deque[dict[str, object]] = deque()
        self.destination_counts: Counter[str] = Counter()
        self.port_counts: Counter[int] = Counter()
        self.protocol_counts: Counter[str] = Counter()
        self.label_counts: Counter[int] = Counter()
        self.flow_bytes_sorted: list[float] = []
        self.last_destination_key: str | None = None
        self.destination_switch_count = 0
        self.bytes_out_sum = 0.0
        self.bytes_in_sum = 0.0
        self.packets_out_sum = 0.0
        self.packets_in_sum = 0.0
        self.duration_sum = 0.0
        self.duration_sq_sum = 0.0
        self.novelty_sum = 0.0
        self.flow_bytes_sum = 0.0
        self.small_flow_count = 0
        self.high_port_count = 0
        self.dns_flow_sum = 0.0
        self.web_flow_sum = 0.0
        self.private_destination_sum = 0.0
        self.multicast_destination_sum = 0.0
        self.expanded_sums = {
            "hour_of_day": 0.0,
            "day_of_week": 0.0,
            "is_weekend": 0.0,
            "data_quality_score": 0.0,
            "ttl_gap": 0.0,
            "ttl_metrics_present": 0.0,
            "syn_rate_total": 0.0,
            "rst_rate_total": 0.0,
            "ack_rate_total": 0.0,
            "fin_rate_total": 0.0,
            "psh_rate_total": 0.0,
            "fragment_rate_total": 0.0,
            "tcp_window_mean": 0.0,
            "ack_delay_mean": 0.0,
            "inter_packet_gap_mean": 0.0,
            "payload_mean": 0.0,
            "load_mean": 0.0,
            "transport_metrics_present": 0.0,
            "destination_risk": 0.0,
            "lookalike_score_flow": 0.0,
            "suspicious_destination": 0.0,
            "known_identity": 0.0,
            "mitre_technique_flow": 0.0,
            "threat_tag_flow": 0.0,
        }

    def append(self, row: dict[str, object]) -> None:
        self.rows.append(row)
        destination_key = str(row["destination_key"])
        if self.last_destination_key is not None and self.last_destination_key != destination_key:
            self.destination_switch_count += 1
        self.last_destination_key = destination_key
        self.destination_counts[destination_key] += 1
        self.port_counts[int(row["dst_port"])] += 1
        self.protocol_counts[str(row["protocol"])] += 1
        label = int(row.get("__label", 0))
        self.label_counts[label] += 1
        bytes_out = float(row["bytes_out"])
        bytes_in = float(row["bytes_in"])
        packets_out = float(row["packets_out"])
        packets_in = float(row["packets_in"])
        duration_ms = float(row["duration_ms"])
        novelty = float(row["dst_novelty"])
        flow_bytes = bytes_out + bytes_in
        self.bytes_out_sum += bytes_out
        self.bytes_in_sum += bytes_in
        self.packets_out_sum += packets_out
        self.packets_in_sum += packets_in
        self.duration_sum += duration_ms
        self.duration_sq_sum += duration_ms * duration_ms
        self.novelty_sum += novelty
        self.flow_bytes_sum += flow_bytes
        self.small_flow_count += 1 if flow_bytes <= 256.0 else 0
        self.high_port_count += 1 if int(row["dst_port"]) >= 1024 else 0
        self.dns_flow_sum += float(row["dns_flow"])
        self.web_flow_sum += float(row["web_flow"])
        self.private_destination_sum += float(row["private_destination"])
        self.multicast_destination_sum += float(row["multicast_destination"])
        for column in self.expanded_sums:
            self.expanded_sums[column] += float(row[column])
        insort(self.flow_bytes_sorted, flow_bytes)
        self._expire(int(row["timestamp_end"]))

    def has_positive_label(self) -> bool:
        return any(key > 0 and count > 0 for key, count in self.label_counts.items())

    def _expire(self, now_ms: int) -> None:
        cutoff = now_ms - self.horizon_ms
        while self.rows and (int(self.rows[0]["timestamp_end"]) < cutoff or len(self.rows) > self.row_limit):
            removed = self.rows.popleft()
            destination = str(removed["destination_key"])
            port = int(removed["dst_port"])
            protocol = str(removed["protocol"])
            label = int(removed.get("__label", 0))
            self.destination_counts[destination] -= 1
            self.port_counts[port] -= 1
            self.protocol_counts[protocol] -= 1
            self.label_counts[label] -= 1
            if self.destination_counts[destination] <= 0:
                del self.destination_counts[destination]
            if self.port_counts[port] <= 0:
                del self.port_counts[port]
            if self.protocol_counts[protocol] <= 0:
                del self.protocol_counts[protocol]
            if self.label_counts[label] <= 0:
                del self.label_counts[label]
            bytes_out = float(removed["bytes_out"])
            bytes_in = float(removed["bytes_in"])
            packets_out = float(removed["packets_out"])
            packets_in = float(removed["packets_in"])
            duration_ms = float(removed["duration_ms"])
            novelty = float(removed["dst_novelty"])
            flow_bytes = bytes_out + bytes_in
            self.bytes_out_sum -= bytes_out
            self.bytes_in_sum -= bytes_in
            self.packets_out_sum -= packets_out
            self.packets_in_sum -= packets_in
            self.duration_sum -= duration_ms
            self.duration_sq_sum -= duration_ms * duration_ms
            self.novelty_sum -= novelty
            self.flow_bytes_sum -= flow_bytes
            self.small_flow_count -= 1 if flow_bytes <= 256.0 else 0
            self.high_port_count -= 1 if port >= 1024 else 0
            self.dns_flow_sum -= float(removed["dns_flow"])
            self.web_flow_sum -= float(removed["web_flow"])
            self.private_destination_sum -= float(removed["private_destination"])
            self.multicast_destination_sum -= float(removed["multicast_destination"])
            for column in self.expanded_sums:
                self.expanded_sums[column] -= float(removed[column])
            sorted_index = bisect_right(self.flow_bytes_sorted, flow_bytes) - 1
            if sorted_index >= 0:
                self.flow_bytes_sorted.pop(sorted_index)
            self.last_destination_key = str(self.rows[-1]["destination_key"]) if self.rows else None
            self.destination_switch_count = 0
            previous_destination: str | None = None
            for remaining in self.rows:
                destination_key = str(remaining["destination_key"])
                if previous_destination is not None and previous_destination != destination_key:
                    self.destination_switch_count += 1
                previous_destination = destination_key

    def build_row(
        self,
        app_id: str,
        window_end_ms: int,
        label_column: str | None,
        *,
        focal_label: int = 0,
    ) -> dict[str, float | int | str]:
        flow_count = max(1, len(self.rows))
        window_start_ms = int(window_end_ms) - self.horizon_ms
        duration_seconds = max(1.0, self.horizon_ms / 1000.0)
        total_bytes = float(self.bytes_out_sum + self.bytes_in_sum)
        total_packets_out = float(self.packets_out_sum)
        total_packets_in = float(self.packets_in_sum)
        total_packets = max(1.0, total_packets_out + total_packets_in)
        mean_flow_bytes = self.flow_bytes_sum / flow_count
        if mean_flow_bytes > 0.0 and self.flow_bytes_sorted:
            split = bisect_right(self.flow_bytes_sorted, mean_flow_bytes)
            lower_sum = float(sum(self.flow_bytes_sorted[:split]))
            upper_sum = self.flow_bytes_sum - lower_sum
            lower_delta = (mean_flow_bytes * split) - lower_sum
            upper_delta = upper_sum - (mean_flow_bytes * (flow_count - split))
            burstiness = ((lower_delta + upper_delta) / flow_count) / mean_flow_bytes
        else:
            burstiness = 0.0
        mean_duration_ms = self.duration_sum / flow_count
        duration_variance = max(0.0, (self.duration_sq_sum / flow_count) - (mean_duration_ms * mean_duration_ms))
        window_positive = 1 if self.has_positive_label() else 0
        return {
            "app_id": str(app_id),
            "app_family": derive_app_family(str(app_id)),
            "window_bucket": int(window_end_ms // 1000),
            "window_start_ms": int(window_start_ms),
            "window_end_ms": int(window_end_ms),
            "adaptive_window_seconds": int(self.horizon_ms // 1000),
            "flow_count": int(flow_count),
            "total_bytes_out": float(self.bytes_out_sum),
            "total_bytes_in": float(self.bytes_in_sum),
            "mean_packet_size": float(total_bytes / total_packets),
            "outbound_ratio": float(self.bytes_out_sum / (total_bytes + 1.0)),
            "burstiness": float(np.clip(burstiness, 0.0, 4.0)),
            "novelty_score": float(self.novelty_sum / flow_count) if flow_count else 0.0,
            "connection_frequency_delta": float(np.log1p(flow_count / duration_seconds)),
            "bytes_per_flow": float(total_bytes / flow_count),
            "destination_diversity": float(min(1.0, len(self.destination_counts) / flow_count)),
            "activity_ratio": float(np.clip(self.duration_sum / max(1.0, self.horizon_ms), 0.0, 1.0)),
            "periodic_beacon_score": _periodic_beacon_score_from_rows(self.rows),
            "byte_rate": float(total_bytes / duration_seconds),
            "packet_rate": float(total_packets / duration_seconds),
            "mean_duration_ms": float(mean_duration_ms) if flow_count else 0.0,
            "duration_jitter": float(np.sqrt(duration_variance)) if flow_count > 1 else 0.0,
            "port_diversity": float(min(1.0, len(self.port_counts) / flow_count)),
            "protocol_diversity": float(min(1.0, len(self.protocol_counts) / flow_count)),
            "packet_imbalance": float(abs(total_packets_out - total_packets_in) / (total_packets + 1.0)),
            "small_flow_ratio": float(self.small_flow_count / flow_count),
            "high_port_ratio": float(self.high_port_count / flow_count),
            "destination_concentration": float(max(self.destination_counts.values(), default=0) / flow_count),
            "destination_transition_rate": float((self.destination_switch_count / max(1, flow_count - 1))),
            "dns_flow_ratio": float(self.dns_flow_sum / flow_count),
            "web_flow_ratio": float(self.web_flow_sum / flow_count),
            "private_destination_ratio": float(self.private_destination_sum / flow_count),
            "multicast_destination_ratio": float(self.multicast_destination_sum / flow_count),
            **{column: float(total / flow_count) for column, total in self.expanded_sums.items()},
            "destination_risk_score": float(self.expanded_sums["destination_risk"] / flow_count),
            "lookalike_score": float(self.expanded_sums["lookalike_score_flow"] / flow_count),
            "suspicious_destination_ratio": float(self.expanded_sums["suspicious_destination"] / flow_count),
            "known_identity_ratio": float(self.expanded_sums["known_identity"] / flow_count),
            "mitre_technique_ratio": float(self.expanded_sums["mitre_technique_flow"] / flow_count),
            "threat_tag_ratio": float(self.expanded_sums["threat_tag_flow"] / flow_count),
            "flow_count_deviation": 0.0,
            "byte_rate_deviation": 0.0,
            "destination_diversity_shift": 0.0,
            "novelty_shift": 0.0,
            "dataset_source": str(self.rows[-1].get("dataset_source", "unknown_source")),
            "dataset_profile": str(self.rows[-1].get("dataset_profile", "unknown_profile")),
            "dataset_variant": str(self.rows[-1].get("dataset_variant", "unknown_variant")),
            "environment_id": str(self.rows[-1].get("environment_id", "unknown_environment")),
            "session_id": str(self.rows[-1].get("session_id", "unknown_session")),
            "label": int(focal_label),
            "window_contains_positive": int(window_positive),
        }


def build_android_sliding_feature_windows(
    df: pd.DataFrame,
    window_seconds: int = 60,
    *,
    adaptive: bool = True,
    row_limit: int = 240,
    max_windows: int = 0,
    label_strategy: str = "focal",
    emit_all_horizons: bool = False,
) -> pd.DataFrame:
    validate_flow_df(df)
    working = df.copy()
    working["timestamp_end"] = pd.to_numeric(working["timestamp_end"], errors="coerce")
    working = working.dropna(subset=["timestamp_end"]).copy()
    working["timestamp_end"] = working["timestamp_end"].astype("int64")
    for column in ("bytes_out", "bytes_in", "packets_out", "packets_in", "duration_ms", "dst_novelty", "dst_port"):
        if column == "duration_ms":
            working[column] = _numeric_series(working, column).clip(lower=0.0)
        elif column == "dst_novelty":
            working[column] = _numeric_series(working, column).clip(lower=0.0, upper=1.0)
        elif column == "dst_port":
            working[column] = _numeric_series(working, column).fillna(0).astype("int64")
        else:
            working[column] = _numeric_series(working, column)
    working["protocol"] = _text_series(working, "protocol", "UNKNOWN").str.upper().replace({"": "UNKNOWN"})
    working["destination_key"] = _text_series(working, "destination_key", "unknown:0")
    label_column = "label" if "label" in working.columns else ("is_anomaly" if "is_anomaly" in working.columns else None)
    if label_column:
        working[label_column] = pd.to_numeric(working[label_column], errors="coerce").fillna(0).astype(int)
    for column, default in {
        "dataset_source": "unknown_source",
        "dataset_profile": "unknown_profile",
        "dataset_variant": "unknown_variant",
        "environment_id": "unknown_environment",
        "session_id": "unknown_session",
    }.items():
        if column not in working.columns:
            working[column] = default
        working[column] = working[column].fillna(default).astype(str)

    row_columns = [
        "timestamp_end",
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
        "duration_ms",
        "dst_novelty",
        "dst_port",
        "protocol",
        "destination_key",
        "dataset_source",
        "dataset_profile",
        "dataset_variant",
        "environment_id",
        "session_id",
    ]
    raw_expanded_columns = [
        "dst_ip",
        "destination_ip",
        "sttl",
        "rttl",
        "has_ttl_metrics",
        "s_syn_rate",
        "r_syn_rate",
        "s_rst_rate",
        "r_rst_rate",
        "s_ack_rate",
        "r_ack_rate",
        "s_fin_rate",
        "r_fin_rate",
        "s_psh_rate",
        "r_psh_rate",
        "s_fragment_rate",
        "r_fragment_rate",
        "s_win_tcp",
        "r_win_tcp",
        "s_ack_delay_avg",
        "r_ack_delay_avg",
        "s_inter_packet_avg",
        "r_inter_packet_avg",
        "s_payload_avg",
        "r_payload_avg",
        "s_load",
        "r_load",
        "has_tcp_flag_metrics",
        "has_fragment_metrics",
        "has_window_metrics",
        "has_ack_delay_metrics",
        "has_inter_packet_metrics",
        "has_payload_metrics",
        "has_load_metrics",
    ]
    row_columns.extend([column for column in raw_expanded_columns if column in working.columns])
    if label_column:
        row_columns.append(label_column)
    slim_columns = ["app_id", *row_columns]
    working = working.loc[:, list(dict.fromkeys(slim_columns))].copy()

    horizons = sorted({30, int(window_seconds), 300} if adaptive else {int(window_seconds)})
    rows: list[dict[str, float | int | str]] = []
    max_windows = int(max_windows or 0)
    emit_stride = max(1, int(np.ceil(len(working) / max_windows))) if max_windows > 0 else 1
    processed_rows = 0
    for app_id, group in working.sort_values(["app_id", "timestamp_end"], kind="mergesort").groupby("app_id", sort=False):
        states = {horizon: _SlidingWindowState(horizon, row_limit=row_limit) for horizon in horizons}
        for values in group[row_columns].itertuples(index=False, name=None):
            processed_rows += 1
            row = dict(zip(row_columns, values, strict=False))
            _add_android_expanded_row_values(row)
            row["__label"] = int(row[label_column]) if label_column else 0
            for state in states.values():
                state.append(row)
            horizon = _adaptive_window_seconds(str(app_id), len(states.get(60, next(iter(states.values()))).rows)) if adaptive else int(window_seconds)
            current_label = int(row["__label"])
            selected_state = states[horizon]
            positive_for_emit = current_label > 0 if label_strategy == "focal" else selected_state.has_positive_label()
            should_emit = max_windows <= 0 or processed_rows % emit_stride == 0 or positive_for_emit
            if should_emit:
                horizons_to_emit = horizons if emit_all_horizons else [horizon]
                for emitted_horizon in horizons_to_emit:
                    state = states[emitted_horizon]
                    focal_label = current_label if label_strategy == "focal" else (1 if state.has_positive_label() else 0)
                    rows.append(
                        state.build_row(
                            str(app_id),
                            int(row["timestamp_end"]),
                            label_column,
                            focal_label=focal_label,
                        )
                    )
    windows = pd.DataFrame(rows)
    if windows.empty:
        return windows
    return _add_rolling_baseline_features(windows)


def feature_matrix(feature_windows: pd.DataFrame, feature_columns: list[str] | None = None) -> pd.DataFrame:
    columns = feature_columns or FEATURE_COLUMNS
    missing = [column for column in columns if column not in feature_windows.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    return feature_windows[columns].fillna(0.0)
