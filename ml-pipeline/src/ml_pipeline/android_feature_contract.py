from __future__ import annotations

from pathlib import Path
import re


ANDROID_FEATURE_COLUMNS = [
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
    "destination_concentration",
    "destination_transition_rate",
    "dns_flow_ratio",
    "web_flow_ratio",
    "private_destination_ratio",
    "multicast_destination_ratio",
    "flow_count_deviation",
    "byte_rate_deviation",
    "destination_diversity_shift",
    "novelty_shift",
    "recent_flow_count_mean",
    "recent_byte_rate_mean",
    "recent_novelty_mean",
    "flow_count_trend",
    "byte_rate_trend",
    "novelty_trend",
    "destination_diversity_trend",
    "consecutive_burst_windows",
    "low_volume_periodic_score",
    "destination_risk_score",
    "lookalike_score",
    "suspicious_destination_ratio",
    "known_identity_ratio",
    "mitre_technique_ratio",
    "threat_tag_ratio",
]


def validate_android_feature_order(feature_order: list[str]) -> None:
    if list(feature_order) != ANDROID_FEATURE_COLUMNS:
        raise ValueError(
            "Android feature contract mismatch. "
            f"Expected {ANDROID_FEATURE_COLUMNS}, got {list(feature_order)}"
        )


def read_android_runtime_feature_order(repo_root: Path) -> list[str]:
    feature_window = (
        repo_root
        / "android-app"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "manta"
        / "app"
        / "core"
        / "model"
        / "FeatureWindow.kt"
    )
    text = feature_window.read_text(encoding="utf-8")
    match = re.search(r"portableFeatureOrder\s*=\s*listOf\((.*?)\)", text, flags=re.S)
    if not match:
        raise ValueError(f"Could not find portableFeatureOrder in {feature_window}")
    return re.findall(r'"([^"]+)"', match.group(1))


def validate_against_android_runtime(repo_root: Path) -> None:
    runtime_order = read_android_runtime_feature_order(repo_root)
    if runtime_order != ANDROID_FEATURE_COLUMNS:
        raise ValueError(
            "Python Android feature contract does not match runtime FeatureWindow.portableFeatureOrder. "
            f"Runtime={runtime_order}; Python={ANDROID_FEATURE_COLUMNS}"
        )
