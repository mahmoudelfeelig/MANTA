from __future__ import annotations

import re
from pathlib import Path

import pandas as pd


PROFILE_TO_SOURCE = {
    "generic_flow": "generic_flow",
    "cicflowmeter": "cicandmal2017_android",
    "westermo": "westermo",
    "sdncampus": "sdncampus_flow_statistics",
    "parrot": "parrot2025_mitmproxy",
    "android_spyware": "android_spyware_mendeley",
    "android_mischief": "android_mischief_rat_traffic",
    "itc_net_blend": "itc_net_blend60_scenario_e",
    "android_apt_behavior": "android_apt_behavior_dataset",
}

PLACEHOLDER_DATASET_SOURCE = "unknown_source"
PLACEHOLDER_DATASET_PROFILE = "unknown_profile"
PLACEHOLDER_DATASET_VARIANT = "unknown_variant"
PLACEHOLDER_ENVIRONMENT = "unknown_environment"
PLACEHOLDER_SESSION = "unknown_session"

_LEGACY_PROFILE_HINTS: tuple[tuple[str, str], ...] = (
    ("sdncampus", "sdncampus"),
    ("westermo", "westermo"),
    ("android_spyware", "android_spyware"),
    ("android-spyware", "android_spyware"),
    ("android_mischief", "android_mischief"),
    ("android-mischief", "android_mischief"),
    ("itc_net_blend", "itc_net_blend"),
    ("itc-net-blend", "itc_net_blend"),
    ("cicandmal2017", "cicflowmeter"),
    ("pcap_iscx", "cicflowmeter"),
    ("parrot", "parrot"),
)

HARD_BENIGN_SOURCES = {
    "parrot2025_mitmproxy",
    "sdncampus_flow_statistics",
    "itc_net_blend60_scenario_e",
}

HARD_BENIGN_FAMILIES = {
    "browser",
    "telemetry",
    "system",
    "background",
}


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_") or "unknown"


def infer_dataset_source(profile: str, input_path: Path) -> str:
    stem = normalize_token(input_path.stem)
    if profile == "android_spyware":
        return "android_spyware_mendeley"
    if profile == "android_mischief":
        return "android_mischief_rat_traffic"
    if profile == "itc_net_blend":
        return "itc_net_blend60_scenario_e"
    if profile == "android_apt_behavior":
        return "android_apt_behavior_dataset"
    return PROFILE_TO_SOURCE.get(profile, stem)


def infer_dataset_profile_from_path(input_path: Path) -> str:
    normalized_path = normalize_token(str(input_path))
    for needle, profile in _LEGACY_PROFILE_HINTS:
        if needle in normalized_path:
            return profile
    return "generic_flow"


def infer_dataset_variant(input_path: Path) -> str:
    return normalize_token(input_path.stem)


def infer_environment_id(input_path: Path, profile: str | None = None) -> str:
    active_profile = profile or infer_dataset_profile_from_path(input_path)
    stem = normalize_token(input_path.stem)
    parent = normalize_token(input_path.parent.name if input_path.parent.name else input_path.stem)
    if active_profile == "westermo":
        return stem
    if active_profile == "sdncampus":
        return "sdncampus"
    if active_profile == "android_spyware":
        return "android_spyware_lab"
    if active_profile == "android_mischief":
        return "android_mischief_lab"
    if active_profile == "itc_net_blend":
        return "itc_net_blend60_scenario_e"
    if active_profile == "parrot":
        return "parrot2025_mitmproxy"
    if active_profile == "cicflowmeter":
        return parent if parent not in {"real", "data"} else "cicandmal2017"
    return parent if parent not in {"real", "data"} else stem


def infer_session_id(input_path: Path, profile: str | None = None) -> str:
    active_profile = profile or infer_dataset_profile_from_path(input_path)
    stem = normalize_token(input_path.stem)
    if active_profile == "sdncampus":
        return stem
    if active_profile == "westermo":
        return stem
    if active_profile in {"android_spyware", "android_mischief", "itc_net_blend", "parrot", "cicflowmeter"}:
        return stem
    return stem


def recover_legacy_flow_metadata(frame: pd.DataFrame, input_path: Path) -> pd.DataFrame:
    recovered = frame.copy()
    profile = infer_dataset_profile_from_path(input_path)
    inferred = {
        "dataset_source": infer_dataset_source(profile, input_path),
        "dataset_profile": profile,
        "dataset_variant": infer_dataset_variant(input_path),
        "environment_id": infer_environment_id(input_path, profile=profile),
        "session_id": infer_session_id(input_path, profile=profile),
    }
    placeholders = {
        "dataset_source": {PLACEHOLDER_DATASET_SOURCE, "", "nan", "none"},
        "dataset_profile": {PLACEHOLDER_DATASET_PROFILE, "", "nan", "none"},
        "dataset_variant": {PLACEHOLDER_DATASET_VARIANT, "", "nan", "none"},
        "environment_id": {PLACEHOLDER_ENVIRONMENT, "", "nan", "none"},
        "session_id": {PLACEHOLDER_SESSION, "", "nan", "none"},
    }
    for column, fallback in inferred.items():
        if column not in recovered.columns:
            recovered[column] = fallback
            continue
        series = recovered[column]
        normalized = series.astype(str).str.strip().str.lower()
        mask = series.isna() | normalized.isin(placeholders[column])
        if mask.any():
            recovered.loc[mask, column] = fallback
        recovered[column] = recovered[column].fillna(fallback).astype(str)
    if "app_family" not in recovered.columns:
        app_ids = recovered["app_id"].astype(str) if "app_id" in recovered.columns else pd.Series(["unknown"] * len(recovered), index=recovered.index)
        recovered["app_family"] = app_ids.map(derive_app_family)
    else:
        normalized = recovered["app_family"].astype(str).str.strip().str.lower()
        mask = recovered["app_family"].isna() | normalized.isin({"", "nan", "none", "other_app", "unknown"})
        if "app_id" in recovered.columns and mask.any():
            recovered.loc[mask, "app_family"] = recovered.loc[mask, "app_id"].astype(str).map(derive_app_family)
        recovered["app_family"] = recovered["app_family"].fillna("other_app").astype(str)
    return recovered


def derive_app_family(app_id: str) -> str:
    normalized = normalize_token(app_id)
    if normalized.startswith("service_"):
        return "service"
    if normalized.startswith("uid_"):
        return "system"
    if any(token in normalized for token in ("chrome", "firefox", "browser", "opera", "edge", "safari", "duckduckgo", "brave")):
        return "browser"
    if any(token in normalized for token in ("analytics", "telemetry", "doubleclick", "googleads", "scorecardresearch", "tracking")):
        return "telemetry"
    if any(token in normalized for token in ("vpn", "ssh", "rdp", "teamviewer", "anydesk", "openvpn", "ipsec", "l2tp")):
        return "remote_access"
    if any(token in normalized for token in ("gmail", "outlook", "telegram", "whatsapp", "fbmessenger", "facebook", "instagram", "snapchat", "twitter", "tiktok", "spotify", "netflix", "youtube")):
        return "consumer_app"
    if any(token in normalized for token in ("android", "systemui", "gms", "play_services", "packageinstaller")):
        return "system"
    if any(token in normalized for token in ("background", "daemon", "worker", "sensor", "watersensor", "temp_humidity")):
        return "background"
    if any(token in normalized for token in ("spy", "rat", "mal", "phish", "attack", "anomaly", "bot")):
        return "malware"
    return "other_app"


def add_flow_metadata(frame: pd.DataFrame, *, dataset_source: str, dataset_profile: str, dataset_variant: str, environment_id: str, session_id: str) -> pd.DataFrame:
    enriched = frame.copy()
    enriched["dataset_source"] = dataset_source
    enriched["dataset_profile"] = dataset_profile
    enriched["dataset_variant"] = dataset_variant
    enriched["environment_id"] = environment_id
    enriched["session_id"] = session_id
    app_ids = enriched["app_id"].astype(str) if "app_id" in enriched.columns else pd.Series(["unknown"] * len(enriched), index=enriched.index)
    enriched["app_family"] = app_ids.map(derive_app_family)
    return enriched


def hard_example_weight(label: int, dataset_source: str, app_family: str) -> float:
    weight = 1.0
    if int(label) == 0:
        if dataset_source in HARD_BENIGN_SOURCES:
            weight += 1.25
        if app_family in HARD_BENIGN_FAMILIES:
            weight += 0.65
    else:
        weight += 0.15
        if dataset_source == "cicandmal2017_android":
            weight += 0.15
        if app_family == "service":
            weight += 0.30
        if app_family == "malware":
            weight += 0.15
    return float(weight)


def compute_source_balance_weights(source_series: pd.Series) -> dict[str, float]:
    normalized = source_series.astype(str).fillna("unknown_source").replace({"": "unknown_source"})
    counts = normalized.value_counts()
    if counts.empty:
        return {}
    median_count = float(counts.median())
    weights: dict[str, float] = {}
    for source, count in counts.items():
        if count <= 0:
            weights[str(source)] = 1.0
            continue
        ratio = max(1e-6, median_count / float(count))
        weights[str(source)] = float(min(3.0, max(0.65, ratio ** 0.5)))
    return weights
