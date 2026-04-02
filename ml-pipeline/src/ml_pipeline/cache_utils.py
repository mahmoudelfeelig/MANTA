from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import joblib
import numpy as np
import pandas as pd

from .dataset_metadata import derive_app_family


CACHE_SCHEMA_VERSION = "manta-cache-v3"


@dataclass(frozen=True)
class FastModeConfig:
    enabled: bool = False
    max_total_windows: int = 0
    max_benign_windows: int = 0
    random_seed: int = 42

    @classmethod
    def from_env(cls) -> "FastModeConfig":
        enabled = os.getenv("MANTA_FAST_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
        max_total = int(os.getenv("MANTA_MAX_TOTAL_WINDOWS", "0") or 0)
        max_benign = int(os.getenv("MANTA_MAX_BENIGN_WINDOWS", "0") or 0)
        random_seed = int(os.getenv("MANTA_FAST_RANDOM_SEED", "42") or 42)
        return cls(enabled=enabled, max_total_windows=max_total, max_benign_windows=max_benign, random_seed=random_seed)

    def suffix(self) -> str:
        if not self.enabled:
            return "full"
        return f"fast-total{self.max_total_windows}-benign{self.max_benign_windows}-seed{self.random_seed}"


def _file_fingerprint(path: str | Path) -> str:
    file_path = Path(path).expanduser().resolve()
    stat = file_path.stat()
    payload = f"{CACHE_SCHEMA_VERSION}|{file_path}|{stat.st_size}|{stat.st_mtime_ns}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def resolve_cache_root(input_path: str | Path, explicit_cache_dir: str | Path | None = None) -> Path:
    if explicit_cache_dir:
        root = Path(explicit_cache_dir).expanduser().resolve()
    else:
        env_dir = os.getenv("MANTA_CACHE_DIR", "").strip()
        if env_dir:
            root = Path(env_dir).expanduser().resolve()
        else:
            root = Path(input_path).expanduser().resolve().parent / ".manta-cache"
    root.mkdir(parents=True, exist_ok=True)
    return root


def cache_namespace_dir(input_path: str | Path, explicit_cache_dir: str | Path | None = None) -> Path:
    input_file = Path(input_path).expanduser().resolve()
    cache_root = resolve_cache_root(input_file, explicit_cache_dir=explicit_cache_dir)
    namespace = f"{input_file.stem}-{_file_fingerprint(input_file)}"
    target = cache_root / namespace
    target.mkdir(parents=True, exist_ok=True)
    return target


def _cache_path(input_path: str | Path, name: str, *, explicit_cache_dir: str | Path | None = None, suffix: str = ".joblib") -> Path:
    return cache_namespace_dir(input_path, explicit_cache_dir=explicit_cache_dir) / f"{name}{suffix}"


def _load_or_build_joblib(
    path: Path,
    builder: Callable[[], object],
    metadata: dict[str, object] | None = None,
    validator: Callable[[object], bool] | None = None,
) -> object:
    if path.exists():
        print(f"[cache] hit {path.name}", flush=True)
        cached_value = joblib.load(path)
        if validator is None:
            return cached_value
        try:
            is_valid = bool(validator(cached_value))
        except Exception:
            is_valid = False
        if is_valid:
            return cached_value
        print(f"[cache] stale {path.name}; rebuilding", flush=True)
    print(f"[cache] miss {path.name}", flush=True)
    value = builder()
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(value, path, compress=3)
    if metadata is not None:
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return value


def _sample_by_source(frame: pd.DataFrame, limit: int, random_seed: int) -> pd.DataFrame:
    if limit <= 0 or len(frame) <= limit:
        return frame.reset_index(drop=True)
    rng = np.random.default_rng(random_seed)
    if "dataset_source" not in frame.columns:
        chosen = rng.choice(frame.index.to_numpy(dtype=int), size=limit, replace=False)
        return frame.loc[np.sort(chosen)].reset_index(drop=True)
    groups = frame.groupby(frame["dataset_source"].astype(str), sort=False, dropna=False)
    selected_indices: list[int] = []
    total_rows = max(1, len(frame))
    remaining = limit
    group_items = list(groups)
    for index, (_source, group) in enumerate(group_items, start=1):
        if remaining <= 0:
            break
        proportional = max(1, int(round((len(group) / total_rows) * limit)))
        if index == len(group_items):
            take = min(len(group), remaining)
        else:
            take = min(len(group), proportional, remaining)
        if take >= len(group):
            selected_indices.extend(group.index.to_list())
        else:
            chosen = rng.choice(group.index.to_numpy(dtype=int), size=take, replace=False)
            selected_indices.extend(chosen.tolist())
        remaining = limit - len(selected_indices)
    if len(selected_indices) < limit:
        leftover = frame.index.difference(pd.Index(selected_indices))
        extra_count = min(limit - len(selected_indices), len(leftover))
        if extra_count > 0:
            extra = rng.choice(leftover.to_numpy(dtype=int), size=extra_count, replace=False)
            selected_indices.extend(extra.tolist())
    return frame.loc[sorted(set(selected_indices))].reset_index(drop=True)


def apply_fast_mode_to_windows(frame: pd.DataFrame, config: FastModeConfig) -> pd.DataFrame:
    if not config.enabled:
        return frame.reset_index(drop=True)
    working = frame.copy()
    if "app_family" not in working.columns and "app_id" in working.columns:
        working["app_family"] = working["app_id"].astype(str).map(derive_app_family)
    if "label" in working.columns and config.max_benign_windows > 0:
        labels = pd.to_numeric(working["label"], errors="coerce").fillna(0).astype(int)
        benign = working[labels == 0]
        anomalous = working[labels == 1]
        benign_sampled = _sample_by_source(benign, config.max_benign_windows, config.random_seed)
        working = pd.concat([anomalous, benign_sampled], ignore_index=True, sort=False)
    if config.max_total_windows > 0:
        working = _sample_by_source(working, config.max_total_windows, config.random_seed)
    return working.sort_values("window_bucket" if "window_bucket" in working.columns else working.index.name or working.columns[0], kind="mergesort").reset_index(drop=True)


def _privacy_views_cache_valid(candidate: object) -> bool:
    from .privacy_views import PRIVACY_FEATURE_SETS, PRIVACY_METADATA_COLUMNS

    if not isinstance(candidate, dict):
        return False
    for view_name, expected_features in PRIVACY_FEATURE_SETS.items():
        if view_name not in candidate:
            return False
        frame = pd.DataFrame(candidate[view_name])
        if frame.empty:
            return False
        if "app_id" not in frame.columns or "window_bucket" not in frame.columns:
            return False
        present_features = [column for column in expected_features if column in frame.columns]
        if not present_features:
            return False
        present_metadata = [column for column in PRIVACY_METADATA_COLUMNS if column in frame.columns]
        if not present_metadata:
            return False
    return True


def _feature_windows_cache_valid(candidate: object) -> bool:
    from .features import FEATURE_COLUMNS

    frame = pd.DataFrame(candidate)
    if frame.empty:
        return False
    required_columns = {
        "app_id",
        "window_bucket",
        "label",
        "dataset_source",
        "environment_id",
        "session_id",
        "app_family",
        *FEATURE_COLUMNS,
    }
    return required_columns.issubset(frame.columns)


def _remote_windows_cache_valid(candidate: object) -> bool:
    frame = pd.DataFrame(candidate)
    if frame.empty:
        return False
    required_columns = {
        "app_id",
        "window_bucket",
        "flow_count",
        "bytes_out",
        "bytes_in",
        "novelty_score",
        "dataset_source",
        "environment_id",
        "session_id",
        "app_family",
        "transport_metrics_present",
    }
    return required_columns.issubset(frame.columns)


def load_feature_windows_cached(
    input_path: str | Path,
    *,
    build_windows_fn: Callable[[pd.DataFrame, int], pd.DataFrame],
    read_frame_fn: Callable[[str | Path], pd.DataFrame],
    explicit_cache_dir: str | Path | None = None,
    window_seconds: int = 60,
    fast_config: FastModeConfig | None = None,
) -> pd.DataFrame:
    fast = fast_config or FastModeConfig.from_env()
    base_name = f"feature_windows_w{window_seconds}"
    full_cache = _cache_path(input_path, base_name, explicit_cache_dir=explicit_cache_dir)
    full_windows = _load_or_build_joblib(
        full_cache,
        lambda: build_windows_fn(read_frame_fn(input_path), window_seconds),
        metadata={"type": "feature_windows", "window_seconds": window_seconds},
        validator=_feature_windows_cache_valid,
    )
    full_frame = pd.DataFrame(full_windows)
    if not fast.enabled:
        return full_frame.reset_index(drop=True)
    fast_cache = _cache_path(input_path, f"{base_name}_{fast.suffix()}", explicit_cache_dir=explicit_cache_dir)
    sampled = _load_or_build_joblib(
        fast_cache,
        lambda: apply_fast_mode_to_windows(full_frame, fast),
        metadata={"type": "feature_windows_fast", "window_seconds": window_seconds, "fast": fast.__dict__},
    )
    return pd.DataFrame(sampled).reset_index(drop=True)


def load_remote_windows_cached(
    input_path: str | Path,
    *,
    build_remote_windows_fn: Callable[[pd.DataFrame, int], pd.DataFrame],
    read_frame_fn: Callable[[str | Path], pd.DataFrame],
    explicit_cache_dir: str | Path | None = None,
    window_seconds: int = 60,
    fast_config: FastModeConfig | None = None,
) -> pd.DataFrame:
    fast = fast_config or FastModeConfig.from_env()
    base_name = f"remote_windows_w{window_seconds}"
    full_cache = _cache_path(input_path, base_name, explicit_cache_dir=explicit_cache_dir)
    full_windows = _load_or_build_joblib(
        full_cache,
        lambda: build_remote_windows_fn(read_frame_fn(input_path), window_seconds),
        metadata={"type": "remote_windows", "window_seconds": window_seconds},
        validator=_remote_windows_cache_valid,
    )
    full_frame = pd.DataFrame(full_windows)
    if not fast.enabled:
        return full_frame.reset_index(drop=True)
    fast_cache = _cache_path(input_path, f"{base_name}_{fast.suffix()}", explicit_cache_dir=explicit_cache_dir)
    sampled = _load_or_build_joblib(
        fast_cache,
        lambda: apply_fast_mode_to_windows(full_frame, fast),
        metadata={"type": "remote_windows_fast", "window_seconds": window_seconds, "fast": fast.__dict__},
    )
    return pd.DataFrame(sampled).reset_index(drop=True)


def load_privacy_views_cached(
    input_path: str | Path,
    *,
    build_feature_windows_fn: Callable[[pd.DataFrame, int], pd.DataFrame],
    build_privacy_views_from_windows_fn: Callable[[pd.DataFrame], dict[str, pd.DataFrame]],
    read_frame_fn: Callable[[str | Path], pd.DataFrame],
    explicit_cache_dir: str | Path | None = None,
    window_seconds: int = 60,
    fast_config: FastModeConfig | None = None,
) -> dict[str, pd.DataFrame]:
    fast = fast_config or FastModeConfig.from_env()
    base_name = f"privacy_views_w{window_seconds}"
    full_cache = _cache_path(input_path, base_name, explicit_cache_dir=explicit_cache_dir)

    def _builder() -> dict[str, pd.DataFrame]:
        windows = load_feature_windows_cached(
            input_path,
            build_windows_fn=build_feature_windows_fn,
            read_frame_fn=read_frame_fn,
            explicit_cache_dir=explicit_cache_dir,
            window_seconds=window_seconds,
            fast_config=FastModeConfig(enabled=False, random_seed=fast.random_seed),
        )
        return build_privacy_views_from_windows_fn(windows)

    full_views = _load_or_build_joblib(
        full_cache,
        _builder,
        metadata={"type": "privacy_views", "window_seconds": window_seconds},
        validator=_privacy_views_cache_valid,
    )
    result = {name: pd.DataFrame(frame).reset_index(drop=True) for name, frame in dict(full_views).items()}
    if not fast.enabled:
        return result
    fast_cache = _cache_path(input_path, f"{base_name}_{fast.suffix()}", explicit_cache_dir=explicit_cache_dir)
    sampled = _load_or_build_joblib(
        fast_cache,
        lambda: {name: apply_fast_mode_to_windows(frame, fast) for name, frame in result.items()},
        metadata={"type": "privacy_views_fast", "window_seconds": window_seconds, "fast": fast.__dict__},
        validator=_privacy_views_cache_valid,
    )
    return {name: pd.DataFrame(frame).reset_index(drop=True) for name, frame in dict(sampled).items()}
