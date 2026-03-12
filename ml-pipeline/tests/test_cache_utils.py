from __future__ import annotations

import joblib
import pandas as pd

from ml_pipeline.cache_utils import FastModeConfig, _cache_path, apply_fast_mode_to_windows, load_privacy_views_cached
from ml_pipeline.features import build_feature_windows
from ml_pipeline.io_utils import read_csv_resilient
from ml_pipeline.privacy_views import build_window_privacy_views_from_windows


def test_apply_fast_mode_caps_benign_windows_but_keeps_anomalies() -> None:
    frame = pd.DataFrame(
        [
            {
                "app_id": f"app_{index}",
                "window_bucket": index,
                "label": 1 if index < 5 else 0,
                "dataset_source": "source_a" if index % 2 == 0 else "source_b",
                "app_family": "malware" if index < 5 else "browser",
            }
            for index in range(55)
        ]
    )

    sampled = apply_fast_mode_to_windows(
        frame,
        FastModeConfig(enabled=True, max_total_windows=20, max_benign_windows=10, random_seed=42),
    )

    assert int((sampled["label"] == 1).sum()) == 5
    assert len(sampled) <= 20


def test_load_privacy_views_cached_rebuilds_stale_cache(tmp_path) -> None:
    input_csv = tmp_path / "flows.csv"
    cache_dir = tmp_path / "cache"
    pd.DataFrame(
        [
            {
                "app_id": "app_a",
                "timestamp_end": 60_000,
                "bytes_out": 120.0,
                "bytes_in": 20.0,
                "packets_out": 4.0,
                "packets_in": 1.0,
                "dst_novelty": 0.8,
                "destination_key": "example.com:443",
                "label": 1,
                "dataset_source": "source_a",
                "environment_id": "env_1",
                "session_id": "session_1",
            },
            {
                "app_id": "app_b",
                "timestamp_end": 120_000,
                "bytes_out": 40.0,
                "bytes_in": 60.0,
                "packets_out": 2.0,
                "packets_in": 3.0,
                "dst_novelty": 0.1,
                "destination_key": "example.net:80",
                "label": 0,
                "dataset_source": "source_b",
                "environment_id": "env_2",
                "session_id": "session_2",
            },
        ]
    ).to_csv(input_csv, index=False)

    stale_views = {
        name: pd.DataFrame({"app_id": ["app_a"], "window_bucket": [1], "label": [0]})
        for name in ("off", "low", "medium", "strict")
    }
    stale_cache_path = _cache_path(input_csv, "privacy_views_w60", explicit_cache_dir=cache_dir)
    stale_cache_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(stale_views, stale_cache_path)

    views = load_privacy_views_cached(
        input_csv,
        build_feature_windows_fn=build_feature_windows,
        build_privacy_views_from_windows_fn=build_window_privacy_views_from_windows,
        read_frame_fn=read_csv_resilient,
        explicit_cache_dir=cache_dir,
    )

    assert "activity_level_bucket" in views["medium"].columns
    assert "flow_count" in views["off"].columns
