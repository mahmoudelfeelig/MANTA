from __future__ import annotations

import pandas as pd

from ml_pipeline.privacy_views import build_window_privacy_views


def test_window_privacy_views_preserve_dataset_metadata() -> None:
    rows = [
        {
            "app_id": "com.browser.alpha",
            "timestamp_end": 1_700_000_000_000 + (index * 61_000),
            "bytes_out": 500 + index,
            "bytes_in": 900 + index,
            "packets_out": 3,
            "packets_in": 4,
            "dst_novelty": 0.0,
            "label": 0,
            "dataset_source": "sdncampus_flow_statistics",
            "dataset_profile": "sdncampus",
            "dataset_variant": "capture_a",
            "environment_id": "campus_wifi",
            "session_id": "session_alpha",
            "destination_key": "example.com:443",
            "protocol": "TCP",
            "dst_port": 443,
        }
        for index in range(6)
    ]
    frame = pd.DataFrame(rows)

    views = build_window_privacy_views(frame)

    for view in views.values():
        assert "dataset_source" in view.columns
        assert "dataset_profile" in view.columns
        assert "dataset_variant" in view.columns
        assert "environment_id" in view.columns
        assert "session_id" in view.columns
        assert "app_family" in view.columns
        assert set(view["dataset_source"]) == {"sdncampus_flow_statistics"}
