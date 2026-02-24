import pandas as pd

from ml_pipeline.features import build_feature_windows, feature_matrix


def test_build_feature_windows_produces_expected_columns() -> None:
    df = pd.DataFrame(
        [
            {
                "app_id": "com.test",
                "timestamp_end": 1000,
                "bytes_out": 10,
                "bytes_in": 20,
                "packets_out": 1,
                "packets_in": 1,
                "dst_novelty": 1.0,
                "label": 0,
            },
            {
                "app_id": "com.test",
                "timestamp_end": 2000,
                "bytes_out": 15,
                "bytes_in": 25,
                "packets_out": 1,
                "packets_in": 1,
                "dst_novelty": 0.0,
                "label": 1,
            },
        ]
    )

    windows = build_feature_windows(df, window_seconds=60)
    X = feature_matrix(windows)

    assert not windows.empty
    assert "flow_count" in windows.columns
    assert "label" in windows.columns
    assert X.shape[1] == 8
