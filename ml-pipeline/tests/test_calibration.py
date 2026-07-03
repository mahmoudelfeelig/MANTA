import pandas as pd

from ml_pipeline.calibration import calibrate_thresholds


def test_calibrate_thresholds_creates_default_and_app_overrides() -> None:
    df = pd.DataFrame(
        {
            "app_id": ["a"] * 15 + ["b"] * 15,
            "anomaly_score": [0.1 + i * 0.02 for i in range(15)] + [0.2 + i * 0.015 for i in range(15)],
        }
    )

    policy = calibrate_thresholds(df, score_column="anomaly_score", app_column="app_id")

    assert "default_thresholds" in policy
    assert "app_threshold_overrides" in policy
    assert "a" in policy["app_threshold_overrides"]
    assert policy["default_thresholds"]["high"] >= policy["default_thresholds"]["medium"]
