import pandas as pd

from ml_pipeline.explain import compute_feature_contributions


def test_compute_feature_contributions_returns_explanations() -> None:
    windows = pd.DataFrame(
        {
            "flow_count": [10, 200],
            "total_bytes_out": [1000, 500000],
            "total_bytes_in": [1500, 3000],
            "mean_packet_size": [200, 4000],
            "outbound_ratio": [0.4, 0.98],
            "burstiness": [10, 800],
            "novelty_score": [0.1, 1.0],
            "connection_frequency_delta": [1.0, 45.0],
        }
    )

    explanations = compute_feature_contributions(windows)

    assert len(explanations) == 2
    assert "top_features" in explanations.columns
    assert "explanation" in explanations.columns
