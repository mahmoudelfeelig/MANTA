import numpy as np
import pandas as pd

from ml_pipeline.ids_baseline import score_ids_baseline


def test_ids_baseline_scores_anomalous_window_higher() -> None:
    windows = pd.DataFrame(
        {
            "flow_count": [12, 180],
            "total_bytes_out": [3_000, 400_000],
            "total_bytes_in": [9_000, 4_500],
            "mean_packet_size": [500, 5_000],
            "outbound_ratio": [0.25, 0.97],
            "burstiness": [12.0, 900.0],
            "novelty_score": [0.1, 1.0],
            "connection_frequency_delta": [0.4, 33.0],
        }
    )

    scores = score_ids_baseline(windows)

    assert scores.shape == (2,)
    assert np.all(scores >= 0.0)
    assert np.all(scores <= 1.0)
    assert scores[1] > scores[0]
