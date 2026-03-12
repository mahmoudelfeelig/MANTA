from __future__ import annotations

import pandas as pd

from ml_pipeline.splits import source_aware_train_test_split


def test_source_aware_split_falls_back_when_metadata_groups_collapse() -> None:
    rows = []
    for index in range(60):
        rows.append(
            {
                "app_id": "com.browser.alpha" if index < 30 else "com.spyware.bad",
                "timestamp_end": 1_700_000_000_000 + (index * 61_000),
                "window_bucket": index,
                "label": 0 if index < 30 else 1,
                "dataset_source": "unknown_source",
                "environment_id": "unknown_environment",
                "session_id": "unknown_session",
                "app_family": "browser" if index < 30 else "malware",
            }
        )
    frame = pd.DataFrame(rows)

    split = source_aware_train_test_split(frame, label_column="label", test_size=0.3, random_seed=42)

    assert len(split.train_idx) > 0
    assert len(split.test_idx) > 0
    assert split.strategy in {
        "family_time",
        "app_family_time",
        "temporal_holdout",
        "stratified_random_fallback",
        "random_fallback",
    }
