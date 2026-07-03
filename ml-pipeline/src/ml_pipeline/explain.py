from __future__ import annotations

import pandas as pd

from .features import FEATURE_COLUMNS


def compute_feature_contributions(feature_windows: pd.DataFrame) -> pd.DataFrame:
    if feature_windows.empty:
        return pd.DataFrame(columns=["window_index", "top_features", "explanation"])

    feature_columns = [col for col in FEATURE_COLUMNS if col in feature_windows.columns]
    if not feature_columns:
        feature_columns = [
            str(column)
            for column in feature_windows.select_dtypes(include="number").columns
            if str(column) not in {"label", "window_bucket", "timestamp_end", "window_end_ms"}
        ]
    if not feature_columns:
        raise ValueError("No numeric feature columns available for explanation.")

    stats = {}
    for column in feature_columns:
        mean = feature_windows[column].astype(float).mean()
        std = feature_windows[column].astype(float).std()
        stats[column] = (mean, std if std and std > 0 else 1.0)

    rows = []
    for idx, row in feature_windows.iterrows():
        z_scores = {
            col: abs((float(row[col]) - stats[col][0]) / stats[col][1])
            for col in feature_columns
        }
        top = sorted(z_scores.items(), key=lambda item: item[1], reverse=True)[:3]
        top_features = [name for name, _ in top]
        explanation = "Top contributors: " + ", ".join(top_features)
        rows.append(
            {
                "window_index": int(idx),
                "top_features": top_features,
                "explanation": explanation,
            }
        )

    return pd.DataFrame(rows)
