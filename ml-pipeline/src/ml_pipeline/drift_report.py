from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate concept-drift report from scored windows")
    parser.add_argument("--input", required=True, help="CSV with scored windows")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    parser.add_argument("--series-output", default="", help="Optional CSV path with per-window drift series")
    parser.add_argument("--app-column", default="app_id")
    parser.add_argument("--time-column", default="window_bucket")
    parser.add_argument("--score-column", default="anomaly_score")
    parser.add_argument("--window-size", type=int, default=40, help="Rolling baseline window size")
    parser.add_argument("--min-history", type=int, default=12, help="Minimum rows before drift is considered mature")
    parser.add_argument("--high-threshold", type=float, default=0.65)
    return parser.parse_args()


def _resolve_time_column(df: pd.DataFrame, preferred: str) -> str:
    if preferred in df.columns:
        return preferred
    for candidate in ("window_bucket", "timestamp_end", "timestamp_end_ms", "timestamp"):
        if candidate in df.columns:
            return candidate
    raise SystemExit("No usable time column found. Provide --time-column explicitly.")


def _require_column(df: pd.DataFrame, column: str) -> None:
    if column not in df.columns:
        raise SystemExit(f"Required column is missing: {column}")


def _drift_components(df: pd.DataFrame, feature_columns: list[str], window_size: int, min_history: int) -> pd.DataFrame:
    result = df.copy()
    grouped = result.groupby("app_id", dropna=False, sort=False)

    for feature in feature_columns:
        z_col = f"{feature}_z"
        shifted = grouped[feature].shift(1)
        rolling_mean = shifted.groupby(result["app_id"]).rolling(window=window_size, min_periods=min_history).mean()
        rolling_std = shifted.groupby(result["app_id"]).rolling(window=window_size, min_periods=min_history).std()
        rolling_mean = rolling_mean.reset_index(level=0, drop=True)
        rolling_std = rolling_std.reset_index(level=0, drop=True).replace(0.0, np.nan)
        z = ((result[feature] - rolling_mean) / rolling_std).abs()
        result[z_col] = z.fillna(0.0).clip(0.0, 10.0)

    z_cols = [f"{feature}_z" for feature in feature_columns]
    result["drift_score_raw"] = result[z_cols].mean(axis=1)
    result["drift_score"] = (result["drift_score_raw"] / 5.0).clip(0.0, 1.0)
    result["high_drift"] = result["drift_score"] >= 0.65
    return result


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    df = pd.read_csv(input_path)
    _require_column(df, args.app_column)
    _require_column(df, args.score_column)
    time_column = _resolve_time_column(df, args.time_column)

    normalized = df.rename(columns={args.app_column: "app_id", args.score_column: "anomaly_score", time_column: "time_key"})
    normalized = normalized.sort_values(["app_id", "time_key"], kind="mergesort").reset_index(drop=True)

    candidate_features = [
        "anomaly_score",
        "novelty_score",
        "burstiness",
        "connection_frequency_delta",
        "periodic_beacon_score",
        "data_quality_score",
    ]
    feature_columns = [column for column in candidate_features if column in normalized.columns]
    if not feature_columns:
        raise SystemExit("No drift features available after normalization")

    series = _drift_components(
        df=normalized,
        feature_columns=feature_columns,
        window_size=max(5, args.window_size),
        min_history=max(2, args.min_history),
    )
    series["high_drift"] = series["drift_score"] >= args.high_threshold

    per_app_max = (
        series.groupby("app_id", dropna=False)["drift_score"]
        .max()
        .sort_values(ascending=False)
        .to_dict()
    )
    per_app_high = (
        series.groupby("app_id", dropna=False)["high_drift"]
        .sum()
        .sort_values(ascending=False)
        .to_dict()
    )

    report = {
        "rows": int(len(series)),
        "apps": int(series["app_id"].nunique(dropna=False)),
        "feature_columns": feature_columns,
        "window_size": int(max(5, args.window_size)),
        "min_history": int(max(2, args.min_history)),
        "high_threshold": float(args.high_threshold),
        "high_drift_rows": int(series["high_drift"].sum()),
        "high_drift_ratio": float(series["high_drift"].mean() if len(series) else 0.0),
        "drift_score_mean": float(series["drift_score"].mean() if len(series) else 0.0),
        "drift_score_max": float(series["drift_score"].max() if len(series) else 0.0),
        "per_app_max_drift": {str(k): float(v) for k, v in per_app_max.items()},
        "per_app_high_drift_rows": {str(k): int(v) for k, v in per_app_high.items()},
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.series_output:
        series_path = Path(args.series_output)
        series_path.parent.mkdir(parents=True, exist_ok=True)
        columns = ["app_id", "time_key", "drift_score", "high_drift"] + [f"{feature}_z" for feature in feature_columns]
        series[columns].to_csv(series_path, index=False)


if __name__ == "__main__":
    main()
