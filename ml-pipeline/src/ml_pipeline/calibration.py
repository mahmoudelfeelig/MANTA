from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd


@dataclass
class Thresholds:
    medium: float
    high: float


def calibrate_thresholds(
    windows_df: pd.DataFrame,
    score_column: str = "anomaly_score",
    app_column: str = "app_id",
    medium_quantile: float = 0.90,
    high_quantile: float = 0.98,
) -> dict:
    if score_column not in windows_df.columns:
        raise ValueError(f"Missing score column: {score_column}")

    if windows_df.empty:
        return {
            "default_thresholds": {"medium": 0.6, "high": 0.85},
            "app_threshold_overrides": {},
        }

    def _pair(series: pd.Series) -> Thresholds:
        medium = float(np.quantile(series, medium_quantile))
        high = float(np.quantile(series, high_quantile))
        if high < medium:
            high = medium
        return Thresholds(medium=max(0.0, min(1.0, medium)), high=max(0.0, min(1.0, high)))

    overall = _pair(windows_df[score_column].astype(float))

    overrides: dict[str, dict[str, float]] = {}
    if app_column in windows_df.columns:
        grouped = windows_df.groupby(app_column)
        for app_id, app_rows in grouped:
            if len(app_rows) < 10:
                continue
            pair = _pair(app_rows[score_column].astype(float))
            overrides[str(app_id)] = {"medium": pair.medium, "high": pair.high}

    return {
        "default_thresholds": {"medium": overall.medium, "high": overall.high},
        "app_threshold_overrides": overrides,
    }


def write_policy_payload(
    calibration: dict,
    output_path: Path,
    policy_version: int,
    export_enabled: bool,
    retention_days: int,
) -> None:
    payload = {
        "policy_version": policy_version,
        "default_thresholds": calibration["default_thresholds"],
        "app_threshold_overrides": calibration["app_threshold_overrides"],
        "export_enabled": export_enabled,
        "retention_days": retention_days,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
