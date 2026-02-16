from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .calibration import calibrate_thresholds, write_policy_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calibrate adaptive thresholds from anomaly scores")
    parser.add_argument("--input", required=True, help="Path to CSV with anomaly scores")
    parser.add_argument("--output", required=True, help="Output policy JSON path")
    parser.add_argument("--score-column", default="anomaly_score")
    parser.add_argument("--app-column", default="app_id")
    parser.add_argument("--medium-quantile", type=float, default=0.90)
    parser.add_argument("--high-quantile", type=float, default=0.98)
    parser.add_argument("--policy-version", type=int, default=1)
    parser.add_argument("--export-enabled", action="store_true")
    parser.add_argument("--retention-days", type=int, default=7)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)

    calibration = calibrate_thresholds(
        windows_df=df,
        score_column=args.score_column,
        app_column=args.app_column,
        medium_quantile=args.medium_quantile,
        high_quantile=args.high_quantile,
    )

    write_policy_payload(
        calibration=calibration,
        output_path=Path(args.output),
        policy_version=args.policy_version,
        export_enabled=args.export_enabled,
        retention_days=args.retention_days,
    )


if __name__ == "__main__":
    main()
