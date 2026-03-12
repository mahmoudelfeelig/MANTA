from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .cache_utils import load_feature_windows_cached
from .features import FEATURE_COLUMNS, build_feature_windows, feature_matrix
from .io_utils import read_csv_resilient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train baseline IsolationForest on flow windows")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--output", required=True, help="Output artifact directory")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    windows = load_feature_windows_cached(
        input_path,
        build_windows_fn=build_feature_windows,
        read_frame_fn=read_csv_resilient,
    )
    X = feature_matrix(windows)

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "detector",
                IsolationForest(
                    contamination=args.contamination,
                    n_estimators=200,
                    random_state=args.random_seed,
                ),
            ),
        ]
    )
    model.fit(X)

    joblib.dump(model, output_dir / "baseline_model.joblib")
    windows.to_csv(output_dir / "training_windows.csv", index=False)

    metadata = {
        "algorithm": "IsolationForest",
        "features": FEATURE_COLUMNS,
        "contamination": args.contamination,
        "random_seed": args.random_seed,
        "rows": int(len(X)),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
