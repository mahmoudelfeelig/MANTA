from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .explain import compute_feature_contributions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate top-feature explanations from feature windows")
    parser.add_argument("--input", required=True, help="CSV containing feature windows")
    parser.add_argument("--output", required=True, help="CSV output path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    windows = pd.read_csv(args.input)
    output = compute_feature_contributions(windows)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(output_path, index=False)


if __name__ == "__main__":
    main()
