from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge normalized MANTA canonical CSV datasets")
    parser.add_argument("--inputs", nargs="+", required=True, help="Normalized canonical CSV files")
    parser.add_argument("--output", required=True, help="Merged CSV output path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    frames = [pd.read_csv(Path(path).expanduser().resolve()) for path in args.inputs]
    merged = pd.concat(frames, ignore_index=True, sort=False)
    merged = merged.sort_values("timestamp_end", kind="mergesort").reset_index(drop=True)
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)
    print(f"Merged {len(frames)} dataset(s) into {output_path} with {len(merged)} rows")


if __name__ == "__main__":
    main()
