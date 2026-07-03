from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .dataset_manifest import build_dataset_manifest
from .dataset_metadata import derive_app_family, recover_legacy_flow_metadata
from .io_utils import read_csv_resilient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge normalized MANTA canonical CSV datasets")
    parser.add_argument("--inputs", nargs="+", required=True, help="Normalized canonical CSV files")
    parser.add_argument("--output", required=True, help="Merged CSV output path")
    parser.add_argument("--manifest-output", default="", help="Optional dataset manifest JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    frames = []
    resolved_inputs = [Path(path).expanduser().resolve() for path in args.inputs]
    for input_path in resolved_inputs:
        frame = read_csv_resilient(input_path)
        frame = recover_legacy_flow_metadata(frame, input_path)
        frames.append(frame)
    merged = pd.concat(frames, ignore_index=True, sort=False)
    for column, default in {
        "dataset_source": "unknown_source",
        "dataset_profile": "unknown_profile",
        "dataset_variant": "unknown_variant",
        "environment_id": "unknown_environment",
        "session_id": "unknown_session",
    }.items():
        if column not in merged.columns:
            merged[column] = default
        else:
            merged[column] = merged[column].fillna(default).astype(str)
    if "app_family" not in merged.columns:
        merged["app_family"] = merged["app_id"].astype(str).map(derive_app_family)
    else:
        merged["app_family"] = merged["app_family"].fillna("other_app").astype(str)
    merged = merged.sort_values("timestamp_end", kind="mergesort").reset_index(drop=True)
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)
    if args.manifest_output:
        manifest_path = Path(args.manifest_output).expanduser().resolve()
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest = build_dataset_manifest(merged, input_path=str(output_path))
        manifest["inputs"] = [str(path) for path in resolved_inputs]
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Merged {len(frames)} dataset(s) into {output_path} with {len(merged)} rows")


if __name__ == "__main__":
    main()
