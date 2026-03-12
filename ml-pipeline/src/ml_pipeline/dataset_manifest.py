from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .dataset_metadata import compute_source_balance_weights, derive_app_family
from .io_utils import read_csv_resilient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a dataset manifest for a canonical MANTA corpus")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output", required=True, help="Output JSON manifest path")
    return parser.parse_args()


def build_dataset_manifest(frame: pd.DataFrame, *, input_path: str | None = None) -> dict[str, object]:
    working = frame.copy()
    for column, default in {
        "dataset_source": "unknown_source",
        "dataset_profile": "unknown_profile",
        "dataset_variant": "unknown_variant",
        "environment_id": "unknown_environment",
        "session_id": "unknown_session",
    }.items():
        if column not in working.columns:
            working[column] = default
        else:
            working[column] = working[column].fillna(default).astype(str).replace({"": default})
    if "app_family" not in working.columns:
        working["app_family"] = working["app_id"].astype(str).map(derive_app_family) if "app_id" in working.columns else "other_app"
    else:
        working["app_family"] = working["app_family"].fillna("other_app").astype(str).replace({"": "other_app"})

    metadata_columns = ["dataset_source", "dataset_profile", "dataset_variant", "environment_id", "session_id", "app_family"]
    metadata_completeness = {
        column: float((working[column].astype(str).str.strip() != "").mean()) if column in working.columns else 0.0
        for column in metadata_columns
    }

    source_rows: list[dict[str, object]] = []
    for source, group in working.groupby("dataset_source", dropna=False, sort=True):
        label_counts = (
            pd.to_numeric(group["label"], errors="coerce").fillna(0).astype(int).value_counts().sort_index().to_dict()
            if "label" in group.columns
            else {}
        )
        source_rows.append(
            {
                "dataset_source": str(source),
                "rows": int(len(group)),
                "label_counts": {str(key): int(value) for key, value in label_counts.items()},
                "app_family_count": int(group["app_family"].nunique(dropna=False)),
                "session_count": int(group["session_id"].nunique(dropna=False)),
                "environment_count": int(group["environment_id"].nunique(dropna=False)),
            }
        )

    manifest = {
        "input": input_path,
        "rows": int(len(working)),
        "columns": list(working.columns),
        "label_counts": (
            {str(key): int(value) for key, value in pd.to_numeric(working["label"], errors="coerce").fillna(0).astype(int).value_counts().sort_index().to_dict().items()}
            if "label" in working.columns
            else {}
        ),
        "dataset_sources": source_rows,
        "app_family_counts": {
            str(key): int(value)
            for key, value in working["app_family"].value_counts(dropna=False).to_dict().items()
        },
        "metadata_completeness": metadata_completeness,
        "source_balance_weights": compute_source_balance_weights(working["dataset_source"]),
        "public_only_protocol_ready": all(metadata_completeness[column] >= 0.999 for column in metadata_columns),
    }
    return manifest


def main() -> None:
    args = parse_args()
    frame = read_csv_resilient(args.input)
    manifest = build_dataset_manifest(frame, input_path=str(Path(args.input).expanduser().resolve()))
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
