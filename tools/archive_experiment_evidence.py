from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

from ml_pipeline.progress import PhaseProgress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Archive MANTA experiment evidence for appendix/publication handoff")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-zip", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_dir = Path(args.input_dir).expanduser().resolve()
    output_zip = Path(args.output_zip).expanduser().resolve()
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    progress = PhaseProgress("Evidence archive")

    files = [
        path
        for path in sorted(input_dir.rglob("*"))
        if path.is_file() and path.resolve() != output_zip
    ]
    manifest = []
    total_files = max(1, len(files))
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, path in enumerate(files, start=1):
            rel = path.relative_to(input_dir)
            archive.write(path, arcname=str(rel))
            manifest.append({"path": str(rel), "size": path.stat().st_size})
            percent = 5.0 + (90.0 * index / total_files)
            progress.update(percent, f"Adding {rel}")
        archive.writestr("archive-manifest.json", json.dumps({"files": manifest}, indent=2))
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
