from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .cache_utils import load_privacy_views_cached
from .features import build_feature_windows
from .io_utils import read_csv_resilient
from .privacy_views import build_window_privacy_views_from_windows, derive_flow_privacy_view, ensure_directory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Derive raw and privacy-tier dataset views for MANTA experiments")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-dir", required=True, help="Directory for derived privacy views")
    parser.add_argument("--salt", default="manta", help="Stable hashing salt label for low-privacy hashed views")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_dir = ensure_directory(Path(args.output_dir).expanduser().resolve())
    flow_dir = ensure_directory(output_dir / "flow-views")
    window_dir = ensure_directory(output_dir / "window-views")

    flows = read_csv_resilient(input_path)
    for view_name in ("off", "low", "medium", "strict"):
        derive_flow_privacy_view(flows, view_name, salt=args.salt).to_csv(flow_dir / f"{view_name}.csv", index=False)
    windows = load_privacy_views_cached(
        input_path,
        build_feature_windows_fn=build_feature_windows,
        build_privacy_views_from_windows_fn=build_window_privacy_views_from_windows,
        read_frame_fn=read_csv_resilient,
    )
    for view_name, frame in windows.items():
        frame.to_csv(window_dir / f"{view_name}.csv", index=False)

    manifest = {
        "input": str(input_path),
        "output_dir": str(output_dir),
        "flow_views": [f"flow-views/{name}.csv" for name in ("off", "low", "medium", "strict")],
        "window_views": [f"window-views/{name}.csv" for name in sorted(windows)],
        "raw_data_policy": "Raw packet captures stay outside this directory. This directory stores only canonical and privacy-derived CSV views.",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
