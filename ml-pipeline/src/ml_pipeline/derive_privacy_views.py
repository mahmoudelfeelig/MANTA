from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .privacy_views import build_window_privacy_views, derive_flow_privacy_view, ensure_directory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Derive raw and privacy-tier dataset views for MANTA experiments")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-dir", required=True, help="Directory for derived privacy views")
    parser.add_argument("--salt", default="manta", help="Stable hashing salt label for pseudonymous views")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_dir = ensure_directory(Path(args.output_dir).expanduser().resolve())
    flow_dir = ensure_directory(output_dir / "flow-views")
    window_dir = ensure_directory(output_dir / "window-views")

    flows = pd.read_csv(input_path)
    for view_name in ("full", "pseudonymous", "semantic_private", "strict"):
        derive_flow_privacy_view(flows, view_name, salt=args.salt).to_csv(flow_dir / f"{view_name}.csv", index=False)
    windows = build_window_privacy_views(flows)
    for view_name, frame in windows.items():
        frame.to_csv(window_dir / f"{view_name}.csv", index=False)

    manifest = {
        "input": str(input_path),
        "output_dir": str(output_dir),
        "flow_views": [f"flow-views/{name}.csv" for name in ("full", "pseudonymous", "semantic_private", "strict")],
        "window_views": [f"window-views/{name}.csv" for name in sorted(windows)],
        "raw_data_policy": "Raw packet captures stay outside this directory. This directory stores only canonical and privacy-derived CSV views.",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
