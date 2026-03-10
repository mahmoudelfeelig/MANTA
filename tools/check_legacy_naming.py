from __future__ import annotations

import argparse
import os
from pathlib import Path


SKIP_PARTS = {
    ".git",
    ".gradle",
    ".idea",
    ".kotlin",
    ".pytest_cache",
    ".venv",
    ".venv-manim",
    "node_modules",
    "build",
    "downloads",
    "data",
    "artifacts",
    "reports",
    "experiment-runs",
    "study-plans",
    "media",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
}
ALLOWED_SUBSTRINGS = {
    "elf" + "eel.me",
    "elf" + "eelig",
}
SEARCH_TOKEN = "fe" + "el"
INCLUDED_SUFFIXES = {
    ".bib",
    ".gradle",
    ".html",
    ".java",
    ".json",
    ".kt",
    ".kts",
    ".md",
    ".properties",
    ".ps1",
    ".py",
    ".tex",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail if legacy project naming remains outside allowed domain references.")
    parser.add_argument("--root", type=Path, default=Path("."))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    for root, dirnames, filenames in os.walk(args.root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_PARTS and not name.endswith(".egg-info")]
        root_path = Path(root)
        for filename in filenames:
            path = root_path / filename
            if path.suffix.lower() not in INCLUDED_SUFFIXES:
                continue
            if path.name == "check_legacy_naming.py":
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                lower = line.lower()
                if SEARCH_TOKEN not in lower:
                    continue
                if any(allowed in lower for allowed in ALLOWED_SUBSTRINGS):
                    continue
                failures.append(f"{path}:{line_number}: {line.strip()}")

    if failures:
        print("Legacy naming references still present:")
        for failure in failures:
            print(failure)
        return 1

    print("No legacy project naming found outside allowed domain references.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
