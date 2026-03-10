from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a thesis-ready comparison matrix across MANTA model families")
    parser.add_argument("--android-report", required=True)
    parser.add_argument("--remote-report", required=True)
    parser.add_argument("--tflite-report", required=True)
    parser.add_argument("--privacy-student-report", required=True)
    parser.add_argument("--federated-report", required=True)
    parser.add_argument("--family-comparison-report", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    args = parse_args()
    android = _load(args.android_report)
    remote = _load(args.remote_report)
    tflite = _load(args.tflite_report)
    privacy_student = _load(args.privacy_student_report)
    federated = _load(args.federated_report)
    family = _load(args.family_comparison_report)

    matrix = [
        {"model": "android_linear", **{key: android.get(key) for key in ("precision", "recall", "f1", "pr_auc", "roc_auc")}},
        {"model": "tflite_one_class", **{key: tflite.get(key) for key in ("precision", "recall", "f1", "pr_auc", "roc_auc")}},
        {"model": "remote_primary", **{key: (remote.get("training_report") or {}).get("metrics", {}).get(key) for key in ("precision", "recall", "f1", "pr_auc", "roc_auc")}},
        {"model": "privacy_student", **{key: privacy_student.get(key) for key in ("precision", "recall", "f1", "pr_auc", "roc_auc")}},
        {"model": "federated_semantic_private", **{key: federated.get(key) for key in ("precision", "recall", "f1", "pr_auc", "roc_auc")}},
    ]
    for row in family.get("families", []):
        matrix.append({"model": f"remote_family::{row['family']}", **{key: row.get(key) for key in ("precision", "recall", "f1", "pr_auc", "roc_auc")}})

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"matrix": matrix}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
