from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ANDROID_GATES = {
    "roc_auc": 0.95,
    "pr_auc": 0.90,
    "f1": 0.90,
    "precision": 0.88,
    "recall": 0.92,
}

REMOTE_GATES = {
    "roc_auc": 0.95,
    "pr_auc": 0.92,
    "f1": 0.90,
    "precision": 0.88,
    "recall": 0.92,
}

TFLITE_GATES = {
    "roc_auc": 0.90,
    "pr_auc": 0.88,
    "f1": 0.86,
    "precision": 0.84,
    "recall": 0.88,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check MANTA report files against documented validation gates.")
    parser.add_argument("--android-report", type=Path, default=Path("ml-pipeline/reports/android-model-evaluation.json"))
    parser.add_argument("--remote-report", type=Path, default=Path("ml-pipeline/reports/remote-assisted-model.json"))
    parser.add_argument("--tflite-report", type=Path, default=Path("ml-pipeline/reports/tflite-autoencoder-evaluation.json"))
    parser.add_argument("--allow-missing", action="store_true", help="Skip checks if a report file is missing.")
    return parser.parse_args()


def load_json(path: Path, allow_missing: bool) -> dict[str, Any] | None:
    if not path.exists():
        if allow_missing:
            print(f"skip: missing report {path}")
            return None
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def require_metric(name: str, payload: dict[str, Any]) -> float:
    value = payload.get(name)
    if value is None:
        raise ValueError(f"missing metric: {name}")
    return float(value)


def check_threshold_range(report: dict[str, Any], failures: list[str]) -> None:
    threshold = report.get("threshold")
    if threshold is None:
        return
    value = float(threshold)
    if value < 0.02 or value > 0.85:
        failures.append(f"android threshold {value:.4f} is outside the expected calibration band [0.02, 0.85]")


def check_metric_block(label: str, report: dict[str, Any], gates: dict[str, float], failures: list[str]) -> None:
    for metric_name, minimum in gates.items():
        value = require_metric(metric_name, report)
        if value < minimum:
            failures.append(f"{label} {metric_name}={value:.4f} is below gate {minimum:.4f}")


def check_remote_corpus(report: dict[str, Any], failures: list[str]) -> None:
    label_counts = report.get("label_counts") or {}
    benign = int(label_counts.get("0", 0))
    anomalous = int(label_counts.get("1", 0))
    if benign < 10_000:
        failures.append(f"remote benign window count {benign} is below 10000")
    if anomalous < 500:
        failures.append(f"remote anomalous window count {anomalous} is below 500")


def main() -> int:
    args = parse_args()
    failures: list[str] = []

    android_report = load_json(args.android_report, allow_missing=args.allow_missing)
    remote_report = load_json(args.remote_report, allow_missing=args.allow_missing)
    tflite_report = load_json(args.tflite_report, allow_missing=True)

    if android_report is not None:
        check_metric_block("android", android_report, ANDROID_GATES, failures)
        check_threshold_range(android_report, failures)

    if remote_report is not None:
        training_report = remote_report.get("training_report") or {}
        metrics = training_report.get("metrics") or {}
        check_metric_block("remote", metrics, REMOTE_GATES, failures)
        check_remote_corpus(remote_report, failures)

    if tflite_report is not None:
        check_metric_block("tflite", tflite_report, TFLITE_GATES, failures)
        check_threshold_range(tflite_report, failures)

    if failures:
        print("MANTA validation gate failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("MANTA validation gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
