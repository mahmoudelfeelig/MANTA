from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run end-to-end baseline experiment suite")
    parser.add_argument("--input", required=True, help="Flow CSV input")
    parser.add_argument("--output-dir", required=True, help="Output directory for artifacts and reports")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--model-threshold", type=float, default=0.5)
    parser.add_argument("--ids-threshold", type=float, default=0.55)
    return parser.parse_args()



def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return None


def _dependency_versions() -> dict[str, str]:
    packages = ["numpy", "pandas", "scikit-learn", "joblib", "tensorflow-cpu"]
    versions: dict[str, str] = {}
    for package in packages:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def _has_labels(path: str) -> bool:
    sample = pd.read_csv(path, nrows=5)
    return "label" in sample.columns or "is_anomaly" in sample.columns



def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    artifacts_dir = output_dir / "artifacts"
    reports_dir = output_dir / "reports"

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    train_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.train_baseline",
        "--input",
        args.input,
        "--output",
        str(artifacts_dir / "baseline"),
        "--contamination",
        str(args.contamination),
    ]

    eval_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.evaluate",
        "--input",
        args.input,
        "--artifacts",
        str(artifacts_dir / "baseline"),
        "--output",
        str(reports_dir / "evaluation.json"),
        "--explanations-output",
        str(reports_dir / "explanations.csv"),
        "--policy-output",
        str(reports_dir / "policy-calibrated.json"),
        "--window-scores-output",
        str(reports_dir / "windows-scored.csv"),
        "--threshold-sweep-output",
        str(reports_dir / "threshold-sweep.csv"),
        "--roc-output",
        str(reports_dir / "roc-curve.csv"),
        "--pr-output",
        str(reports_dir / "pr-curve.csv"),
        "--confusion-output",
        str(reports_dir / "confusion-matrix.json"),
        "--threshold",
        str(args.model_threshold),
        "--auto-threshold",
    ]

    compare_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.compare_baselines",
        "--input",
        args.input,
        "--artifacts",
        str(artifacts_dir / "baseline"),
        "--output",
        str(reports_dir / "comparison.json"),
        "--model-threshold",
        str(args.model_threshold),
        "--ids-threshold",
        str(args.ids_threshold),
        "--windows-output",
        str(reports_dir / "window-comparison.csv"),
    ]

    privacy_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.privacy_ablation",
        "--input",
        args.input,
        "--output",
        str(reports_dir / "privacy-ablation.json"),
        "--contamination",
        str(args.contamination),
    ]

    drift_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.drift_report",
        "--input",
        str(reports_dir / "windows-scored.csv"),
        "--output",
        str(reports_dir / "drift-report.json"),
        "--series-output",
        str(reports_dir / "drift-series.csv"),
        "--app-column",
        "app_id",
        "--time-column",
        "window_bucket",
        "--score-column",
        "anomaly_score",
    ]

    policy_sim_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.simulate_policy",
        "--input",
        str(reports_dir / "windows-scored.csv"),
        "--policy",
        str(reports_dir / "policy-calibrated.json"),
        "--output",
        str(reports_dir / "policy-simulation.json"),
        "--per-app-output",
        str(reports_dir / "policy-simulation-per-app.csv"),
        "--app-column",
        "app_id",
        "--score-column",
        "anomaly_score",
    ]

    android_model_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.train_android_model",
        "--input",
        args.input,
        "--output-model",
        str(artifacts_dir / "android" / "anomaly-linear.json"),
        "--output-report",
        str(reports_dir / "android-model-evaluation.json"),
    ]

    _run(train_cmd)
    _run(eval_cmd)
    _run(compare_cmd)
    _run(privacy_cmd)
    _run(drift_cmd)
    _run(policy_sim_cmd)

    labels_present = _has_labels(args.input)
    if labels_present:
        _run(android_model_cmd)

    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "git_commit": _git_commit(),
        "dependency_versions": _dependency_versions(),
        "train_cmd": train_cmd,
        "eval_cmd": eval_cmd,
        "compare_cmd": compare_cmd,
        "privacy_cmd": privacy_cmd,
        "drift_cmd": drift_cmd,
        "policy_sim_cmd": policy_sim_cmd,
        "android_model_cmd": android_model_cmd if labels_present else None,
        "input": args.input,
        "input_sha256": _sha256_file(args.input),
        "output_dir": str(output_dir),
        "contamination": args.contamination,
        "model_threshold": args.model_threshold,
        "ids_threshold": args.ids_threshold,
        "labels_present": labels_present,
    }
    (reports_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
