from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from .cache_utils import FastModeConfig, load_feature_windows_cached
from .features import build_feature_windows
from .io_utils import read_csv_resilient
from .progress import PhaseProgress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run end-to-end baseline experiment suite")
    parser.add_argument("--input", required=True, help="Flow CSV input")
    parser.add_argument("--output-dir", required=True, help="Output directory for artifacts and reports")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--model-threshold", type=float, default=0.5)
    parser.add_argument("--ids-threshold", type=float, default=0.55)
    parser.add_argument("--cache-dir", default="", help="Optional cache directory for precomputed windows/views")
    parser.add_argument("--parallel-jobs", type=int, default=1, help="Maximum parallel subprocesses for independent model/report steps")
    parser.add_argument("--fast-mode", action="store_true", help="Use cached fast-mode sampled windows for iteration")
    parser.add_argument("--max-total-windows", type=int, default=0)
    parser.add_argument("--max-benign-windows", type=int, default=0)
    parser.add_argument("--skip-evaluation-protocol", action="store_true", help="Skip the heavy multi-split evaluation-protocol report")
    parser.add_argument("--allow-existing-output", action="store_true", help="Allow writing into an existing output directory")
    parser.add_argument("--resume", action="store_true", help="Reuse already-finished step outputs inside an existing output directory")
    return parser.parse_args()


def _run(cmd: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(cmd, check=True, env=env)


def _run_parallel(steps: list[tuple[str, list[str]]], *, env: dict[str, str], max_workers: int) -> None:
    if max_workers <= 1 or len(steps) <= 1:
        for _label, command in steps:
            _run(command, env=env)
        return
    with ThreadPoolExecutor(max_workers=min(max_workers, len(steps))) as executor:
        futures = {executor.submit(_run, command, env=env): label for label, command in steps}
        for future in as_completed(futures):
            future.result()


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
    sample = read_csv_resilient(path, nrows=5)
    return "label" in sample.columns or "is_anomaly" in sample.columns


def _prepare_env(cache_dir: Path, fast_config: FastModeConfig) -> dict[str, str]:
    env = os.environ.copy()
    env["MANTA_CACHE_DIR"] = str(cache_dir)
    env.setdefault("MANTA_PROGRESS_HEARTBEAT_SECONDS", "20")
    if fast_config.enabled:
        env["MANTA_FAST_MODE"] = "1"
        env["MANTA_MAX_TOTAL_WINDOWS"] = str(fast_config.max_total_windows)
        env["MANTA_MAX_BENIGN_WINDOWS"] = str(fast_config.max_benign_windows)
        env["MANTA_FAST_RANDOM_SEED"] = str(fast_config.random_seed)
    else:
        env.pop("MANTA_FAST_MODE", None)
        env.pop("MANTA_MAX_TOTAL_WINDOWS", None)
        env.pop("MANTA_MAX_BENIGN_WINDOWS", None)
        env.pop("MANTA_FAST_RANDOM_SEED", None)
    return env


def _all_exist(paths: list[Path]) -> bool:
    return bool(paths) and all(path.exists() for path in paths)


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Experiment suite")
    output_dir = Path(args.output_dir).expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not (args.allow_existing_output or args.resume):
        raise SystemExit(f"Output directory already exists and is not empty: {output_dir}. Use a new run directory or pass --allow-existing-output.")
    artifacts_dir = output_dir / "artifacts"
    reports_dir = output_dir / "reports"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    cache_dir = Path(args.cache_dir).expanduser().resolve() if args.cache_dir else (output_dir / "cache").resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    fast_config = FastModeConfig(
        enabled=args.fast_mode,
        max_total_windows=int(args.max_total_windows),
        max_benign_windows=int(args.max_benign_windows),
        random_seed=42,
    )
    subprocess_env = _prepare_env(cache_dir, fast_config)

    progress.update(1, "Warming feature-window cache")
    load_feature_windows_cached(
        args.input,
        build_windows_fn=build_feature_windows,
        read_frame_fn=read_csv_resilient,
        explicit_cache_dir=cache_dir,
        fast_config=fast_config,
    )

    dataset_manifest_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.dataset_manifest",
        "--input",
        args.input,
        "--output",
        str(reports_dir / "dataset-manifest.json"),
    ]
    evaluation_protocol_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.evaluation_protocol_report",
        "--input",
        args.input,
        "--output",
        str(reports_dir / "evaluation-protocol.json"),
    ]
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
    derive_privacy_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.derive_privacy_views",
        "--input",
        args.input,
        "--output-dir",
        str(reports_dir / "privacy-views"),
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
    leakage_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.privacy_leakage_benchmark",
        "--input",
        args.input,
        "--output",
        str(reports_dir / "privacy-leakage.json"),
    ]
    pareto_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.privacy_pareto_report",
        "--ablation-report",
        str(reports_dir / "privacy-ablation.json"),
        "--leakage-report",
        str(reports_dir / "privacy-leakage.json"),
        "--output-json",
        str(reports_dir / "privacy-pareto.json"),
        "--output-csv",
        str(reports_dir / "privacy-pareto.csv"),
    ]
    privacy_gate_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.privacy_gate_report",
        "--ablation-report",
        str(reports_dir / "privacy-ablation.json"),
        "--leakage-report",
        str(reports_dir / "privacy-leakage.json"),
        "--output",
        str(reports_dir / "privacy-gate.json"),
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
    tflite_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.export_tflite",
        "--input",
        args.input,
        "--output",
        str(artifacts_dir / "tflite" / "anomaly.tflite"),
        "--output-report",
        str(reports_dir / "tflite-autoencoder-evaluation.json"),
    ]
    remote_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.train_remote_backend_model",
        "--input",
        args.input,
        "--output-model",
        str(artifacts_dir / "backend" / "remote-assisted-model.json"),
        "--output-report",
        str(reports_dir / "remote-assisted-model.json"),
        "--model-family",
        "hybrid_dual_channel",
    ]
    compare_families_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.compare_model_families",
        "--input",
        args.input,
        "--output-dir",
        str(reports_dir / "model-family-matrix"),
    ]
    privacy_student_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.train_privacy_student",
        "--input",
        args.input,
        "--output-model",
        str(artifacts_dir / "privacy" / "privacy-student.json"),
        "--output-report",
        str(reports_dir / "privacy-student-report.json"),
        "--student-view",
        "medium",
    ]
    federated_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.simulate_federated_rounds",
        "--input",
        args.input,
        "--view",
        "medium",
        "--student-model",
        str(artifacts_dir / "privacy" / "privacy-student.json"),
        "--output-report",
        str(reports_dir / "federated-report.json"),
    ]
    performance_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.benchmark_performance",
        "--input",
        args.input,
        "--output",
        str(reports_dir / "performance-gates.json"),
    ]
    full_matrix_cmd = [
        sys.executable,
        "-m",
        "ml_pipeline.compare_full_matrix",
        "--android-report",
        str(reports_dir / "android-model-evaluation.json"),
        "--remote-report",
        str(reports_dir / "remote-assisted-model.json"),
        "--tflite-report",
        str(reports_dir / "tflite-autoencoder-evaluation.json"),
        "--privacy-student-report",
        str(reports_dir / "privacy-student-report.json"),
        "--federated-report",
        str(reports_dir / "federated-report.json"),
        "--family-comparison-report",
        str(reports_dir / "model-family-matrix" / "comparison-summary.json"),
        "--privacy-gate-report",
        str(reports_dir / "privacy-gate.json"),
        "--performance-report",
        str(reports_dir / "performance-gates.json"),
        "--dataset-manifest",
        str(reports_dir / "dataset-manifest.json"),
        "--output",
        str(reports_dir / "full-model-matrix.json"),
    ]
    step_outputs: dict[str, list[Path]] = {
        "dataset manifest": [reports_dir / "dataset-manifest.json"],
        "evaluation protocol": [reports_dir / "evaluation-protocol.json"],
        "baseline training": [artifacts_dir / "baseline" / "baseline_model.joblib"],
        "baseline evaluation": [reports_dir / "evaluation.json", reports_dir / "windows-scored.csv"],
        "baseline comparison": [reports_dir / "comparison.json"],
        "privacy-view derivation": [reports_dir / "privacy-views" / "manifest.json"],
        "privacy ablation": [reports_dir / "privacy-ablation.json"],
        "privacy leakage": [reports_dir / "privacy-leakage.json"],
        "privacy Pareto summary": [reports_dir / "privacy-pareto.json", reports_dir / "privacy-pareto.csv"],
        "privacy gate report": [reports_dir / "privacy-gate.json"],
        "drift report": [reports_dir / "drift-report.json"],
        "policy simulation": [reports_dir / "policy-simulation.json"],
        "android linear model": [reports_dir / "android-model-evaluation.json", artifacts_dir / "android" / "anomaly-linear.json"],
        "tflite autoencoder": [reports_dir / "tflite-autoencoder-evaluation.json", artifacts_dir / "tflite" / "anomaly.tflite"],
        "remote model": [reports_dir / "remote-assisted-model.json", artifacts_dir / "backend" / "remote-assisted-model.json"],
        "remote family comparison": [reports_dir / "model-family-matrix" / "comparison-summary.json"],
        "privacy student": [reports_dir / "privacy-student-report.json", artifacts_dir / "privacy" / "privacy-student.json"],
        "federated simulation": [reports_dir / "federated-report.json"],
        "performance benchmark": [reports_dir / "performance-gates.json"],
        "full model matrix": [reports_dir / "full-model-matrix.json"],
    }

    labels_present = _has_labels(args.input)

    progress.update(10, "Dataset manifest")
    if args.resume and _all_exist(step_outputs["dataset manifest"]):
        progress.update(12, "Dataset manifest already present")
    else:
        _run(dataset_manifest_cmd, env=subprocess_env)
    if not args.skip_evaluation_protocol:
        progress.update(14, "Evaluation protocol")
        if args.resume and _all_exist(step_outputs["evaluation protocol"]):
            progress.update(16, "Evaluation protocol already present")
        else:
            _run(evaluation_protocol_cmd, env=subprocess_env)

    progress.update(20, "Baseline training")
    if not (args.resume and _all_exist(step_outputs["baseline training"])):
        _run(train_cmd, env=subprocess_env)
    progress.update(28, "Baseline evaluation")
    if not (args.resume and _all_exist(step_outputs["baseline evaluation"])):
        _run(eval_cmd, env=subprocess_env)
    progress.update(34, "Baseline comparison")
    if not (args.resume and _all_exist(step_outputs["baseline comparison"])):
        _run(compare_cmd, env=subprocess_env)

    progress.update(40, "Privacy view + utility/leakage group")
    privacy_group = [
        (label, command)
        for label, command in [
            ("privacy-view derivation", derive_privacy_cmd),
            ("privacy ablation", privacy_cmd),
            ("privacy leakage", leakage_cmd),
        ]
        if not (args.resume and _all_exist(step_outputs[label]))
    ]
    if privacy_group:
        _run_parallel(privacy_group, env=subprocess_env, max_workers=args.parallel_jobs)
    progress.update(50, "Privacy summaries")
    if not (args.resume and _all_exist(step_outputs["privacy Pareto summary"])):
        _run(pareto_cmd, env=subprocess_env)
    if not (args.resume and _all_exist(step_outputs["privacy gate report"])):
        _run(privacy_gate_cmd, env=subprocess_env)
    progress.update(58, "Drift and policy simulation")
    if not (args.resume and _all_exist(step_outputs["drift report"])):
        _run(drift_cmd, env=subprocess_env)
    if not (args.resume and _all_exist(step_outputs["policy simulation"])):
        _run(policy_sim_cmd, env=subprocess_env)

    if labels_present:
        progress.update(66, "Model training group")
        model_group = [
            (label, command)
            for label, command in [
                ("android linear model", android_model_cmd),
                ("tflite autoencoder", tflite_cmd),
                ("remote model", remote_cmd),
                ("remote family comparison", compare_families_cmd),
                ("privacy student", privacy_student_cmd),
                ("performance benchmark", performance_cmd),
            ]
            if not (args.resume and _all_exist(step_outputs[label]))
        ]
        if model_group:
            _run_parallel(model_group, env=subprocess_env, max_workers=args.parallel_jobs)
        progress.update(88, "Federated simulation")
        if not (args.resume and _all_exist(step_outputs["federated simulation"])):
            _run(federated_cmd, env=subprocess_env)
        progress.update(94, "Full model matrix")
        if not (args.resume and _all_exist(step_outputs["full model matrix"])):
            _run(full_matrix_cmd, env=subprocess_env)

    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "git_commit": _git_commit(),
        "dependency_versions": _dependency_versions(),
        "input": args.input,
        "input_sha256": _sha256_file(args.input),
        "output_dir": str(output_dir),
        "cache_dir": str(cache_dir),
        "fast_mode": fast_config.__dict__,
        "parallel_jobs": int(args.parallel_jobs),
        "contamination": args.contamination,
        "model_threshold": args.model_threshold,
        "ids_threshold": args.ids_threshold,
        "labels_present": labels_present,
        "skip_evaluation_protocol": bool(args.skip_evaluation_protocol),
        "resume": bool(args.resume),
    }
    (reports_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    archive_script = Path(__file__).resolve().parents[3] / "tools" / "archive_experiment_evidence.py"
    archive_target = output_dir / "manta-evidence.zip"
    progress.update(98, "Archiving experiment evidence")
    subprocess.run(
        [sys.executable, str(archive_script), "--input-dir", str(output_dir), "--output-zip", str(archive_target)],
        check=True,
        env=subprocess_env,
    )
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
