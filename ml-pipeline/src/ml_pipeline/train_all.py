from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full MANTA training workflow into the next numbered experiment run")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--runs-root", default="experiment-runs", help="Root directory for numbered experiment runs")
    parser.add_argument("--run-prefix", default="manta-run-", help="Prefix for numbered run directories")
    parser.add_argument("--cache-root", default="", help="Shared cache root reused across numbered runs")
    parser.add_argument("--model-threshold", type=float, default=0.5)
    parser.add_argument("--ids-threshold", type=float, default=0.55)
    parser.add_argument("--parallel-jobs", type=int, default=2)
    parser.add_argument("--fast-mode", action="store_true")
    parser.add_argument("--max-total-windows", type=int, default=0)
    parser.add_argument("--max-benign-windows", type=int, default=0)
    parser.add_argument("--skip-evaluation-protocol", action="store_true")
    parser.add_argument("--resume-latest", action="store_true", help="Resume the latest numbered run instead of creating a new one")
    parser.add_argument("--resume-run-dir", default="", help="Resume a specific numbered run directory")
    return parser.parse_args()


def _next_run_dir(runs_root: Path, prefix: str) -> Path:
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    max_index = 0
    if runs_root.exists():
        for child in runs_root.iterdir():
            if not child.is_dir():
                continue
            match = pattern.match(child.name)
            if match:
                max_index = max(max_index, int(match.group(1)))
    return runs_root / f"{prefix}{max_index + 1:03d}"


def _load_json_if_exists(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _default_cache_root(runs_root: Path) -> Path:
    return runs_root / ".shared-cache"


def _build_run_diff(previous_run_dir: Path | None, current_run_dir: Path) -> dict[str, object]:
    current_matrix = _load_json_if_exists(current_run_dir / "reports" / "full-model-matrix.json") or {}
    if previous_run_dir is None:
        return {"has_previous": False}
    previous_matrix = _load_json_if_exists(previous_run_dir / "reports" / "full-model-matrix.json") or {}
    previous_rows = {row["model"]: row for row in (previous_matrix.get("matrix") or []) if isinstance(row, dict) and row.get("model")}
    current_rows = {row["model"]: row for row in (current_matrix.get("matrix") or []) if isinstance(row, dict) and row.get("model")}
    deltas: list[dict[str, object]] = []
    for model_name, current_row in current_rows.items():
        previous_row = previous_rows.get(model_name)
        if not previous_row:
            continue
        deltas.append(
            {
                "model": model_name,
                "f1_delta": (float(current_row.get("f1")) - float(previous_row.get("f1"))) if isinstance(current_row.get("f1"), (int, float)) and isinstance(previous_row.get("f1"), (int, float)) else None,
                "pr_auc_delta": (float(current_row.get("pr_auc")) - float(previous_row.get("pr_auc"))) if isinstance(current_row.get("pr_auc"), (int, float)) and isinstance(previous_row.get("pr_auc"), (int, float)) else None,
                "roc_auc_delta": (float(current_row.get("roc_auc")) - float(previous_row.get("roc_auc"))) if isinstance(current_row.get("roc_auc"), (int, float)) and isinstance(previous_row.get("roc_auc"), (int, float)) else None,
            }
        )
    return {
        "has_previous": True,
        "previous_run_dir": str(previous_run_dir),
        "deltas": deltas,
    }


def _print_summary(run_dir: Path, diff: dict[str, object]) -> None:
    full_matrix = _load_json_if_exists(run_dir / "reports" / "full-model-matrix.json") or {}
    privacy_gate = _load_json_if_exists(run_dir / "reports" / "privacy-gate.json") or {}
    dataset_manifest = _load_json_if_exists(run_dir / "reports" / "dataset-manifest.json") or {}
    summary = full_matrix.get("summary") or {}
    recommended = full_matrix.get("recommended_deployment") or {}
    print("Run summary:", flush=True)
    print(f"  best_f1_model: {summary.get('best_f1_model')}", flush=True)
    print(f"  best_pr_auc_model: {summary.get('best_pr_auc_model')}", flush=True)
    print(f"  recommended_on_device: {recommended.get('on_device_primary')}", flush=True)
    print(f"  recommended_remote: {recommended.get('remote_primary')}", flush=True)
    print(f"  recommended_privacy: {recommended.get('privacy_variant')}", flush=True)
    print(f"  recommended_federated: {recommended.get('federated_variant')}", flush=True)
    medium_verdict = ((privacy_gate.get("verdicts") or {}).get("medium") or {})
    strict_verdict = ((privacy_gate.get("verdicts") or {}).get("strict") or {})
    print(f"  privacy_medium_pass: {medium_verdict.get('overall_pass')}", flush=True)
    print(f"  privacy_strict_pass: {strict_verdict.get('overall_pass')}", flush=True)
    sources = (dataset_manifest.get("dataset_sources") or [])[:5]
    if sources:
        print("  top_dataset_sources:", flush=True)
        for source in sources:
            if isinstance(source, dict):
                print(f"    - {source.get('dataset_source')}: {source.get('rows')} rows", flush=True)
    app_families = list((dataset_manifest.get("app_family_counts") or {}).items())[:5]
    if app_families:
        print("  top_app_families:", flush=True)
        for family, count in app_families:
            print(f"    - {family}: {count}", flush=True)
    if diff.get("has_previous"):
        best_delta = None
        for row in diff.get("deltas") or []:
            if not isinstance(row, dict):
                continue
            f1_delta = row.get("f1_delta")
            if not isinstance(f1_delta, (int, float)):
                continue
            if best_delta is None or f1_delta > best_delta["f1_delta"]:
                best_delta = {"model": row.get("model"), "f1_delta": f1_delta}
        if best_delta is not None:
            print(f"  biggest_f1_gain_vs_previous: {best_delta['model']} ({best_delta['f1_delta']:+.4f})", flush=True)


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise SystemExit(f"Input dataset not found: {input_path}")
    if not input_path.is_file():
        raise SystemExit(f"Input dataset must be a file, not a directory: {input_path}")
    runs_root = Path(args.runs_root).expanduser().resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    previous_latest = _load_json_if_exists(runs_root / "latest-run.json")
    previous_run_dir = Path(previous_latest["run_dir"]) if isinstance(previous_latest, dict) and previous_latest.get("run_dir") else None
    cache_root = Path(args.cache_root).expanduser().resolve() if args.cache_root else _default_cache_root(runs_root).resolve()
    cache_root.mkdir(parents=True, exist_ok=True)

    resume_manifest: dict | None = None
    if args.resume_latest and args.resume_run_dir:
        raise SystemExit("Use either --resume-latest or --resume-run-dir, not both.")
    if args.resume_latest:
        if not isinstance(previous_latest, dict) or not previous_latest.get("run_dir"):
            raise SystemExit("Cannot resume latest run because latest-run.json is missing or incomplete.")
        resume_manifest = previous_latest
        run_dir = Path(str(previous_latest["run_dir"])).expanduser().resolve()
    elif args.resume_run_dir:
        run_dir = Path(args.resume_run_dir).expanduser().resolve()
        manifest_candidate = _load_json_if_exists(run_dir.parent / "latest-run.json")
        if isinstance(manifest_candidate, dict) and manifest_candidate.get("run_dir") == str(run_dir):
            resume_manifest = manifest_candidate
        elif (run_dir / "cache").exists():
            resume_manifest = {"cache_dir": str((run_dir / "cache").resolve())}
    else:
        run_dir = _next_run_dir(runs_root, args.run_prefix)

    if resume_manifest and resume_manifest.get("previous_run_dir"):
        previous_run_dir = Path(str(resume_manifest["previous_run_dir"])).expanduser().resolve()

    cache_dir = Path(str(resume_manifest["cache_dir"])).expanduser().resolve() if resume_manifest and resume_manifest.get("cache_dir") else cache_root

    command = [
        sys.executable,
        "-m",
        "ml_pipeline.run_experiment_suite",
        "--input",
        str(input_path),
        "--output-dir",
        str(run_dir),
        "--cache-dir",
        str(cache_dir),
        "--model-threshold",
        str(args.model_threshold),
        "--ids-threshold",
        str(args.ids_threshold),
        "--parallel-jobs",
        str(args.parallel_jobs),
    ]
    if args.fast_mode:
        command.append("--fast-mode")
    if args.max_total_windows > 0:
        command.extend(["--max-total-windows", str(args.max_total_windows)])
    if args.max_benign_windows > 0:
        command.extend(["--max-benign-windows", str(args.max_benign_windows)])
    if args.skip_evaluation_protocol:
        command.append("--skip-evaluation-protocol")
    if args.resume_latest or args.resume_run_dir:
        command.extend(["--allow-existing-output", "--resume"])

    latest_manifest = {
        "run_dir": str(run_dir),
        "cache_dir": str(cache_dir),
        "cache_root": str(cache_root),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "previous_run_dir": str(previous_run_dir) if previous_run_dir else None,
        "status": "running",
    }
    latest_path = runs_root / "latest-run.json"
    latest_path.write_text(json.dumps(latest_manifest, indent=2), encoding="utf-8")

    print(f"Starting training run in: {run_dir}", flush=True)
    subprocess.run(command, check=True)
    diff = _build_run_diff(previous_run_dir, run_dir)
    (run_dir / "reports" / "run-diff.json").write_text(json.dumps(diff, indent=2), encoding="utf-8")
    _print_summary(run_dir, diff)

    latest_manifest["status"] = "completed"
    latest_manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    latest_path.write_text(json.dumps(latest_manifest, indent=2), encoding="utf-8")
    print(f"Latest run manifest written to: {latest_path}", flush=True)


if __name__ == "__main__":
    main()
