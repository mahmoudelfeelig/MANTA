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
    parser.add_argument("--privacy-gate-report", default="")
    parser.add_argument("--performance-report", default="")
    parser.add_argument("--dataset-manifest", default="")
    parser.add_argument("--traffic-fingerprint-report", default="")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _metric_keys(payload: dict) -> dict[str, object]:
    return {
        key: payload.get(key)
        for key in ("precision", "recall", "f1", "pr_auc", "roc_auc", "brier_score", "ece", "threshold", "training_seconds")
    }


def _gate_thresholds(category: str) -> dict[str, float]:
    if category == "on_device_one_class":
        return {"roc_auc": 0.90, "pr_auc": 0.88, "f1": 0.86, "precision": 0.84, "recall": 0.88}
    if category in {"on_device_supervised", "remote_primary", "remote_family_benchmark", "privacy_preserving_student", "federated"}:
        return {"roc_auc": 0.95, "pr_auc": 0.90 if category == "on_device_supervised" else 0.92, "f1": 0.90, "precision": 0.88, "recall": 0.92}
    return {}


def _gate_verdict(category: str, row: dict[str, object]) -> dict[str, object]:
    thresholds = _gate_thresholds(category)
    checks: dict[str, bool | None] = {}
    for metric, minimum in thresholds.items():
        value = row.get(metric)
        checks[metric] = None if not isinstance(value, (int, float)) else float(value) >= float(minimum)
    completed_checks = [value for value in checks.values() if value is not None]
    overall = all(value is True for value in completed_checks) if completed_checks else None
    return {"thresholds": thresholds, "checks": checks, "pass": overall}


def main() -> None:
    args = parse_args()
    android = _load(args.android_report)
    remote = _load(args.remote_report)
    tflite = _load(args.tflite_report)
    privacy_student = _load(args.privacy_student_report)
    federated = _load(args.federated_report)
    family = _load(args.family_comparison_report)
    privacy_gate = _load(args.privacy_gate_report) if args.privacy_gate_report else {}
    performance = _load(args.performance_report) if args.performance_report else {}
    dataset_manifest = _load(args.dataset_manifest) if args.dataset_manifest else {}
    traffic_fingerprint = _load(args.traffic_fingerprint_report) if args.traffic_fingerprint_report else {}

    remote_metrics = (remote.get("training_report") or {}).get("metrics", {})
    remote_family = remote.get("model_family") or (remote.get("training_report") or {}).get("model_family")
    matrix = [
        {
            "model": "android_linear",
            "category": "on_device_supervised",
            **_metric_keys(android),
        },
        {
            "model": "tflite_one_class",
            "category": "on_device_one_class",
            **_metric_keys(tflite),
        },
        {
            "model": "remote_primary",
            "category": "remote_primary",
            "family": remote_family,
            "training_seconds": remote.get("training_seconds"),
            **_metric_keys(remote_metrics),
        },
        {
            "model": "privacy_student",
            "category": "privacy_preserving_student",
            "view": privacy_student.get("student_view"),
            **_metric_keys(privacy_student),
        },
        {
            "model": "federated_medium",
            "category": "federated",
            "view": federated.get("view"),
            "representation": federated.get("representation"),
            **_metric_keys(federated),
        },
    ]
    for row in family.get("families", []):
        matrix.append(
            {
                "model": f"remote_family::{row['family']}",
                "category": "remote_family_benchmark",
                "family": row["family"],
                **_metric_keys(row),
            }
        )

    for row in matrix:
        row["gate_verdict"] = _gate_verdict(str(row["category"]), row)
        if performance:
            row["feature_extraction_p95_ms"] = (performance.get("window_extraction_single_ms") or {}).get("p95")
            row["feature_matrix_p95_ms"] = (performance.get("feature_matrix_single_window_ms") or {}).get("p95")

    ranked_by_f1 = [row for row in matrix if isinstance(row.get("f1"), (int, float))]
    ranked_by_pr = [row for row in matrix if isinstance(row.get("pr_auc"), (int, float))]
    summary = {
        "remote_primary_family": remote_family,
        "best_f1_model": max(ranked_by_f1, key=lambda row: float(row["f1"]))["model"] if ranked_by_f1 else None,
        "best_pr_auc_model": max(ranked_by_pr, key=lambda row: float(row["pr_auc"]))["model"] if ranked_by_pr else None,
        "federated_view": federated.get("view"),
        "federated_representation": federated.get("representation"),
        "privacy_gate_verdicts": privacy_gate.get("verdicts"),
        "observer_inference_audit": privacy_gate.get("observer_inference_audit"),
        "traffic_fingerprint_strongest_task": traffic_fingerprint.get("strongest_task"),
        "dataset_public_only_protocol_ready": dataset_manifest.get("public_only_protocol_ready"),
    }

    passing_rows = [row for row in matrix if (row.get("gate_verdict") or {}).get("pass") is True]
    recommended = {
        "on_device_primary": next((row["model"] for row in passing_rows if row["model"] == "android_linear"), None),
        "remote_primary": next((row["model"] for row in passing_rows if row["model"] == "remote_primary"), None),
        "privacy_variant": (
            "privacy_student"
            if (privacy_gate.get("verdicts") or {}).get("medium", {}).get("overall_pass") and any(row["model"] == "privacy_student" and (row.get("gate_verdict") or {}).get("pass") for row in matrix)
            else None
        ),
        "federated_variant": next((row["model"] for row in passing_rows if row["model"] == "federated_medium"), None),
    }

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"summary": summary, "recommended_deployment": recommended, "matrix": matrix}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
