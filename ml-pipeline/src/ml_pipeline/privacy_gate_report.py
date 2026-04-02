from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a combined privacy gate verdict from utility and leakage reports")
    parser.add_argument("--ablation-report", required=True)
    parser.add_argument("--leakage-report", required=True)
    parser.add_argument("--traffic-fingerprint-report", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--claim-scope", choices=("release", "observer", "combined"), default="release")
    parser.add_argument("--medium-max-relative-drop", type=float, default=0.05)
    parser.add_argument("--strict-max-relative-drop", type=float, default=0.10)
    parser.add_argument("--medium-max-app-reid", type=float, default=0.45)
    parser.add_argument("--strict-max-app-reid", type=float, default=0.25)
    parser.add_argument("--medium-max-normalized-app-reid", type=float, default=0.35)
    parser.add_argument("--strict-max-normalized-app-reid", type=float, default=0.15)
    parser.add_argument("--medium-max-app-family-normalized-leakage", type=float, default=0.50)
    parser.add_argument("--strict-max-app-family-normalized-leakage", type=float, default=0.30)
    parser.add_argument("--medium-max-destination-behavior-normalized-leakage", type=float, default=0.50)
    parser.add_argument("--strict-max-destination-behavior-normalized-leakage", type=float, default=0.30)
    parser.add_argument("--medium-max-observer-app-id-normalized-leakage", type=float, default=0.25)
    parser.add_argument("--strict-max-observer-app-id-normalized-leakage", type=float, default=0.10)
    parser.add_argument("--medium-max-observer-app-family-normalized-leakage", type=float, default=0.60)
    parser.add_argument("--strict-max-observer-app-family-normalized-leakage", type=float, default=0.35)
    return parser.parse_args()


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _tier_thresholds(view: str, args: argparse.Namespace) -> dict[str, float | None]:
    if view == "medium":
        return {
            "max_relative_drop": float(args.medium_max_relative_drop),
            "max_app_reid": float(args.medium_max_app_reid),
            "max_normalized_app_reid": float(args.medium_max_normalized_app_reid),
            "max_app_family_normalized_leakage": float(args.medium_max_app_family_normalized_leakage),
            "max_destination_behavior_normalized_leakage": float(args.medium_max_destination_behavior_normalized_leakage),
            "max_observer_app_id_normalized_leakage": float(args.medium_max_observer_app_id_normalized_leakage),
            "max_observer_app_family_normalized_leakage": float(args.medium_max_observer_app_family_normalized_leakage),
        }
    if view == "strict":
        return {
            "max_relative_drop": float(args.strict_max_relative_drop),
            "max_app_reid": float(args.strict_max_app_reid),
            "max_normalized_app_reid": float(args.strict_max_normalized_app_reid),
            "max_app_family_normalized_leakage": float(args.strict_max_app_family_normalized_leakage),
            "max_destination_behavior_normalized_leakage": float(args.strict_max_destination_behavior_normalized_leakage),
            "max_observer_app_id_normalized_leakage": float(args.strict_max_observer_app_id_normalized_leakage),
            "max_observer_app_family_normalized_leakage": float(args.strict_max_observer_app_family_normalized_leakage),
        }
    return {
        "max_relative_drop": None,
        "max_app_reid": None,
        "max_normalized_app_reid": None,
        "max_app_family_normalized_leakage": None,
        "max_destination_behavior_normalized_leakage": None,
        "max_observer_app_id_normalized_leakage": None,
        "max_observer_app_family_normalized_leakage": None,
    }


def _observer_risk_level(normalized_leakage: float | None) -> str | None:
    if not isinstance(normalized_leakage, (int, float)):
        return None
    if float(normalized_leakage) >= 0.75:
        return "severe"
    if float(normalized_leakage) >= 0.45:
        return "elevated"
    if float(normalized_leakage) >= 0.20:
        return "reduced"
    return "low"


def _sequence_audit(report: dict) -> dict[str, object]:
    tasks = report.get("results") or {}
    strongest_rows = [
        {
            "task_name": task_name,
            **payload.get("strongest_model", {}),
        }
        for task_name, payload in tasks.items()
        if isinstance(payload, dict) and isinstance(payload.get("strongest_model"), dict)
    ]
    strongest = max(
        strongest_rows,
        key=lambda row: (
            float(row.get("normalized_leakage") or 0.0),
            float(row.get("macro_f1") or 0.0),
            float(row.get("accuracy") or 0.0),
        ),
        default=None,
    )
    summary = {
        "benchmark": report.get("benchmark"),
        "representation": report.get("representation"),
        "strongest_task": strongest,
        "observer_risk_level": _observer_risk_level((strongest or {}).get("normalized_leakage") if isinstance(strongest, dict) else None),
        "note": "This sequence benchmark audits encrypted-flow observer leakage separately from the release-privacy feature views.",
    }
    return summary


def _task_strongest(report: dict, task_name: str) -> dict[str, object]:
    task = ((report.get("tasks") or {}).get(task_name) or {}) if isinstance(report, dict) else {}
    return task.get("strongest_model") or {}


def _observer_task_strongest(report: dict, task_name: str) -> dict[str, object]:
    task = ((report.get("results") or {}).get(task_name) or {}) if isinstance(report, dict) else {}
    return task.get("strongest_model") or {}


def _threshold_check(value: object, maximum: float | None) -> bool | None:
    if maximum is None:
        return None
    if not isinstance(value, (int, float)):
        return None
    return float(value) <= float(maximum)


def main() -> None:
    args = parse_args()
    ablation = _load(args.ablation_report)
    leakage = _load(args.leakage_report)
    traffic_fingerprint = _load(args.traffic_fingerprint_report) if args.traffic_fingerprint_report else {}

    verdicts: dict[str, dict[str, object]] = {}
    observer_app_id = _observer_task_strongest(traffic_fingerprint, "app_id") if traffic_fingerprint else {}
    observer_app_family = _observer_task_strongest(traffic_fingerprint, "app_family") if traffic_fingerprint else {}
    for view_name, metrics in (ablation.get("results") or {}).items():
        leakage_metrics = (leakage.get("results") or {}).get(view_name, {})
        deltas = (ablation.get("deltas") or {}).get(view_name, {})
        thresholds = _tier_thresholds(view_name, args)
        relative_drop_values = [
            value
            for key, value in deltas.items()
            if key.endswith("_relative_drop_vs_off") and isinstance(value, (int, float))
        ]
        utility_pass = True
        leakage_pass = True
        if thresholds["max_relative_drop"] is not None:
            utility_pass = all(float(value) <= float(thresholds["max_relative_drop"]) for value in relative_drop_values)
        app_family_metrics = _task_strongest(leakage_metrics, "app_family")
        destination_behavior_metrics = _task_strongest(leakage_metrics, "destination_behavior")
        metadata_task_checks = {
            "app_reidentification_accuracy": _threshold_check(leakage_metrics.get("app_reidentification_accuracy"), thresholds["max_app_reid"]),
            "app_reidentification_normalized": _threshold_check(leakage_metrics.get("normalized_app_reidentification"), thresholds["max_normalized_app_reid"]),
            "app_family_normalized": _threshold_check(app_family_metrics.get("normalized_leakage"), thresholds["max_app_family_normalized_leakage"]),
            "destination_behavior_normalized": _threshold_check(destination_behavior_metrics.get("normalized_leakage"), thresholds["max_destination_behavior_normalized_leakage"]),
        }
        active_metadata_checks = [value for value in metadata_task_checks.values() if value is not None]
        leakage_pass = all(value is True for value in active_metadata_checks) if active_metadata_checks else True
        observer_task_checks = {
            "observer_app_id_normalized": _threshold_check(observer_app_id.get("normalized_leakage"), thresholds["max_observer_app_id_normalized_leakage"]),
            "observer_app_family_normalized": _threshold_check(observer_app_family.get("normalized_leakage"), thresholds["max_observer_app_family_normalized_leakage"]),
        }
        active_observer_checks = [value for value in observer_task_checks.values() if value is not None]
        observer_pass = all(value is True for value in active_observer_checks) if active_observer_checks else True

        feature_group_results = leakage_metrics.get("feature_group_results") or {}
        hotspot_groups = sorted(
            [
                {
                    "group": str(group_name),
                    "app_reidentification_accuracy": group_metrics.get("app_reidentification_accuracy"),
                    "macro_f1": group_metrics.get("macro_f1"),
                    "normalized_leakage": group_metrics.get("normalized_leakage"),
                }
                for group_name, group_metrics in feature_group_results.items()
            ],
            key=lambda row: float(row["app_reidentification_accuracy"] or 0.0),
            reverse=True,
        )
        release_privacy_pass = utility_pass and leakage_pass
        observer_privacy_pass = observer_pass
        if args.claim_scope == "combined":
            overall_pass = release_privacy_pass and observer_privacy_pass
        elif args.claim_scope == "observer":
            overall_pass = observer_privacy_pass
        else:
            overall_pass = release_privacy_pass
        verdicts[view_name] = {
            "utility_pass": utility_pass,
            "leakage_pass": leakage_pass,
            "observer_pass": observer_pass,
            "release_privacy_pass": release_privacy_pass,
            "observer_privacy_pass": observer_privacy_pass,
            "claim_scope": args.claim_scope,
            "overall_pass": overall_pass,
            "utility_relative_drops": deltas,
            "leakage": leakage_metrics,
            "thresholds": thresholds,
            "metadata_task_checks": metadata_task_checks,
            "observer_task_checks": observer_task_checks,
            "feature_group_hotspots": hotspot_groups[:5],
        }

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {"verdicts": verdicts}
    if traffic_fingerprint:
        payload["observer_inference_audit"] = _sequence_audit(traffic_fingerprint)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
