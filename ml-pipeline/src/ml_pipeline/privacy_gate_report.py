from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a combined privacy gate verdict from utility and leakage reports")
    parser.add_argument("--ablation-report", required=True)
    parser.add_argument("--leakage-report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--medium-max-relative-drop", type=float, default=0.05)
    parser.add_argument("--strict-max-relative-drop", type=float, default=0.10)
    parser.add_argument("--medium-max-app-reid", type=float, default=0.45)
    parser.add_argument("--strict-max-app-reid", type=float, default=0.25)
    return parser.parse_args()


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _tier_thresholds(view: str, args: argparse.Namespace) -> dict[str, float | None]:
    if view == "medium":
        return {
            "max_relative_drop": float(args.medium_max_relative_drop),
            "max_app_reid": float(args.medium_max_app_reid),
        }
    if view == "strict":
        return {
            "max_relative_drop": float(args.strict_max_relative_drop),
            "max_app_reid": float(args.strict_max_app_reid),
        }
    return {
        "max_relative_drop": None,
        "max_app_reid": None,
    }


def main() -> None:
    args = parse_args()
    ablation = _load(args.ablation_report)
    leakage = _load(args.leakage_report)

    verdicts: dict[str, dict[str, object]] = {}
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
        app_reid = leakage_metrics.get("app_reidentification_accuracy")
        if thresholds["max_app_reid"] is not None and isinstance(app_reid, (int, float)):
            leakage_pass = float(app_reid) <= float(thresholds["max_app_reid"])

        feature_group_results = leakage_metrics.get("feature_group_results") or {}
        hotspot_groups = sorted(
            [
                {
                    "group": str(group_name),
                    "app_reidentification_accuracy": group_metrics.get("app_reidentification_accuracy"),
                    "macro_f1": group_metrics.get("macro_f1"),
                }
                for group_name, group_metrics in feature_group_results.items()
            ],
            key=lambda row: float(row["app_reidentification_accuracy"] or 0.0),
            reverse=True,
        )
        verdicts[view_name] = {
            "utility_pass": utility_pass,
            "leakage_pass": leakage_pass,
            "overall_pass": utility_pass and leakage_pass,
            "utility_relative_drops": deltas,
            "leakage": leakage_metrics,
            "thresholds": thresholds,
            "feature_group_hotspots": hotspot_groups[:5],
        }

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"verdicts": verdicts}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
