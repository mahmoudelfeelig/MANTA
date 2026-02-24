from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate policy thresholds against scored windows")
    parser.add_argument("--input", required=True, help="CSV with app_id and anomaly_score columns")
    parser.add_argument("--policy", required=True, help="Policy JSON path")
    parser.add_argument("--output", required=True, help="Simulation report JSON path")
    parser.add_argument("--per-app-output", default="", help="Optional CSV for per-app severity distribution")
    parser.add_argument("--app-column", default="app_id")
    parser.add_argument("--score-column", default="anomaly_score")
    parser.add_argument("--existing-severity-column", default="severity")
    parser.add_argument("--limit", type=int, default=0, help="Evaluate only the latest N rows (0 = all)")
    return parser.parse_args()


def _load_policy(path: Path) -> dict:
    root = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(root, dict) and isinstance(root.get("policy"), dict):
        return root["policy"]
    if isinstance(root, dict):
        return root
    raise SystemExit("Policy file must be a JSON object")


def _severity(score: float, medium: float, high: float) -> str:
    if score >= high:
        return "HIGH"
    if score >= medium:
        return "MEDIUM"
    return "LOW"


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    if args.app_column not in df.columns:
        raise SystemExit(f"Missing app column: {args.app_column}")
    if args.score_column not in df.columns:
        raise SystemExit(f"Missing score column: {args.score_column}")

    if args.limit > 0 and len(df) > args.limit:
        df = df.tail(args.limit).reset_index(drop=True)

    policy = _load_policy(Path(args.policy))
    defaults = policy.get("default_thresholds", {}) if isinstance(policy, dict) else {}
    medium_default = float(defaults.get("medium", 0.6))
    high_default = float(defaults.get("high", 0.85))
    if high_default < medium_default:
        high_default = medium_default
    overrides = policy.get("app_threshold_overrides", {}) if isinstance(policy, dict) else {}

    simulation = df[[args.app_column, args.score_column]].copy()
    simulation.columns = ["app_id", "anomaly_score"]

    medium_values = []
    high_values = []
    simulated_severity = []
    for app_id, score in simulation[["app_id", "anomaly_score"]].itertuples(index=False):
        override = overrides.get(str(app_id), {}) if isinstance(overrides, dict) else {}
        medium = float(override.get("medium", medium_default))
        high = float(override.get("high", high_default))
        if high < medium:
            high = medium
        medium_values.append(medium)
        high_values.append(high)
        simulated_severity.append(_severity(float(score), medium=medium, high=high))

    simulation["medium_threshold"] = medium_values
    simulation["high_threshold"] = high_values
    simulation["simulated_severity"] = simulated_severity

    severity_distribution = (
        simulation["simulated_severity"]
        .value_counts()
        .reindex(["LOW", "MEDIUM", "HIGH"], fill_value=0)
        .to_dict()
    )

    per_app = (
        simulation.groupby(["app_id", "simulated_severity"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=["LOW", "MEDIUM", "HIGH"], fill_value=0)
        .reset_index()
    )
    per_app["total"] = per_app[["LOW", "MEDIUM", "HIGH"]].sum(axis=1)
    per_app = per_app.sort_values("total", ascending=False, kind="mergesort")

    change_summary: dict[str, int] = {}
    if args.existing_severity_column in df.columns:
        old = df[args.existing_severity_column].astype(str).str.upper()
        merged = pd.DataFrame(
            {
                "old_severity": old.values,
                "new_severity": simulation["simulated_severity"].values,
            }
        )
        changed = merged[merged["old_severity"] != merged["new_severity"]]
        change_summary = {
            "rows_with_existing_severity": int(len(merged)),
            "rows_changed": int(len(changed)),
        }

    report = {
        "rows_evaluated": int(len(simulation)),
        "default_thresholds": {"medium": medium_default, "high": high_default},
        "override_count": int(len(overrides)) if isinstance(overrides, dict) else 0,
        "severity_distribution": {k: int(v) for k, v in severity_distribution.items()},
        "per_app_distribution_top10": [
            {
                "app_id": str(row["app_id"]),
                "low": int(row["LOW"]),
                "medium": int(row["MEDIUM"]),
                "high": int(row["HIGH"]),
                "total": int(row["total"]),
            }
            for _, row in per_app.head(10).iterrows()
        ],
        "change_summary": change_summary,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.per_app_output:
        per_app_output = Path(args.per_app_output)
        per_app_output.parent.mkdir(parents=True, exist_ok=True)
        per_app.to_csv(per_app_output, index=False)


if __name__ == "__main__":
    main()
