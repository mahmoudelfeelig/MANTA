from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Combine privacy utility and leakage reports into a Pareto summary")
    parser.add_argument("--ablation-report", required=True)
    parser.add_argument("--leakage-report", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-csv", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ablation = json.loads(Path(args.ablation_report).read_text(encoding="utf-8"))
    leakage = json.loads(Path(args.leakage_report).read_text(encoding="utf-8"))
    rows: list[dict[str, object]] = []
    for view_name, metrics in (ablation.get("results") or {}).items():
        leakage_metrics = (leakage.get("results") or {}).get(view_name, {})
        rows.append(
            {
                "view": view_name,
                "f1": metrics.get("f1"),
                "pr_auc": metrics.get("pr_auc"),
                "roc_auc": metrics.get("roc_auc"),
                "app_reidentification_accuracy": leakage_metrics.get("app_reidentification_accuracy"),
                "macro_f1_leakage": leakage_metrics.get("macro_f1"),
            }
        )
    payload = {"rows": rows}
    output_json = Path(args.output_json).expanduser().resolve()
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    output_csv = Path(args.output_csv).expanduser().resolve()
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        headers = list(rows[0].keys())
        lines = [",".join(headers)]
        for row in rows:
            lines.append(",".join("" if row[key] is None else str(row[key]) for key in headers))
        output_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        output_csv.write_text("view,f1,pr_auc,roc_auc,app_reidentification_accuracy,macro_f1_leakage\n", encoding="utf-8")


if __name__ == "__main__":
    main()
