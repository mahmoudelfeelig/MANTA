from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


POSITIVE_STATUSES = {"RESOLVED", "DANGEROUS", "TRUE_POSITIVE", "MALICIOUS"}
NEGATIVE_STATUSES = {"FALSE_POSITIVE", "NEUTRAL", "DISMISSED", "BENIGN"}


def _read_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    parsed = json.loads(text)
    if isinstance(parsed, list):
        return [row for row in parsed if isinstance(row, dict)]
    for key in ("alerts", "records", "items", "events"):
        value = parsed.get(key) if isinstance(parsed, dict) else None
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def android_alert_feedback_to_training_csv(input_json: Path, output_csv: Path) -> None:
    rows = []
    for record in _read_records(input_json):
        status = str(record.get("triage_status") or record.get("triageStatus") or "").upper()
        if status in POSITIVE_STATUSES:
            label = 1
        elif status in NEGATIVE_STATUSES:
            label = 0
        else:
            continue
        row = {
            "app_id": record.get("app_id") or record.get("appId") or "unknown",
            "timestamp_end": int(record.get("last_seen") or record.get("timestamp") or record.get("createdAtMillis") or 0),
            "label": label,
            "feedback_status": status,
            "dataset_source": "android_feedback",
            "dataset_profile": "user_triage",
            "dataset_variant": "local_feedback",
            "environment_id": record.get("device_id_pseudo") or "local_device",
            "session_id": record.get("alert_id") or record.get("id") or "feedback",
        }
        features = record.get("feature_window") or record.get("features") or {}
        if isinstance(features, dict):
            row.update(features)
        rows.append(row)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output_csv, index=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert Android alert triage feedback into training rows")
    parser.add_argument("--input-alerts-json", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    android_alert_feedback_to_training_csv(Path(args.input_alerts_json), Path(args.output))


if __name__ == "__main__":
    main()
