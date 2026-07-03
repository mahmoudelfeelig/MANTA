from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build retraining dataset from analyst triage samples")
    parser.add_argument("--input", required=True, help="Input JSON or CSV containing triaged alert samples")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--report", required=True, help="Output JSON quality report path")
    parser.add_argument("--max-rows", type=int, default=50_000)
    parser.add_argument("--min-per-class", type=int, default=25)
    return parser.parse_args()


def _load_frame(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("samples"), list):
        return pd.DataFrame(payload["samples"])
    if isinstance(payload, list):
        return pd.DataFrame(payload)
    raise SystemExit("Unsupported JSON payload shape; expected list or {'samples': [...]} object")


def _derive_label(frame: pd.DataFrame) -> pd.Series:
    if "label" in frame.columns:
        return frame["label"].fillna(-1).astype(int)
    if "triage_status" in frame.columns:
        status = frame["triage_status"].astype(str).str.upper().str.strip()
        label = pd.Series([-1] * len(frame), index=frame.index, dtype="int64")
        label = label.mask(status == "FALSE_POSITIVE", 0)
        label = label.mask(status == "RESOLVED", 1)
        return label
    return pd.Series([-1] * len(frame), index=frame.index, dtype="int64")


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    report_path = Path(args.report)

    raw = _load_frame(input_path)
    if raw.empty:
        raise SystemExit("Input samples are empty")

    frame = raw.copy()
    frame["label"] = _derive_label(frame)
    frame = frame[frame["label"].isin([0, 1])].copy()
    if frame.empty:
        raise SystemExit("No trainable samples found. Provide triage statuses RESOLVED/FALSE_POSITIVE or explicit labels.")

    # Keep latest record for duplicate alert IDs.
    if "alert_id" in frame.columns:
        timestamp_col = "timestamp" if "timestamp" in frame.columns else None
        if timestamp_col:
            frame = frame.sort_values(timestamp_col, kind="mergesort").drop_duplicates("alert_id", keep="last")
        else:
            frame = frame.drop_duplicates("alert_id", keep="last")

    numeric_defaults = {
        "anomaly_score": 0.0,
        "confidence": 0.5,
        "uncertainty": 0.5,
        "drift_score": 0.0,
        "beacon_score": 0.0,
        "timestamp": 0,
    }
    for column, default in numeric_defaults.items():
        if column not in frame.columns:
            frame[column] = default
        frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(default)

    for column in ("app_id", "source_model", "triage_status", "triage_note"):
        if column not in frame.columns:
            frame[column] = ""
        frame[column] = frame[column].astype(str)

    selected_columns = [
        "alert_id",
        "app_id",
        "source_model",
        "anomaly_score",
        "confidence",
        "uncertainty",
        "drift_score",
        "beacon_score",
        "triage_status",
        "triage_note",
        "timestamp",
        "label",
    ]
    for column in selected_columns:
        if column not in frame.columns:
            frame[column] = ""

    dataset = frame[selected_columns].copy()
    dataset = dataset.sort_values("timestamp", kind="mergesort")
    if len(dataset) > args.max_rows:
        dataset = dataset.tail(args.max_rows).reset_index(drop=True)
    else:
        dataset = dataset.reset_index(drop=True)

    class_counts = dataset["label"].value_counts().to_dict()
    positives = int(class_counts.get(1, 0))
    negatives = int(class_counts.get(0, 0))
    total = int(len(dataset))
    positive_ratio = float(positives / total) if total > 0 else 0.0
    imbalance_ratio = float(max(positives, negatives) / max(1, min(positives, negatives)))
    too_small = positives < args.min_per_class or negatives < args.min_per_class

    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(output_path, index=False)

    report = {
        "rows_raw": int(len(raw)),
        "rows_labeled": int(len(frame)),
        "rows_exported": total,
        "class_counts": {"label_0": negatives, "label_1": positives},
        "positive_ratio": positive_ratio,
        "imbalance_ratio": imbalance_ratio,
        "min_per_class": int(args.min_per_class),
        "sufficient_per_class": bool(not too_small),
        "feature_columns": [
            "anomaly_score",
            "confidence",
            "uncertainty",
            "drift_score",
            "beacon_score",
            "source_model",
        ],
    }
    if too_small:
        report["warning"] = "Class counts are below min-per-class; collect more triaged alerts before retraining."

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
