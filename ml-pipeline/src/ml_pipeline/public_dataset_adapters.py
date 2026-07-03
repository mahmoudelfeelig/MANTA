from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


BENIGN_TOKENS = {"benign", "normal", "legitimate", "goodware"}


def _first_present(frame: pd.DataFrame, candidates: list[str]) -> str | None:
    normalized = {column.strip().lower(): column for column in frame.columns}
    for candidate in candidates:
        key = candidate.strip().lower()
        if key in normalized:
            return normalized[key]
    return None


def _numeric(frame: pd.DataFrame, candidates: list[str], default: float = 0.0) -> pd.Series:
    column = _first_present(frame, candidates)
    if column is None:
        return pd.Series([default] * len(frame), index=frame.index, dtype=float)
    return pd.to_numeric(frame[column], errors="coerce").fillna(default)


def _text(frame: pd.DataFrame, candidates: list[str], default: str) -> pd.Series:
    column = _first_present(frame, candidates)
    if column is None:
        return pd.Series([default] * len(frame), index=frame.index, dtype="object")
    return frame[column].astype(str).replace({"": default}).fillna(default)


def _label_from_frame_or_path(frame: pd.DataFrame, path: Path) -> pd.Series:
    label_column = _first_present(frame, ["label", "class", "category", "malware", "is_anomaly"])
    if label_column is not None:
        raw = frame[label_column].astype(str).str.strip().str.lower()
        numeric = pd.to_numeric(frame[label_column], errors="coerce")
        return (
            numeric.fillna(raw.map(lambda value: 0 if value in BENIGN_TOKENS else 1))
            .fillna(1)
            .astype(int)
            .clip(lower=0, upper=1)
        )
    path_text = " ".join(part.lower() for part in path.parts)
    label = 0 if any(token in path_text for token in BENIGN_TOKENS) else 1
    return pd.Series([label] * len(frame), index=frame.index, dtype=int)


def _profile_from_path(path: Path) -> str:
    parts = [part.lower() for part in path.parts]
    for token in ("adware", "ransomware", "scareware", "smsmalware", "benign", "malware"):
        if any(token in part for part in parts):
            return token
    return "unknown_profile"


def normalize_public_android_flow_csv(path: Path, *, dataset_source: str) -> pd.DataFrame:
    frame = pd.read_csv(path)
    label = _label_from_frame_or_path(frame, path)
    timestamp = _numeric(frame, ["timestamp_end", "timestamp", "flow end time", "flow_end_time", "time"], default=0.0)
    if timestamp.max() < 10_000_000_000:
        timestamp = (timestamp + 1_700_000_000) * 1000

    bytes_out = _numeric(frame, ["bytes_out", "totlen fwd pkts", "total length of fwd packets", "fwd bytes", "sbytes"])
    bytes_in = _numeric(frame, ["bytes_in", "totlen bwd pkts", "total length of bwd packets", "bwd bytes", "dbytes"])
    packets_out = _numeric(frame, ["packets_out", "tot fwd pkts", "total fwd packets", "spkts"], default=1.0)
    packets_in = _numeric(frame, ["packets_in", "tot bwd pkts", "total backward packets", "dpkts"], default=1.0)
    dst_port = _numeric(frame, ["dst_port", "destination port", "dport", "destination_port"], default=0.0)
    protocol = _text(frame, ["protocol", "proto"], default="TCP")
    app_id = _text(frame, ["app_id", "package", "package_name", "app", "application"], default=f"{dataset_source}.unknown")
    destination = _text(
        frame,
        ["destination_key", "dst_ip", "destination ip", "destination_ip", "remote_ip", "dstip"],
        default="unknown",
    )

    canonical = pd.DataFrame(
        {
            "app_id": app_id,
            "timestamp_end": timestamp.astype("int64"),
            "bytes_out": bytes_out.clip(lower=0),
            "bytes_in": bytes_in.clip(lower=0),
            "packets_out": packets_out.clip(lower=0).astype(int),
            "packets_in": packets_in.clip(lower=0).astype(int),
            "dst_novelty": label.astype(float),
            "duration_ms": _numeric(frame, ["duration_ms", "flow duration", "dur"], default=0.0).clip(lower=0),
            "dst_port": dst_port.fillna(0).astype(int),
            "protocol": protocol,
            "destination_key": destination.astype(str) + ":" + dst_port.fillna(0).astype(int).astype(str),
            "label": label,
            "dataset_source": dataset_source,
            "dataset_profile": _profile_from_path(path),
            "dataset_variant": path.stem,
            "environment_id": dataset_source,
            "session_id": path.stem,
        }
    )
    return canonical


def convert_public_dataset(input_path: Path, output_csv: Path, *, dataset_source: str) -> None:
    paths = [input_path] if input_path.is_file() else sorted(input_path.rglob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"No CSV files found under {input_path}")
    frames = [normalize_public_android_flow_csv(path, dataset_source=dataset_source) for path in paths]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    pd.concat(frames, ignore_index=True).to_csv(output_csv, index=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize public Android network datasets to MANTA flow CSV")
    parser.add_argument("--input", required=True, help="Input CSV file or directory of CSV files")
    parser.add_argument("--output", required=True, help="Output canonical flow CSV")
    parser.add_argument(
        "--dataset-source",
        required=True,
        choices=["cic_andmal2017", "cic_aagm2017", "cic_maldroid2020", "other_public_android"],
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    convert_public_dataset(
        Path(args.input).expanduser(),
        Path(args.output).expanduser(),
        dataset_source=args.dataset_source,
    )


if __name__ == "__main__":
    main()
