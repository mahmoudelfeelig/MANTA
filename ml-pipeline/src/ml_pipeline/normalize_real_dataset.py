from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd


DEFAULT_ALIASES = {
    "timestamp_end": [
        "timestamp_end",
        "timestamp",
        "time",
        "ts",
        "flow_end",
        "flow_end_ms",
        "bidirectional_last_seen_ms",
        "last_seen_ms",
        "bidirectional_last_seen",
    ],
    "app_id": [
        "app_id",
        "app",
        "application",
        "application_name",
        "package_name",
        "service",
        "process_name",
        "category",
    ],
    "bytes_out": [
        "bytes_out",
        "src2dst_bytes",
        "src_to_dst_bytes",
        "fwd_bytes",
        "tot_fwd_pkts_len",
        "total_fwd_bytes",
        "totlen_fwd_pkts",
    ],
    "bytes_in": [
        "bytes_in",
        "dst2src_bytes",
        "dst_to_src_bytes",
        "bwd_bytes",
        "total_bwd_bytes",
        "totlen_bwd_pkts",
    ],
    "bytes_total": [
        "total_bytes",
        "bytes",
        "tot_bytes",
        "bidirectional_bytes",
    ],
    "packets_out": [
        "packets_out",
        "src2dst_packets",
        "src_to_dst_packets",
        "fwd_packets",
        "tot_fwd_pkts",
    ],
    "packets_in": [
        "packets_in",
        "dst2src_packets",
        "dst_to_src_packets",
        "bwd_packets",
        "tot_bwd_pkts",
    ],
    "packets_total": [
        "packets",
        "total_packets",
        "tot_pkts",
        "bidirectional_packets",
    ],
    "protocol": ["protocol", "proto", "l4_proto"],
    "dst_ip": ["dst_ip", "destination_ip", "dstip", "id_resp_h"],
    "dst_port": ["dst_port", "destination_port", "dstport", "l4_dst_port", "id_resp_p"],
    "dst_host": ["dst_host", "server_name", "host", "domain", "fqdn"],
    "label": ["label", "is_anomaly", "attack", "malicious", "class"],
    "dst_novelty": ["dst_novelty", "novelty_score"],
    "duration_ms": ["duration_ms", "duration", "flow_duration_ms", "dur"],
    "s_load": ["s_load", "sload", "src_load"],
    "r_load": ["r_load", "rload", "dst_load"],
    "s_payload_avg": ["s_payload_avg", "spayloadavg", "src_payload_avg"],
    "r_payload_avg": ["r_payload_avg", "rpayloadavg", "dst_payload_avg"],
    "s_inter_packet_avg": ["s_inter_packet_avg", "sinterpacketavg", "src_inter_packet_avg"],
    "r_inter_packet_avg": ["r_inter_packet_avg", "rinterpacketavg", "dst_inter_packet_avg"],
    "sttl": ["sttl", "src_ttl"],
    "rttl": ["rttl", "dst_ttl"],
    "s_ack_rate": ["s_ack_rate", "sackrate", "src_ack_rate"],
    "r_ack_rate": ["r_ack_rate", "rackrate", "dst_ack_rate"],
    "s_fin_rate": ["s_fin_rate", "sfinrate", "src_fin_rate"],
    "r_fin_rate": ["r_fin_rate", "rfinrate", "dst_fin_rate"],
    "s_psh_rate": ["s_psh_rate", "spshrate", "src_psh_rate"],
    "r_psh_rate": ["r_psh_rate", "rpshrate", "dst_psh_rate"],
    "s_syn_rate": ["s_syn_rate", "ssynrate", "src_syn_rate"],
    "r_syn_rate": ["r_syn_rate", "rsynrate", "dst_syn_rate"],
    "s_rst_rate": ["s_rst_rate", "srstrate", "src_rst_rate"],
    "r_rst_rate": ["r_rst_rate", "rrstrate", "dst_rst_rate"],
    "s_fragment_rate": ["s_fragment_rate", "sfragmentrate", "src_fragment_rate"],
    "r_fragment_rate": ["r_fragment_rate", "rfragmentrate", "dst_fragment_rate"],
    "s_win_tcp": ["s_win_tcp", "swintcp", "src_win_tcp"],
    "r_win_tcp": ["r_win_tcp", "rwintcp", "dst_win_tcp"],
    "s_ack_delay_avg": ["s_ack_delay_avg", "sackdelayavg", "src_ack_delay_avg"],
    "r_ack_delay_avg": ["r_ack_delay_avg", "rackdelayavg", "dst_ack_delay_avg"],
}


PROFILE_ALIASES = {
    "generic_flow": DEFAULT_ALIASES,
    "cicflowmeter": {
        **DEFAULT_ALIASES,
        "timestamp_end": DEFAULT_ALIASES["timestamp_end"] + ["timestamp_start"],
        "bytes_out": DEFAULT_ALIASES["bytes_out"] + ["total_length_of_fwd_packet", "subflow_fwd_bytes"],
        "bytes_in": DEFAULT_ALIASES["bytes_in"] + ["total_length_of_bwd_packet", "subflow_bwd_bytes"],
        "packets_out": DEFAULT_ALIASES["packets_out"] + ["total_fwd_packet", "subflow_fwd_packets"],
        "packets_in": DEFAULT_ALIASES["packets_in"] + ["total_bwd_packets", "subflow_bwd_packets"],
        "duration_ms": DEFAULT_ALIASES["duration_ms"] + ["flow_duration"],
        "s_payload_avg": DEFAULT_ALIASES["s_payload_avg"] + ["fwd_packet_length_mean", "fwd_segment_size_avg"],
        "r_payload_avg": DEFAULT_ALIASES["r_payload_avg"] + ["bwd_packet_length_mean", "bwd_segment_size_avg"],
        "s_inter_packet_avg": DEFAULT_ALIASES["s_inter_packet_avg"] + ["fwd_iat_mean"],
        "r_inter_packet_avg": DEFAULT_ALIASES["r_inter_packet_avg"] + ["bwd_iat_mean"],
        "s_ack_rate": DEFAULT_ALIASES["s_ack_rate"] + ["ack_flag_count"],
        "s_fin_rate": DEFAULT_ALIASES["s_fin_rate"] + ["fin_flag_count"],
        "s_psh_rate": DEFAULT_ALIASES["s_psh_rate"] + ["psh_flag_count", "fwd_psh_flags"],
        "s_syn_rate": DEFAULT_ALIASES["s_syn_rate"] + ["syn_flag_count"],
        "s_rst_rate": DEFAULT_ALIASES["s_rst_rate"] + ["rst_flag_count"],
        "s_win_tcp": DEFAULT_ALIASES["s_win_tcp"] + ["fwd_init_win_bytes"],
        "r_win_tcp": DEFAULT_ALIASES["r_win_tcp"] + ["bwd_init_win_bytes"],
    },
    "westermo": {
        **DEFAULT_ALIASES,
        "timestamp_end": DEFAULT_ALIASES["timestamp_end"] + ["end", "enddate"],
        "bytes_out": DEFAULT_ALIASES["bytes_out"] + ["sbytessum"],
        "bytes_in": DEFAULT_ALIASES["bytes_in"] + ["rbytessum"],
        "packets_out": DEFAULT_ALIASES["packets_out"] + ["spackets"],
        "packets_in": DEFAULT_ALIASES["packets_in"] + ["rpackets"],
        "protocol": DEFAULT_ALIASES["protocol"] + ["protocol"],
        "dst_ip": DEFAULT_ALIASES["dst_ip"] + ["rips", "raddress"],
        "label": ["it_b_label", "nst_b_label", "it_m_label", "nst_m_label"] + DEFAULT_ALIASES["label"],
        "duration_ms": DEFAULT_ALIASES["duration_ms"] + ["duration"],
        "s_load": DEFAULT_ALIASES["s_load"] + ["sload"],
        "r_load": DEFAULT_ALIASES["r_load"] + ["rload"],
        "s_payload_avg": DEFAULT_ALIASES["s_payload_avg"] + ["spayloadavg"],
        "r_payload_avg": DEFAULT_ALIASES["r_payload_avg"] + ["rpayloadavg"],
        "s_inter_packet_avg": DEFAULT_ALIASES["s_inter_packet_avg"] + ["sinterpacketavg"],
        "r_inter_packet_avg": DEFAULT_ALIASES["r_inter_packet_avg"] + ["rinterpacketavg"],
        "sttl": DEFAULT_ALIASES["sttl"] + ["sttl"],
        "rttl": DEFAULT_ALIASES["rttl"] + ["rttl"],
        "s_ack_rate": DEFAULT_ALIASES["s_ack_rate"] + ["sackrate"],
        "r_ack_rate": DEFAULT_ALIASES["r_ack_rate"] + ["rackrate"],
        "s_fin_rate": DEFAULT_ALIASES["s_fin_rate"] + ["sfinrate"],
        "r_fin_rate": DEFAULT_ALIASES["r_fin_rate"] + ["rfinrate"],
        "s_psh_rate": DEFAULT_ALIASES["s_psh_rate"] + ["spshrate"],
        "r_psh_rate": DEFAULT_ALIASES["r_psh_rate"] + ["rpshrate"],
        "s_syn_rate": DEFAULT_ALIASES["s_syn_rate"] + ["ssynrate"],
        "r_syn_rate": DEFAULT_ALIASES["r_syn_rate"] + ["rsynrate"],
        "s_rst_rate": DEFAULT_ALIASES["s_rst_rate"] + ["srstrate"],
        "r_rst_rate": DEFAULT_ALIASES["r_rst_rate"] + ["rrstrate"],
        "s_fragment_rate": DEFAULT_ALIASES["s_fragment_rate"] + ["sfragmentrate"],
        "r_fragment_rate": DEFAULT_ALIASES["r_fragment_rate"] + ["rfragmentrate"],
        "s_win_tcp": DEFAULT_ALIASES["s_win_tcp"] + ["swintcp"],
        "r_win_tcp": DEFAULT_ALIASES["r_win_tcp"] + ["rwintcp"],
        "s_ack_delay_avg": DEFAULT_ALIASES["s_ack_delay_avg"] + ["sackdelayavg"],
        "r_ack_delay_avg": DEFAULT_ALIASES["r_ack_delay_avg"] + ["rackdelayavg"],
    },
    "sdncampus": {
        **{
            key: list(value) if isinstance(value, list) else value
            for key, value in {
                **DEFAULT_ALIASES,
                **{
                    "bytes_out": DEFAULT_ALIASES["bytes_out"] + ["total_length_of_fwd_packet", "subflow_fwd_bytes"],
                    "bytes_in": DEFAULT_ALIASES["bytes_in"] + ["total_length_of_bwd_packet", "subflow_bwd_bytes"],
                    "packets_out": DEFAULT_ALIASES["packets_out"] + ["total_fwd_packet", "subflow_fwd_packets"],
                    "packets_in": DEFAULT_ALIASES["packets_in"] + ["total_bwd_packets", "subflow_bwd_packets"],
                    "duration_ms": DEFAULT_ALIASES["duration_ms"] + ["flow_duration"],
                    "s_payload_avg": DEFAULT_ALIASES["s_payload_avg"] + ["fwd_packet_length_mean", "fwd_segment_size_avg"],
                    "r_payload_avg": DEFAULT_ALIASES["r_payload_avg"] + ["bwd_packet_length_mean", "bwd_segment_size_avg"],
                    "s_inter_packet_avg": DEFAULT_ALIASES["s_inter_packet_avg"] + ["fwd_iat_mean"],
                    "r_inter_packet_avg": DEFAULT_ALIASES["r_inter_packet_avg"] + ["bwd_iat_mean"],
                    "s_ack_rate": DEFAULT_ALIASES["s_ack_rate"] + ["ack_flag_count"],
                    "s_fin_rate": DEFAULT_ALIASES["s_fin_rate"] + ["fin_flag_count"],
                    "s_psh_rate": DEFAULT_ALIASES["s_psh_rate"] + ["psh_flag_count", "fwd_psh_flags"],
                    "s_syn_rate": DEFAULT_ALIASES["s_syn_rate"] + ["syn_flag_count"],
                    "s_rst_rate": DEFAULT_ALIASES["s_rst_rate"] + ["rst_flag_count"],
                    "s_win_tcp": DEFAULT_ALIASES["s_win_tcp"] + ["fwd_init_win_bytes"],
                    "r_win_tcp": DEFAULT_ALIASES["r_win_tcp"] + ["bwd_init_win_bytes"],
                },
            }.items()
        },
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize a public flow dataset into MANTA canonical flow CSV")
    parser.add_argument("--input", required=True, help="Input CSV/TSV/Parquet file")
    parser.add_argument("--output", required=True, help="Output canonical CSV path")
    parser.add_argument("--profile", default="generic_flow", choices=sorted(PROFILE_ALIASES), help="Alias profile")
    parser.add_argument("--report", required=True, help="JSON report path")
    return parser.parse_args()


def canonicalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    renamed = {}
    for column in frame.columns:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(column).strip().lower()).strip("_")
        renamed[column] = normalized
    return frame.rename(columns=renamed)


def read_frame(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in {".tsv", ".txt"}:
        return pd.read_csv(path, sep="\t")
    if suffix == ".parquet":
        return pd.read_parquet(path)
    raise ValueError(f"Unsupported input format: {path.suffix}")


def pick_series(frame: pd.DataFrame, aliases: list[str]) -> tuple[str | None, pd.Series | None]:
    for alias in aliases:
        if alias in frame.columns:
            return alias, frame[alias]
    return None, None


def to_ms(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().mean() >= 0.7:
        median = float(numeric.dropna().median()) if numeric.notna().any() else 0.0
        if median < 1e11:
            return (numeric * 1000).round()
        return numeric.round()
    parsed = pd.to_datetime(series, errors="coerce", utc=True)
    millis = (parsed.astype("int64") // 1_000_000).astype("float64")
    millis[parsed.isna()] = np.nan
    return millis


def numeric_or_default(series: pd.Series | None, size: int, default: float = 0.0) -> pd.Series:
    if series is None:
        return pd.Series(np.full(size, default, dtype=float))
    numeric = pd.to_numeric(series, errors="coerce").fillna(default)
    if len(numeric) != size:
        numeric = numeric.reindex(range(size), fill_value=default)
    return numeric


def text_or_default(series: pd.Series | None, size: int, default: str = "") -> pd.Series:
    if series is None:
        return pd.Series([default] * size, dtype="object")
    values = series.astype(str).fillna(default)
    values = values.replace({"nan": default, "NaN": default, "None": default, "<NA>": default})
    if len(values) != size:
        values = values.reindex(range(size), fill_value=default)
    return values


def normalize_protocol_values(series: pd.Series) -> pd.Series:
    raw = series.astype(str).str.strip()
    mapped = raw.replace(
        {
            "6": "TCP",
            "17": "UDP",
            "1": "ICMP",
            "58": "ICMPV6",
        }
    )
    normalized = mapped.str.upper().str.replace(r"[^A-Z0-9]+", "_", regex=True).str.strip("_")
    return normalized.replace({"": "UNKNOWN"})


def normalize_label(series: pd.Series | None, size: int) -> pd.Series:
    if series is None:
        return pd.Series(np.zeros(size, dtype=int))
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().mean() >= 0.6:
        return numeric.fillna(0).clip(lower=0, upper=1).astype(int)
    values = series.astype(str).str.strip().str.lower()
    benign = values.str.contains(r"benign|normal|background|legitimate|allowed", regex=True)
    malicious = values.str.contains(r"attack|mal|anom|bot|spy|phish|intrusion|malware|bad|scan|mitm|ssh", regex=True)
    return malicious.where(malicious, False).astype(int).where(~benign, 0)


def derive_destination_key(frame: pd.DataFrame, dst_host: pd.Series | None, dst_ip: pd.Series | None, dst_port: pd.Series | None) -> pd.Series:
    host = text_or_default(dst_host, len(frame), "")
    ip = text_or_default(dst_ip, len(frame), "")
    port = text_or_default(dst_port, len(frame), "0")
    key = host.where(host.str.strip() != "", ip.where(ip.str.strip() != "", "unknown"))
    return key.str.strip() + ":" + port.str.strip().replace({"": "0"})


def derive_app_id(
    frame: pd.DataFrame,
    app_series: pd.Series | None,
    dst_port: pd.Series | None,
    protocol: pd.Series | None,
    dst_ip: pd.Series | None,
) -> pd.Series:
    if app_series is not None:
        values = app_series.astype(str).str.strip()
        return values.where(values != "", other="unknown_app")
    port = text_or_default(dst_port, len(frame), "0").str.strip().replace({"": "0"})
    proto = text_or_default(protocol, len(frame), "unknown").str.lower().str.strip().str.replace(r"[^a-z0-9]+", "_", regex=True)
    ip = text_or_default(dst_ip, len(frame), "unknown").str.strip().replace({"": "unknown"})
    return "service:" + proto + ":" + ip + ":" + port


def compute_dst_novelty(app_ids: pd.Series, destination_keys: pd.Series, timestamps: pd.Series) -> pd.Series:
    working = pd.DataFrame({
        "app_id": app_ids.astype(str),
        "destination_key": destination_keys.astype(str),
        "timestamp_end": timestamps,
    }).sort_values("timestamp_end", kind="mergesort")
    novelty = pd.Series(np.zeros(len(working), dtype=float), index=working.index)
    seen: dict[str, set[str]] = {}
    for index, row in working.iterrows():
        app_id = row["app_id"]
        destination_key = row["destination_key"]
        known = seen.setdefault(app_id, set())
        novelty.loc[index] = 0.0 if destination_key in known else 1.0
        known.add(destination_key)
    return novelty.sort_index()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    report_path = Path(args.report).expanduser().resolve()

    frame = canonicalize_columns(read_frame(input_path))
    aliases = PROFILE_ALIASES[args.profile]
    mapping_report: dict[str, str | None] = {}

    ts_name, ts_series = pick_series(frame, aliases["timestamp_end"])
    if ts_series is None:
        if args.profile == "sdncampus":
            mapping_report["timestamp_end"] = "row_index_ms"
            timestamp_end = pd.Series((np.arange(len(frame), dtype="int64") + 1) * 1000)
        else:
            raise ValueError("Could not find a timestamp column for timestamp_end")
    else:
        mapping_report["timestamp_end"] = ts_name
        timestamp_end = to_ms(ts_series)

    app_name, app_series = pick_series(frame, aliases["app_id"])
    mapping_report["app_id"] = app_name
    protocol_name, protocol_series = pick_series(frame, aliases["protocol"])
    mapping_report["protocol"] = protocol_name
    dst_ip_name, dst_ip_series = pick_series(frame, aliases["dst_ip"])
    mapping_report["dst_ip"] = dst_ip_name
    dst_port_name, dst_port_series = pick_series(frame, aliases["dst_port"])
    mapping_report["dst_port"] = dst_port_name
    dst_host_name, dst_host_series = pick_series(frame, aliases["dst_host"])
    mapping_report["dst_host"] = dst_host_name

    bytes_out_name, bytes_out_series = pick_series(frame, aliases["bytes_out"])
    bytes_in_name, bytes_in_series = pick_series(frame, aliases["bytes_in"])
    bytes_total_name, bytes_total_series = pick_series(frame, aliases["bytes_total"])
    mapping_report["bytes_out"] = bytes_out_name
    mapping_report["bytes_in"] = bytes_in_name
    mapping_report["bytes_total"] = bytes_total_name

    packets_out_name, packets_out_series = pick_series(frame, aliases["packets_out"])
    packets_in_name, packets_in_series = pick_series(frame, aliases["packets_in"])
    packets_total_name, packets_total_series = pick_series(frame, aliases["packets_total"])
    mapping_report["packets_out"] = packets_out_name
    mapping_report["packets_in"] = packets_in_name
    mapping_report["packets_total"] = packets_total_name

    label_name, label_series = pick_series(frame, aliases["label"])
    novelty_name, novelty_series = pick_series(frame, aliases["dst_novelty"])
    mapping_report["label"] = label_name
    mapping_report["dst_novelty"] = novelty_name

    if args.profile == "sdncampus" and app_series is None and label_series is not None:
        app_name = f"{label_name}(app_id)"
        app_series = label_series
        mapping_report["app_id"] = app_name

    optional_numeric_keys = [
        "duration_ms",
        "s_load",
        "r_load",
        "s_payload_avg",
        "r_payload_avg",
        "s_inter_packet_avg",
        "r_inter_packet_avg",
        "sttl",
        "rttl",
        "s_ack_rate",
        "r_ack_rate",
        "s_fin_rate",
        "r_fin_rate",
        "s_psh_rate",
        "r_psh_rate",
        "s_syn_rate",
        "r_syn_rate",
        "s_rst_rate",
        "r_rst_rate",
        "s_fragment_rate",
        "r_fragment_rate",
        "s_win_tcp",
        "r_win_tcp",
        "s_ack_delay_avg",
        "r_ack_delay_avg",
    ]
    optional_numeric_values: dict[str, pd.Series] = {}
    for key in optional_numeric_keys:
        source_name, source_series = pick_series(frame, aliases[key])
        mapping_report[key] = source_name
        optional_numeric_values[key] = numeric_or_default(source_series, len(frame))
    if mapping_report["duration_ms"] == "duration":
        duration_series = optional_numeric_values["duration_ms"]
        median_duration = float(duration_series.median()) if not duration_series.empty else 0.0
        if median_duration <= 100.0:
            optional_numeric_values["duration_ms"] = duration_series * 1000.0
    availability_flags = {
        "has_duration_ms": 1 if mapping_report["duration_ms"] is not None else 0,
        "has_load_metrics": 1 if mapping_report["s_load"] is not None or mapping_report["r_load"] is not None else 0,
        "has_payload_metrics": 1 if mapping_report["s_payload_avg"] is not None or mapping_report["r_payload_avg"] is not None else 0,
        "has_inter_packet_metrics": 1 if mapping_report["s_inter_packet_avg"] is not None or mapping_report["r_inter_packet_avg"] is not None else 0,
        "has_ttl_metrics": 1 if mapping_report["sttl"] is not None or mapping_report["rttl"] is not None else 0,
        "has_tcp_flag_metrics": 1 if any(mapping_report[key] is not None for key in ["s_ack_rate", "r_ack_rate", "s_fin_rate", "r_fin_rate", "s_psh_rate", "r_psh_rate", "s_syn_rate", "r_syn_rate", "s_rst_rate", "r_rst_rate"]) else 0,
        "has_fragment_metrics": 1 if mapping_report["s_fragment_rate"] is not None or mapping_report["r_fragment_rate"] is not None else 0,
        "has_window_metrics": 1 if mapping_report["s_win_tcp"] is not None or mapping_report["r_win_tcp"] is not None else 0,
        "has_ack_delay_metrics": 1 if mapping_report["s_ack_delay_avg"] is not None or mapping_report["r_ack_delay_avg"] is not None else 0,
    }

    bytes_out = numeric_or_default(bytes_out_series, len(frame))
    bytes_in = numeric_or_default(bytes_in_series, len(frame))
    if bytes_out.empty or bytes_in.empty:
        total = numeric_or_default(bytes_total_series, len(frame))
        if total.empty:
            raise ValueError("Could not derive bytes_out/bytes_in from the dataset")
        bytes_out = total * 0.5
        bytes_in = total * 0.5

    packets_out = numeric_or_default(packets_out_series, len(frame))
    packets_in = numeric_or_default(packets_in_series, len(frame))
    if packets_out.empty or packets_in.empty:
        total_packets = numeric_or_default(packets_total_series, len(frame))
        if total_packets.empty:
            total_packets = pd.Series(np.ones(len(frame), dtype=float))
        packets_out = np.ceil(total_packets * 0.5)
        packets_in = np.floor(total_packets * 0.5)

    protocol = normalize_protocol_values(text_or_default(protocol_series, len(frame), "UNKNOWN"))
    dst_port = numeric_or_default(dst_port_series, len(frame), 0).fillna(0).astype(int)
    destination_key = derive_destination_key(frame, dst_host_series, dst_ip_series, dst_port.astype(str))
    app_id = derive_app_id(frame, app_series, dst_port.astype(str), protocol, dst_ip_series)
    dst_novelty = (
        numeric_or_default(novelty_series, len(frame)).clip(lower=0.0, upper=1.0)
        if novelty_series is not None
        else compute_dst_novelty(app_id, destination_key, timestamp_end)
    )
    label = pd.Series(np.zeros(len(frame), dtype=int)) if args.profile == "sdncampus" else normalize_label(label_series, len(frame))

    canonical = pd.DataFrame(
        {
            "app_id": app_id.astype(str),
            "timestamp_end": timestamp_end.astype("int64"),
            "bytes_out": bytes_out.clip(lower=0).round().astype("int64"),
            "bytes_in": bytes_in.clip(lower=0).round().astype("int64"),
            "packets_out": pd.Series(packets_out).clip(lower=0).round().astype("int64"),
            "packets_in": pd.Series(packets_in).clip(lower=0).round().astype("int64"),
            "dst_novelty": dst_novelty.clip(lower=0.0, upper=1.0).astype("float64"),
            "label": label.astype("int64"),
            "destination_key": destination_key.astype(str),
            "protocol": protocol.astype(str),
            "dst_port": dst_port.astype("int64"),
            "duration_ms": optional_numeric_values["duration_ms"].clip(lower=0).round().astype("int64"),
            "s_load": optional_numeric_values["s_load"].clip(lower=0.0).astype("float64"),
            "r_load": optional_numeric_values["r_load"].clip(lower=0.0).astype("float64"),
            "s_payload_avg": optional_numeric_values["s_payload_avg"].clip(lower=0.0).astype("float64"),
            "r_payload_avg": optional_numeric_values["r_payload_avg"].clip(lower=0.0).astype("float64"),
            "s_inter_packet_avg": optional_numeric_values["s_inter_packet_avg"].clip(lower=0.0).astype("float64"),
            "r_inter_packet_avg": optional_numeric_values["r_inter_packet_avg"].clip(lower=0.0).astype("float64"),
            "sttl": optional_numeric_values["sttl"].clip(lower=0.0).astype("float64"),
            "rttl": optional_numeric_values["rttl"].clip(lower=0.0).astype("float64"),
            "s_ack_rate": optional_numeric_values["s_ack_rate"].clip(lower=0.0).astype("float64"),
            "r_ack_rate": optional_numeric_values["r_ack_rate"].clip(lower=0.0).astype("float64"),
            "s_fin_rate": optional_numeric_values["s_fin_rate"].clip(lower=0.0).astype("float64"),
            "r_fin_rate": optional_numeric_values["r_fin_rate"].clip(lower=0.0).astype("float64"),
            "s_psh_rate": optional_numeric_values["s_psh_rate"].clip(lower=0.0).astype("float64"),
            "r_psh_rate": optional_numeric_values["r_psh_rate"].clip(lower=0.0).astype("float64"),
            "s_syn_rate": optional_numeric_values["s_syn_rate"].clip(lower=0.0).astype("float64"),
            "r_syn_rate": optional_numeric_values["r_syn_rate"].clip(lower=0.0).astype("float64"),
            "s_rst_rate": optional_numeric_values["s_rst_rate"].clip(lower=0.0).astype("float64"),
            "r_rst_rate": optional_numeric_values["r_rst_rate"].clip(lower=0.0).astype("float64"),
            "s_fragment_rate": optional_numeric_values["s_fragment_rate"].clip(lower=0.0).astype("float64"),
            "r_fragment_rate": optional_numeric_values["r_fragment_rate"].clip(lower=0.0).astype("float64"),
            "s_win_tcp": optional_numeric_values["s_win_tcp"].clip(lower=0.0).astype("float64"),
            "r_win_tcp": optional_numeric_values["r_win_tcp"].clip(lower=0.0).astype("float64"),
            "s_ack_delay_avg": optional_numeric_values["s_ack_delay_avg"].clip(lower=0.0).astype("float64"),
            "r_ack_delay_avg": optional_numeric_values["r_ack_delay_avg"].clip(lower=0.0).astype("float64"),
            "has_duration_ms": availability_flags["has_duration_ms"],
            "has_load_metrics": availability_flags["has_load_metrics"],
            "has_payload_metrics": availability_flags["has_payload_metrics"],
            "has_inter_packet_metrics": availability_flags["has_inter_packet_metrics"],
            "has_ttl_metrics": availability_flags["has_ttl_metrics"],
            "has_tcp_flag_metrics": availability_flags["has_tcp_flag_metrics"],
            "has_fragment_metrics": availability_flags["has_fragment_metrics"],
            "has_window_metrics": availability_flags["has_window_metrics"],
            "has_ack_delay_metrics": availability_flags["has_ack_delay_metrics"],
        }
    ).dropna(subset=["timestamp_end"])

    canonical = canonical.sort_values("timestamp_end", kind="mergesort").reset_index(drop=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    canonical.to_csv(output_path, index=False)
    report = {
        "input": str(input_path),
        "output": str(output_path),
        "profile": args.profile,
        "rows": int(len(canonical)),
        "columns": list(canonical.columns),
        "label_counts": canonical["label"].value_counts().to_dict(),
        "column_mapping": mapping_report,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
