from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import sys


FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "frame.len",
    "ip.proto",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "http.host",
]


@dataclass
class FlowAccumulator:
    app_id: str
    label: int
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    start_ts: float
    end_ts: float
    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0
    site_hint: str | None = None


@dataclass
class CaptureIssue:
    path: str
    severity: str
    message: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert PCAP captures into MANTA canonical flow CSV using tshark")
    parser.add_argument("--profile", choices=["parrot", "android_spyware"], required=True)
    parser.add_argument("--input-dir", required=True, help="Directory containing .pcap files")
    parser.add_argument("--glob", default="*.pcap", help="Glob for PCAP files under input-dir")
    parser.add_argument("--output", required=True, help="Canonical CSV output path")
    parser.add_argument("--report", required=True, help="JSON-free CSV conversion report path")
    parser.add_argument("--tshark", default="tshark", help="Path to tshark executable")
    return parser.parse_args()


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def pick_ip(row: dict[str, str], primary: str, secondary: str) -> str:
    return (row.get(primary) or row.get(secondary) or "").strip()


def pick_port(row: dict[str, str], tcp_key: str, udp_key: str) -> int:
    raw = (row.get(tcp_key) or row.get(udp_key) or "").strip()
    try:
        return int(raw)
    except ValueError:
        return 0


def normalize_protocol(raw_protocol: str, ip_proto: str) -> str:
    candidate = raw_protocol.strip().upper().replace("/", "-").replace(" ", "-")
    if candidate in {"TCP", "UDP", "TLS", "HTTP", "HTTP2", "QUIC", "DNS"}:
        return candidate
    proto_map = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPV6",
    }
    if ip_proto in proto_map:
        return proto_map[ip_proto]
    if candidate:
        return candidate
    return "UNKNOWN"


def infer_app_id(path: Path, profile: str) -> str:
    stem = path.stem
    if profile == "parrot":
        stem = re.sub(r"_\d{4}-\d{2}-\d{2}-\d{4}_\d+$", "", stem)
        return stem.strip()
    normalized = re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")
    return normalized or "unknown_spyware_capture"


def infer_label(path: Path, profile: str) -> int:
    if profile == "parrot":
        return 0
    stem = path.stem.lower()
    return 0 if "normal" in stem else 1


def run_tshark(tshark: str, path: Path) -> tuple[list[dict[str, str]], str | None]:
    cmd = [tshark, "-r", str(path), "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    warning = result.stderr.strip() or None
    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(f"tshark exited with code {result.returncode}: {warning or 'no stderr output'}")
    reader = csv.DictReader(io.StringIO(result.stdout))
    return list(reader), warning


def infer_capture_local_ip(rows: list[dict[str, str]]) -> str | None:
    counts: Counter[str] = Counter()
    for row in rows:
        for key_a, key_b in (("ip.src", "ipv6.src"), ("ip.dst", "ipv6.dst")):
            ip = pick_ip(row, key_a, key_b)
            if ip and is_private_ip(ip):
                counts[ip] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def preferred_host(row: dict[str, str]) -> str | None:
    for key in ("tls.handshake.extensions_server_name", "http.host", "dns.qry.name"):
        value = (row.get(key) or "").strip().lower()
        if value:
            return value.removeprefix("www.")
    return None


def convert_capture(path: Path, profile: str, tshark: str) -> tuple[list[FlowAccumulator], str | None]:
    rows, warning = run_tshark(tshark=tshark, path=path)
    local_ip = infer_capture_local_ip(rows)
    app_id = infer_app_id(path=path, profile=profile)
    label = infer_label(path=path, profile=profile)
    flows: dict[tuple[str, int, str, int, str], FlowAccumulator] = {}

    for row in rows:
        src_ip = pick_ip(row, "ip.src", "ipv6.src")
        dst_ip = pick_ip(row, "ip.dst", "ipv6.dst")
        if not src_ip or not dst_ip:
            continue
        src_port = pick_port(row, "tcp.srcport", "udp.srcport")
        dst_port = pick_port(row, "tcp.dstport", "udp.dstport")
        protocol = normalize_protocol((row.get("_ws.col.Protocol") or ""), (row.get("ip.proto") or "").strip())
        try:
            ts = float((row.get("frame.time_epoch") or "0").strip() or "0")
        except ValueError:
            continue
        try:
            frame_len = int(float((row.get("frame.len") or "0").strip() or "0"))
        except ValueError:
            frame_len = 0

        if local_ip:
            if src_ip == local_ip:
                outbound = True
            elif dst_ip == local_ip:
                outbound = False
            elif is_private_ip(src_ip) and not is_private_ip(dst_ip):
                outbound = True
            elif is_private_ip(dst_ip) and not is_private_ip(src_ip):
                outbound = False
            else:
                outbound = True
        else:
            outbound = True

        local_endpoint_ip = src_ip if outbound else dst_ip
        remote_endpoint_ip = dst_ip if outbound else src_ip
        local_port = src_port if outbound else dst_port
        remote_port = dst_port if outbound else src_port
        key = (local_endpoint_ip, local_port, remote_endpoint_ip, remote_port, protocol)
        flow = flows.get(key)
        if flow is None:
            flow = FlowAccumulator(
                app_id=app_id,
                label=label,
                protocol=protocol,
                local_ip=local_endpoint_ip,
                local_port=local_port,
                remote_ip=remote_endpoint_ip,
                remote_port=remote_port,
                start_ts=ts,
                end_ts=ts,
            )
            flows[key] = flow

        flow.start_ts = min(flow.start_ts, ts)
        flow.end_ts = max(flow.end_ts, ts)
        if outbound:
            flow.bytes_out += frame_len
            flow.packets_out += 1
        else:
            flow.bytes_in += frame_len
            flow.packets_in += 1
        host = preferred_host(row)
        if host and not flow.site_hint:
            flow.site_hint = host

    return list(flows.values()), warning


def write_output(
    flows: list[FlowAccumulator],
    output: Path,
    report: Path,
    processed_pcaps: int,
    skipped_pcaps: int,
    issues: list[CaptureIssue],
) -> None:
    rows = []
    seen_destinations: dict[str, set[str]] = {}
    ordered = sorted(flows, key=lambda item: (item.app_id, item.end_ts, item.remote_ip, item.remote_port))
    for item in ordered:
        destination_key = f"{(item.site_hint or item.remote_ip or 'unknown').strip()}:{item.remote_port or 0}"
        novelty_seen = seen_destinations.setdefault(item.app_id, set())
        novelty = 0.0 if destination_key in novelty_seen else 1.0
        novelty_seen.add(destination_key)
        rows.append(
            {
                "app_id": item.app_id,
                "timestamp_end": int(round(item.end_ts * 1000)),
                "bytes_out": item.bytes_out,
                "bytes_in": item.bytes_in,
                "packets_out": item.packets_out,
                "packets_in": item.packets_in,
                "dst_novelty": novelty,
                "label": item.label,
                "destination_key": destination_key,
                "protocol": item.protocol,
                "dst_port": item.remote_port,
                "duration_ms": int(max(0.0, (item.end_ts - item.start_ts) * 1000.0)),
            }
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "app_id",
                "timestamp_end",
                "bytes_out",
                "bytes_in",
                "packets_out",
                "packets_in",
                "dst_novelty",
                "label",
                "destination_key",
                "protocol",
                "dst_port",
                "duration_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    label_counts = Counter(str(row["label"]) for row in rows)
    apps = Counter(row["app_id"] for row in rows)
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("w", encoding="utf-8") as handle:
        handle.write("kind,pcap,rows,label_0,label_1,apps,processed_pcaps,skipped_pcaps,message\n")
        handle.write(
            f"summary,all,{len(rows)},{label_counts.get('0', 0)},{label_counts.get('1', 0)},{len(apps)},{processed_pcaps},{skipped_pcaps},conversion_complete\n"
        )
        for issue in issues:
            safe_message = issue.message.replace("\n", " ").replace("\r", " ").replace(",", ";")
            handle.write(f"{issue.severity},{issue.path},0,0,0,0,{processed_pcaps},{skipped_pcaps},{safe_message}\n")


def resolve_pcaps(input_dir: Path, pattern: str) -> list[Path]:
    return sorted(path for path in input_dir.rglob(pattern) if path.is_file())


def main() -> None:
    args = parse_args()
    input_dir = Path(args.input_dir).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    report = Path(args.report).expanduser().resolve()
    pcaps = resolve_pcaps(input_dir=input_dir, pattern=args.glob)
    if not pcaps:
        raise SystemExit(f"No PCAP files matched {args.glob!r} under {input_dir}")

    flows: list[FlowAccumulator] = []
    issues: list[CaptureIssue] = []
    processed_pcaps = 0
    skipped_pcaps = 0
    for pcap in pcaps:
        try:
            converted, warning = convert_capture(path=pcap, profile=args.profile, tshark=args.tshark)
            flows.extend(converted)
            processed_pcaps += 1
            if warning:
                issues.append(CaptureIssue(path=str(pcap), severity="warning", message=warning))
                print(f"[warn] {pcap.name}: tshark reported a non-fatal warning", file=sys.stderr)
        except RuntimeError as exc:
            skipped_pcaps += 1
            issues.append(CaptureIssue(path=str(pcap), severity="skipped", message=str(exc)))
            print(f"[skip] {pcap.name}: {exc}", file=sys.stderr)
    if not flows:
        raise SystemExit("No convertible IP flows were found in the selected PCAP set")
    write_output(
        flows=flows,
        output=output,
        report=report,
        processed_pcaps=processed_pcaps,
        skipped_pcaps=skipped_pcaps,
        issues=issues,
    )
    print(f"Converted {processed_pcaps} PCAP(s) into {len(flows)} canonical flow rows")
    if skipped_pcaps:
        print(f"Skipped {skipped_pcaps} PCAP(s); see {report} for details")
    print(output)


if __name__ == "__main__":
    main()
