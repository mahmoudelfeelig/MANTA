from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay exported MANTA events against a backend and record soak results")
    parser.add_argument("--events-json", required=True, help="JSON file containing a list of event payloads")
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def send_event(base_url: str, token: str, payload: dict) -> int:
    event_type = payload.get("event_type", "")
    path = "/api/v1/events/mobile_flow" if event_type == "mobile_flow" else "/api/v1/events/mobile_alert"
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.getcode()


def main() -> None:
    args = parse_args()
    payload = json.loads(Path(args.events_json).read_text(encoding="utf-8"))
    events = payload if isinstance(payload, list) else payload.get("events", [])
    started = time.time()
    sent = 0
    failures: list[dict[str, object]] = []
    for index, event in enumerate(events, start=1):
        try:
            status = send_event(args.backend_url, args.token, event)
            if status < 200 or status >= 300:
                failures.append({"index": index, "status": status})
            else:
                sent += 1
        except Exception as exc:  # noqa: BLE001
            failures.append({"index": index, "error": str(exc)})
    report = {
        "started_epoch": int(started),
        "duration_seconds": time.time() - started,
        "events_total": len(events),
        "events_sent": sent,
        "events_failed": len(failures),
        "success_rate": float(sent / max(1, len(events))),
        "failures": failures[:100],
    }
    report["gates"] = {
        "success_rate_ge_0_99": report["success_rate"] >= 0.99,
        "no_failures": report["events_failed"] == 0,
    }
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
