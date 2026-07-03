from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify MANTA backend/SIEM contract surfaces against a live backend")
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def fetch_json(url: str, token: str, path: str) -> dict:
    request = urllib.request.Request(
        f"{url.rstrip('/')}{path}",
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    args = parse_args()
    health = fetch_json(args.backend_url, args.token, "/health")
    payload = {
        "backend_url": args.backend_url,
        "health": health,
        "wazuh_configured": health.get("wazuh_configured"),
        "resistine_configured": health.get("resistine_configured"),
        "status": "ok",
    }
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
