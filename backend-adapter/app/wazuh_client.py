from __future__ import annotations

import json
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class WazuhConfig:
    ingest_url: str
    api_token: str
    allow_insecure: bool


class WazuhClient:
    def __init__(self, config: WazuhConfig) -> None:
        self._config = config

    def configured(self) -> bool:
        return bool(self._config.ingest_url)

    def send(self, payload_json: str) -> None:
        if not self.configured():
            return

        if not self._config.allow_insecure and not self._config.ingest_url.startswith("https://"):
            raise ValueError("Insecure Wazuh URL is not allowed")

        headers = {"Content-Type": "application/json"}
        if self._config.api_token:
            headers["Authorization"] = f"Bearer {self._config.api_token}"

        payload_obj = json.loads(payload_json)
        with httpx.Client(timeout=8.0, verify=not self._config.allow_insecure) as client:
            response = client.post(self._config.ingest_url, headers=headers, json=payload_obj)
            response.raise_for_status()
