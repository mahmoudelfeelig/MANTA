from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ResistineConfig:
    base_url: str
    api_token: str
    allow_insecure: bool


class ResistineClient:
    def __init__(self, config: ResistineConfig) -> None:
        self._config = config

    def configured(self) -> bool:
        return bool(self._config.base_url)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._config.api_token:
            headers["Authorization"] = f"Bearer {self._config.api_token}"
        return headers

    def _build_url(self, path: str) -> str:
        if not self._config.base_url:
            raise ValueError("Resistine base URL is not configured")
        if not self._config.allow_insecure and not self._config.base_url.startswith("https://"):
            raise ValueError("Insecure Resistine URL is not allowed")
        return f"{self._config.base_url.rstrip('/')}{path}"

    def register_endpoint(self, payload: dict) -> dict:
        url = self._build_url("/api/v1/register")
        with httpx.Client(timeout=8.0, verify=not self._config.allow_insecure) as client:
            response = client.post(url, headers=self._headers(), json=payload)
            response.raise_for_status()
            return response.json()

    def get_connection(self, device_id: str) -> dict:
        url = self._build_url(f"/api/v1/connection/{device_id}")
        with httpx.Client(timeout=8.0, verify=not self._config.allow_insecure) as client:
            response = client.get(url, headers=self._headers())
            response.raise_for_status()
            return response.json()

    def send_data(self, stream_id: str, payload: dict) -> dict:
        url = self._build_url(f"/api/v1/stream/{stream_id}/data")
        with httpx.Client(timeout=8.0, verify=not self._config.allow_insecure) as client:
            response = client.post(url, headers=self._headers(), json=payload)
            response.raise_for_status()
            return response.json()
