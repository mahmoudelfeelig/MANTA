from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    shared_token: str
    wazuh_ingest_url: str
    wazuh_api_token: str
    allow_insecure_wazuh: bool
    max_event_size_bytes: int
    max_retries: int
    retry_base_seconds: int
    sqlite_path: str



def load_settings() -> Settings:
    return Settings(
        shared_token=os.getenv("ADAPTER_SHARED_TOKEN", ""),
        wazuh_ingest_url=os.getenv("WAZUH_INGEST_URL", "").strip(),
        wazuh_api_token=os.getenv("WAZUH_API_TOKEN", "").strip(),
        allow_insecure_wazuh=_bool_env("ALLOW_INSECURE_WAZUH", False),
        max_event_size_bytes=int(os.getenv("MAX_EVENT_SIZE_BYTES", "65536")),
        max_retries=int(os.getenv("MAX_RETRIES", "5")),
        retry_base_seconds=int(os.getenv("RETRY_BASE_SECONDS", "5")),
        sqlite_path=os.getenv("SQLITE_PATH", "adapter_state.db").strip(),
    )
