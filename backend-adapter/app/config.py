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
    resistine_base_url: str
    resistine_api_token: str
    allow_insecure_resistine: bool
    max_event_size_bytes: int
    max_retries: int
    retry_base_seconds: int
    sqlite_path: str



def load_settings() -> Settings:
    shared_token = os.getenv("ADAPTER_SHARED_TOKEN", "").strip()
    max_event_size_bytes = max(1_024, int(os.getenv("MAX_EVENT_SIZE_BYTES", "65536")))
    max_retries = max(1, min(20, int(os.getenv("MAX_RETRIES", "5"))))
    retry_base_seconds = max(1, min(60, int(os.getenv("RETRY_BASE_SECONDS", "5"))))
    sqlite_path = os.getenv("SQLITE_PATH", "adapter_state.db").strip() or "adapter_state.db"

    return Settings(
        shared_token=shared_token,
        wazuh_ingest_url=os.getenv("WAZUH_INGEST_URL", "").strip(),
        wazuh_api_token=os.getenv("WAZUH_API_TOKEN", "").strip(),
        allow_insecure_wazuh=_bool_env("ALLOW_INSECURE_WAZUH", False),
        resistine_base_url=os.getenv("RESISTINE_BASE_URL", "").strip(),
        resistine_api_token=os.getenv("RESISTINE_API_TOKEN", "").strip(),
        allow_insecure_resistine=_bool_env("ALLOW_INSECURE_RESISTINE", False),
        max_event_size_bytes=max_event_size_bytes,
        max_retries=max_retries,
        retry_base_seconds=retry_base_seconds,
        sqlite_path=sqlite_path,
    )
