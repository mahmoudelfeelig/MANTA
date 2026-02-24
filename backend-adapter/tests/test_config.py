from __future__ import annotations

from app.config import load_settings



def test_load_settings_clamps_ranges(monkeypatch) -> None:
    monkeypatch.setenv("MAX_EVENT_SIZE_BYTES", "10")
    monkeypatch.setenv("MAX_RETRIES", "999")
    monkeypatch.setenv("RETRY_BASE_SECONDS", "0")

    settings = load_settings()

    assert settings.max_event_size_bytes >= 1024
    assert settings.max_retries <= 20
    assert settings.retry_base_seconds >= 1
    assert settings.resistine_base_url == ""
    assert settings.allow_insecure_resistine is False
