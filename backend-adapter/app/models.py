from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class MobileFlowEvent(BaseModel):
    event_type: str = Field(default="mobile_flow")
    event_version: str = Field(default="1.0")
    device_id_pseudo: str = Field(min_length=8, max_length=128)
    app_id: str = Field(min_length=1, max_length=256)
    protocol: str = Field(min_length=1, max_length=16)
    src_ip: str | None = None
    src_port: int = Field(ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int = Field(ge=0, le=65535)
    dst_host_hash: str = Field(min_length=8, max_length=256)
    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)
    packets_out: int | None = Field(default=0, ge=0)
    packets_in: int | None = Field(default=0, ge=0)
    duration_ms: int = Field(ge=0)
    timestamp_start: int
    timestamp_end: int
    anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)
    explain_top_features: list[str] | None = None

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if value != "mobile_flow":
            raise ValueError("Only mobile_flow events are accepted")
        return value

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        normalized = value.upper().strip()
        if normalized not in {"TCP", "UDP", "ICMP", "UNKNOWN"}:
            raise ValueError("Unsupported protocol")
        return normalized
