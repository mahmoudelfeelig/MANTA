from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class ThresholdProfile(BaseModel):
    medium: float = Field(ge=0.0, le=1.0)
    high: float = Field(ge=0.0, le=1.0)

    @field_validator("high")
    @classmethod
    def validate_high_ge_medium(cls, value: float, info):
        medium = info.data.get("medium") if info and info.data else None
        if medium is not None and value < medium:
            raise ValueError("high threshold must be >= medium")
        return value


class DevicePolicyPayload(BaseModel):
    policy_version: int = Field(ge=1)
    default_thresholds: ThresholdProfile
    app_threshold_overrides: dict[str, ThresholdProfile] = Field(default_factory=dict)
    export_enabled: bool = True
    retention_days: int = Field(default=7, ge=1, le=90)

    @model_validator(mode="after")
    def validate_override_count(self):
        if len(self.app_threshold_overrides) > 1000:
            raise ValueError("Too many app threshold overrides")
        return self


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

    # P1: NetFlow/IPFIX-style fields
    netflow_version: int | None = Field(default=None, ge=1)
    ipfix_template_id: int | None = Field(default=None, ge=0)
    ipfix_elements: list[dict] | None = None

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if value != "mobile_flow":
            raise ValueError("Only mobile_flow events are accepted")
        return value

    @field_validator("event_version")
    @classmethod
    def validate_event_version(cls, value: str) -> str:
        if value not in {"1.0", "1.1"}:
            raise ValueError("Unsupported event_version")
        return value

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        normalized = value.upper().strip()
        if normalized not in {"TCP", "UDP", "ICMP", "UNKNOWN"}:
            raise ValueError("Unsupported protocol")
        return normalized

    @model_validator(mode="after")
    def validate_time_and_payload_shape(self):
        if self.timestamp_end < self.timestamp_start:
            raise ValueError("timestamp_end must be >= timestamp_start")
        if self.explain_top_features is not None and len(self.explain_top_features) > 16:
            raise ValueError("Too many explain_top_features")
        if self.ipfix_elements is not None and len(self.ipfix_elements) > 512:
            raise ValueError("Too many ipfix_elements")
        return self


class MobileAlertEvent(BaseModel):
    event_type: str = Field(default="mobile_alert")
    event_version: str = Field(default="1.0")
    device_id_pseudo: str = Field(min_length=8, max_length=128)
    alert_id: str = Field(min_length=8, max_length=128)
    app_id: str = Field(min_length=1, max_length=256)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    top_features: list[str] = Field(default_factory=list)
    explanation: str = Field(default="", max_length=2048)
    source_model: str = Field(default="unknown", max_length=128)
    triage_status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"] = "OPEN"
    triage_note: str = Field(default="", max_length=1024)
    timestamp: int

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if value != "mobile_alert":
            raise ValueError("Only mobile_alert events are accepted")
        return value

    @field_validator("event_version")
    @classmethod
    def validate_event_version(cls, value: str) -> str:
        if value != "1.0":
            raise ValueError("Unsupported event_version")
        return value

    @model_validator(mode="after")
    def validate_top_features(self):
        if len(self.top_features) > 16:
            raise ValueError("Too many top_features")
        return self


class AlertTriageUpdate(BaseModel):
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    note: str = Field(default="", max_length=1024)


class AdapterEventAck(BaseModel):
    status: Literal["accepted"]
    event_id: str
    forwarded: bool
