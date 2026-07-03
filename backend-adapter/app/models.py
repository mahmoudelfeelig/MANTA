from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class ThresholdProfile(BaseModel):
    low: float = Field(ge=0.0, le=1.0)
    medium: float = Field(ge=0.0, le=1.0)
    high: float = Field(ge=0.0, le=1.0)

    @field_validator("medium")
    @classmethod
    def validate_medium_ge_low(cls, value: float, info):
        low = info.data.get("low") if info and info.data else None
        if low is not None and value < low:
            raise ValueError("medium threshold must be >= low")
        return value

    @field_validator("high")
    @classmethod
    def validate_high_ge_medium(cls, value: float, info):
        medium = info.data.get("medium") if info and info.data else None
        if medium is not None and value < medium:
            raise ValueError("high threshold must be >= medium")
        return value


class FusionWeightsPayload(BaseModel):
    statistical: float = Field(default=0.28, ge=0.0, le=1.0)
    multivariate: float = Field(default=0.20, ge=0.0, le=1.0)
    sequence: float = Field(default=0.12, ge=0.0, le=1.0)
    local: float = Field(default=0.16, ge=0.0, le=1.0)
    tflite: float = Field(default=0.12, ge=0.0, le=1.0)
    remote: float = Field(default=0.12, ge=0.0, le=1.0)
    beacon: float = Field(default=0.15, ge=0.0, le=1.0)
    drift: float = Field(default=0.10, ge=0.0, le=1.0)
    reputation: float = Field(default=0.18, ge=0.0, le=1.0)
    data_quality_penalty: float = Field(default=0.10, ge=0.0, le=1.0)
    response_anomaly: float = Field(default=0.82, ge=0.0, le=1.0)
    response_context: float = Field(default=0.18, ge=0.0, le=1.0)

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_linear_weight(cls, data):
        if isinstance(data, dict) and "local" not in data and "linear" in data:
            data = {**data, "local": data["linear"]}
        return data


class DevicePolicyPayload(BaseModel):
    policy_version: int = Field(ge=1)
    default_thresholds: ThresholdProfile
    app_threshold_overrides: dict[str, ThresholdProfile] = Field(default_factory=dict)
    export_enabled: bool = True
    retention_days: int = Field(default=90, ge=1, le=90)
    detection_model: str = Field(default="ensemble_fusion", max_length=64)
    shadow_model: str | None = Field(default=None, max_length=64)
    false_positive_budget_per_app_day: int = Field(default=12, ge=1, le=250)
    drift_high_threshold: float = Field(default=0.65, ge=0.1, le=1.0)
    capture_enabled: bool = True
    theme_mode: Literal["SYSTEM", "LIGHT", "DARK"] = "SYSTEM"
    debug_mode_enabled: bool = False
    fusion_weights: FusionWeightsPayload = Field(default_factory=FusionWeightsPayload)
    disable_volume_features: bool = False
    disable_timing_features: bool = False
    disable_destination_features: bool = False
    app_profile_overrides: dict[str, Literal["DEFAULT", "TRUSTED", "HIGH_CHURN", "BROWSER", "SYSTEM"]] = Field(default_factory=dict)
    protected_brands_csv: str | None = Field(default=None, max_length=8192)

    @field_validator("detection_model", "shadow_model", mode="before")
    @classmethod
    def normalize_legacy_model_names(cls, value):
        aliases = {
            "linear": "local",
            "linear_v13_recall": "local_sensitive",
            "linear_v14_quiet": "local_quiet",
            "hybrid_v15": "local_balanced",
        }
        if value is None:
            return value
        return aliases.get(value, value)

    @model_validator(mode="after")
    def validate_override_count(self):
        if len(self.app_threshold_overrides) > 1000:
            raise ValueError("Too many app threshold overrides")
        if len(self.app_profile_overrides) > 1000:
            raise ValueError("Too many app profile overrides")
        supported = {
            "ensemble_fusion",
            "statistical",
            "multivariate",
            "sequence",
            "local",
            "local_sensitive",
            "local_quiet",
            "local_balanced",
            "local_privacy",
            "tflite",
            "remote_assisted",
        }
        if self.detection_model not in supported:
            raise ValueError("Unsupported detection_model")
        if self.shadow_model is not None and self.shadow_model not in supported:
            raise ValueError("Unsupported shadow_model")
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
    is_new_destination_for_app: float | None = Field(default=None, ge=0.0, le=1.0)
    dst_novelty: float | None = Field(default=None, ge=0.0, le=1.0)
    anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)
    explain_top_features: list[str] | None = None
    site_hint: str | None = Field(default=None, max_length=512)
    device_label: str | None = Field(default=None, max_length=256)
    destination_key: str | None = Field(default=None, max_length=512)
    dns_query_name: str | None = Field(default=None, max_length=512)
    dns_query_type: str | None = Field(default=None, max_length=64)
    dns_response_code: int | None = Field(default=None, ge=0, le=255)
    dns_answer_value: str | None = Field(default=None, max_length=512)
    tls_sni: str | None = Field(default=None, max_length=512)
    tls_alpn: str | None = Field(default=None, max_length=64)
    tls_version: str | None = Field(default=None, max_length=64)
    tls_ja3_like: str | None = Field(default=None, max_length=128)
    tls_leaf_subject: str | None = Field(default=None, max_length=1024)
    tls_leaf_issuer: str | None = Field(default=None, max_length=1024)
    tls_leaf_san: str | None = Field(default=None, max_length=2048)
    http_method: str | None = Field(default=None, max_length=32)
    http_host: str | None = Field(default=None, max_length=512)
    http_path: str | None = Field(default=None, max_length=2048)
    quic_version: str | None = Field(default=None, max_length=64)
    quic_detected: bool | None = None
    http3_detected: bool | None = None
    registrable_domain: str | None = Field(default=None, max_length=512)
    brand_match: str | None = Field(default=None, max_length=128)
    lookalike_score: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_tags: list[str] | None = None
    mitre_techniques: list[str] | None = None

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
    base_anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)
    context_score: float | None = Field(default=None, ge=0.0, le=1.0)
    response_score: float | None = Field(default=None, ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    top_features: list[str] = Field(default_factory=list)
    feature_contributions: dict[str, float] | None = Field(default=None)
    explanation: str = Field(default="", max_length=2048)
    source_model: str = Field(default="unknown", max_length=128)
    site_hint: str | None = Field(default=None, max_length=512)
    device_label: str | None = Field(default=None, max_length=256)
    window_features: "RemoteFeatureWindowPayload | None" = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    uncertainty: float | None = Field(default=None, ge=0.0, le=1.0)
    drift_score: float | None = Field(default=None, ge=0.0, le=1.0)
    occurrence_count: int | None = Field(default=1, ge=1, le=100000)
    first_seen: int | None = None
    last_seen: int | None = None
    correlation_key: str | None = Field(default=None, max_length=256)
    shadow_model: str | None = Field(default=None, max_length=128)
    shadow_score: float | None = Field(default=None, ge=0.0, le=1.0)
    suppression_reason: str | None = Field(default=None, max_length=512)
    data_quality_warnings: list[str] | None = Field(default=None)
    beacon_score: float | None = Field(default=None, ge=0.0, le=1.0)
    mitre_techniques: list[str] | None = Field(default=None)
    mitre_matches: list[dict] | None = Field(default=None)
    destination_identity: str | None = Field(default=None, max_length=512)
    lookalike_score: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_tags: list[str] | None = Field(default=None)
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
        if self.data_quality_warnings is not None and len(self.data_quality_warnings) > 64:
            raise ValueError("Too many data_quality_warnings")
        return self


class AlertTriageUpdate(BaseModel):
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    note: str = Field(default="", max_length=1024)


class AdapterEventAck(BaseModel):
    status: Literal["accepted"]
    event_id: str
    forwarded: bool


class DeviceHeartbeatPayload(BaseModel):
    device_id_pseudo: str = Field(min_length=8, max_length=128)
    device_label: str | None = Field(default=None, max_length=256)
    capture_enabled: bool = False
    export_enabled: bool = False
    policy_version: int = Field(default=1, ge=1)


class PolicySimulationRequest(BaseModel):
    policy: DevicePolicyPayload
    limit: int = Field(default=5000, ge=10, le=50000)


class RemoteFeatureWindowPayload(BaseModel):
    flow_count: int = Field(ge=0)
    total_bytes_out: int = Field(default=0, ge=0)
    total_bytes_in: int = Field(default=0, ge=0)
    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)
    mean_packet_size: float = Field(ge=0.0)
    outbound_ratio: float = Field(ge=0.0, le=1.0)
    burstiness: float = Field(ge=0.0)
    novelty_score: float = Field(ge=0.0, le=1.0)
    connection_frequency_delta: float = Field(ge=0.0)
    bytes_per_flow: float = Field(ge=0.0)
    destination_diversity: float = Field(ge=0.0, le=1.0)
    activity_ratio: float = Field(ge=0.0, le=1.0)
    periodic_beacon_score: float = Field(ge=0.0, le=1.0)
    byte_rate: float = Field(default=0.0, ge=0.0)
    packet_rate: float = Field(default=0.0, ge=0.0)
    mean_duration_ms: float = Field(default=0.0, ge=0.0)
    duration_jitter: float = Field(default=0.0, ge=0.0)
    port_diversity: float = Field(default=0.0, ge=0.0, le=1.0)
    protocol_diversity: float = Field(default=0.0, ge=0.0, le=1.0)
    packet_imbalance: float = Field(default=0.0, ge=0.0, le=1.0)
    small_flow_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    high_port_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    hour_of_day: int = Field(ge=0, le=23)
    day_of_week: int = Field(default=0, ge=0, le=7)
    is_weekend: bool = False
    data_quality_score: float = Field(ge=0.0, le=1.0)
    ttl_gap: float = Field(default=0.0, ge=0.0)
    ttl_metrics_present: float = Field(default=0.0, ge=0.0, le=1.0)
    syn_rate_total: float = Field(default=0.0, ge=0.0)
    rst_rate_total: float = Field(default=0.0, ge=0.0)
    ack_rate_total: float = Field(default=0.0, ge=0.0)
    fin_rate_total: float = Field(default=0.0, ge=0.0)
    psh_rate_total: float = Field(default=0.0, ge=0.0)
    fragment_rate_total: float = Field(default=0.0, ge=0.0)
    tcp_window_mean: float = Field(default=0.0, ge=0.0)
    ack_delay_mean: float = Field(default=0.0, ge=0.0)
    inter_packet_gap_mean: float = Field(default=0.0, ge=0.0)
    payload_mean: float = Field(default=0.0, ge=0.0)
    load_mean: float = Field(default=0.0, ge=0.0)
    transport_metrics_present: float = Field(default=0.0, ge=0.0, le=1.0)
    destination_concentration: float = Field(default=0.0, ge=0.0, le=1.0)
    destination_transition_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    dns_flow_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    web_flow_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    private_destination_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    multicast_destination_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    flow_count_deviation: float = 0.0
    byte_rate_deviation: float = 0.0
    destination_diversity_shift: float = 0.0
    novelty_shift: float = 0.0
    recent_flow_count_mean: float = Field(default=0.0, ge=0.0)
    recent_byte_rate_mean: float = Field(default=0.0, ge=0.0)
    recent_novelty_mean: float = Field(default=0.0, ge=0.0, le=1.0)
    flow_count_trend: float = 0.0
    byte_rate_trend: float = 0.0
    novelty_trend: float = 0.0
    destination_diversity_trend: float = 0.0
    consecutive_burst_windows: float = Field(default=0.0, ge=0.0)
    low_volume_periodic_score: float = Field(default=0.0, ge=0.0, le=1.0)
    destination_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    lookalike_score: float = Field(default=0.0, ge=0.0, le=1.0)
    suspicious_destination_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    known_identity_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_technique_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_tag_ratio: float = Field(default=0.0, ge=0.0, le=1.0)


class DestinationEnrichmentRequest(BaseModel):
    site_hint: str | None = Field(default=None, max_length=512)
    dns_query_name: str | None = Field(default=None, max_length=512)
    tls_sni: str | None = Field(default=None, max_length=512)
    http_host: str | None = Field(default=None, max_length=512)
    dst_ip: str | None = Field(default=None, max_length=128)
    dst_port: int = Field(default=443, ge=0, le=65535)
    fetch_certificate: bool = False
    protected_brands_csv: str | None = Field(default=None, max_length=8192)


class RemoteInferenceRequest(BaseModel):
    device_id_pseudo: str = Field(min_length=8, max_length=128)
    app_id: str = Field(min_length=1, max_length=256)
    site_hint: str | None = Field(default=None, max_length=512)
    feature_window: RemoteFeatureWindowPayload


class PolicyApplyScopeRequest(BaseModel):
    scope: Literal["device", "selected_devices", "all_devices", "global_default"]
    policy: DevicePolicyPayload
    device_ids: list[str] = Field(default_factory=list)


class AdminPurgeRequest(BaseModel):
    device_ids: list[str] = Field(default_factory=list)
    all_devices: bool = False
    clear_events: bool = False
    clear_alerts: bool = False
    clear_policies: bool = False
    clear_models: bool = False
    clear_dead_letter: bool = False
    purge_test_data: bool = False


class RemoteModelUpsertRequest(BaseModel):
    model: dict
    activate: bool = True
    family: str | None = Field(default=None, max_length=64)


class DeviceDisplayNameUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
