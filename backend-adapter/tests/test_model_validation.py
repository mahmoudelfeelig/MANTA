from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import DevicePolicyPayload, MobileAlertEvent, MobileFlowEvent, ThresholdProfile



def test_mobile_flow_rejects_invalid_timestamp_order() -> None:
    with pytest.raises(ValidationError):
        MobileFlowEvent(
            event_type="mobile_flow",
            event_version="1.0",
            device_id_pseudo="abcd1234",
            app_id="com.test",
            protocol="TCP",
            src_ip="10.0.0.2",
            src_port=44444,
            dst_ip="8.8.8.8",
            dst_port=443,
            dst_host_hash="abcd1234",
            bytes_out=100,
            bytes_in=200,
            packets_out=1,
            packets_in=1,
            duration_ms=100,
            timestamp_start=2000,
            timestamp_end=1000,
        )



def test_mobile_alert_rejects_too_many_top_features() -> None:
    with pytest.raises(ValidationError):
        MobileAlertEvent(
            event_type="mobile_alert",
            event_version="1.0",
            device_id_pseudo="abcd1234",
            alert_id="alert-12345",
            app_id="com.test",
            anomaly_score=0.8,
            severity="HIGH",
            top_features=[f"f{i}" for i in range(30)],
            explanation="x",
            source_model="statistical",
            triage_status="OPEN",
            triage_note="",
            timestamp=1234,
        )



def test_policy_rejects_too_many_overrides() -> None:
    overrides = {f"app{i}": ThresholdProfile(low=0.3, medium=0.5, high=0.9) for i in range(1200)}
    with pytest.raises(ValidationError):
        DevicePolicyPayload(
            policy_version=1,
            default_thresholds=ThresholdProfile(low=0.3, medium=0.6, high=0.85),
            app_threshold_overrides=overrides,
            export_enabled=True,
            retention_days=90,
        )


def test_policy_rejects_unsupported_detection_model() -> None:
    with pytest.raises(ValidationError):
        DevicePolicyPayload(
            policy_version=1,
            default_thresholds=ThresholdProfile(low=0.3, medium=0.6, high=0.85),
            app_threshold_overrides={},
            export_enabled=True,
            retention_days=90,
            detection_model="xgboost",
        )


def test_policy_rejects_unsupported_shadow_model() -> None:
    with pytest.raises(ValidationError):
        DevicePolicyPayload(
            policy_version=1,
            default_thresholds=ThresholdProfile(low=0.3, medium=0.6, high=0.85),
            app_threshold_overrides={},
            export_enabled=True,
            retention_days=90,
            detection_model="ensemble_fusion",
            shadow_model="random_forest",
        )
