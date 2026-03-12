from __future__ import annotations

from pathlib import Path

import pandas as pd

from ml_pipeline.dataset_metadata import recover_legacy_flow_metadata


def test_recover_legacy_sdncampus_metadata_from_path(tmp_path: Path) -> None:
    input_path = tmp_path / "sdncampus" / "facebook-normalized.csv"
    input_path.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(
        [
            {
                "app_id": "facebook",
                "timestamp_end": 1,
                "bytes_out": 10,
                "bytes_in": 20,
                "packets_out": 1,
                "packets_in": 1,
                "dst_novelty": 0.0,
            }
        ]
    )

    recovered = recover_legacy_flow_metadata(frame, input_path)

    assert set(recovered["dataset_source"]) == {"sdncampus_flow_statistics"}
    assert set(recovered["dataset_profile"]) == {"sdncampus"}
    assert set(recovered["dataset_variant"]) == {"facebook_normalized"}
    assert set(recovered["environment_id"]) == {"sdncampus"}
    assert set(recovered["session_id"]) == {"facebook_normalized"}
    assert set(recovered["app_family"]) == {"consumer_app"}


def test_recover_legacy_westermo_metadata_from_path(tmp_path: Path) -> None:
    input_path = tmp_path / "westermo-bottom-normalized.csv"
    frame = pd.DataFrame(
        [
            {
                "app_id": "service:arp:unknown:0",
                "dataset_source": "unknown_source",
                "dataset_profile": "unknown_profile",
                "dataset_variant": "unknown_variant",
                "environment_id": "unknown_environment",
                "session_id": "unknown_session",
            }
        ]
    )

    recovered = recover_legacy_flow_metadata(frame, input_path)

    assert set(recovered["dataset_source"]) == {"westermo"}
    assert set(recovered["dataset_profile"]) == {"westermo"}
    assert set(recovered["dataset_variant"]) == {"westermo_bottom_normalized"}
    assert set(recovered["environment_id"]) == {"westermo_bottom_normalized"}
    assert set(recovered["session_id"]) == {"westermo_bottom_normalized"}
    assert set(recovered["app_family"]) == {"service"}


def test_recover_legacy_metadata_preserves_existing_values(tmp_path: Path) -> None:
    input_path = tmp_path / "android-spyware-converted.csv"
    frame = pd.DataFrame(
        [
            {
                "app_id": "flexispy_installation",
                "dataset_source": "android_spyware_mendeley",
                "dataset_profile": "android_spyware",
                "dataset_variant": "custom_variant",
                "environment_id": "malware_lab",
                "session_id": "session_a",
                "app_family": "malware",
            }
        ]
    )

    recovered = recover_legacy_flow_metadata(frame, input_path)

    assert recovered.iloc[0]["dataset_source"] == "android_spyware_mendeley"
    assert recovered.iloc[0]["dataset_profile"] == "android_spyware"
    assert recovered.iloc[0]["dataset_variant"] == "custom_variant"
    assert recovered.iloc[0]["environment_id"] == "malware_lab"
    assert recovered.iloc[0]["session_id"] == "session_a"
    assert recovered.iloc[0]["app_family"] == "malware"
