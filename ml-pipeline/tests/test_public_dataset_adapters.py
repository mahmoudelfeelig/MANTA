from pathlib import Path

import pandas as pd

from ml_pipeline.public_dataset_adapters import normalize_public_android_flow_csv


def test_public_dataset_adapter_maps_cic_like_columns(tmp_path: Path) -> None:
    csv_path = tmp_path / "Benign" / "sample.csv"
    csv_path.parent.mkdir()
    pd.DataFrame(
        [
            {
                "Flow End Time": 1_700_000_001,
                "Total Fwd Packets": 2,
                "Total Backward Packets": 3,
                "Total Length of Fwd Packets": 100,
                "Total Length of Bwd Packets": 200,
                "Destination Port": 443,
                "Protocol": "TCP",
                "Label": "BENIGN",
            }
        ]
    ).to_csv(csv_path, index=False)

    normalized = normalize_public_android_flow_csv(csv_path, dataset_source="cic_andmal2017")

    assert normalized.loc[0, "label"] == 0
    assert normalized.loc[0, "bytes_out"] == 100
    assert normalized.loc[0, "bytes_in"] == 200
    assert normalized.loc[0, "dataset_source"] == "cic_andmal2017"
