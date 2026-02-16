import pandas as pd

from ml_pipeline.generate_controlled_dataset import SCENARIOS, generate_controlled_dataset



def test_generate_controlled_dataset_contains_expected_scenarios_and_labels() -> None:
    df = generate_controlled_dataset(rows_per_scenario=25, seed=7)

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    assert set(df["scenario"].unique()) == set(SCENARIOS)
    assert set(df["label"].unique()) == {0, 1}
    assert {"bytes_out", "bytes_in", "packets_out", "packets_in", "dst_novelty"}.issubset(df.columns)
