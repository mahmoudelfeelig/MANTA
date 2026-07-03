from pathlib import Path

from ml_pipeline.android_feature_contract import ANDROID_FEATURE_COLUMNS, validate_against_android_runtime
from ml_pipeline.features import FEATURE_COLUMNS


def test_python_feature_contract_is_android_runtime_contract() -> None:
    assert FEATURE_COLUMNS == ANDROID_FEATURE_COLUMNS
    repo_root = Path(__file__).resolve().parents[2]
    validate_against_android_runtime(repo_root)
