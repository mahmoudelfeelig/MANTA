from __future__ import annotations

from pathlib import Path

from ml_pipeline.train_all import _default_cache_root, _next_run_dir


def test_next_run_dir_increments_existing_runs(tmp_path: Path) -> None:
    runs_root = tmp_path / "experiment-runs"
    (runs_root / "manta-run-001").mkdir(parents=True)
    (runs_root / "manta-run-003").mkdir(parents=True)
    (runs_root / "other-dir").mkdir(parents=True)

    next_dir = _next_run_dir(runs_root, "manta-run-")

    assert next_dir.name == "manta-run-004"


def test_default_cache_root_is_shared_under_runs_root(tmp_path: Path) -> None:
    runs_root = tmp_path / "experiment-runs"

    cache_root = _default_cache_root(runs_root)

    assert cache_root == runs_root / ".shared-cache"
