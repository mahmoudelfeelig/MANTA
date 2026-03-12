from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit

from .dataset_metadata import derive_app_family


@dataclass
class SplitResult:
    train_idx: np.ndarray
    test_idx: np.ndarray
    strategy: str
    summary: dict[str, object]


def add_split_metadata(frame: pd.DataFrame) -> pd.DataFrame:
    enriched = frame.copy()
    if "dataset_source" not in enriched.columns:
        enriched["dataset_source"] = "unknown_source"
    if "environment_id" not in enriched.columns:
        enriched["environment_id"] = "unknown_environment"
    if "dataset_variant" not in enriched.columns:
        enriched["dataset_variant"] = enriched["dataset_source"].astype(str)
    if "session_id" not in enriched.columns:
        enriched["session_id"] = enriched["dataset_variant"].astype(str)
    if "app_family" not in enriched.columns:
        enriched["app_family"] = enriched["app_id"].astype(str).map(derive_app_family) if "app_id" in enriched.columns else "other_app"
    if "window_bucket" in enriched.columns:
        enriched["time_fold"] = (pd.to_numeric(enriched["window_bucket"], errors="coerce").fillna(0).astype("int64") // 240).astype(str)
    elif "timestamp_end" in enriched.columns:
        enriched["time_fold"] = (pd.to_numeric(enriched["timestamp_end"], errors="coerce").fillna(0).astype("int64") // (4 * 60 * 60 * 1000)).astype(str)
    else:
        enriched["time_fold"] = "0"
    return enriched


def _valid_split(y: np.ndarray, train_idx: np.ndarray, test_idx: np.ndarray) -> bool:
    if len(train_idx) == 0 or len(test_idx) == 0:
        return False
    train_classes = set(y[train_idx].tolist())
    test_classes = set(y[test_idx].tolist())
    return len(train_classes) >= 2 and len(test_classes) >= 2


def _group_series(series: pd.Series, default_prefix: str) -> pd.Series:
    normalized = series.astype(str).fillna("").replace({"nan": "", "None": "", "<NA>": ""}).str.strip()
    fallback = [f"{default_prefix}_{index:06d}" for index in range(len(normalized))]
    return normalized.where(normalized != "", fallback)


def _candidate_groups(working: pd.DataFrame) -> dict[str, pd.Series]:
    dataset_source = _group_series(working["dataset_source"], "unknown_source")
    environment_id = _group_series(working["environment_id"], "unknown_environment")
    session_id = _group_series(working["session_id"], "unknown_session")
    app_family = _group_series(working["app_family"], "other_app")
    time_fold = _group_series(working["time_fold"], "time")
    app_id = _group_series(
        working["app_id"].astype(str) if "app_id" in working.columns else pd.Series(["unknown_app"] * len(working), index=working.index),
        "app",
    )
    return {
        "source_env_session": dataset_source + "|" + environment_id + "|" + session_id,
        "source_env_family_time": dataset_source + "|" + environment_id + "|" + app_family + "|" + time_fold,
        "source_family": dataset_source + "|" + app_family,
        "family_time": app_family + "|" + time_fold,
        "app_family_time": app_id + "|" + app_family + "|" + time_fold,
        "temporal_holdout": time_fold,
    }


def _split_summary(frame: pd.DataFrame, train_idx: np.ndarray, test_idx: np.ndarray, strategy: str) -> dict[str, object]:
    train = frame.iloc[train_idx]
    test = frame.iloc[test_idx]
    return {
        "strategy": strategy,
        "rows_train": int(len(train)),
        "rows_test": int(len(test)),
        "train_dataset_sources": sorted(train["dataset_source"].astype(str).unique().tolist()),
        "test_dataset_sources": sorted(test["dataset_source"].astype(str).unique().tolist()),
        "train_app_families": sorted(train["app_family"].astype(str).unique().tolist()),
        "test_app_families": sorted(test["app_family"].astype(str).unique().tolist()),
        "train_time_folds": sorted(train["time_fold"].astype(str).unique().tolist())[:12],
        "test_time_folds": sorted(test["time_fold"].astype(str).unique().tolist())[:12],
    }


def source_aware_train_test_split(
    frame: pd.DataFrame,
    *,
    label_column: str = "label",
    test_size: float = 0.25,
    random_seed: int = 42,
) -> SplitResult:
    working = add_split_metadata(frame)
    labels = pd.to_numeric(working[label_column], errors="coerce").fillna(0).astype(int).to_numpy()
    if len(np.unique(labels)) < 2:
        raise ValueError("Need at least two classes for source-aware split.")

    for strategy, groups in _candidate_groups(working).items():
        unique_groups = pd.Series(groups, copy=False).astype(str).nunique(dropna=False)
        if unique_groups < 2:
            continue
        splitter = GroupShuffleSplit(n_splits=max(1, min(12, unique_groups)), test_size=test_size, random_state=random_seed)
        try:
            iterator = splitter.split(working, labels, groups=groups)
        except ValueError:
            continue
        for train_idx, test_idx in iterator:
            if _valid_split(labels, train_idx, test_idx):
                return SplitResult(
                    train_idx=np.asarray(train_idx, dtype=int),
                    test_idx=np.asarray(test_idx, dtype=int),
                    strategy=strategy,
                    summary=_split_summary(working, np.asarray(train_idx, dtype=int), np.asarray(test_idx, dtype=int), strategy),
                )

    try:
        stratified = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_seed)
        train_idx, test_idx = next(stratified.split(working, labels))
        strategy = "stratified_random_fallback"
    except ValueError:
        permutation = np.random.default_rng(random_seed).permutation(len(working))
        split_point = max(1, min(len(working) - 1, int(round(len(working) * (1.0 - test_size)))))
        train_idx = permutation[:split_point]
        test_idx = permutation[split_point:]
        strategy = "random_fallback"
    return SplitResult(
        train_idx=np.asarray(train_idx, dtype=int),
        test_idx=np.asarray(test_idx, dtype=int),
        strategy=strategy,
        summary=_split_summary(working, np.asarray(train_idx, dtype=int), np.asarray(test_idx, dtype=int), strategy),
    )


def split_for_strategy(
    frame: pd.DataFrame,
    *,
    strategy: str,
    label_column: str = "label",
    test_size: float = 0.25,
    random_seed: int = 42,
) -> SplitResult:
    working = add_split_metadata(frame)
    labels = pd.to_numeric(working[label_column], errors="coerce").fillna(0).astype(int).to_numpy()
    if strategy == "source_aware_auto":
        return source_aware_train_test_split(working, label_column=label_column, test_size=test_size, random_seed=random_seed)
    groups = _candidate_groups(working).get(strategy)
    if groups is None:
        raise ValueError(f"Unknown split strategy: {strategy}")
    unique_groups = pd.Series(groups, copy=False).astype(str).nunique(dropna=False)
    if unique_groups >= 2:
        splitter = GroupShuffleSplit(n_splits=max(1, min(12, unique_groups)), test_size=test_size, random_state=random_seed)
        try:
            iterator = splitter.split(working, labels, groups=groups)
        except ValueError:
            iterator = []
        for train_idx, test_idx in iterator:
            if _valid_split(labels, train_idx, test_idx):
                return SplitResult(
                    train_idx=np.asarray(train_idx, dtype=int),
                    test_idx=np.asarray(test_idx, dtype=int),
                    strategy=strategy,
                    summary=_split_summary(working, np.asarray(train_idx, dtype=int), np.asarray(test_idx, dtype=int), strategy),
                )
    return source_aware_train_test_split(working, label_column=label_column, test_size=test_size, random_seed=random_seed)


def nested_source_aware_split(
    frame: pd.DataFrame,
    *,
    label_column: str = "label",
    outer_test_size: float = 0.25,
    inner_validation_size: float = 0.25,
    random_seed: int = 42,
) -> tuple[SplitResult, SplitResult]:
    outer = source_aware_train_test_split(frame, label_column=label_column, test_size=outer_test_size, random_seed=random_seed)
    inner_frame = frame.iloc[outer.train_idx].reset_index(drop=True)
    inner = source_aware_train_test_split(
        inner_frame,
        label_column=label_column,
        test_size=inner_validation_size,
        random_seed=random_seed + 17,
    )
    return outer, inner
