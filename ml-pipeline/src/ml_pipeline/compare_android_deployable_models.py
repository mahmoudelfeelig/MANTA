from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .error_analysis import score_android_model
from .metrics import binary_classification_metrics, select_threshold_by_f1, threshold_sweep_metrics
from .splits import source_aware_train_test_split
from .window_builders import add_window_protocol_args, adaptive_cache_name, load_android_windows_for_protocol


REPO_ROOT = Path(__file__).resolve().parents[3]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Android-deployable model artifacts on one shared evaluation protocol")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-json", required=True, help="Output JSON report")
    parser.add_argument("--output-csv", default="", help="Optional flat CSV comparison table")
    parser.add_argument("--output-md", default="", help="Optional Markdown comparison table")
    parser.add_argument("--remote-model", default="", help="Optional backend remote-assisted JSON model")
    parser.add_argument("--include-artifacts", action="store_true", help="Include historical ml-pipeline/artifacts/android anomaly JSONs")
    parser.add_argument("--max-eval-rows", type=int, default=5000, help="Max rows per evaluation view; 0 means full holdout")
    parser.add_argument("--cache-prefix", default="android", help="Feature-window cache prefix; default reuses Android training caches")
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--random-seed", type=int, default=42)
    add_window_protocol_args(parser)
    return parser.parse_args()


def _load_backend_remote_modeling():
    module_path = Path(__file__).resolve().parents[3] / "backend-adapter" / "app" / "remote_modeling.py"
    spec = importlib.util.spec_from_file_location("manta_backend_remote_modeling", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load backend remote modeling module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _score_remote_model(remote_module, payload: dict[str, Any], frame: pd.DataFrame) -> np.ndarray:
    scores: list[float] = []
    for row in frame.to_dict(orient="records"):
        if "bytes_out" not in row:
            row["bytes_out"] = row.get("total_bytes_out", 0.0)
        if "bytes_in" not in row:
            row["bytes_in"] = row.get("total_bytes_in", 0.0)
        result = remote_module.score_remote_model(payload, row, row.get("site_hint"))
        scores.append(float(result.get("score", 0.0)))
    return np.asarray(scores, dtype=float)


def _threshold_from_model(payload: dict[str, Any]) -> float:
    return float(payload.get("recommended_threshold", payload.get("threshold", 0.5)))


def _sample_natural(frame: pd.DataFrame, max_rows: int, random_seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(frame) <= max_rows:
        return frame.reset_index(drop=True)
    return frame.sample(n=max_rows, random_state=random_seed).reset_index(drop=True)


def _sample_balanced(frame: pd.DataFrame, max_rows: int, random_seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(frame) <= max_rows or "label" not in frame.columns:
        return frame.reset_index(drop=True)
    groups = list(frame.groupby(frame["label"].fillna(0).astype(int), sort=False))
    if len(groups) < 2:
        return _sample_natural(frame, max_rows, random_seed)
    per_group = max(1, max_rows // len(groups))
    samples = []
    for _, group in groups:
        samples.append(group.sample(n=min(len(group), per_group), random_state=random_seed))
    sampled = pd.concat(samples, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=random_seed)
    return sampled.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


def _app_models() -> list[dict[str, str]]:
    root = REPO_ROOT / "android-app/app/src/main/assets/models"
    return [
        {"name": "Current app: Balanced local", "path": str(root / "anomaly-local.json"), "group": "current_app"},
        {"name": "Current app: Sensitive local", "path": str(root / "anomaly-v13-recall.json"), "group": "current_app"},
        {"name": "Current app: Quiet local", "path": str(root / "anomaly-v14-quiet.json"), "group": "current_app"},
        {"name": "Current app: Privacy local", "path": str(root / "anomaly-privacy-local.json"), "group": "current_app"},
    ]


def _artifact_models() -> list[dict[str, str]]:
    root = REPO_ROOT / "ml-pipeline/artifacts/android"
    rows: list[dict[str, str]] = []
    for path in sorted(root.glob("anomaly*.json")):
        if "threshold" in path.name:
            continue
        rows.append({"name": f"Artifact: {path.stem}", "path": str(path), "group": "historical_artifact"})
    return rows


def _load_model(path: str | Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None
    if payload.get("model_type") not in {"logistic_regression", "random_forest_classifier", "boosted_tree_classifier"}:
        return None
    return payload


def _evaluate_one(name: str, group: str, path: str, payload: dict[str, Any], frame: pd.DataFrame, view: str) -> dict[str, Any]:
    labels = frame["label"].fillna(0).astype(int).to_numpy()
    threshold = _threshold_from_model(payload)
    scores = score_android_model(payload, frame)
    metrics = binary_classification_metrics(labels, scores, threshold)
    best_threshold = select_threshold_by_f1(labels, scores)
    best_metrics = binary_classification_metrics(labels, scores, best_threshold)
    frontier = threshold_sweep_metrics(labels, scores)
    target = frontier[(frontier["precision"] >= 0.70) & (frontier["recall"] >= 0.70)]
    return {
        "name": name,
        "group": group,
        "view": view,
        "path": str(path),
        "model_type": payload.get("model_type"),
        "algorithm": payload.get("algorithm", payload.get("model_type")),
        "feature_count": len(payload.get("feature_order", [])),
        "input_transform": payload.get("input_transform", "none"),
        "threshold": threshold,
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positive_rate": metrics["false_positive_rate"],
        "positive_predictions": metrics["positive_predictions"],
        "pr_auc": metrics["pr_auc"],
        "roc_auc": metrics["roc_auc"],
        "best_f1_threshold": best_threshold,
        "best_f1_precision": best_metrics["precision"],
        "best_f1_recall": best_metrics["recall"],
        "best_f1": best_metrics["f1"],
        "achieves_70_precision_70_recall": bool(not target.empty),
    }


def _evaluate_remote(name: str, path: str, frame: pd.DataFrame, view: str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    module = _load_backend_remote_modeling()
    labels = frame["label"].fillna(0).astype(int).to_numpy()
    threshold = _threshold_from_model(payload)
    scores = _score_remote_model(module, payload, frame)
    metrics = binary_classification_metrics(labels, scores, threshold)
    best_threshold = select_threshold_by_f1(labels, scores)
    best_metrics = binary_classification_metrics(labels, scores, best_threshold)
    frontier = threshold_sweep_metrics(labels, scores)
    target = frontier[(frontier["precision"] >= 0.70) & (frontier["recall"] >= 0.70)]
    return {
        "name": name,
        "group": "remote_backend",
        "view": view,
        "path": str(path),
        "model_type": payload.get("model_type", "remote_backend"),
        "algorithm": payload.get("model_type", "remote_backend"),
        "feature_count": len(payload.get("feature_order", [])),
        "input_transform": "remote_backend",
        "threshold": threshold,
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positive_rate": metrics["false_positive_rate"],
        "positive_predictions": metrics["positive_predictions"],
        "pr_auc": metrics["pr_auc"],
        "roc_auc": metrics["roc_auc"],
        "best_f1_threshold": best_threshold,
        "best_f1_precision": best_metrics["precision"],
        "best_f1_recall": best_metrics["recall"],
        "best_f1": best_metrics["f1"],
        "achieves_70_precision_70_recall": bool(not target.empty),
    }


def _write_markdown(rows: list[dict[str, Any]], output: str | Path) -> None:
    columns = [
        "view",
        "name",
        "threshold",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "best_f1",
        "achieves_70_precision_70_recall",
        "feature_count",
        "input_transform",
    ]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in rows:
        values = []
        for column in columns:
            value = row.get(column)
            if isinstance(value, float):
                value = f"{value:.4f}"
            values.append(str(value))
        lines.append("| " + " | ".join(values) + " |")
    Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    windows = load_android_windows_for_protocol(args.input, args, cache_prefix=args.cache_prefix)
    if "label" not in windows.columns or windows["label"].fillna(0).astype(int).nunique() < 2:
        raise SystemExit("Comparison requires labeled windows with both classes.")
    split = source_aware_train_test_split(
        windows,
        label_column="label",
        test_size=float(args.test_ratio),
        random_seed=int(args.random_seed),
    )
    holdout = windows.iloc[split.test_idx].reset_index(drop=True)
    evaluation_views = {
        "natural_holdout": _sample_natural(holdout, int(args.max_eval_rows), int(args.random_seed)),
        "balanced_holdout": _sample_balanced(holdout, int(args.max_eval_rows), int(args.random_seed)),
    }

    model_specs = _app_models()
    if args.include_artifacts:
        model_specs.extend(_artifact_models())

    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for spec in model_specs:
        path = str(Path(spec["path"]))
        if path in seen_paths:
            continue
        seen_paths.add(path)
        payload = _load_model(path)
        if payload is None:
            skipped.append({"name": spec["name"], "path": path, "reason": "not an Android-deployable scorer JSON"})
            continue
        for view_name, frame in evaluation_views.items():
            try:
                rows.append(_evaluate_one(spec["name"], spec["group"], path, payload, frame, view_name))
            except Exception as exc:
                skipped.append({"name": spec["name"], "path": path, "view": view_name, "reason": str(exc)})

    if args.remote_model:
        for view_name, frame in evaluation_views.items():
            try:
                rows.append(_evaluate_remote("Backend: Remote assisted", args.remote_model, frame, view_name))
            except Exception as exc:
                skipped.append({"name": "Backend: Remote assisted", "path": args.remote_model, "view": view_name, "reason": str(exc)})

    rows.sort(key=lambda row: (row["view"], -float(row["f1"]), row["name"]))
    payload = {
        "input": str(Path(args.input).expanduser().resolve()),
        "window_protocol": {
            "window_mode": args.window_mode,
            "window_seconds": int(args.window_seconds),
            "label_strategy": args.label_strategy,
            "max_adaptive_windows": int(args.max_adaptive_windows),
            "max_flow_rows": int(args.max_flow_rows),
            "multi_horizon_training": bool(args.multi_horizon_training),
            "cache_name": adaptive_cache_name(args, args.cache_prefix),
        },
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "holdout_rows": int(len(holdout)),
        "evaluation_views": {
            name: {
                "rows": int(len(frame)),
                "label_counts": {str(key): int(value) for key, value in frame["label"].fillna(0).astype(int).value_counts().to_dict().items()},
            }
            for name, frame in evaluation_views.items()
        },
        "rows": rows,
        "skipped": skipped,
    }
    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_csv:
        csv_path = Path(args.output_csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(csv_path, index=False)
    if args.output_md:
        md_path = Path(args.output_md)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        _write_markdown(rows, md_path)


if __name__ == "__main__":
    main()
