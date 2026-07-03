from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from .android_feature_contract import ANDROID_FEATURE_COLUMNS, validate_android_feature_order


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy a validated Android-compatible model artifact")
    parser.add_argument("--model", required=True, help="Input model JSON")
    parser.add_argument(
        "--android-model",
        default="android-app/app/src/main/assets/models/anomaly-local.json",
        help="Android asset destination",
    )
    return parser.parse_args()


def validate_deployable_model(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    model_type = payload.get("model_type")
    if model_type not in {"logistic_regression", "random_forest_classifier", "boosted_tree_classifier"}:
        raise ValueError(f"Unsupported Android-deployable model_type: {model_type}")
    validate_android_feature_order(list(payload.get("feature_order", [])))
    if model_type == "logistic_regression":
        for key in ("means", "scales", "weights"):
            values = payload.get(key)
            if not isinstance(values, list) or len(values) != len(ANDROID_FEATURE_COLUMNS):
                raise ValueError(f"Invalid {key}: expected {len(ANDROID_FEATURE_COLUMNS)} values")
    if model_type in {"random_forest_classifier", "boosted_tree_classifier"}:
        trees = payload.get("trees")
        if not isinstance(trees, list) or not trees:
            raise ValueError("random_forest_classifier payload must include a non-empty trees list")
        for tree_index, tree in enumerate(trees):
            nodes = tree.get("nodes") if isinstance(tree, dict) else None
            if not isinstance(nodes, list) or not nodes:
                raise ValueError(f"Tree {tree_index} must include a non-empty nodes list")
            for node_index, node in enumerate(nodes):
                if not isinstance(node, dict):
                    raise ValueError(f"Tree {tree_index} node {node_index} must be an object")
                for key in ("feature_index", "threshold", "left", "right", "value"):
                    if key not in node:
                        raise ValueError(f"Tree {tree_index} node {node_index} missing {key}")
    return payload


def main() -> None:
    args = parse_args()
    model_path = Path(args.model).expanduser().resolve()
    destination = Path(args.android_model).expanduser()
    validate_deployable_model(model_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(model_path, destination)
    print(f"deployed {model_path} -> {destination}")


if __name__ == "__main__":
    main()
