from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_SETS, build_window_privacy_views


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate privacy-preserving federated rounds for MANTA")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-report", required=True, help="Output JSON report path")
    parser.add_argument("--view", choices=sorted(PRIVACY_FEATURE_SETS), default="semantic_private")
    parser.add_argument(
        "--client-column",
        default="synthetic_balanced_shard",
        help="Use synthetic_balanced_shard for balanced client simulation, or a real column name for grouped clients",
    )
    parser.add_argument("--client-count", type=int, default=12)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _balanced_shards(labels: np.ndarray, client_count: int, rng: np.random.Generator) -> np.ndarray:
    assignments = np.zeros(len(labels), dtype=int)
    for label in sorted(np.unique(labels).tolist()):
        indices = np.where(labels == label)[0]
        shuffled = rng.permutation(indices)
        for offset, index in enumerate(shuffled):
            assignments[index] = offset % client_count
    return assignments


def main() -> None:
    args = parse_args()
    progress = PhaseProgress("Federated simulation")
    flows = pd.read_csv(args.input)
    progress.update(15, "Building privacy views")
    views = build_window_privacy_views(flows)
    frame = views[args.view]
    if "label" not in frame.columns:
        raise SystemExit("Federated simulation requires labels.")
    feature_columns = [column for column in PRIVACY_FEATURE_SETS[args.view] if column in frame.columns]
    labels = frame["label"].fillna(0).astype(int).to_numpy()
    train_idx, test_idx = train_test_split(
        np.arange(len(frame)),
        test_size=0.3,
        random_state=args.random_seed,
        stratify=labels,
    )
    train = frame.iloc[train_idx].copy().reset_index(drop=True)
    test = frame.iloc[test_idx].copy().reset_index(drop=True)
    train_y = train["label"].fillna(0).astype(int).to_numpy()
    test_y = test["label"].fillna(0).astype(int).to_numpy()

    scaler = StandardScaler()
    train_x = scaler.fit_transform(train[feature_columns].fillna(0.0))
    test_x = scaler.transform(test[feature_columns].fillna(0.0))

    rng = np.random.default_rng(args.random_seed)
    if args.client_column == "synthetic_balanced_shard":
        shard_ids = _balanced_shards(train_y, client_count=max(2, args.client_count), rng=rng)
        client_ids = [f"client_{index:02d}" for index in range(max(2, args.client_count))]
        client_masks = {client_id: shard_ids == index for index, client_id in enumerate(client_ids)}
        split_mode = "synthetic_balanced_shard"
    else:
        if args.client_column not in train.columns:
            raise SystemExit(f"Client column {args.client_column!r} not present in privacy view.")
        client_ids = sorted(train[args.client_column].astype(str).unique().tolist())
        client_masks = {
            client_id: train[args.client_column].astype(str).to_numpy() == client_id
            for client_id in client_ids
        }
        split_mode = f"real_column:{args.client_column}"

    client_rows: list[dict[str, object]] = []
    coef_stack: list[np.ndarray] = []
    intercept_stack: list[np.ndarray] = []
    weights: list[float] = []
    progress.update(30, "Training client-local models")
    total_clients = max(1, len(client_masks))
    for index, (client_id, mask) in enumerate(client_masks.items(), start=1):
        rows = int(mask.sum())
        if rows < 32 or len(np.unique(train_y[mask])) < 2:
            continue
        clf = LogisticRegression(max_iter=1200, class_weight="balanced", random_state=args.random_seed)
        clf.fit(train_x[mask], train_y[mask])
        coef_stack.append(clf.coef_[0])
        intercept_stack.append(clf.intercept_)
        weights.append(float(rows))
        client_rows.append(
            {
                "client": client_id,
                "rows": rows,
                "label_0": int((train_y[mask] == 0).sum()),
                "label_1": int((train_y[mask] == 1).sum()),
            }
        )
        progress.update(30 + (55 * index / total_clients), f"Aggregating client {index}/{total_clients}")

    if not coef_stack:
        raise SystemExit("Not enough client diversity to simulate federated rounds.")

    normalized_weights = np.asarray(weights, dtype=float) / np.sum(weights)
    averaged_coef = np.average(np.vstack(coef_stack), axis=0, weights=normalized_weights)
    averaged_intercept = np.average(np.vstack(intercept_stack), axis=0, weights=normalized_weights)
    logits = test_x @ averaged_coef + averaged_intercept[0]
    scores = 1.0 / (1.0 + np.exp(-logits))
    pred = (scores >= 0.5).astype(int)

    report = {
        "view": args.view,
        "split_mode": split_mode,
        "client_count": len(client_rows),
        "clients": client_rows,
        "precision": float(precision_score(test_y, pred, zero_division=0)),
        "recall": float(recall_score(test_y, pred, zero_division=0)),
        "f1": float(f1_score(test_y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(test_y, scores)),
        "roc_auc": float(roc_auc_score(test_y, scores)),
        "secure_aggregation": "simulated_weighted_average",
    }
    output_path = Path(args.output_report).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
