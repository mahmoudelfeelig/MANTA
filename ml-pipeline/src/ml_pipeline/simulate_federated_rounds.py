from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from .cache_utils import load_privacy_views_cached
from .features import build_feature_windows
from .io_utils import read_csv_resilient
from .metrics import binary_classification_metrics, per_group_binary_metrics
from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_SETS, PRIVACY_VIEW_CHOICES, build_window_privacy_views_from_windows, canonical_privacy_view_name
from .splits import add_split_metadata, source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate federated rounds on privacy-reduced public proxy clients")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-report", required=True, help="Output JSON report path")
    parser.add_argument("--view", choices=PRIVACY_VIEW_CHOICES, default="medium")
    parser.add_argument("--student-model", default="", help="Optional privacy-student model JSON for latent representations")
    parser.add_argument("--client-column", default="public_proxy_client", help="public_proxy_client or a real metadata column in the privacy view")
    parser.add_argument("--client-count", type=int, default=16)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--local-epochs", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--proximal-mu", type=float, default=0.02)
    parser.add_argument("--algorithm", choices=("fedprox", "scaffold"), default="fedprox")
    parser.add_argument("--validation-ratio", type=float, default=0.2)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-values))


def _relu(values: np.ndarray) -> np.ndarray:
    return np.maximum(values, 0.0)


def _encode_with_student(features: np.ndarray, student_model: dict[str, object]) -> np.ndarray:
    weights = student_model.get("weights") or {}
    current = np.asarray(features, dtype=float)
    for layer_name in ("dense_1", "dense_2", "latent"):
        layer_weights = weights.get(layer_name) or []
        if len(layer_weights) < 2:
            continue
        w = np.asarray(layer_weights[0], dtype=float)
        b = np.asarray(layer_weights[1], dtype=float)
        current = _relu(current @ w + b)
    latent_mean = np.asarray(student_model.get("latent_mean") or [0.0] * current.shape[1], dtype=float)
    latent_scale = np.asarray(student_model.get("latent_scale") or [1.0] * current.shape[1], dtype=float)
    if latent_mean.shape[0] == current.shape[1] and latent_scale.shape[0] == current.shape[1]:
        safe_scale = np.where(np.abs(latent_scale) <= 1e-6, 1.0, latent_scale)
        current = (current - latent_mean) / safe_scale
    return current


def _client_assignments(frame: pd.DataFrame, client_column: str, client_count: int) -> tuple[np.ndarray, str]:
    if client_column != "public_proxy_client":
        if client_column not in frame.columns:
            raise SystemExit(f"Client column {client_column!r} not present in privacy view.")
        values = frame[client_column].astype(str).to_numpy(dtype=object)
        return values, f"real_column:{client_column}"

    primary = (
        frame["dataset_source"].astype(str) + "|" +
        frame["environment_id"].astype(str) + "|" +
        frame["session_id"].astype(str) + "|" +
        frame["app_family"].astype(str)
    )
    primary_counts = primary.value_counts()
    primary_keep = primary_counts[primary_counts >= 8].index.tolist()
    if len(primary_keep) >= max(4, min(client_count, 6)):
        filtered = primary.where(primary.isin(primary_keep), frame["dataset_source"].astype(str) + "|" + frame["app_family"].astype(str))
        return filtered.to_numpy(dtype=object), "public_proxy_client"

    fallback = (
        frame["dataset_source"].astype(str) + "|" +
        frame["app_family"].astype(str) + "|" +
        frame["time_fold"].astype(str)
    )
    ranked = fallback.value_counts().index.tolist()
    buckets = {name: f"client_{idx % max(1, client_count):02d}" for idx, name in enumerate(ranked)}
    values = np.asarray([buckets[item] for item in fallback.astype(str).tolist()], dtype=object)
    return values, "bucketed_public_proxy_client"


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.05, 0.95, 181):
        current = binary_classification_metrics(y_true, scores, float(threshold))
        f1_value = float(current["f1"] or 0.0)
        if f1_value > best_f1:
            best_f1 = f1_value
            best_threshold = float(threshold)
    return best_threshold


def _client_rows(clients: np.ndarray, labels: np.ndarray) -> list[dict[str, int | str | float]]:
    rows: list[dict[str, int | str | float]] = []
    unique_clients = sorted(np.unique(clients).tolist())
    for client in unique_clients:
        mask = clients == client
        positive_rate = float(np.mean(labels[mask])) if int(mask.sum()) else 0.0
        rows.append(
            {
                "client": str(client),
                "rows": int(mask.sum()),
                "label_0": int((labels[mask] == 0).sum()),
                "label_1": int((labels[mask] == 1).sum()),
                "positive_rate": positive_rate,
            }
        )
    return rows


def _evaluate_scores(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float | int | None]:
    return binary_classification_metrics(y_true, scores, threshold)


def _fedprox_train(
    X_train: np.ndarray,
    y_train: np.ndarray,
    clients: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    *,
    rounds: int,
    local_epochs: int,
    learning_rate: float,
    proximal_mu: float,
) -> tuple[np.ndarray, float, list[dict[str, object]], list[dict[str, int | str | float]]]:
    unique_clients = sorted(np.unique(clients).tolist())
    client_rows = _client_rows(clients, y_train)
    global_w = np.zeros(X_train.shape[1], dtype=float)
    global_b = 0.0
    history: list[dict[str, object]] = []

    for round_index in range(1, rounds + 1):
        updated_weights: list[np.ndarray] = []
        updated_biases: list[float] = []
        sample_counts: list[float] = []
        participants = 0
        for client in unique_clients:
            mask = clients == client
            if int(mask.sum()) < 24 or len(np.unique(y_train[mask])) < 2:
                continue
            local_x = X_train[mask]
            local_y = y_train[mask].astype(float)
            local_w = global_w.copy()
            local_b = float(global_b)
            for _epoch in range(local_epochs):
                logits = local_x @ local_w + local_b
                probs = _sigmoid(logits)
                error = probs - local_y
                grad_w = (local_x.T @ error) / max(1, len(local_x)) + proximal_mu * (local_w - global_w)
                grad_b = float(np.mean(error))
                local_w -= learning_rate * grad_w
                local_b -= learning_rate * grad_b
            updated_weights.append(local_w)
            updated_biases.append(local_b)
            sample_counts.append(float(mask.sum()))
            participants += 1
        if not updated_weights:
            break
        weights = np.asarray(sample_counts, dtype=float)
        weights = weights / weights.sum()
        global_w = np.average(np.vstack(updated_weights), axis=0, weights=weights)
        global_b = float(np.average(np.asarray(updated_biases, dtype=float), weights=weights))
        val_scores = _sigmoid(X_val @ global_w + global_b)
        val_threshold = _best_threshold(y_val, val_scores)
        history.append(
            {
                "round": int(round_index),
                "participants": int(participants),
                "threshold": float(val_threshold),
                "validation": _evaluate_scores(y_val, val_scores, val_threshold),
            }
        )
    return global_w, global_b, history, client_rows


def _scaffold_train(
    X_train: np.ndarray,
    y_train: np.ndarray,
    clients: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    *,
    rounds: int,
    local_epochs: int,
    learning_rate: float,
) -> tuple[np.ndarray, float, list[dict[str, object]], list[dict[str, int | str | float]]]:
    unique_clients = sorted(np.unique(clients).tolist())
    client_rows = _client_rows(clients, y_train)
    global_w = np.zeros(X_train.shape[1], dtype=float)
    global_b = 0.0
    global_c_w = np.zeros(X_train.shape[1], dtype=float)
    global_c_b = 0.0
    client_controls_w = {str(client): np.zeros(X_train.shape[1], dtype=float) for client in unique_clients}
    client_controls_b = {str(client): 0.0 for client in unique_clients}
    history: list[dict[str, object]] = []

    for round_index in range(1, rounds + 1):
        updated_weights: list[np.ndarray] = []
        updated_biases: list[float] = []
        updated_control_w: list[np.ndarray] = []
        updated_control_b: list[float] = []
        sample_counts: list[float] = []
        participants = 0
        for client in unique_clients:
            mask = clients == client
            if int(mask.sum()) < 24 or len(np.unique(y_train[mask])) < 2:
                continue
            local_x = X_train[mask]
            local_y = y_train[mask].astype(float)
            local_w = global_w.copy()
            local_b = float(global_b)
            client_c_w = client_controls_w[str(client)]
            client_c_b = client_controls_b[str(client)]
            steps = 0
            for _epoch in range(local_epochs):
                logits = local_x @ local_w + local_b
                probs = _sigmoid(logits)
                error = probs - local_y
                grad_w = (local_x.T @ error) / max(1, len(local_x)) - client_c_w + global_c_w
                grad_b = float(np.mean(error) - client_c_b + global_c_b)
                local_w -= learning_rate * grad_w
                local_b -= learning_rate * grad_b
                steps += 1
            if steps > 0:
                new_c_w = client_c_w - global_c_w + ((global_w - local_w) / max(learning_rate * steps, 1e-6))
                new_c_b = client_c_b - global_c_b + ((global_b - local_b) / max(learning_rate * steps, 1e-6))
                client_controls_w[str(client)] = new_c_w
                client_controls_b[str(client)] = float(new_c_b)
                updated_control_w.append(new_c_w)
                updated_control_b.append(float(new_c_b))
            updated_weights.append(local_w)
            updated_biases.append(local_b)
            sample_counts.append(float(mask.sum()))
            participants += 1
        if not updated_weights:
            break
        weights = np.asarray(sample_counts, dtype=float)
        weights = weights / weights.sum()
        global_w = np.average(np.vstack(updated_weights), axis=0, weights=weights)
        global_b = float(np.average(np.asarray(updated_biases, dtype=float), weights=weights))
        if updated_control_w:
            global_c_w = np.mean(np.vstack(updated_control_w), axis=0)
            global_c_b = float(np.mean(np.asarray(updated_control_b, dtype=float)))
        val_scores = _sigmoid(X_val @ global_w + global_b)
        val_threshold = _best_threshold(y_val, val_scores)
        history.append(
            {
                "round": int(round_index),
                "participants": int(participants),
                "threshold": float(val_threshold),
                "validation": _evaluate_scores(y_val, val_scores, val_threshold),
            }
        )
    return global_w, global_b, history, client_rows


def main() -> None:
    args = parse_args()
    view_name = canonical_privacy_view_name(args.view)
    progress = PhaseProgress("Federated simulation")
    progress.update(10, "Building privacy views")
    views = load_privacy_views_cached(
        args.input,
        build_feature_windows_fn=build_feature_windows,
        build_privacy_views_from_windows_fn=build_window_privacy_views_from_windows,
        read_frame_fn=read_csv_resilient,
    )
    frame = add_split_metadata(views[view_name])
    if "label" not in frame.columns:
        raise SystemExit("Federated simulation requires labels.")

    split = source_aware_train_test_split(frame, label_column="label", test_size=0.3, random_seed=args.random_seed)
    train = frame.iloc[split.train_idx].reset_index(drop=True)
    test = frame.iloc[split.test_idx].reset_index(drop=True)
    train_split = source_aware_train_test_split(
        train,
        label_column="label",
        test_size=args.validation_ratio,
        random_seed=args.random_seed + 19,
    )
    federation_train = train.iloc[train_split.train_idx].reset_index(drop=True)
    validation = train.iloc[train_split.test_idx].reset_index(drop=True)

    feature_columns = [column for column in PRIVACY_FEATURE_SETS[view_name] if column in frame.columns]
    y_train = federation_train["label"].fillna(0).astype(int).to_numpy()
    y_val = validation["label"].fillna(0).astype(int).to_numpy()
    y_test = test["label"].fillna(0).astype(int).to_numpy()

    scaler = StandardScaler()
    train_x = scaler.fit_transform(federation_train[feature_columns].fillna(0.0))
    val_x = scaler.transform(validation[feature_columns].fillna(0.0))
    test_x = scaler.transform(test[feature_columns].fillna(0.0))

    if args.student_model:
        student_model = json.loads(Path(args.student_model).read_text(encoding="utf-8"))
        train_x = _encode_with_student(train_x, student_model)
        val_x = _encode_with_student(val_x, student_model)
        test_x = _encode_with_student(test_x, student_model)
        representation = "privacy_student_latent"
    else:
        representation = "raw_privacy_view_features"

    clients, split_mode = _client_assignments(federation_train, args.client_column, args.client_count)
    progress.update(28, f"Training federated rounds with {args.algorithm}")
    fit_start = time.perf_counter()
    if args.algorithm == "scaffold":
        global_w, global_b, history, client_rows = _scaffold_train(
            train_x,
            y_train,
            clients,
            val_x,
            y_val,
            rounds=args.rounds,
            local_epochs=args.local_epochs,
            learning_rate=args.learning_rate,
        )
        secure_aggregation = "simulated_scaffold_weighted_average"
    else:
        global_w, global_b, history, client_rows = _fedprox_train(
            train_x,
            y_train,
            clients,
            val_x,
            y_val,
            rounds=args.rounds,
            local_epochs=args.local_epochs,
            learning_rate=args.learning_rate,
            proximal_mu=args.proximal_mu,
        )
        secure_aggregation = "simulated_fedprox_weighted_average"
    training_seconds = float(time.perf_counter() - fit_start)

    if history:
        threshold = float(history[-1]["threshold"])
    else:
        threshold = 0.5
    test_scores = _sigmoid(test_x @ global_w + global_b)
    test_metrics = _evaluate_scores(y_test, test_scores, threshold)
    fairness = per_group_binary_metrics(
        y_test,
        test_scores,
        test["dataset_source"].astype(str) + "|" + test["app_family"].astype(str),
        threshold,
        min_rows=24,
    )
    client_positive_rates = np.asarray([float(row["positive_rate"]) for row in client_rows], dtype=float) if client_rows else np.asarray([], dtype=float)
    heterogeneity = {
        "client_count": int(len(client_rows)),
        "positive_rate_std": float(client_positive_rates.std(ddof=0)) if client_positive_rates.size else 0.0,
        "rows_min": int(min((int(row["rows"]) for row in client_rows), default=0)),
        "rows_max": int(max((int(row["rows"]) for row in client_rows), default=0)),
    }

    report = {
        "view": view_name,
        "representation": representation,
        "algorithm": args.algorithm,
        "split_mode": split_mode,
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "validation_split_strategy": train_split.strategy,
        "validation_split_summary": train_split.summary,
        "client_count": len(client_rows),
        "training_seconds": training_seconds,
        "rounds": int(args.rounds),
        "local_epochs": int(args.local_epochs),
        "learning_rate": float(args.learning_rate),
        "proximal_mu": float(args.proximal_mu),
        "threshold": threshold,
        "clients": client_rows,
        "round_history": history,
        "client_heterogeneity": heterogeneity,
        "fairness_by_group": fairness,
        **test_metrics,
        "secure_aggregation": secure_aggregation,
    }
    output_path = Path(args.output_report).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
