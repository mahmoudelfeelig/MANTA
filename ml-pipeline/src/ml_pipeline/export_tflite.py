from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
from sklearn.cluster import KMeans

from .cache_utils import load_feature_windows_cached
from .dataset_metadata import hard_example_weight
from .features import build_feature_windows, feature_matrix
from .io_utils import read_csv_resilient
from .metrics import binary_classification_metrics, per_group_binary_metrics
from .progress import EpochPercentCallback, PhaseProgress
from .splits import nested_source_aware_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train tiny autoencoder and export TFLite model")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--output", required=True, help="Output .tflite path")
    parser.add_argument("--output-report", help="Optional evaluation report JSON path")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--minimum-recall", type=float, default=0.78)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _best_precision_threshold(y_true: np.ndarray, scores: np.ndarray, minimum_recall: float) -> float:
    best_threshold = 0.5
    best_precision = -1.0
    best_f1 = -1.0
    for threshold in np.linspace(0.0, 1.0, 401):
        metrics = binary_classification_metrics(y_true, scores, float(threshold))
        recall = float(metrics["recall"] or 0.0)
        precision = float(metrics["precision"] or 0.0)
        f1 = float(metrics["f1"] or 0.0)
        if recall >= minimum_recall and (precision > best_precision or (np.isclose(precision, best_precision) and f1 > best_f1)):
            best_threshold = float(threshold)
            best_precision = precision
            best_f1 = f1
    return best_threshold


def _nearest_centroid_residuals(values: np.ndarray, centroids: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    if len(centroids) == 0:
        return values, np.zeros(len(values), dtype=int)
    distances = np.sum((values[:, None, :] - centroids[None, :, :]) ** 2, axis=2)
    nearest = np.argmin(distances, axis=1)
    return values - centroids[nearest], nearest


def _oversample_hard_benign(train_df, features: np.ndarray) -> np.ndarray:
    weights = np.asarray(
        [
            hard_example_weight(
                int(label),
                str(source),
                str(family),
            )
            for label, source, family in zip(
                train_df["label"].fillna(0).astype(int).to_numpy(),
                train_df["dataset_source"],
                train_df["app_family"],
                strict=False,
            )
        ],
        dtype=float,
    )
    benign_mask = train_df["label"].fillna(0).astype(int).to_numpy() == 0
    if not np.any(benign_mask):
        return features
    benign_features = features[benign_mask]
    benign_weights = weights[benign_mask]
    repeats = np.clip(np.rint(benign_weights), 1, 3).astype(int)
    expanded = np.repeat(benign_features, repeats, axis=0)
    return expanded.astype(np.float32)


def _cluster_thresholds(calibration_scores: np.ndarray, y_calibration: np.ndarray | None, cluster_ids: np.ndarray, minimum_recall: float) -> tuple[float, list[float]]:
    benign_scores = calibration_scores if y_calibration is None else calibration_scores[np.asarray(y_calibration) == 0]
    if benign_scores.size == 0:
        benign_scores = calibration_scores
    global_p99 = float(np.percentile(benign_scores, 99))
    global_p999 = float(np.percentile(benign_scores, 99.9))
    global_threshold = float(max(global_p99, global_p99 + (1.5 * max(0.0, global_p999 - global_p99))))
    if y_calibration is not None and len(np.unique(y_calibration)) > 1:
        global_threshold = float(max(global_threshold, _best_precision_threshold(y_calibration, calibration_scores, minimum_recall)))

    thresholds: list[float] = []
    for cluster_id in range(int(cluster_ids.max()) + 1 if cluster_ids.size else 1):
        mask = cluster_ids == cluster_id
        if not np.any(mask):
            thresholds.append(global_threshold)
            continue
        cluster_scores = calibration_scores[mask]
        cluster_labels = None if y_calibration is None else np.asarray(y_calibration)[mask]
        cluster_benign = cluster_scores if cluster_labels is None else cluster_scores[cluster_labels == 0]
        if cluster_benign.size < 24:
            thresholds.append(global_threshold)
            continue
        cluster_threshold = float(np.percentile(cluster_benign, 99))
        if cluster_labels is not None and len(np.unique(cluster_labels)) > 1:
            cluster_threshold = float(
                max(
                    cluster_threshold,
                    _best_precision_threshold(cluster_labels, cluster_scores, minimum_recall),
                )
            )
        thresholds.append(cluster_threshold)
    return global_threshold, thresholds


def main() -> None:
    try:
        import tensorflow as tf
        from tensorflow.python.framework.convert_to_constants import convert_variables_to_constants_v2
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("TensorFlow is required. Install with: pip install -e .[tflite]") from exc

    args = parse_args()
    progress = PhaseProgress("TFLite autoencoder export")
    progress.update(5, "Loading flow CSV")
    progress.update(16, "Building feature windows")
    windows = load_feature_windows_cached(
        args.input,
        build_windows_fn=build_feature_windows,
        read_frame_fn=read_csv_resilient,
    )
    X = feature_matrix(windows).astype(np.float32).values
    labels = windows["label"].fillna(0).astype(int).to_numpy() if "label" in windows.columns else None

    if labels is not None and len(np.unique(labels)) > 1:
        outer_split, inner_split = nested_source_aware_split(
            windows,
            label_column="label",
            outer_test_size=args.test_ratio,
            inner_validation_size=0.25,
            random_seed=args.random_seed,
        )
        outer_train = windows.iloc[outer_split.train_idx].reset_index(drop=True)
        outer_test = windows.iloc[outer_split.test_idx].reset_index(drop=True)
        train_core = outer_train.iloc[inner_split.train_idx].reset_index(drop=True)
        calibration_df = outer_train.iloc[inner_split.test_idx].reset_index(drop=True)

        benign_train = train_core[train_core["label"].fillna(0).astype(int) == 0]
        if benign_train.empty:
            benign_train = train_core

        X_train = feature_matrix(benign_train).astype(np.float32).values
        X_train = _oversample_hard_benign(benign_train, X_train)
        X_calibration = feature_matrix(calibration_df).astype(np.float32).values
        y_calibration = calibration_df["label"].fillna(0).astype(int).to_numpy()
        X_eval = feature_matrix(outer_test).astype(np.float32).values
        y_eval = outer_test["label"].fillna(0).astype(int).to_numpy()
        eval_sources = outer_test["dataset_source"].astype(str)
        split_summary = {
            "outer": outer_split.summary,
            "inner": inner_split.summary,
        }
    else:
        X_train = X
        X_calibration = X
        y_calibration = labels
        X_eval = X
        y_eval = labels
        eval_sources = windows["dataset_source"].astype(str) if "dataset_source" in windows.columns else None
        split_summary = None

    mean = X_train.mean(axis=0).astype(np.float32)
    scale = np.where(X_train.std(axis=0) < 1e-6, 1.0, X_train.std(axis=0)).astype(np.float32)
    X_train_scaled = np.clip((X_train - mean) / scale, -8.0, 8.0).astype(np.float32)
    X_calibration_scaled = np.clip((X_calibration - mean) / scale, -8.0, 8.0).astype(np.float32)
    X_eval_scaled = np.clip((X_eval - mean) / scale, -8.0, 8.0).astype(np.float32)

    cluster_count = int(min(8, max(1, len(X_train_scaled) // 4000 + 1)))
    if len(X_train_scaled) >= cluster_count and cluster_count > 1:
        kmeans = KMeans(n_clusters=cluster_count, random_state=args.random_seed, n_init=10)
        kmeans.fit(X_train_scaled)
        centroids = kmeans.cluster_centers_.astype(np.float32)
    else:
        centroids = np.zeros((1, X_train_scaled.shape[1]), dtype=np.float32)

    X_train_clustered, train_cluster_ids = _nearest_centroid_residuals(X_train_scaled, centroids)
    X_calibration_clustered, calibration_cluster_ids = _nearest_centroid_residuals(X_calibration_scaled, centroids)
    X_eval_clustered, eval_cluster_ids = _nearest_centroid_residuals(X_eval_scaled, centroids)

    input_dim = X.shape[1]
    inputs = tf.keras.Input(shape=(input_dim,))
    noisy = tf.keras.layers.GaussianNoise(0.06)(inputs)
    encoded = tf.keras.layers.Dense(48, activation="relu")(noisy)
    encoded = tf.keras.layers.Dropout(0.10)(encoded)
    encoded = tf.keras.layers.Dense(18, activation="relu")(encoded)
    bottleneck = tf.keras.layers.Dense(6, activation="linear")(encoded)
    decoded = tf.keras.layers.Dense(18, activation="relu")(bottleneck)
    decoded = tf.keras.layers.Dense(48, activation="relu")(decoded)
    outputs = tf.keras.layers.Dense(input_dim, activation="linear")(decoded)

    autoencoder = tf.keras.Model(inputs=inputs, outputs=outputs)
    autoencoder.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3), loss="mse")
    progress.update(30, "Training one-class autoencoder")
    callback = EpochPercentCallback(progress, start_percent=30, end_percent=72, epochs=args.epochs, label="autoencoder")

    class KerasProgressCallback(tf.keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs=None):  # noqa: ANN001
            callback.on_epoch_end(epoch)

    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor="val_loss",
        patience=6,
        restore_best_weights=True,
        min_delta=1e-4,
    )
    fit_start = time.perf_counter()
    autoencoder.fit(
        X_train_clustered,
        X_train_clustered,
        epochs=args.epochs,
        batch_size=args.batch_size,
        verbose=0,
        validation_split=0.1,
        callbacks=[KerasProgressCallback(), early_stopping],
    )
    training_seconds = float(time.perf_counter() - fit_start)

    progress.update(78, "Calibrating cluster-aware thresholds")
    train_reconstruction = autoencoder.predict(X_train_clustered, verbose=0)
    train_mse = np.mean(np.square(X_train_clustered - train_reconstruction), axis=1)
    calibration_reconstruction = autoencoder.predict(X_calibration_clustered, verbose=0)
    calibration_mse = np.mean(np.square(X_calibration_clustered - calibration_reconstruction), axis=1)
    global_threshold, cluster_thresholds = _cluster_thresholds(
        calibration_mse,
        y_calibration,
        calibration_cluster_ids,
        args.minimum_recall,
    )
    cluster_threshold_array = np.asarray(cluster_thresholds if cluster_thresholds else [global_threshold], dtype=np.float32)

    class ScoringModule(tf.Module):
        def __init__(self, model: tf.keras.Model):
            super().__init__()
            self.model = model
            self.mean = tf.constant(mean.reshape((1, input_dim)), dtype=tf.float32)
            self.scale = tf.constant(scale.reshape((1, input_dim)), dtype=tf.float32)
            self.centroids = tf.constant(centroids, dtype=tf.float32)
            self.cluster_thresholds = tf.constant(cluster_threshold_array.reshape((-1, 1)), dtype=tf.float32)
            self.global_threshold = tf.constant(global_threshold, dtype=tf.float32)

        @tf.function(input_signature=[tf.TensorSpec(shape=[None, input_dim], dtype=tf.float32)])
        def __call__(self, features: tf.Tensor) -> tf.Tensor:
            normalized = tf.clip_by_value((features - self.mean) / self.scale, -8.0, 8.0)
            expanded = tf.expand_dims(normalized, axis=1)
            distances = tf.reduce_sum(tf.square(expanded - self.centroids), axis=2)
            nearest = tf.argmin(distances, axis=1)
            nearest_centroid = tf.gather(self.centroids, nearest)
            thresholds = tf.gather(self.cluster_thresholds, nearest)
            centered = normalized - nearest_centroid
            reconstructed = self.model(centered)
            mse_val = tf.reduce_mean(tf.square(centered - reconstructed), axis=1, keepdims=True)
            safe_threshold = tf.maximum(thresholds, self.global_threshold * 0.5)
            return tf.clip_by_value(mse_val / tf.maximum(safe_threshold, 1e-6), 0.0, 1.0)

    progress.update(86, "Converting to TFLite")
    module = ScoringModule(autoencoder)
    concrete = module.__call__.get_concrete_function()
    frozen_concrete = convert_variables_to_constants_v2(concrete)
    converter = tf.lite.TFLiteConverter.from_concrete_functions([frozen_concrete])
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tflite_model)

    if args.output_report:
        progress.update(94, "Writing evaluation report")
        eval_reconstruction = autoencoder.predict(X_eval_clustered, verbose=0)
        eval_scores_raw = np.mean(np.square(X_eval_clustered - eval_reconstruction), axis=1)
        eval_thresholds = cluster_threshold_array[np.clip(eval_cluster_ids, 0, len(cluster_threshold_array) - 1)]
        eval_scores = np.clip(eval_scores_raw / np.maximum(eval_thresholds, 1e-6), 0.0, 1.0)
        report_payload = {
            "model_type": "one_class_autoencoder",
            "rows_train_normal": int(len(X_train)),
            "rows_eval": int(len(X_eval)),
            "training_seconds": training_seconds,
            "threshold": float(global_threshold),
            "cluster_thresholds": [float(value) for value in cluster_threshold_array.tolist()],
            "mean_reconstruction_error_train": float(np.mean(train_mse)) if len(train_mse) else 0.0,
            "p99_reconstruction_error_train": float(np.percentile(train_mse, 99)) if len(train_mse) else 0.0,
            "p999_reconstruction_error_train": float(np.percentile(train_mse, 99.9)) if len(train_mse) else 0.0,
            "feature_scaling": "zscore_clipped_cluster_centered_cluster_thresholded",
            "cluster_count": int(len(centroids)),
            "split_summary": split_summary,
            "threshold_strategy": "cluster_aware_evt_with_precision_floor",
        }
        if y_eval is not None and len(np.unique(y_eval)) > 1:
            report_payload.update(binary_classification_metrics(y_eval, eval_scores, 1.0))
            report_payload["label_counts_eval"] = {
                "0": int((y_eval == 0).sum()),
                "1": int((y_eval == 1).sum()),
            }
            if eval_sources is not None:
                report_payload["per_source_metrics"] = per_group_binary_metrics(y_eval, eval_scores, eval_sources, 1.0, min_rows=24)
        report_path = Path(args.output_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
