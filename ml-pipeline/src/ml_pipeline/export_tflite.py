from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .features import build_feature_windows, feature_matrix
from .progress import EpochPercentCallback, PhaseProgress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train tiny autoencoder and export TFLite model")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--output", required=True, help="Output .tflite path")
    parser.add_argument("--output-report", help="Optional evaluation report JSON path")
    parser.add_argument("--epochs", type=int, default=35)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    try:
        import tensorflow as tf
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("TensorFlow is required. Install with: pip install -e .[tflite]") from exc

    args = parse_args()
    progress = PhaseProgress("TFLite autoencoder export")
    progress.update(5, "Loading flow CSV")
    df = pd.read_csv(args.input)
    progress.update(16, "Building feature windows")
    windows = build_feature_windows(df)
    X = feature_matrix(windows).astype(np.float32).values
    labels = windows["label"].fillna(0).astype(int).to_numpy() if "label" in windows.columns else None

    if labels is not None and len(np.unique(labels)) > 1:
        all_indices = np.arange(len(windows))
        train_idx, test_idx = train_test_split(
            all_indices,
            test_size=args.test_ratio,
            random_state=args.random_seed,
            stratify=labels,
        )
        benign_train_idx = train_idx[labels[train_idx] == 0]
        if len(benign_train_idx) == 0:
            benign_train_idx = train_idx
        X_train = X[benign_train_idx]
        X_eval = X[test_idx]
        y_eval = labels[test_idx]
    else:
        X_train = X
        X_eval = X
        y_eval = labels

    mean = X_train.mean(axis=0)
    scale = X_train.std(axis=0)
    scale = np.where(scale < 1e-6, 1.0, scale).astype(np.float32)
    mean = mean.astype(np.float32)
    X_train_scaled = np.clip((X_train - mean) / scale, -8.0, 8.0).astype(np.float32)
    X_eval_scaled = np.clip((X_eval - mean) / scale, -8.0, 8.0).astype(np.float32)

    input_dim = X.shape[1]
    inputs = tf.keras.Input(shape=(input_dim,))
    noisy = tf.keras.layers.GaussianNoise(0.05)(inputs)
    encoded = tf.keras.layers.Dense(64, activation="relu")(noisy)
    encoded = tf.keras.layers.Dense(24, activation="relu")(encoded)
    bottleneck = tf.keras.layers.Dense(8, activation="linear")(encoded)
    decoded = tf.keras.layers.Dense(24, activation="relu")(bottleneck)
    decoded = tf.keras.layers.Dense(64, activation="relu")(decoded)
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
        patience=5,
        restore_best_weights=True,
        min_delta=1e-4,
    )
    autoencoder.fit(
        X_train_scaled,
        X_train_scaled,
        epochs=args.epochs,
        batch_size=args.batch_size,
        verbose=0,
        validation_split=0.1,
        callbacks=[KerasProgressCallback(), early_stopping],
    )

    progress.update(78, "Calibrating reconstruction threshold")
    train_reconstruction = autoencoder.predict(X_train_scaled, verbose=0)
    train_mse = np.mean(np.square(X_train_scaled - train_reconstruction), axis=1)
    threshold = float(np.percentile(train_mse, 99))

    class ScoringModule(tf.Module):
        def __init__(self, model: tf.keras.Model, threshold_value: float):
            super().__init__()
            self.model = model
            self.threshold = tf.constant(threshold_value, dtype=tf.float32)
            self.mean = tf.constant(mean.reshape((1, input_dim)), dtype=tf.float32)
            self.scale = tf.constant(scale.reshape((1, input_dim)), dtype=tf.float32)

        @tf.function(input_signature=[tf.TensorSpec(shape=[None, input_dim], dtype=tf.float32)])
        def __call__(self, features: tf.Tensor) -> tf.Tensor:
            normalized = tf.clip_by_value((features - self.mean) / self.scale, -8.0, 8.0)
            reconstructed = self.model(normalized)
            mse_val = tf.reduce_mean(tf.square(normalized - reconstructed), axis=1, keepdims=True)
            score = tf.clip_by_value(mse_val / tf.maximum(self.threshold, 1e-6), 0.0, 1.0)
            return score

    progress.update(86, "Converting to TFLite")
    module = ScoringModule(autoencoder, threshold)
    concrete = module.__call__.get_concrete_function()

    converter = tf.lite.TFLiteConverter.from_concrete_functions([concrete], module)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tflite_model)

    if args.output_report:
        progress.update(94, "Writing evaluation report")
        eval_reconstruction = autoencoder.predict(X_eval_scaled, verbose=0)
        eval_scores = np.mean(np.square(X_eval_scaled - eval_reconstruction), axis=1)
        report_payload = {
            "model_type": "one_class_autoencoder",
            "rows_train_normal": int(len(X_train)),
            "rows_eval": int(len(X_eval)),
            "threshold": threshold,
            "mean_reconstruction_error_train": float(np.mean(train_mse)) if len(train_mse) else 0.0,
            "p99_reconstruction_error_train": threshold,
            "feature_scaling": "zscore_clipped",
        }
        if y_eval is not None and len(np.unique(y_eval)) > 1:
            pred = (eval_scores >= threshold).astype(int)
            report_payload.update(
                {
                    "precision": float(precision_score(y_eval, pred, zero_division=0)),
                    "recall": float(recall_score(y_eval, pred, zero_division=0)),
                    "f1": float(f1_score(y_eval, pred, zero_division=0)),
                    "pr_auc": float(average_precision_score(y_eval, eval_scores)),
                    "roc_auc": float(roc_auc_score(y_eval, eval_scores)),
                    "label_counts_eval": {
                        "0": int((y_eval == 0).sum()),
                        "1": int((y_eval == 1).sum()),
                    },
                }
            )
        report_path = Path(args.output_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
