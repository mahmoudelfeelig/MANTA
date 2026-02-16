from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from .features import build_feature_windows, feature_matrix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train tiny autoencoder and export TFLite model")
    parser.add_argument("--input", required=True, help="Path to flow CSV")
    parser.add_argument("--output", required=True, help="Output .tflite path")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=64)
    return parser.parse_args()


def main() -> None:
    try:
        import tensorflow as tf
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("TensorFlow is required. Install with: pip install -e .[tflite]") from exc

    args = parse_args()
    df = pd.read_csv(args.input)
    windows = build_feature_windows(df)
    X = feature_matrix(windows).astype(np.float32).values

    input_dim = X.shape[1]
    inputs = tf.keras.Input(shape=(input_dim,))
    encoded = tf.keras.layers.Dense(16, activation="relu")(inputs)
    bottleneck = tf.keras.layers.Dense(8, activation="relu")(encoded)
    decoded = tf.keras.layers.Dense(16, activation="relu")(bottleneck)
    outputs = tf.keras.layers.Dense(input_dim, activation="linear")(decoded)

    autoencoder = tf.keras.Model(inputs=inputs, outputs=outputs)
    autoencoder.compile(optimizer="adam", loss="mse")
    autoencoder.fit(X, X, epochs=args.epochs, batch_size=args.batch_size, verbose=0)

    reconstruction = autoencoder.predict(X, verbose=0)
    mse = np.mean(np.square(X - reconstruction), axis=1)
    threshold = float(np.percentile(mse, 95))

    class ScoringModule(tf.Module):
        def __init__(self, model: tf.keras.Model, threshold_value: float):
            super().__init__()
            self.model = model
            self.threshold = tf.constant(threshold_value, dtype=tf.float32)

        @tf.function(input_signature=[tf.TensorSpec(shape=[None, input_dim], dtype=tf.float32)])
        def __call__(self, features: tf.Tensor) -> tf.Tensor:
            reconstructed = self.model(features)
            mse_val = tf.reduce_mean(tf.square(features - reconstructed), axis=1, keepdims=True)
            score = tf.clip_by_value(mse_val / tf.maximum(self.threshold, 1e-6), 0.0, 1.0)
            return score

    module = ScoringModule(autoencoder, threshold)
    concrete = module.__call__.get_concrete_function()

    converter = tf.lite.TFLiteConverter.from_concrete_functions([concrete], module)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tflite_model)


if __name__ == "__main__":
    main()
