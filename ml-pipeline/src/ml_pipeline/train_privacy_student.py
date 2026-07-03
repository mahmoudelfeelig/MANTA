from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, f1_score, mean_squared_error
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .cache_utils import load_privacy_views_cached
from .dataset_metadata import compute_source_balance_weights, hard_example_weight
from .features import build_feature_windows
from .io_utils import read_csv_resilient
from .metrics import binary_classification_metrics, per_group_binary_metrics
from .progress import PhaseProgress
from .privacy_views import PRIVACY_FEATURE_SETS, PRIVACY_VIEW_CHOICES, build_window_privacy_views_from_windows, canonical_privacy_view_name
from .splits import add_split_metadata, source_aware_train_test_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train an adversarial privacy student on reduced-view features")
    parser.add_argument("--input", required=True, help="Canonical flow CSV input")
    parser.add_argument("--output-model", required=True, help="Output JSON path for the student")
    parser.add_argument("--output-report", required=True, help="Output JSON report path")
    parser.add_argument("--student-view", choices=PRIVACY_VIEW_CHOICES, default="medium")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--latent-dim", type=int, default=8)
    parser.add_argument("--dropout-rate", type=float, default=0.30)
    parser.add_argument("--primary-adversary-target", choices=("auto", "app_id", "app_family"), default="app_family")
    parser.add_argument("--adversary-weight", type=float, default=0.45, help="Primary app/app-family adversary weight")
    parser.add_argument("--app-id-adversary-weight", type=float, default=0.18)
    parser.add_argument("--app-family-adversary-weight", type=float, default=0.45)
    parser.add_argument("--source-adversary-weight", type=float, default=0.24)
    parser.add_argument("--context-adversary-weight", type=float, default=0.16)
    parser.add_argument("--destination-adversary-weight", type=float, default=0.18)
    parser.add_argument("--teacher-weight", type=float, default=0.45)
    parser.add_argument("--reconstruction-weight", type=float, default=0.30)
    parser.add_argument("--pretrain-epochs", type=int, default=8)
    parser.add_argument("--noise-std", type=float, default=0.08)
    parser.add_argument("--l2-regularization", type=float, default=1e-4)
    parser.add_argument("--max-app-adversary-classes", type=int, default=512)
    parser.add_argument("--max-app-id-adversary-classes", type=int, default=256)
    parser.add_argument("--max-destination-adversary-classes", type=int, default=128)
    parser.add_argument("--destination-buckets", type=int, default=3)
    parser.add_argument("--latent-l1-weight", type=float, default=0.01)
    parser.add_argument("--latent-covariance-weight", type=float, default=0.01)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def _best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.0, 1.0, 201):
        current_f1 = float(binary_classification_metrics(y_true, scores, float(threshold))["f1"] or 0.0)
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = float(threshold)
    return best_threshold


def _quantile_bucket(series: pd.Series, buckets: int) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0).astype(float)
    bucket_count = max(2, int(buckets))
    if values.nunique(dropna=False) <= 1:
        return pd.Series(np.zeros(len(values), dtype=int), index=series.index)
    ranks = values.rank(method="average", pct=True).fillna(0.0).to_numpy(dtype=float)
    bucket_ids = np.floor(np.clip(ranks, 0.0, 0.999999) * bucket_count).astype(int)
    bucket_ids = np.clip(bucket_ids, 0, bucket_count - 1)
    return pd.Series(bucket_ids, index=series.index, dtype=int)


def _destination_behavior_target(frame: pd.DataFrame, buckets: int) -> pd.Series:
    novelty = _quantile_bucket(frame["novelty_score"], buckets)
    diversity = _quantile_bucket(frame["destination_diversity"], buckets)
    high_port = _quantile_bucket(frame["high_port_ratio"], buckets)
    beacon = _quantile_bucket(frame["periodic_beacon_score"], buckets)
    return (
        "nov" + novelty.astype(str) +
        "|div" + diversity.astype(str) +
        "|port" + high_port.astype(str) +
        "|beacon" + beacon.astype(str)
    )


def _balanced_class_sample_weights(labels: np.ndarray) -> np.ndarray:
    labels = np.asarray(labels, dtype=int)
    if labels.size == 0:
        return np.asarray([], dtype=np.float32)
    counts = np.bincount(labels)
    class_count = int(np.count_nonzero(counts))
    total = float(labels.size)
    weights = np.ones(labels.size, dtype=np.float32)
    for class_index, count in enumerate(counts):
        if count <= 0:
            continue
        weights[labels == class_index] = float(total / (class_count * count))
    mean_weight = float(weights.mean()) if weights.size else 1.0
    if mean_weight > 0:
        weights = weights / mean_weight
    return weights.astype(np.float32)


def _capped_label_series(series: pd.Series, max_classes: int, *, other_label: str = "__other__") -> tuple[pd.Series, int, bool]:
    values = series.astype(str).fillna(other_label)
    original_count = int(values.nunique())
    limit = int(max_classes)
    if limit <= 0 or original_count <= limit:
        return values, original_count, False
    keep_count = max(1, limit - 1)
    keep = set(values.value_counts().index[:keep_count].tolist())
    capped = values.where(values.isin(keep), other_label)
    return capped, original_count, True


def _adversary_metrics(labels: np.ndarray, probs: np.ndarray | None, target_name: str, class_count: int) -> dict[str, float | int | str | None]:
    if probs is None or probs.size == 0 or class_count <= 1:
        return {
            "target": target_name,
            "class_count": int(class_count),
            "accuracy": None,
            "macro_f1": None,
            "balanced_accuracy": None,
            "random_baseline_accuracy": None,
            "leakage_advantage": None,
        }
    pred = np.argmax(np.asarray(probs, dtype=float), axis=1)
    accuracy = float(np.mean(pred == labels))
    random_baseline = float(1.0 / max(1, class_count))
    return {
        "target": target_name,
        "class_count": int(class_count),
        "accuracy": accuracy,
        "macro_f1": float(f1_score(labels, pred, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, pred)),
        "random_baseline_accuracy": random_baseline,
        "leakage_advantage": float(max(0.0, accuracy - random_baseline)),
    }


def main() -> None:
    try:
        import tensorflow as tf
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("TensorFlow is required for adversarial privacy-student training. Install with: pip install -e .[tflite]") from exc

    args = parse_args()
    student_view = canonical_privacy_view_name(args.student_view)
    progress = PhaseProgress("Privacy student training")
    progress.update(5, "Loading flow CSV")
    progress.update(15, "Building privacy views")
    views = load_privacy_views_cached(
        args.input,
        build_feature_windows_fn=build_feature_windows,
        build_privacy_views_from_windows_fn=build_window_privacy_views_from_windows,
        read_frame_fn=read_csv_resilient,
    )
    full = add_split_metadata(views["off"])
    student = add_split_metadata(views[student_view])
    if "label" not in full.columns:
        raise SystemExit("Privacy-student training requires labels.")

    split = source_aware_train_test_split(full, label_column="label", test_size=0.3, random_seed=args.random_seed)
    train_idx, test_idx = split.train_idx, split.test_idx
    train_full = full.iloc[train_idx].reset_index(drop=True)
    test_full = full.iloc[test_idx].reset_index(drop=True)
    train_student = student.iloc[train_idx].reset_index(drop=True)
    test_student = student.iloc[test_idx].reset_index(drop=True)
    y_train = train_full["label"].fillna(0).astype(int).to_numpy()
    y_test = test_full["label"].fillna(0).astype(int).to_numpy()

    teacher_pipe = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=args.random_seed)),
        ]
    )
    full_features = [column for column in PRIVACY_FEATURE_SETS["off"] if column in train_full.columns]
    student_features = [column for column in PRIVACY_FEATURE_SETS[student_view] if column in train_student.columns]
    progress.update(32, "Training off-view teacher")
    teacher_pipe.fit(train_full[full_features].fillna(0.0), y_train)
    teacher_scores_train = teacher_pipe.predict_proba(train_full[full_features].fillna(0.0))[:, 1]
    teacher_scores_test = teacher_pipe.predict_proba(test_full[full_features].fillna(0.0))[:, 1]

    original_app_class_count = int(full["app_id"].astype(str).nunique())
    primary_adversary_target = args.primary_adversary_target
    if primary_adversary_target == "auto":
        primary_adversary_target = "app_family"
    effective_app_id_weight = float(args.app_id_adversary_weight)
    effective_app_family_weight = float(args.app_family_adversary_weight)
    if primary_adversary_target == "app_id":
        effective_app_id_weight = max(effective_app_id_weight, float(args.adversary_weight))
    elif primary_adversary_target == "app_family":
        effective_app_family_weight = max(effective_app_family_weight, float(args.adversary_weight))

    app_id_series, original_app_id_class_count, app_id_capped = _capped_label_series(
        full["app_id"].astype(str),
        args.max_app_id_adversary_classes if args.max_app_id_adversary_classes > 0 else args.max_app_adversary_classes,
    )
    app_family_series = full["app_family"].astype(str)
    app_id_encoder = LabelEncoder()
    app_id_labels = app_id_encoder.fit_transform(app_id_series)
    train_app_id_labels = app_id_labels[train_idx]
    test_app_id_labels = app_id_labels[test_idx]
    app_family_encoder = LabelEncoder()
    app_family_labels = app_family_encoder.fit_transform(app_family_series)
    train_app_family_labels = app_family_labels[train_idx]
    test_app_family_labels = app_family_labels[test_idx]
    source_encoder = LabelEncoder()
    source_labels = source_encoder.fit_transform(full["dataset_source"].astype(str))
    train_source_labels = source_labels[train_idx]
    test_source_labels = source_labels[test_idx]
    context_series = full["environment_id"].astype(str) + "|" + full["time_fold"].astype(str)
    context_encoder = LabelEncoder()
    context_labels = context_encoder.fit_transform(context_series)
    train_context_labels = context_labels[train_idx]
    test_context_labels = context_labels[test_idx]
    destination_behavior_series = _destination_behavior_target(full, args.destination_buckets)
    destination_encoder = LabelEncoder()
    destination_labels = destination_encoder.fit_transform(destination_behavior_series.astype(str))
    train_destination_labels = destination_labels[train_idx]
    test_destination_labels = destination_labels[test_idx]

    scaler = StandardScaler()
    train_x = scaler.fit_transform(train_student[student_features].fillna(0.0)).astype(np.float32)
    test_x = scaler.transform(test_student[student_features].fillna(0.0)).astype(np.float32)
    source_weights = compute_source_balance_weights(train_full["dataset_source"])
    detection_sample_weights = np.asarray(
        [
            hard_example_weight(int(label), str(source), str(family)) * float(source_weights.get(str(source), 1.0))
            for label, source, family in zip(
                y_train,
                train_full["dataset_source"],
                train_full["app_family"],
                strict=False,
            )
        ],
        dtype=np.float32,
    )
    app_id_sample_weights = _balanced_class_sample_weights(train_app_id_labels)
    app_family_sample_weights = _balanced_class_sample_weights(train_app_family_labels)
    source_sample_weights = _balanced_class_sample_weights(train_source_labels)
    context_sample_weights = _balanced_class_sample_weights(train_context_labels)
    destination_sample_weights = _balanced_class_sample_weights(train_destination_labels)

    tf.random.set_seed(args.random_seed)

    @tf.custom_gradient
    def _gradient_reversal(x: tf.Tensor, lambda_value: tf.Tensor) -> tuple[tf.Tensor, object]:
        def grad(dy: tf.Tensor) -> tuple[tf.Tensor, tf.Tensor]:
            return -lambda_value * dy, tf.zeros_like(lambda_value)
        return tf.identity(x), grad

    class GradientReversal(tf.keras.layers.Layer):
        def __init__(self, lambda_value: float) -> None:
            super().__init__()
            self.lambda_value = tf.constant(lambda_value, dtype=tf.float32)

        def call(self, inputs: tf.Tensor) -> tf.Tensor:
            return _gradient_reversal(inputs, self.lambda_value)

    class LatentPenalty(tf.keras.layers.Layer):
        def __init__(self, l1_weight: float, covariance_weight: float) -> None:
            super().__init__()
            self.l1_weight = float(l1_weight)
            self.covariance_weight = float(covariance_weight)

        def call(self, inputs: tf.Tensor) -> tf.Tensor:
            if self.l1_weight > 0.0:
                self.add_loss(self.l1_weight * tf.reduce_mean(tf.abs(inputs)))
            if self.covariance_weight > 0.0:
                centered = inputs - tf.reduce_mean(inputs, axis=0, keepdims=True)
                batch_size = tf.cast(tf.maximum(tf.shape(centered)[0] - 1, 1), tf.float32)
                covariance = tf.matmul(centered, centered, transpose_a=True) / batch_size
                off_diagonal = covariance - tf.linalg.diag(tf.linalg.diag_part(covariance))
                self.add_loss(self.covariance_weight * tf.reduce_mean(tf.square(off_diagonal)))
            return inputs

    regularizer = tf.keras.regularizers.L2(args.l2_regularization)
    inputs = tf.keras.Input(shape=(len(student_features),), name="student_features")
    noise_layer = tf.keras.layers.GaussianNoise(args.noise_std, name="noise")
    input_dropout_layer = tf.keras.layers.Dropout(args.dropout_rate * 0.4, name="input_dropout")
    dense_1_layer = tf.keras.layers.Dense(64, activation="relu", kernel_regularizer=regularizer, name="dense_1")
    dense_2_layer = tf.keras.layers.Dense(32, activation="relu", kernel_regularizer=regularizer, name="dense_2")
    dropout_layer = tf.keras.layers.Dropout(args.dropout_rate, name="dropout")
    latent_layer = tf.keras.layers.Dense(args.latent_dim, activation="relu", kernel_regularizer=regularizer, name="latent")
    latent_penalty_layer = LatentPenalty(args.latent_l1_weight, args.latent_covariance_weight)
    decoder_dense_1_layer = tf.keras.layers.Dense(32, activation="relu", kernel_regularizer=regularizer, name="decoder_dense_1")
    decoder_dense_2_layer = tf.keras.layers.Dense(64, activation="relu", kernel_regularizer=regularizer, name="decoder_dense_2")
    reconstruction_layer = tf.keras.layers.Dense(len(student_features), activation="linear", name="reconstruction")

    x = noise_layer(inputs)
    x = input_dropout_layer(x)
    x = dense_1_layer(x)
    x = dense_2_layer(x)
    x = dropout_layer(x)
    latent_raw = latent_layer(x)
    latent = latent_penalty_layer(latent_raw)
    reconstructed_hidden = decoder_dense_1_layer(latent)
    reconstructed_hidden = decoder_dense_2_layer(reconstructed_hidden)
    reconstruction_output = reconstruction_layer(reconstructed_hidden)

    if args.pretrain_epochs > 0 and len(train_x) > 0:
        progress.update(46, f"Reconstruction pretraining ({args.pretrain_epochs} epochs)")
        pretrain_model = tf.keras.Model(inputs=inputs, outputs=reconstruction_output)
        pretrain_model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
            loss=tf.keras.losses.MeanSquaredError(),
        )
        pretrain_callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                mode="min",
                patience=3,
                restore_best_weights=True,
                min_delta=1e-4,
            )
        ]
        pretrain_model.fit(
            train_x,
            train_x,
            validation_split=0.1,
            epochs=args.pretrain_epochs,
            batch_size=args.batch_size,
            verbose=0,
            callbacks=pretrain_callbacks,
        )

    detector = tf.keras.layers.Dense(24, activation="relu", kernel_regularizer=regularizer, name="detector_hidden")(latent)
    detector = tf.keras.layers.Dropout(args.dropout_rate * 0.5, name="detector_dropout")(detector)
    detection_output = tf.keras.layers.Dense(1, activation="sigmoid", name="detection")(detector)
    teacher_output = tf.keras.layers.Dense(1, activation="sigmoid", name="teacher_distill")(latent)

    outputs: dict[str, tf.Tensor] = {
        "detection": detection_output,
        "teacher_distill": teacher_output,
        "reconstruction": reconstruction_output,
    }
    losses: dict[str, object] = {
        "detection": tf.keras.losses.BinaryCrossentropy(),
        "teacher_distill": tf.keras.losses.MeanSquaredError(),
        "reconstruction": tf.keras.losses.MeanSquaredError(),
    }
    loss_weights: dict[str, float] = {
        "detection": 1.0,
        "teacher_distill": float(args.teacher_weight),
        "reconstruction": float(args.reconstruction_weight),
    }

    if effective_app_id_weight > 0.0 and len(app_id_encoder.classes_) > 1:
        app_id_reversal = GradientReversal(effective_app_id_weight)(latent)
        app_id_hidden = tf.keras.layers.Dense(48, activation="relu", kernel_regularizer=regularizer, name="app_id_adversary_hidden")(app_id_reversal)
        outputs["app_id_adversary"] = tf.keras.layers.Dense(len(app_id_encoder.classes_), activation="softmax", name="app_id_adversary")(app_id_hidden)
        losses["app_id_adversary"] = tf.keras.losses.SparseCategoricalCrossentropy()
        loss_weights["app_id_adversary"] = float(effective_app_id_weight)
    if effective_app_family_weight > 0.0 and len(app_family_encoder.classes_) > 1:
        app_family_reversal = GradientReversal(effective_app_family_weight)(latent)
        app_family_hidden = tf.keras.layers.Dense(32, activation="relu", kernel_regularizer=regularizer, name="app_family_adversary_hidden")(app_family_reversal)
        outputs["app_family_adversary"] = tf.keras.layers.Dense(len(app_family_encoder.classes_), activation="softmax", name="app_family_adversary")(app_family_hidden)
        losses["app_family_adversary"] = tf.keras.losses.SparseCategoricalCrossentropy()
        loss_weights["app_family_adversary"] = float(effective_app_family_weight)
    if len(source_encoder.classes_) > 1:
        source_reversal = GradientReversal(args.source_adversary_weight)(latent)
        source_head = tf.keras.layers.Dense(32, activation="relu", kernel_regularizer=regularizer, name="source_adversary_hidden")(source_reversal)
        outputs["dataset_source"] = tf.keras.layers.Dense(len(source_encoder.classes_), activation="softmax", name="dataset_source")(source_head)
        losses["dataset_source"] = tf.keras.losses.SparseCategoricalCrossentropy()
        loss_weights["dataset_source"] = float(args.source_adversary_weight)
    if len(context_encoder.classes_) > 1:
        context_reversal = GradientReversal(args.context_adversary_weight)(latent)
        context_head = tf.keras.layers.Dense(32, activation="relu", kernel_regularizer=regularizer, name="context_adversary_hidden")(context_reversal)
        outputs["context_bucket"] = tf.keras.layers.Dense(len(context_encoder.classes_), activation="softmax", name="context_bucket")(context_head)
        losses["context_bucket"] = tf.keras.losses.SparseCategoricalCrossentropy()
        loss_weights["context_bucket"] = float(args.context_adversary_weight)
    if args.destination_adversary_weight > 0.0 and len(destination_encoder.classes_) > 1 and len(destination_encoder.classes_) <= max(2, args.max_destination_adversary_classes):
        destination_reversal = GradientReversal(args.destination_adversary_weight)(latent)
        destination_head = tf.keras.layers.Dense(24, activation="relu", kernel_regularizer=regularizer, name="destination_adversary_hidden")(destination_reversal)
        outputs["destination_behavior"] = tf.keras.layers.Dense(len(destination_encoder.classes_), activation="softmax", name="destination_behavior")(destination_head)
        losses["destination_behavior"] = tf.keras.losses.SparseCategoricalCrossentropy()
        loss_weights["destination_behavior"] = float(args.destination_adversary_weight)

    model = tf.keras.Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3), loss=losses, loss_weights=loss_weights)
    progress.update(60, f"Training {student_view} adversarial student")
    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor="val_detection_loss",
        mode="min",
        patience=5,
        restore_best_weights=True,
        min_delta=1e-4,
    )
    fit_targets: dict[str, np.ndarray] = {
        "detection": y_train.astype(np.float32),
        "teacher_distill": teacher_scores_train.astype(np.float32),
        "reconstruction": train_x.astype(np.float32),
    }
    fit_sample_weights: dict[str, np.ndarray] = {
        "detection": detection_sample_weights,
        "teacher_distill": detection_sample_weights,
        "reconstruction": detection_sample_weights,
    }
    if "app_id_adversary" in outputs:
        fit_targets["app_id_adversary"] = train_app_id_labels.astype(np.int32)
        fit_sample_weights["app_id_adversary"] = app_id_sample_weights
    if "app_family_adversary" in outputs:
        fit_targets["app_family_adversary"] = train_app_family_labels.astype(np.int32)
        fit_sample_weights["app_family_adversary"] = app_family_sample_weights
    if "dataset_source" in outputs:
        fit_targets["dataset_source"] = train_source_labels.astype(np.int32)
        fit_sample_weights["dataset_source"] = source_sample_weights
    if "context_bucket" in outputs:
        fit_targets["context_bucket"] = train_context_labels.astype(np.int32)
        fit_sample_weights["context_bucket"] = context_sample_weights
    if "destination_behavior" in outputs:
        fit_targets["destination_behavior"] = train_destination_labels.astype(np.int32)
        fit_sample_weights["destination_behavior"] = destination_sample_weights
    fit_start = time.perf_counter()
    model.fit(
        train_x,
        fit_targets,
        validation_split=0.1,
        epochs=args.epochs,
        batch_size=args.batch_size,
        verbose=0,
        callbacks=[early_stopping],
        sample_weight=fit_sample_weights,
    )
    training_seconds = float(time.perf_counter() - fit_start)

    progress.update(84, "Evaluating student and leakage resistance")
    predictions = model.predict(test_x, verbose=0, batch_size=min(args.batch_size, 1024))
    detector_scores_test = np.asarray(predictions["detection"], dtype=float).reshape(-1)
    distill_scores_test = np.asarray(predictions["teacher_distill"], dtype=float).reshape(-1)
    student_scores_test = ((0.65 * detector_scores_test) + (0.35 * distill_scores_test)).astype(float)
    threshold = _best_threshold(y_test, student_scores_test)
    primary_metrics = binary_classification_metrics(y_test, student_scores_test, threshold)
    reconstruction_test = np.asarray(predictions["reconstruction"], dtype=float) if "reconstruction" in predictions else None
    app_id_probs = np.asarray(predictions["app_id_adversary"], dtype=float) if "app_id_adversary" in predictions else None
    app_family_probs = np.asarray(predictions["app_family_adversary"], dtype=float) if "app_family_adversary" in predictions else None
    source_probs = np.asarray(predictions["dataset_source"], dtype=float) if "dataset_source" in predictions else None
    context_probs = np.asarray(predictions["context_bucket"], dtype=float) if "context_bucket" in predictions else None
    destination_probs = np.asarray(predictions["destination_behavior"], dtype=float) if "destination_behavior" in predictions else None
    app_id_metrics_report = _adversary_metrics(test_app_id_labels, app_id_probs, "app_id", int(len(app_id_encoder.classes_)))
    app_family_metrics_report = _adversary_metrics(test_app_family_labels, app_family_probs, "app_family", int(len(app_family_encoder.classes_)))
    source_metrics_report = _adversary_metrics(test_source_labels, source_probs, "dataset_source", int(len(source_encoder.classes_)))
    context_metrics_report = _adversary_metrics(test_context_labels, context_probs, "context_bucket", int(len(context_encoder.classes_)))
    destination_metrics_report = _adversary_metrics(test_destination_labels, destination_probs, "destination_behavior", int(len(destination_encoder.classes_)))
    primary_metrics_report = app_id_metrics_report if primary_adversary_target == "app_id" else app_family_metrics_report
    encoder_model = tf.keras.Model(inputs=inputs, outputs=latent)
    latent_train = np.asarray(encoder_model.predict(train_x, verbose=0, batch_size=min(args.batch_size, 1024)), dtype=float)
    latent_mean = latent_train.mean(axis=0) if latent_train.size else np.zeros(args.latent_dim, dtype=float)
    latent_scale = latent_train.std(axis=0) if latent_train.size else np.ones(args.latent_dim, dtype=float)
    latent_scale = np.where(latent_scale <= 1e-6, 1.0, latent_scale)

    model_payload = {
        "model_type": "privacy_adversarial_student",
        "student_view": student_view,
        "feature_order": student_features,
        "scaler_mean": scaler.mean_.astype(float).tolist(),
        "scaler_scale": scaler.scale_.astype(float).tolist(),
        "latent_mean": latent_mean.astype(float).tolist(),
        "latent_scale": latent_scale.astype(float).tolist(),
        "latent_dim": int(args.latent_dim),
        "dropout_rate": float(args.dropout_rate),
        "primary_adversary_target": primary_adversary_target,
        "adversary_weight": float(args.adversary_weight),
        "app_id_adversary_weight": float(effective_app_id_weight),
        "app_family_adversary_weight": float(effective_app_family_weight),
        "source_adversary_weight": float(args.source_adversary_weight),
        "context_adversary_weight": float(args.context_adversary_weight),
        "destination_adversary_weight": float(args.destination_adversary_weight),
        "teacher_weight": float(args.teacher_weight),
        "reconstruction_weight": float(args.reconstruction_weight),
        "pretrain_epochs": int(args.pretrain_epochs),
        "noise_std": float(args.noise_std),
        "l2_regularization": float(args.l2_regularization),
        "latent_l1_weight": float(args.latent_l1_weight),
        "latent_covariance_weight": float(args.latent_covariance_weight),
        "app_adversary_target": primary_adversary_target,
        "primary_adversary_requested": args.primary_adversary_target,
        "original_app_class_count": original_app_class_count,
        "original_app_id_class_count": original_app_id_class_count,
        "app_id_classes_capped": bool(app_id_capped),
        "app_adversary_class_count": int(len(app_id_encoder.classes_ if primary_adversary_target == "app_id" else app_family_encoder.classes_)),
        "app_id_adversary_class_count": int(len(app_id_encoder.classes_)),
        "app_family_adversary_class_count": int(len(app_family_encoder.classes_)),
        "destination_behavior_class_count": int(len(destination_encoder.classes_)),
        "classes_primary_adversary": (app_id_encoder.classes_ if primary_adversary_target == "app_id" else app_family_encoder.classes_).astype(str).tolist(),
        "classes_app_id_adversary": app_id_encoder.classes_.astype(str).tolist(),
        "classes_app_family_adversary": app_family_encoder.classes_.astype(str).tolist(),
        "classes_dataset_source": source_encoder.classes_.astype(str).tolist(),
        "classes_context_bucket": context_encoder.classes_.astype(str).tolist(),
        "classes_destination_behavior": destination_encoder.classes_.astype(str).tolist(),
        "weights": {
            layer.name: [weight.astype(float).tolist() for weight in layer.get_weights()]
            for layer in model.layers
            if layer.get_weights()
        },
    }
    report = {
        "rows_train": int(len(train_idx)),
        "rows_test": int(len(test_idx)),
        "student_view": student_view,
        "training_seconds": training_seconds,
        "split_strategy": split.strategy,
        "split_summary": split.summary,
        "app_adversary_target": primary_adversary_target,
        "primary_adversary_requested": args.primary_adversary_target,
        "original_app_class_count": original_app_class_count,
        "original_app_id_class_count": original_app_id_class_count,
        "app_id_classes_capped": bool(app_id_capped),
        "app_adversary_class_count": int(len(app_id_encoder.classes_ if primary_adversary_target == "app_id" else app_family_encoder.classes_)),
        "app_id_adversary_class_count": int(len(app_id_encoder.classes_)),
        "app_family_adversary_class_count": int(len(app_family_encoder.classes_)),
        "destination_behavior_class_count": int(len(destination_encoder.classes_)),
        **primary_metrics,
        "teacher_student_mse": float(mean_squared_error(teacher_scores_test, student_scores_test)),
        "detector_only_mse": float(mean_squared_error(teacher_scores_test, detector_scores_test)),
        "reconstruction_mse": float(mean_squared_error(test_x, reconstruction_test)) if reconstruction_test is not None else None,
        "app_adversary_accuracy": primary_metrics_report["accuracy"],
        "app_id_adversary_accuracy": app_id_metrics_report["accuracy"],
        "app_family_adversary_accuracy": app_family_metrics_report["accuracy"],
        "dataset_source_adversary_accuracy": source_metrics_report["accuracy"],
        "context_adversary_accuracy": context_metrics_report["accuracy"],
        "destination_behavior_adversary_accuracy": destination_metrics_report["accuracy"],
        "adversary_metrics": {
            "primary": primary_metrics_report,
            "app_id": app_id_metrics_report,
            "app_family": app_family_metrics_report,
            "dataset_source": source_metrics_report,
            "context_bucket": context_metrics_report,
            "destination_behavior": destination_metrics_report,
        },
        "leakage_summary": {
            "max_accuracy": max(
                metric.get("accuracy") or 0.0
                for metric in [app_id_metrics_report, app_family_metrics_report, source_metrics_report, context_metrics_report, destination_metrics_report]
            ),
            "max_leakage_advantage": max(
                metric.get("leakage_advantage") or 0.0
                for metric in [app_id_metrics_report, app_family_metrics_report, source_metrics_report, context_metrics_report, destination_metrics_report]
            ),
        },
        "per_source_metrics": per_group_binary_metrics(y_test, student_scores_test, test_full["dataset_source"], threshold, min_rows=24),
    }

    output_model = Path(args.output_model).expanduser().resolve()
    output_model.parent.mkdir(parents=True, exist_ok=True)
    progress.update(92, "Writing student model and report")
    output_model.write_text(json.dumps(model_payload, indent=2), encoding="utf-8")
    output_report = Path(args.output_report).expanduser().resolve()
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    progress.update(100, "Completed")


if __name__ == "__main__":
    main()
