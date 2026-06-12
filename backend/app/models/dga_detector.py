"""Char-CNN DGA-like domain detector based only on domain character sequences.

This module identifies domains that look random or DGA-like from character
sequence features. The score is an early candidate-screening signal only.
Further confirmation should combine DNS, WHOIS, certificate, web content,
traffic, or threat-intelligence evidence.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import random
import zipfile
from collections import Counter
from typing import Any


try:
    import numpy as np

    HAS_NUMPY = True
except Exception:
    np = None
    HAS_NUMPY = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers

    HAS_TENSORFLOW = True
except Exception:
    tf = None
    keras = None
    layers = None
    HAS_TENSORFLOW = False

try:
    import torch

    HAS_TORCH = True
except Exception:
    torch = None
    HAS_TORCH = False

try:
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.utils.class_weight import compute_class_weight

    HAS_SKLEARN = True
except Exception:
    accuracy_score = None
    classification_report = None
    confusion_matrix = None
    f1_score = None
    precision_score = None
    recall_score = None
    train_test_split = None
    compute_class_weight = None
    HAS_SKLEARN = False

try:
    from .dga_detection_utils import (
        add_score_bucket_stats,
        extract_sld,
        normalize_domain,
        read_csv_records,
        require_columns,
        require_file_exists,
        safe_int_label,
        safe_text,
        validate_required_args,
        write_csv_records,
    )
except ImportError:
    from dga_detection_utils import (
        add_score_bucket_stats,
        extract_sld,
        normalize_domain,
        read_csv_records,
        require_columns,
        require_file_exists,
        safe_int_label,
        safe_text,
        validate_required_args,
        write_csv_records,
    )


SELECTED_FRAMEWORK = "tensorflow" if HAS_TENSORFLOW else None
DEEP_LEARNING_ERROR = (
    "Char-CNN 模型训练需要 TensorFlow/Keras 或 PyTorch，但当前项目环境未检测到相关依赖。"
)

PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
PAD_ID = 0
UNK_ID = 1
BASIC_CHARS = list("abcdefghijklmnopqrstuvwxyz0123456789-_.")

DEFAULT_MAX_LEN = 75
DEFAULT_EMBEDDING_DIM = 32
DEFAULT_FILTERS = 64
DEFAULT_DENSE_UNITS = 64
DEFAULT_DROPOUT = 0.3
DEFAULT_BATCH_SIZE = 256
DEFAULT_EPOCHS = 10
DEFAULT_RANDOM_STATE = 42
DEFAULT_VALIDATION_SIZE = 0.2
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_DGA_TRAIN_FILE = os.path.join(
    PROJECT_ROOT, "dataset", "DGA_domains_dataset", "dga_domains_v2.csv"
)
DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "detection", "models")
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "dga_char_cnn_string_detector.keras")
DEFAULT_METADATA_PATH = os.path.join(
    DEFAULT_MODEL_DIR, "dga_char_cnn_string_detector.metadata.json"
)
DEFAULT_REPORT_PATH = os.path.join(DEFAULT_MODEL_DIR, "dga_char_cnn_training_report.txt")
DEFAULT_PREDICT_DIR = os.path.join(PROJECT_ROOT, "models", "detection", "predict_data")
DEFAULT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "models", "detection", "outputs")
DEFAULT_ZIP_PREDICTION_OUTPUT = os.path.join(
    DEFAULT_OUTPUT_DIR, "dga_char_cnn_predictions.csv"
)


def build_char_vocab(domains: list[str], min_freq: int = 1) -> dict[str, int]:
    counter = Counter()
    for domain in domains:
        counter.update(safe_text(domain).lower())

    char_to_id = {PAD_TOKEN: PAD_ID, UNK_TOKEN: UNK_ID}
    for char in BASIC_CHARS:
        if char not in char_to_id:
            char_to_id[char] = len(char_to_id)

    for char, count in sorted(counter.items()):
        if count >= min_freq and char not in char_to_id:
            char_to_id[char] = len(char_to_id)
    return char_to_id


def encode_domain(domain_text: str, char_to_id: dict[str, int], max_len: int) -> list[int]:
    text = safe_text(domain_text).lower()
    encoded = [char_to_id.get(char, UNK_ID) for char in text[:max_len]]
    if len(encoded) < max_len:
        encoded.extend([PAD_ID] * (max_len - len(encoded)))
    return encoded


def prepare_domain_text(raw_domain: Any, use_full_domain: bool = False) -> tuple[str, str]:
    normalized = normalize_domain(safe_text(raw_domain))
    model_input_text = normalized if use_full_domain else extract_sld(normalized)
    return normalized, model_input_text


def load_training_data(
    train_file: str,
    domain_col: str,
    label_col: str,
    use_full_domain: bool = False,
) -> tuple[list[str], list[str], list[str], list[int]]:
    validate_required_args(
        {"train_file": train_file, "domain_col": domain_col, "label_col": label_col}
    )
    require_file_exists(train_file, "train_file")

    records = read_csv_records(train_file)
    if not records:
        raise ValueError("Training CSV contains no records.")

    columns = list(records[0].keys())
    require_columns(columns, [domain_col, label_col])

    raw_domains: list[str] = []
    normalized_domains: list[str] = []
    model_inputs: list[str] = []
    labels: list[int] = []

    skipped = 0
    for record in records:
        raw_domain = safe_text(record.get(domain_col, ""))
        normalized, model_input_text = prepare_domain_text(raw_domain, use_full_domain)
        if not model_input_text:
            skipped += 1
            continue
        raw_domains.append(raw_domain)
        normalized_domains.append(normalized)
        model_inputs.append(model_input_text)
        labels.append(safe_int_label(record.get(label_col, "")))

    if skipped:
        print(f"Skipped {skipped} rows with empty domain text after preprocessing.")
    if not model_inputs:
        raise ValueError("No valid domain rows found after preprocessing.")
    _validate_binary_labels(labels)
    return raw_domains, normalized_domains, model_inputs, labels


def read_dga_training_dataset(
    train_file: str,
    use_full_domain: bool = False,
) -> tuple[list[str], list[str], list[str], list[int]]:
    """Read the project DGA dataset: label,family,domain without a header row."""
    validate_required_args({"train_file": train_file})
    require_file_exists(train_file, "train_file")

    raw_domains: list[str] = []
    normalized_domains: list[str] = []
    model_inputs: list[str] = []
    labels: list[int] = []
    skipped = 0

    with open(train_file, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for line_number, row in enumerate(reader, start=1):
            if not row:
                continue
            if line_number == 1 and row[0].strip().lower() in {"label", "class", "type"}:
                continue
            if len(row) < 3:
                skipped += 1
                continue

            label_text = row[0].strip().lower()
            if label_text == "dga":
                label = 1
            elif label_text == "legit":
                label = 0
            else:
                skipped += 1
                continue

            raw_domain = row[2].strip()
            normalized, model_input_text = prepare_domain_text(raw_domain, use_full_domain)
            if not model_input_text:
                skipped += 1
                continue

            raw_domains.append(raw_domain)
            normalized_domains.append(normalized)
            model_inputs.append(model_input_text)
            labels.append(label)

    if skipped:
        print(f"Skipped {skipped} malformed training rows.")
    if not model_inputs:
        raise ValueError("No valid training rows found in DGA dataset.")
    _validate_binary_labels(labels)
    return raw_domains, normalized_domains, model_inputs, labels


def read_domains_from_zip_directory(predict_dir: str) -> list[dict[str, str]]:
    """Read domain lines from every .txt file inside every .zip under predict_dir."""
    validate_required_args({"predict_dir": predict_dir})
    if not os.path.isdir(predict_dir):
        raise FileNotFoundError(f"predict_dir does not exist or is not a directory: {predict_dir}")

    records: list[dict[str, str]] = []
    zip_names = sorted(name for name in os.listdir(predict_dir) if name.lower().endswith(".zip"))
    if not zip_names:
        print(f"No zip files found in: {predict_dir}")
        return records

    for zip_name in zip_names:
        zip_path = os.path.join(predict_dir, zip_name)
        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                txt_names = sorted(
                    name
                    for name in archive.namelist()
                    if not name.endswith("/") and name.lower().endswith(".txt")
                )
                for txt_name in txt_names:
                    with archive.open(txt_name, "r") as handle:
                        for raw_line in handle:
                            domain = raw_line.decode("utf-8-sig", errors="ignore").strip()
                            if not domain:
                                continue
                            records.append(
                                {
                                    "source_zip": zip_name,
                                    "source_file": txt_name,
                                    "original_domain": domain,
                                }
                            )
        except zipfile.BadZipFile:
            print(f"Skipped invalid zip file: {zip_path}")

    return records


def build_encoded_matrix(
    domains: list[str],
    char_to_id: dict[str, int],
    max_len: int,
) -> Any:
    rows = [encode_domain(domain, char_to_id, max_len) for domain in domains]
    if HAS_NUMPY:
        return np.asarray(rows, dtype="int32")
    return rows


def build_keras_char_cnn_model(
    vocab_size: int,
    max_len: int,
    embedding_dim: int = DEFAULT_EMBEDDING_DIM,
    filters: int = DEFAULT_FILTERS,
    dense_units: int = DEFAULT_DENSE_UNITS,
    dropout: float = DEFAULT_DROPOUT,
) -> Any:
    _ensure_tensorflow_available()

    inputs = keras.Input(shape=(max_len,), dtype="int32")
    x = layers.Embedding(input_dim=vocab_size, output_dim=embedding_dim)(inputs)

    x = layers.Conv1D(filters=filters, kernel_size=3, padding="same")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation("relu")(x)
    x = layers.MaxPooling1D(pool_size=2)(x)

    x = layers.Conv1D(filters=filters, kernel_size=4, padding="same")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation("relu")(x)
    x = layers.MaxPooling1D(pool_size=2)(x)

    x = layers.Conv1D(filters=filters, kernel_size=5, padding="same")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation("relu")(x)
    x = layers.GlobalMaxPooling1D()(x)

    x = layers.Dropout(dropout)(x)
    x = layers.Dense(dense_units, activation="relu")(x)
    x = layers.Dropout(dropout)(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)

    model = keras.Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


def save_metadata(metadata: dict[str, Any], metadata_output_path: str) -> None:
    validate_required_args({"metadata_output_path": metadata_output_path})
    _ensure_parent_dir(metadata_output_path)
    with open(metadata_output_path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2, sort_keys=True)


def load_metadata(metadata_path: str) -> dict[str, Any]:
    validate_required_args({"metadata_path": metadata_path})
    require_file_exists(metadata_path, "metadata_path")
    with open(metadata_path, "r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    _validate_metadata(metadata)
    return metadata


def save_model(model: Any, model_output_path: str) -> None:
    validate_required_args({"model_output_path": model_output_path})
    _ensure_tensorflow_available()
    _ensure_parent_dir(model_output_path)
    model.save(model_output_path)


def load_model(model_path: str, metadata: dict[str, Any] | None = None) -> Any:
    validate_required_args({"model_path": model_path})
    _require_path_exists(model_path, "model_path")
    framework = (metadata or {}).get("framework", SELECTED_FRAMEWORK)
    if framework != "tensorflow":
        raise RuntimeError(DEEP_LEARNING_ERROR)
    _ensure_tensorflow_available()
    try:
        return keras.models.load_model(model_path)
    except Exception:
        if not metadata:
            raise
        return _load_legacy_keras_model_from_weights(model_path, metadata)


def _load_legacy_keras_model_from_weights(model_path: str, metadata: dict[str, Any]) -> Any:
    config = metadata.get("config") or {}
    model = build_keras_char_cnn_model(
        vocab_size=len(metadata["char_to_id"]),
        max_len=int(metadata["max_len"]),
        embedding_dim=int(config.get("embedding_dim", DEFAULT_EMBEDDING_DIM)),
        filters=int(config.get("filters", DEFAULT_FILTERS)),
        dense_units=int(config.get("dense_units", DEFAULT_DENSE_UNITS)),
        dropout=float(config.get("dropout", DEFAULT_DROPOUT)),
    )
    with zipfile.ZipFile(model_path, "r") as archive:
        weights_bytes = archive.read("model.weights.h5")

    try:
        import h5py
    except Exception as exc:
        raise RuntimeError("Loading legacy .keras DGA model requires h5py.") from exc

    with h5py.File(io.BytesIO(weights_bytes), "r") as weights_file:
        for layer in model.layers:
            layer_key = f"_layer_checkpoint_dependencies\\{layer.name}"
            if layer_key not in weights_file:
                continue
            vars_group = weights_file[layer_key].get("vars")
            if vars_group is None:
                continue
            layer_weights = [
                vars_group[str(index)][()]
                for index in range(len(vars_group.keys()))
            ]
            if layer_weights:
                layer.set_weights(layer_weights)
    return model


def train_model(
    train_file: str,
    domain_col: str,
    label_col: str,
    model_output_path: str,
    metadata_output_path: str | None = None,
    report_output_path: str | None = None,
    use_full_domain: bool = False,
    max_len: int = DEFAULT_MAX_LEN,
    batch_size: int = DEFAULT_BATCH_SIZE,
    epochs: int = DEFAULT_EPOCHS,
    validation_size: float = DEFAULT_VALIDATION_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> None:
    validate_required_args(
        {
            "train_file": train_file,
            "domain_col": domain_col,
            "label_col": label_col,
            "model_output_path": model_output_path,
        }
    )
    _ensure_tensorflow_available()
    _validate_positive_int(max_len, "max_len")
    _validate_positive_int(batch_size, "batch_size")
    _validate_positive_int(epochs, "epochs")
    _validate_validation_size(validation_size)

    _, _, model_inputs, labels = load_training_data(
        train_file=train_file,
        domain_col=domain_col,
        label_col=label_col,
        use_full_domain=use_full_domain,
    )

    _train_from_model_inputs(
        model_inputs=model_inputs,
        labels=labels,
        model_output_path=model_output_path,
        metadata_output_path=metadata_output_path,
        report_output_path=report_output_path,
        use_full_domain=use_full_domain,
        max_len=max_len,
        batch_size=batch_size,
        epochs=epochs,
        validation_size=validation_size,
        random_state=random_state,
        domain_col=domain_col,
        label_col=label_col,
        source_config={"train_file": train_file, "format": "csv_with_header"},
    )


def train_dga_dataset(
    train_file: str = DEFAULT_DGA_TRAIN_FILE,
    model_output_path: str = DEFAULT_MODEL_PATH,
    metadata_output_path: str | None = DEFAULT_METADATA_PATH,
    report_output_path: str | None = DEFAULT_REPORT_PATH,
    use_full_domain: bool = False,
    max_len: int = DEFAULT_MAX_LEN,
    batch_size: int = DEFAULT_BATCH_SIZE,
    epochs: int = DEFAULT_EPOCHS,
    validation_size: float = DEFAULT_VALIDATION_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> None:
    """Train from the project DGA dataset with label,family,domain columns."""
    validate_required_args({"train_file": train_file, "model_output_path": model_output_path})
    _ensure_tensorflow_available()
    _validate_positive_int(max_len, "max_len")
    _validate_positive_int(batch_size, "batch_size")
    _validate_positive_int(epochs, "epochs")
    _validate_validation_size(validation_size)

    _, _, model_inputs, labels = read_dga_training_dataset(
        train_file=train_file,
        use_full_domain=use_full_domain,
    )

    _train_from_model_inputs(
        model_inputs=model_inputs,
        labels=labels,
        model_output_path=model_output_path,
        metadata_output_path=metadata_output_path,
        report_output_path=report_output_path,
        use_full_domain=use_full_domain,
        max_len=max_len,
        batch_size=batch_size,
        epochs=epochs,
        validation_size=validation_size,
        random_state=random_state,
        domain_col="column_3_domain",
        label_col="column_1_label",
        source_config={
            "train_file": train_file,
            "format": "dga_domains_full_csv",
            "label_column_index": 0,
            "family_column_index_ignored": 1,
            "domain_column_index": 2,
        },
    )


def _train_from_model_inputs(
    model_inputs: list[str],
    labels: list[int],
    model_output_path: str,
    metadata_output_path: str | None,
    report_output_path: str | None,
    use_full_domain: bool,
    max_len: int,
    batch_size: int,
    epochs: int,
    validation_size: float,
    random_state: int,
    domain_col: str,
    label_col: str,
    source_config: dict[str, Any],
) -> None:
    char_to_id = build_char_vocab(model_inputs)
    x = build_encoded_matrix(model_inputs, char_to_id, max_len)
    y = np.asarray(labels, dtype="int32") if HAS_NUMPY else labels

    x_train, x_valid, y_train, y_valid = _split_train_valid(
        x,
        y,
        labels,
        validation_size=validation_size,
        random_state=random_state,
    )

    model = build_keras_char_cnn_model(
        vocab_size=len(char_to_id),
        max_len=max_len,
        embedding_dim=DEFAULT_EMBEDDING_DIM,
        filters=DEFAULT_FILTERS,
        dense_units=DEFAULT_DENSE_UNITS,
        dropout=DEFAULT_DROPOUT,
    )

    class_weight = _build_class_weight(labels)
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=2,
            restore_best_weights=True,
        )
    ]

    print(f"Training samples: {len(labels)}")
    print(f"Class distribution: {dict(Counter(labels))}")
    model.fit(
        x_train,
        y_train,
        validation_data=(x_valid, y_valid),
        batch_size=batch_size,
        epochs=epochs,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )

    scores = _predict_scores(model, x_valid)
    y_valid_list = _to_list(y_valid)
    y_pred = [1 if score >= 0.5 else 0 for score in scores]
    metrics = _build_validation_metrics(y_valid_list, y_pred)
    report_text = _format_validation_report(metrics)
    print(report_text)

    metadata_path = metadata_output_path or f"{model_output_path}.metadata.json"
    metadata = {
        "version": "0.1.0",
        "model_type": "dga_char_cnn_string_detector",
        "framework": "tensorflow",
        "char_to_id": char_to_id,
        "max_len": max_len,
        "use_full_domain": use_full_domain,
        "domain_col": domain_col,
        "label_col": label_col,
        "config": {
            "embedding_dim": DEFAULT_EMBEDDING_DIM,
            "filters": DEFAULT_FILTERS,
            "dense_units": DEFAULT_DENSE_UNITS,
            "dropout": DEFAULT_DROPOUT,
            "batch_size": batch_size,
            "epochs": epochs,
            "validation_size": validation_size,
            "random_state": random_state,
            "source": source_config,
        },
    }

    save_model(model, model_output_path)
    save_metadata(metadata, metadata_path)
    print(f"Model saved to: {model_output_path}")
    print(f"Metadata saved to: {metadata_path}")

    if report_output_path:
        _ensure_parent_dir(report_output_path)
        with open(report_output_path, "w", encoding="utf-8") as handle:
            handle.write(report_text)
            handle.write("\n")
        print(f"Validation report saved to: {report_output_path}")


def predict_file(
    input_file: str,
    domain_col: str,
    model_path: str,
    output_file: str,
    metadata_path: str | None = None,
    threshold: float = 0.5,
) -> None:
    validate_required_args(
        {
            "input_file": input_file,
            "domain_col": domain_col,
            "model_path": model_path,
            "output_file": output_file,
        }
    )
    require_file_exists(input_file, "input_file")
    _require_path_exists(model_path, "model_path")
    _validate_threshold(threshold)

    resolved_metadata_path = metadata_path or f"{model_path}.metadata.json"
    metadata = load_metadata(resolved_metadata_path)
    model = load_model(model_path, metadata)

    records = read_csv_records(input_file)
    if not records:
        raise ValueError("Input CSV contains no records.")

    columns = list(records[0].keys())
    require_columns(columns, [domain_col])

    raw_domains = [safe_text(record.get(domain_col, "")) for record in records]
    output_records = _score_raw_domains(
        raw_domains=raw_domains,
        model=model,
        metadata=metadata,
        threshold=threshold,
        domain_field_name=domain_col,
    )
    score_stat_fields = add_score_bucket_stats(output_records)

    write_csv_records(
        output_file,
        output_records,
        [
            domain_col,
            "normalized_domain",
            "model_input_text",
            "dga_like_score",
            "predicted_label",
            *score_stat_fields,
        ],
    )
    print(f"Predictions saved to: {output_file}")


def predict_zip_directory(
    predict_dir: str = DEFAULT_PREDICT_DIR,
    model_path: str = DEFAULT_MODEL_PATH,
    output_file: str = DEFAULT_ZIP_PREDICTION_OUTPUT,
    metadata_path: str | None = DEFAULT_METADATA_PATH,
    threshold: float = 0.5,
) -> None:
    """Predict domains from zip files and save only domains predicted as DGA."""
    validate_required_args(
        {"predict_dir": predict_dir, "model_path": model_path, "output_file": output_file}
    )
    _require_path_exists(model_path, "model_path")
    _validate_threshold(threshold)

    resolved_metadata_path = metadata_path or f"{model_path}.metadata.json"
    metadata = load_metadata(resolved_metadata_path)
    model = load_model(model_path, metadata)

    input_records = read_domains_from_zip_directory(predict_dir)
    raw_domains = [record["original_domain"] for record in input_records]
    scored_records = _score_raw_domains(
        raw_domains=raw_domains,
        model=model,
        metadata=metadata,
        threshold=threshold,
        domain_field_name="original_domain",
    )

    dga_records = []
    for source_record, scored_record in zip(input_records, scored_records):
        if int(scored_record["predicted_label"]) != 1:
            continue
        dga_records.append(
            {
                "source_zip": source_record["source_zip"],
                "source_file": source_record["source_file"],
                "original_domain": scored_record["original_domain"],
                "normalized_domain": scored_record["normalized_domain"],
                "model_input_text": scored_record["model_input_text"],
                "dga_like_score": scored_record["dga_like_score"],
                "predicted_label": scored_record["predicted_label"],
            }
        )

    score_stat_fields = add_score_bucket_stats(dga_records, reference_records=scored_records)
    write_csv_records(
        output_file,
        dga_records,
        [
            "source_zip",
            "source_file",
            "original_domain",
            "normalized_domain",
            "model_input_text",
            "dga_like_score",
            "predicted_label",
            *score_stat_fields,
        ],
    )
    print(f"Scanned domains: {len(input_records)}")
    print(f"Predicted DGA-like domains: {len(dga_records)}")
    print(f"DGA-like prediction CSV saved to: {output_file}")


def _score_raw_domains(
    raw_domains: list[str],
    model: Any,
    metadata: dict[str, Any],
    threshold: float,
    domain_field_name: str,
) -> list[dict[str, Any]]:
    if not raw_domains:
        return []

    char_to_id = metadata["char_to_id"]
    max_len = int(metadata["max_len"])
    use_full_domain = bool(metadata["use_full_domain"])

    normalized_domains = []
    model_inputs = []
    for raw_domain in raw_domains:
        normalized, model_input_text = prepare_domain_text(raw_domain, use_full_domain)
        normalized_domains.append(normalized)
        model_inputs.append(model_input_text)

    x = build_encoded_matrix(model_inputs, char_to_id, max_len)
    scores = _predict_scores(model, x)

    output_records = []
    for raw_domain, normalized, model_input_text, score in zip(
        raw_domains, normalized_domains, model_inputs, scores
    ):
        numeric_score = float(score)
        output_records.append(
            {
                domain_field_name: raw_domain,
                "normalized_domain": normalized,
                "model_input_text": model_input_text,
                "dga_like_score": f"{numeric_score:.6f}",
                "predicted_label": int(numeric_score >= threshold),
            }
        )
    return output_records


def _ensure_tensorflow_available() -> None:
    if not HAS_TENSORFLOW:
        raise RuntimeError(DEEP_LEARNING_ERROR)


def _split_train_valid(
    x: Any,
    y: Any,
    labels: list[int],
    validation_size: float,
    random_state: int,
) -> tuple[Any, Any, Any, Any]:
    if HAS_SKLEARN:
        return train_test_split(
            x,
            y,
            test_size=validation_size,
            stratify=labels,
            random_state=random_state,
        )

    indices_by_label: dict[int, list[int]] = {0: [], 1: []}
    for index, label in enumerate(labels):
        indices_by_label[label].append(index)

    rng = random.Random(random_state)
    train_indices: list[int] = []
    valid_indices: list[int] = []
    for indices in indices_by_label.values():
        shuffled = indices[:]
        rng.shuffle(shuffled)
        valid_count = max(1, int(round(len(shuffled) * validation_size)))
        valid_indices.extend(shuffled[:valid_count])
        train_indices.extend(shuffled[valid_count:])

    train_indices.sort()
    valid_indices.sort()
    return (
        _take_rows(x, train_indices),
        _take_rows(x, valid_indices),
        _take_rows(y, train_indices),
        _take_rows(y, valid_indices),
    )


def _take_rows(values: Any, indices: list[int]) -> Any:
    if HAS_NUMPY and hasattr(values, "shape"):
        return values[indices]
    return [values[index] for index in indices]


def _build_class_weight(labels: list[int]) -> dict[int, float]:
    counts = Counter(labels)
    if HAS_SKLEARN and HAS_NUMPY:
        classes = np.asarray(sorted(counts.keys()))
        weights = compute_class_weight(class_weight="balanced", classes=classes, y=np.asarray(labels))
        return {int(label): float(weight) for label, weight in zip(classes, weights)}

    total = float(len(labels))
    class_count = float(len(counts))
    return {label: total / (class_count * count) for label, count in counts.items()}


def _predict_scores(model: Any, x: Any) -> list[float]:
    predictions = model.predict(x, verbose=0)
    if HAS_NUMPY:
        return np.asarray(predictions).reshape(-1).astype(float).tolist()
    return [float(row[0] if isinstance(row, (list, tuple)) else row) for row in predictions]


def _build_validation_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    if HAS_SKLEARN:
        matrix = confusion_matrix(y_true, y_pred)
        report = classification_report(y_true, y_pred, digits=4, zero_division=0)
        return {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "confusion_matrix": matrix.tolist() if hasattr(matrix, "tolist") else matrix,
            "classification_report": report,
        }

    tn, fp, fn, tp = _confusion_counts(y_true, y_pred)
    accuracy = _safe_divide(tp + tn, len(y_true))
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    report = (
        f"accuracy={accuracy:.4f}, precision={precision:.4f}, "
        f"recall={recall:.4f}, f1={f1:.4f}"
    )
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "classification_report": report,
    }


def _format_validation_report(metrics: dict[str, Any]) -> str:
    lines = [
        "Validation metrics:",
        f"accuracy: {metrics['accuracy']:.6f}",
        f"precision: {metrics['precision']:.6f}",
        f"recall: {metrics['recall']:.6f}",
        f"f1: {metrics['f1']:.6f}",
        f"confusion_matrix: {metrics['confusion_matrix']}",
        "classification_report:",
        str(metrics["classification_report"]),
    ]
    return "\n".join(lines)


def _confusion_counts(y_true: list[int], y_pred: list[int]) -> tuple[int, int, int, int]:
    tn = fp = fn = tp = 0
    for true_label, pred_label in zip(y_true, y_pred):
        if true_label == 0 and pred_label == 0:
            tn += 1
        elif true_label == 0 and pred_label == 1:
            fp += 1
        elif true_label == 1 and pred_label == 0:
            fn += 1
        elif true_label == 1 and pred_label == 1:
            tp += 1
    return tn, fp, fn, tp


def _safe_divide(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def _to_list(values: Any) -> list[int]:
    if hasattr(values, "tolist"):
        return [int(value) for value in values.tolist()]
    return [int(value) for value in values]


def _validate_binary_labels(labels: list[int]) -> None:
    counts = Counter(labels)
    if set(counts.keys()) - {0, 1}:
        raise ValueError(f"Training labels must be 0 or 1, got: {sorted(counts.keys())}")
    if len(counts) < 2:
        raise ValueError("Training labels must contain both 0 and 1 classes.")
    if min(counts.values()) < 2:
        raise ValueError(
            "Each class must contain at least two samples for stratified validation split."
        )


def _validate_metadata(metadata: dict[str, Any]) -> None:
    required = ["char_to_id", "max_len", "use_full_domain", "framework", "model_type"]
    for key in required:
        if key not in metadata:
            raise ValueError(f"Metadata missing required field: {key}")
    if metadata["model_type"] != "dga_char_cnn_string_detector":
        raise ValueError(f"Unsupported metadata model_type: {metadata['model_type']!r}")
    if not isinstance(metadata["char_to_id"], dict) or not metadata["char_to_id"]:
        raise ValueError("Metadata field 'char_to_id' must be a non-empty dict.")
    _validate_positive_int(int(metadata["max_len"]), "max_len")


def _validate_positive_int(value: int, name: str) -> None:
    if int(value) <= 0:
        raise ValueError(f"{name} must be a positive integer.")


def _validate_validation_size(value: float) -> None:
    if value <= 0 or value >= 1:
        raise ValueError("validation_size must be greater than 0 and less than 1.")


def _validate_threshold(value: float) -> None:
    if value < 0 or value > 1:
        raise ValueError("threshold must be between 0 and 1.")


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def _require_path_exists(path: str, name: str) -> None:
    validate_required_args({name: path})
    if not os.path.exists(path):
        raise FileNotFoundError(f"{name} does not exist: {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train or run a Char-CNN string-only DGA-like detector."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Train the Char-CNN detector.")
    train_parser.add_argument(
        "--train-file",
        default=DEFAULT_DGA_TRAIN_FILE,
        help="Training CSV path. Default is the project DGA dataset.",
    )
    train_parser.add_argument(
        "--domain-col",
        default="",
        help="Optional domain column name for a custom header CSV.",
    )
    train_parser.add_argument(
        "--label-col",
        default="",
        help="Optional label column name for a custom header CSV.",
    )
    train_parser.add_argument(
        "--model-output",
        default=DEFAULT_MODEL_PATH,
        help="Output model path.",
    )
    train_parser.add_argument(
        "--metadata-output",
        default=DEFAULT_METADATA_PATH,
        help="Optional metadata JSON path.",
    )
    train_parser.add_argument(
        "--report-output",
        default=DEFAULT_REPORT_PATH,
        help="Optional validation report output path.",
    )
    train_parser.add_argument(
        "--use-full-domain",
        action="store_true",
        help="Use normalized full domain instead of SLD as model input.",
    )
    train_parser.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN)
    train_parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    train_parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)

    predict_parser = subparsers.add_parser("predict", help="Predict DGA-like domains.")
    predict_parser.add_argument(
        "--predict-dir",
        default=DEFAULT_PREDICT_DIR,
        help="Directory containing zip files with txt domain lists.",
    )
    predict_parser.add_argument(
        "--input-file",
        default="",
        help="Optional legacy CSV input path. If set, --domain-col is required.",
    )
    predict_parser.add_argument(
        "--domain-col",
        default="",
        help="Domain column name for --input-file CSV mode.",
    )
    predict_parser.add_argument(
        "--model-path",
        default=DEFAULT_MODEL_PATH,
        help="Trained model path.",
    )
    predict_parser.add_argument(
        "--metadata-path",
        default=DEFAULT_METADATA_PATH,
        help="Optional metadata JSON path.",
    )
    predict_parser.add_argument(
        "--output-file",
        default=DEFAULT_ZIP_PREDICTION_OUTPUT,
        help="Prediction CSV output path.",
    )
    predict_parser.add_argument("--threshold", type=float, default=0.5)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        if args.command == "train":
            if args.domain_col or args.label_col:
                train_model(
                    train_file=args.train_file,
                    domain_col=args.domain_col,
                    label_col=args.label_col,
                    model_output_path=args.model_output,
                    metadata_output_path=args.metadata_output or None,
                    report_output_path=args.report_output or None,
                    use_full_domain=args.use_full_domain,
                    max_len=args.max_len,
                    batch_size=args.batch_size,
                    epochs=args.epochs,
                )
            else:
                train_dga_dataset(
                    train_file=args.train_file,
                    model_output_path=args.model_output,
                    metadata_output_path=args.metadata_output or None,
                    report_output_path=args.report_output or None,
                    use_full_domain=args.use_full_domain,
                    max_len=args.max_len,
                    batch_size=args.batch_size,
                    epochs=args.epochs,
                )
        elif args.command == "predict":
            if args.input_file:
                predict_file(
                    input_file=args.input_file,
                    domain_col=args.domain_col,
                    model_path=args.model_path,
                    metadata_path=args.metadata_path or None,
                    output_file=args.output_file,
                    threshold=args.threshold,
                )
            else:
                predict_zip_directory(
                    predict_dir=args.predict_dir,
                    model_path=args.model_path,
                    metadata_path=args.metadata_path or None,
                    output_file=args.output_file,
                    threshold=args.threshold,
                )
        else:
            raise ValueError(f"Unsupported command: {args.command}")
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
