"""Feature contract, synthetic demo data, training, and prediction.

Prediction uses the medians, means, and scales saved with the model.
Those statistics are fit on the training split only.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from config import (
    DATA_DIR,
    MAX_COLUMNS,
    MAX_ROWS,
    METRICS_PATH,
    MODEL_DIR,
    MODEL_PATH,
    RANDOM_STATE,
    SAMPLE_CSV,
    TEST_SIZE,
)

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Active Mean",
    "Idle Mean",
]
LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"
CLASSES = ["BENIGN", "DoS", "DDoS", "PortScan", "Brute Force", "Web Attack"]
CONFIDENCE_NOTE = (
    "Confidence is the model's estimated probability for the predicted class "
    "(the maximum value from predict_proba). It is a statistical estimate, "
    "not a calibrated certainty and not proof that an attack occurred."
)
DETECTION_RATE_NOTE = (
    "Detection rate is the share of analyzed flows whose predicted class is not BENIGN. "
    "It describes the uploaded file, not the model's recall on the held-out test set."
)
ROWS_PER_CLASS = 200

# Benign-centered means. Attack classes shift a few of these by a fraction of
# the standard deviation so the classes overlap. These are generator settings,
# not measured detection scores.
BASE_MEAN = np.array(
    [
        443,
        5_000_000,
        14,
        12,
        8_000,
        14_000,
        550,
        900,
        18_000,
        8,
        120_000,
        130_000,
        140_000,
        4,
        3,
        720,
        180,
        1,
        1,
        0.3,
        14,
        0.9,
        700,
        16_384,
        65_535,
        80_000,
        250_000,
    ],
    dtype=float,
)
BASE_STD = np.array(
    [
        1,
        1_600_000,
        6,
        5,
        3_500,
        5_000,
        160,
        220,
        7_000,
        4,
        45_000,
        48_000,
        50_000,
        2,
        1.6,
        180,
        70,
        0.7,
        0.8,
        0.6,
        5,
        0.35,
        160,
        5_000,
        8_000,
        30_000,
        90_000,
    ],
    dtype=float,
)
# Column index -> shift in units of BASE_STD.
CLASS_SHIFTS = {
    "BENIGN": {},
    "DoS": {2: 2.1, 8: 2.3, 9: 2.0, 10: -1.8, 18: 1.8, 21: -1.7},
    "DDoS": {1: -1.9, 3: -1.8, 13: 2.2, 18: 2.1, 20: -1.6, 26: -1.8},
    "PortScan": {1: -2.0, 2: -1.9, 4: -1.8, 8: -1.5, 20: -1.8, 22: -1.7},
    "Brute Force": {6: -1.6, 16: -1.7, 19: 2.2, 9: 1.4, 25: 1.5, 21: 1.2},
    "Web Attack": {4: 2.2, 6: 1.8, 15: 1.6, 16: 2.0, 20: 1.5, 22: 1.8},
}
PORT_CHOICES = {
    "BENIGN": ([80, 443, 53, 22, 21, 8080], [0.32, 0.34, 0.1, 0.1, 0.04, 0.1]),
    "DoS": ([80, 443, 8080, 22], [0.5, 0.28, 0.14, 0.08]),
    "DDoS": ([80, 443, 53], [0.55, 0.35, 0.1]),
    "Brute Force": ([22, 21, 80, 443, 3389], [0.42, 0.14, 0.18, 0.18, 0.08]),
    "Web Attack": ([80, 443, 8080, 8443], [0.42, 0.38, 0.12, 0.08]),
}
INTEGER_COLUMNS = [0, 2, 3, 17, 18, 19, 20, 23, 24]
_bundle_cache: dict | None = None


class DatasetError(Exception):
    def __init__(self, message: str, **details):
        super().__init__(message)
        self.details = details


def severity_for(label: str) -> str:
    if label == BENIGN_LABEL:
        return "info"
    text = label.lower()
    if any(token in text for token in ("web", "infiltration", "heartbleed", "bot", "sql")):
        return "critical"
    if any(token in text for token in ("ddos", "dos", "brute", "patator")):
        return "high"
    if "port" in text or "scan" in text:
        return "medium"
    return "medium"


def _class_order(labels) -> list[str]:
    unique = sorted({str(label) for label in labels})
    if BENIGN_LABEL in unique:
        unique.remove(BENIGN_LABEL)
        return [BENIGN_LABEL, *unique]
    return unique


def _shift_vector(name: str) -> np.ndarray:
    delta = np.zeros_like(BASE_STD)
    for index, scale in CLASS_SHIFTS[name].items():
        delta[index] = scale * BASE_STD[index]
    return delta


def _assign_ports(values: np.ndarray, name: str, rng: np.random.Generator) -> None:
    count = len(values)
    if name == "PortScan":
        random_ports = rng.integers(1, 1025, count)
        common = rng.choice([80, 443, 22, 21], count)
        use_random = rng.random(count) < 0.72
        values[:, 0] = np.where(use_random, random_ports, common)
        return
    choices, probabilities = PORT_CHOICES[name]
    values[:, 0] = rng.choice(choices, count, p=probabilities)


def _finalize_features(values: np.ndarray) -> np.ndarray:
    cleaned = values.copy()
    cleaned[:, 1] = np.clip(cleaned[:, 1], 1, None)
    for index in range(2, cleaned.shape[1]):
        cleaned[:, index] = np.clip(cleaned[:, index], 0, None)
    for index in INTEGER_COLUMNS:
        cleaned[:, index] = np.rint(np.clip(cleaned[:, index], 0, None))
    return cleaned


def generate_sample(rows_per_class: int = ROWS_PER_CLASS, seed: int = RANDOM_STATE) -> pd.DataFrame:
    """Build a small class-conditional CSV. It is not a packet capture."""
    rng = np.random.default_rng(seed)
    frames = []
    benign_draw = rng.normal(BASE_MEAN, BASE_STD, size=(rows_per_class, len(FEATURE_COLUMNS)))
    for name in CLASSES:
        draw = rng.normal(
            BASE_MEAN + _shift_vector(name),
            BASE_STD,
            size=(rows_per_class, len(FEATURE_COLUMNS)),
        )
        if name == BENIGN_LABEL:
            contaminate = rng.random(rows_per_class) < 0.05
            for row_index in np.flatnonzero(contaminate):
                attack = CLASSES[int(rng.integers(1, len(CLASSES)))]
                draw[row_index] = rng.normal(BASE_MEAN + _shift_vector(attack), BASE_STD)
        else:
            mix = rng.random(rows_per_class) < 0.08
            draw[mix] = benign_draw[mix]
        _assign_ports(draw, name, rng)
        draw = _finalize_features(draw)
        frame = pd.DataFrame(draw, columns=FEATURE_COLUMNS)
        frame[LABEL_COLUMN] = name
        frames.append(frame)

    sample = pd.concat(frames, ignore_index=True)
    sample = sample.sample(frac=1, random_state=seed).reset_index(drop=True)
    missing = rng.random(sample[FEATURE_COLUMNS].shape) < 0.012
    features = sample[FEATURE_COLUMNS].mask(missing)
    sample[FEATURE_COLUMNS] = features
    return sample


def write_sample(path=SAMPLE_CSV) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    sample = generate_sample()
    sample.to_csv(path, index=False, float_format="%.6g")
    return sample


def _rename_columns(df: pd.DataFrame) -> pd.DataFrame:
    expected = {column.lower(): column for column in [*FEATURE_COLUMNS, LABEL_COLUMN, "Timestamp"]}
    rename = {}
    seen = {}
    for column in df.columns:
        key = str(column).strip().lower()
        if key not in expected:
            continue
        target = expected[key]
        if target in seen:
            raise DatasetError("CSV contains duplicate column names", duplicate_column=target)
        seen[target] = column
        if column != target:
            rename[column] = target
    if rename:
        df = df.rename(columns=rename)
    if df.columns.duplicated().any():
        raise DatasetError("CSV contains duplicate column names")
    return df


def prepare_frame(df: pd.DataFrame, require_label: bool = False):
    if df.shape[1] > MAX_COLUMNS:
        raise DatasetError(
            f"CSV has too many columns. The limit is {MAX_COLUMNS}.",
            column_count=int(df.shape[1]),
        )
    df = _rename_columns(df.copy())
    df.columns = [str(column).strip().lstrip("\ufeff") for column in df.columns]
    missing = [column for column in FEATURE_COLUMNS if column not in df.columns]
    if missing:
        raise DatasetError(
            "CSV is missing required CIC-IDS2017 feature columns.",
            missing_columns=missing,
        )
    if require_label and LABEL_COLUMN not in df.columns:
        raise DatasetError("Training CSV must include a Label column.")
    if len(df) == 0:
        raise DatasetError("CSV has no data rows.")
    if len(df) > MAX_ROWS:
        raise DatasetError(
            f"CSV exceeds the row limit of {MAX_ROWS}. Split the file and analyze it in parts.",
            row_count=int(len(df)),
        )

    features = pd.DataFrame(index=df.index)
    non_numeric = []
    for column in FEATURE_COLUMNS:
        numeric = pd.to_numeric(df[column], errors="coerce")
        as_text = df[column].astype(str).str.strip()
        failed = df[column].notna() & numeric.isna()
        failed &= ~as_text.isin(["", "nan", "NaN", "None", "inf", "-inf", "+inf", "Infinity", "-Infinity"])
        if len(df) and float(failed.sum()) / len(df) > 0.5:
            non_numeric.append(column)
        features[column] = numeric.replace([np.inf, -np.inf], np.nan)
    if non_numeric:
        raise DatasetError(
            "One or more required columns are not numeric.",
            non_numeric_columns=non_numeric,
        )

    labels = None
    if LABEL_COLUMN in df.columns:
        labels = df[LABEL_COLUMN].astype(str).str.strip()
        labels = labels.mask(labels.isin(["", "nan", "NaN", "None"]))

    timestamps = df["Timestamp"].astype(str) if "Timestamp" in df.columns else None
    usable = ~features.isna().all(axis=1)
    dropped = int((~usable).sum())
    features = features.loc[usable].reset_index(drop=True)
    if labels is not None:
        labels = labels.loc[usable].reset_index(drop=True)
    if timestamps is not None:
        timestamps = timestamps.loc[usable].reset_index(drop=True)
    if len(features) == 0:
        raise DatasetError("No usable flow rows after parsing.")

    missing_counts = features.isna().sum()
    report = {
        "rows": int(len(features)),
        "dropped_empty_rows": dropped,
        "imputed_cells": int(missing_counts.sum()),
        "missing_values": {
            column: int(missing_counts[column])
            for column in FEATURE_COLUMNS
            if int(missing_counts[column]) > 0
        },
        "feature_count": len(FEATURE_COLUMNS),
        "has_ground_truth": bool(labels is not None and labels.notna().any()),
    }
    return features, labels, timestamps, report


def fit_preprocessor(features: pd.DataFrame) -> dict:
    medians = features.median(numeric_only=True).fillna(0.0)
    filled = features.fillna(medians)
    means = filled.mean()
    scales = filled.std(ddof=0).replace(0, 1.0).fillna(1.0)
    return {
        "medians": [float(medians[column]) for column in FEATURE_COLUMNS],
        "means": [float(means[column]) for column in FEATURE_COLUMNS],
        "scales": [float(scales[column]) for column in FEATURE_COLUMNS],
    }


def transform(features: pd.DataFrame, preprocessor: dict) -> np.ndarray:
    """Apply the saved training preprocessor. Do not refit statistics here."""
    medians = pd.Series(preprocessor["medians"], index=FEATURE_COLUMNS, dtype=float)
    means = np.asarray(preprocessor["means"], dtype=float)
    scales = np.asarray(preprocessor["scales"], dtype=float)
    filled = features[FEATURE_COLUMNS].astype(float).fillna(medians)
    return (filled.to_numpy(dtype=float) - means) / scales


def build_training_split(features: pd.DataFrame, labels: pd.Series) -> dict:
    clean_labels = labels.astype(str).str.strip()
    keep = labels.notna() & ~clean_labels.isin(["", "nan", "NaN", "None"])
    features = features.loc[keep]
    clean_labels = clean_labels.loc[keep]
    if clean_labels.nunique() < 2:
        raise DatasetError("At least two classes are required to train.")
    if int(clean_labels.value_counts().min()) < 2:
        raise DatasetError("Each class needs at least two rows for a stratified split.")
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        clean_labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=clean_labels,
    )
    return {
        "x_train": x_train,
        "x_test": x_test,
        "y_train": y_train,
        "y_test": y_test,
    }


def _round_number(value):
    if isinstance(value, dict):
        return {str(key): _round_number(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_round_number(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return None
        return round(number, 6)
    return value


def _score(y_true, y_pred, labels: list[str]) -> dict:
    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "confusion_labels": labels,
    }


def _new_models() -> dict:
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=40,
            max_depth=8,
            min_samples_leaf=3,
            random_state=RANDOM_STATE,
            n_jobs=1,
        ),
        "logistic_regression": LogisticRegression(
            max_iter=800,
            random_state=RANDOM_STATE,
        ),
    }


def _importance(model, model_name: str) -> dict:
    if hasattr(model, "feature_importances_"):
        raw = np.asarray(model.feature_importances_, dtype=float)
        kind = "gini_importance"
    else:
        raw = np.abs(np.asarray(model.coef_, dtype=float)).mean(axis=0)
        total = float(raw.sum()) or 1.0
        raw = raw / total
        kind = "normalized_mean_absolute_coefficient"
    pairs = [
        {"feature": feature, "value": float(value)}
        for feature, value in zip(FEATURE_COLUMNS, raw)
    ]
    pairs.sort(key=lambda item: item["value"], reverse=True)
    return {"model": model_name, "kind": kind, "features": pairs}


def train_and_save(features: pd.DataFrame, labels: pd.Series, source_name: str, source_kind: str) -> dict:
    split = build_training_split(features, labels)
    preprocessor = fit_preprocessor(split["x_train"])
    x_train = transform(split["x_train"], preprocessor)
    x_test = transform(split["x_test"], preprocessor)
    labels = _class_order(split["y_train"])
    fitted = {}
    metrics = {}
    for name, model in _new_models().items():
        model.fit(x_train, split["y_train"])
        fitted[name] = model
        metrics[name] = {
            "test": _score(split["y_test"], model.predict(x_test), labels),
            "train": _score(split["y_train"], model.predict(x_train), labels),
        }

    selected = max(
        metrics,
        key=lambda name: (metrics[name]["test"]["f1_macro"], name == "random_forest"),
    )
    trained_at = datetime.now(timezone.utc).isoformat()
    bundle = {
        "model": fitted[selected],
        "model_name": selected,
        "preprocessor": preprocessor,
        "feature_columns": list(FEATURE_COLUMNS),
        "classes": [str(label) for label in fitted[selected].classes_],
        "trained_at": trained_at,
        "training_source": source_name,
        "training_source_kind": source_kind,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
    }
    payload = {
        "trained_at": trained_at,
        "training_source": source_name,
        "training_source_kind": source_kind,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "n_rows": int(len(features)),
        "n_train": int(len(split["x_train"])),
        "n_test": int(len(split["x_test"])),
        "feature_columns": list(FEATURE_COLUMNS),
        "classes": labels,
        "selected_model": selected,
        "selection_rule": "Highest held-out macro F1. Equal scores keep random forest.",
        "model_parameters": {
            "random_forest": {
                "n_estimators": 40,
                "max_depth": 8,
                "min_samples_leaf": 3,
                "random_state": RANDOM_STATE,
            },
            "logistic_regression": {"max_iter": 800, "random_state": RANDOM_STATE},
        },
        "models": metrics,
        "feature_importance": {name: _importance(model, name) for name, model in fitted.items()},
        "notes": [
            "Accuracy, precision, recall, and F1 are computed on a stratified held-out test split.",
            "Train scores are stored only so overfitting can be inspected. The dashboard uses test scores.",
            "The default dataset is synthetic. It is not the CIC-IDS2017 corpus.",
            "Confidence values are maximum predicted-class probabilities, not calibrated certainties.",
            "This system scores uploaded flow CSV files. It does not capture packets.",
        ],
    }
    payload = _round_number(payload)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    global _bundle_cache
    _bundle_cache = bundle
    return payload


def ensure_sample() -> None:
    if not SAMPLE_CSV.exists():
        write_sample(SAMPLE_CSV)


def train_default() -> dict:
    ensure_sample()
    frame = pd.read_csv(SAMPLE_CSV)
    features, labels, _, _ = prepare_frame(frame, require_label=True)
    return train_and_save(features, labels, SAMPLE_CSV.name, "synthetic_demonstration")


def train_csv(path, source_kind: str = "external_csv") -> dict:
    frame = pd.read_csv(path)
    features, labels, _, _ = prepare_frame(frame, require_label=True)
    return train_and_save(features, labels, PathName(path), source_kind)


def PathName(path) -> str:
    from pathlib import Path

    return Path(path).name


def load_metrics() -> dict:
    if not METRICS_PATH.exists():
        train_default()
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def load_bundle(force: bool = False) -> dict:
    global _bundle_cache
    if _bundle_cache is None or force:
        if not MODEL_PATH.exists() or not METRICS_PATH.exists():
            train_default()
        _bundle_cache = joblib.load(MODEL_PATH)
    if _bundle_cache["feature_columns"] != FEATURE_COLUMNS:
        raise RuntimeError("Saved model features do not match this pipeline. Run train.py again.")
    return _bundle_cache


def _confidence_buckets(confidences: list[float]) -> list[dict]:
    bounds = [0.0, 0.5, 0.7, 0.85, 1.000001]
    names = ["<50%", "50-70%", "70-85%", "85-100%"]
    array = np.asarray(confidences, dtype=float)
    return [
        {
            "range": name,
            "count": int(np.sum((array >= bounds[index]) & (array < bounds[index + 1]))),
        }
        for index, name in enumerate(names)
    ]


def predict_flows(features: pd.DataFrame, labels: pd.Series | None, timestamps: pd.Series | None):
    bundle = load_bundle()
    model = bundle["model"]
    matrix = transform(features, bundle["preprocessor"])
    if not hasattr(model, "predict_proba"):
        raise RuntimeError("The loaded model does not provide probability estimates.")
    probabilities = model.predict_proba(matrix)
    classes = [str(label) for label in model.classes_]
    chosen = probabilities.argmax(axis=1)
    rows = []
    for index in range(len(features)):
        label = classes[int(chosen[index])]
        confidence = float(probabilities[index, int(chosen[index])])
        ground_truth = None
        if labels is not None and pd.notna(labels.iloc[index]):
            text = str(labels.iloc[index]).strip()
            if text and text.lower() not in {"nan", "none"}:
                ground_truth = text[:80]
        flow_timestamp = None
        if timestamps is not None and pd.notna(timestamps.iloc[index]):
            flow_timestamp = str(timestamps.iloc[index])[:40]
        rows.append(
            {
                "row_index": int(index),
                "predicted_label": label,
                "verdict": "BENIGN" if label == BENIGN_LABEL else "MALICIOUS",
                "confidence": confidence,
                "severity": severity_for(label),
                "ground_truth": ground_truth,
                "flow_timestamp": flow_timestamp,
            }
        )
    return rows, bundle


def summarize_predictions(filename: str, report: dict, rows: list[dict], bundle: dict) -> dict:
    labels = [row["predicted_label"] for row in rows]
    distribution: dict[str, int] = {}
    for label in labels:
        distribution[label] = distribution.get(label, 0) + 1
    benign = distribution.get(BENIGN_LABEL, 0)
    total = len(rows)
    malicious = total - benign
    confidences = [row["confidence"] for row in rows]
    comparable = [row for row in rows if row["ground_truth"]]
    agreement = None
    if comparable:
        matches = sum(1 for row in comparable if row["ground_truth"] == row["predicted_label"])
        agreement = matches / len(comparable)
    ordered = [
        {"label": label, "count": count}
        for label, count in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "original_filename": filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_flows": total,
        "benign_count": benign,
        "malicious_count": malicious,
        "detection_rate": (malicious / total) if total else 0.0,
        "mean_confidence": float(np.mean(confidences)) if confidences else 0.0,
        "label_agreement": agreement,
        "attack_distribution": ordered,
        "confidence_buckets": _confidence_buckets(confidences),
        "validation_report": report,
        "model_name": bundle["model_name"],
        "training_source_kind": bundle["training_source_kind"],
        "trained_at": bundle["trained_at"],
    }
