"""Retrain, confirm prediction uses the training preprocessor, and exercise the API."""

import io
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi.testclient import TestClient
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

sys.path.insert(0, str(Path(__file__).resolve().parent))

import main as api_main
import pipeline
from config import MAX_UPLOAD_BYTES, SAMPLE_CSV
from pipeline import FEATURE_COLUMNS

CHECKS = []


def check(name: str, passed: bool, detail: str = "") -> None:
    CHECKS.append((name, passed, detail))
    status = "PASS" if passed else "FAIL"
    extra = f" - {detail}" if detail else ""
    print(f"[{status}] {name}{extra}")


def round6(value: float) -> float:
    return round(float(value), 6)


def check_preprocessing(bundle: dict) -> None:
    frame = pd.read_csv(SAMPLE_CSV)
    features, labels, _, _ = pipeline.prepare_frame(frame, require_label=True)
    split = pipeline.build_training_split(features, labels)
    fresh = pipeline.fit_preprocessor(split["x_train"])
    saved = bundle["preprocessor"]
    same_stats = all(
        np.allclose(fresh[key], saved[key], rtol=0, atol=1e-9) for key in ("medians", "means", "scales")
    )
    check("preprocessor matches training split", same_stats)

    train_matrix = pipeline.transform(split["x_test"], fresh)
    predict_matrix = pipeline.transform(split["x_test"], saved)
    check("prediction transform matches training transform", np.allclose(train_matrix, predict_matrix))

    direct = [str(label) for label in bundle["model"].predict(train_matrix)]
    predicted, _ = pipeline.predict_flows(split["x_test"], split["y_test"], None)
    via_api_path = [row["predicted_label"] for row in predicted]
    check("predict_flows uses the saved preprocessor", direct == via_api_path)

    row = split["x_test"].iloc[[0]].copy()
    column = FEATURE_COLUMNS[8]
    row.iloc[0, row.columns.get_loc(column)] = np.nan
    manual = row[FEATURE_COLUMNS].to_numpy(dtype=float)
    medians = np.asarray(saved["medians"], dtype=float)
    means = np.asarray(saved["means"], dtype=float)
    scales = np.asarray(saved["scales"], dtype=float)
    manual = np.where(np.isnan(manual), medians, manual)
    manual = (manual - means) / scales
    produced = pipeline.transform(row, saved)
    check("missing values use training medians", np.allclose(manual, produced))

    metrics = pipeline.load_metrics()
    selected = metrics["selected_model"]
    test_labels = [str(label) for label in split["y_test"]]
    recomputed = {
        "accuracy": round6(accuracy_score(test_labels, direct)),
        "precision_macro": round6(precision_score(test_labels, direct, average="macro", zero_division=0)),
        "recall_macro": round6(recall_score(test_labels, direct, average="macro", zero_division=0)),
        "f1_macro": round6(f1_score(test_labels, direct, average="macro", zero_division=0)),
    }
    stored = metrics["models"][selected]["test"]
    matches = all(recomputed[key] == stored[key] for key in recomputed)
    check("stored test metrics match a fresh sklearn evaluation", matches, str(recomputed))


def check_api() -> None:
    with TestClient(api_main.app) as client:
        health = client.get("/api/health")
        check("GET /api/health", health.status_code == 200 and health.json()["live_capture"] is False)

        metrics = client.get("/api/model/metrics")
        body = metrics.json()
        has_both = {"random_forest", "logistic_regression"} <= set(body.get("models", {}))
        check(
            "GET /api/model/metrics",
            metrics.status_code == 200 and has_both and "accuracy" in body["models"][body["selected_model"]]["test"],
        )

        sample = client.get("/api/sample")
        sample_text = sample.text
        check(
            "GET /api/sample",
            sample.status_code == 200 and "Label" in sample_text.splitlines()[0] and "Destination Port" in sample_text,
        )

        uploaded = client.post(
            "/api/analyses",
            files={"file": ("sample_traffic.csv", sample.content, "text/csv")},
        )
        check("POST /api/analyses", uploaded.status_code == 200 and uploaded.json()["total_flows"] > 0)
        analysis_id = uploaded.json()["id"] if uploaded.status_code == 200 else None

        builtin = client.post("/api/analyses/sample")
        check("POST /api/analyses/sample", builtin.status_code == 200 and builtin.json()["benign_count"] >= 0)

        listing = client.get("/api/analyses")
        check("GET /api/analyses", listing.status_code == 200 and len(listing.json()["items"]) >= 1)

        if analysis_id is not None:
            detail = client.get(f"/api/analyses/{analysis_id}")
            flows = client.get(f"/api/analyses/{analysis_id}/flows?page=1&page_size=10&verdict=MALICIOUS")
            exported = client.get(f"/api/analyses/{analysis_id}/export")
            check("GET /api/analyses/{id}", detail.status_code == 200 and "confidence_note" in detail.json())
            check(
                "GET /api/analyses/{id}/flows",
                flows.status_code == 200 and "items" in flows.json() and "confidence_note" in flows.json(),
            )
            check(
                "GET /api/analyses/{id}/export",
                exported.status_code == 200 and exported.text.splitlines()[0].startswith("row_index"),
            )
            missing = client.get("/api/analyses/999999")
            check("GET missing analysis", missing.status_code == 404)

        traversal = client.post(
            "/api/analyses",
            files={"file": ("../../Windows/win.ini.csv", sample.content, "text/csv")},
        )
        stored_name = traversal.json().get("original_filename", "") if traversal.status_code == 200 else ""
        check(
            "path traversal filename is not used as a path",
            traversal.status_code == 200 and ".." not in stored_name and "/" not in stored_name and "\\" not in stored_name,
            stored_name,
        )

        malformed = client.post("/api/analyses", files={"file": ("bad.csv", b'col\n"unterminated', "text/csv")})
        binary = client.post("/api/analyses", files={"file": ("bad.csv", b"\x00\x01binary", "text/csv")})
        wrong_type = client.post("/api/analyses", files={"file": ("notes.exe", b"a,b\n1,2\n", "application/octet-stream")})
        empty = client.post("/api/analyses", files={"file": ("empty.csv", b"", "text/csv")})
        missing_cols = client.post("/api/analyses", files={"file": ("tiny.csv", b"a,b\n1,2\n", "text/csv")})
        oversized = client.post(
            "/api/analyses",
            files={"file": ("big.csv", b"x" * (MAX_UPLOAD_BYTES + 16), "text/csv")},
        )
        check("malformed CSV returns 400", malformed.status_code == 400)
        check("binary upload returns 400", binary.status_code == 400)
        check("non-CSV extension returns 400", wrong_type.status_code == 400)
        check("empty CSV returns 400", empty.status_code == 400)
        check("missing columns return 422", missing_cols.status_code == 422)
        check("oversize CSV returns 413", oversized.status_code == 413)

        dashboard = client.get("/api/dashboard")
        alerts = client.get("/api/alerts?limit=5")
        check("GET /api/dashboard", dashboard.status_code == 200 and "total_flows" in dashboard.json())
        check("GET /api/alerts", alerts.status_code == 200 and "items" in alerts.json())


def main() -> None:
    print("Training synthetic demonstration model...")
    pipeline.write_sample(SAMPLE_CSV)
    pipeline.train_default()
    bundle = pipeline.load_bundle(force=True)
    check_preprocessing(bundle)
    check_api()
    failed = [name for name, passed, _detail in CHECKS if not passed]
    print(f"\n{len(CHECKS) - len(failed)} passed, {len(failed)} failed")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
