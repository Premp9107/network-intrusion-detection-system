"""Aegis NIDS API. Offline CSV classification only; no packet capture."""

import csv
import io
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import database
from config import CORS_ORIGINS, MAX_UPLOAD_BYTES, MAX_UPLOAD_MB, SAMPLE_CSV
from pipeline import (
    CONFIDENCE_NOTE,
    DETECTION_RATE_NOTE,
    DatasetError,
    ensure_sample,
    load_bundle,
    load_metrics,
    predict_flows,
    prepare_frame,
    summarize_predictions,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_app):
    database.init_db()
    load_bundle()
    yield


app = FastAPI(
    title="Aegis NIDS API",
    version="1.0.0",
    description="Offline flow-CSV intrusion classification. This service does not capture packets.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(DatasetError)
async def handle_dataset_error(_request, exc: DatasetError):
    return JSONResponse(status_code=422, content={"detail": str(exc), **exc.details})


@app.exception_handler(Exception)
async def handle_unexpected(_request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    logger.exception("Unhandled API error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def _safe_filename(filename: str) -> str:
    base = Path((filename or "upload.csv").replace("\\", "/")).name.replace("\x00", "")
    cleaned = []
    for char in base:
        if char.isalnum() or char in "._-":
            cleaned.append(char)
        else:
            cleaned.append("_")
    safe = "".join(cleaned).strip("._") or "upload"
    if not safe.lower().endswith(".csv"):
        safe = f"{safe}.csv"
    return safe[:120]


def _read_upload(filename: str, raw: bytes):
    if not filename or Path(filename.replace("\\", "/")).suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Only .csv uploads are accepted.")
    if len(raw) == 0:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {MAX_UPLOAD_MB} MB limit.",
        )
    if b"\x00" in raw[:4096]:
        raise HTTPException(status_code=400, detail="File does not look like CSV text and was not executed.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 text.") from exc
    try:
        frame = pd.read_csv(io.StringIO(text))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed CSV. The file could not be parsed.") from exc
    return frame


def _run_analysis(frame, filename: str) -> dict:
    features, labels, timestamps, report = prepare_frame(frame)
    rows, bundle = predict_flows(features, labels, timestamps)
    summary = summarize_predictions(filename, report, rows, bundle)
    analysis_id = database.save_analysis(summary, rows)
    stored = database.get_analysis(analysis_id)
    return _public_analysis(stored)


def _public_analysis(analysis: dict) -> dict:
    return {
        **analysis,
        "confidence_note": CONFIDENCE_NOTE,
        "detection_rate_note": DETECTION_RATE_NOTE,
        "mode": "offline_csv",
    }


def _csv_cell(value) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@app.get("/api/health")
def health():
    bundle = load_bundle()
    return {
        "status": "ok",
        "model_loaded": True,
        "model_name": bundle["model_name"],
        "trained_at": bundle["trained_at"],
        "training_source": bundle["training_source"],
        "training_source_kind": bundle["training_source_kind"],
        "mode": "offline_csv",
        "live_capture": False,
    }


@app.get("/api/model/metrics")
def model_metrics():
    return load_metrics()


@app.get("/api/dashboard")
def dashboard():
    stats = database.dashboard_stats()
    return {
        **stats,
        "detection_rate_note": DETECTION_RATE_NOTE,
        "confidence_note": CONFIDENCE_NOTE,
        "mode": "offline_csv",
    }


@app.get("/api/sample")
def download_sample():
    ensure_sample()
    return FileResponse(SAMPLE_CSV, media_type="text/csv", filename="sample_traffic.csv")


@app.get("/api/analyses")
def analyses(limit: int = Query(50, ge=1, le=200)):
    return {"items": database.list_analyses(limit)}


@app.post("/api/analyses/sample")
def analyze_sample():
    ensure_sample()
    frame = pd.read_csv(SAMPLE_CSV)
    return _run_analysis(frame, "sample_traffic.csv")


@app.post("/api/analyses")
async def analyze_upload(file: UploadFile = File(...)):
    raw = await file.read()
    frame = _read_upload(file.filename or "", raw)
    return _run_analysis(frame, _safe_filename(file.filename or "upload.csv"))


@app.get("/api/analyses/{analysis_id}")
def analysis_detail(analysis_id: int):
    analysis = database.get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return _public_analysis(analysis)


@app.get("/api/analyses/{analysis_id}/flows")
def analysis_flows(
    analysis_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    verdict: str = Query(""),
    label: str = Query(""),
):
    if database.get_analysis(analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    verdict = verdict.strip().upper()
    if verdict and verdict not in {"BENIGN", "MALICIOUS"}:
        raise HTTPException(status_code=400, detail="Verdict must be BENIGN or MALICIOUS.")
    flows = database.list_flows(analysis_id, page, page_size, verdict, label.strip())
    flows["confidence_note"] = CONFIDENCE_NOTE
    return flows


@app.get("/api/analyses/{analysis_id}/export")
def export_analysis(analysis_id: int):
    if database.get_analysis(analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "row_index",
            "timestamp",
            "predicted_label",
            "verdict",
            "confidence",
            "severity",
            "ground_truth",
            "confidence_note",
        ]
    )
    for row in database.export_flows(analysis_id):
        writer.writerow(
            [
                row["row_index"],
                _csv_cell(row["flow_timestamp"]),
                _csv_cell(row["predicted_label"]),
                row["verdict"],
                f"{row['confidence']:.6f}",
                row["severity"],
                _csv_cell(row["ground_truth"]),
                CONFIDENCE_NOTE,
            ]
        )
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="analysis_{analysis_id}.csv"'},
    )


@app.get("/api/alerts")
def alerts(limit: int = Query(100, ge=1, le=500)):
    return {
        "confidence_note": CONFIDENCE_NOTE,
        "items": database.list_alerts(limit),
    }
