"""SQLite storage for analysis runs, flow decisions, and alerts."""

import json
import sqlite3

from config import DATA_DIR, DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_filename TEXT NOT NULL,
    created_at TEXT NOT NULL,
    total_flows INTEGER NOT NULL,
    benign_count INTEGER NOT NULL,
    malicious_count INTEGER NOT NULL,
    detection_rate REAL NOT NULL,
    mean_confidence REAL NOT NULL,
    label_agreement REAL,
    attack_distribution TEXT NOT NULL,
    confidence_buckets TEXT NOT NULL,
    validation_report TEXT NOT NULL,
    model_name TEXT NOT NULL,
    training_source_kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL,
    row_index INTEGER NOT NULL,
    predicted_label TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    ground_truth TEXT,
    flow_timestamp TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);

CREATE INDEX IF NOT EXISTS idx_flows_analysis ON flows(analysis_id);
CREATE INDEX IF NOT EXISTS idx_flows_verdict ON flows(verdict);
"""


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def _analysis_from_row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    item = dict(row)
    item["attack_distribution"] = json.loads(item["attack_distribution"])
    item["confidence_buckets"] = json.loads(item["confidence_buckets"])
    item["validation_report"] = json.loads(item["validation_report"])
    return item


def save_analysis(summary: dict, flow_rows: list[dict]) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses (
                original_filename, created_at, total_flows, benign_count,
                malicious_count, detection_rate, mean_confidence, label_agreement,
                attack_distribution, confidence_buckets, validation_report,
                model_name, training_source_kind
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                summary["original_filename"],
                summary["created_at"],
                summary["total_flows"],
                summary["benign_count"],
                summary["malicious_count"],
                summary["detection_rate"],
                summary["mean_confidence"],
                summary["label_agreement"],
                json.dumps(summary["attack_distribution"]),
                json.dumps(summary["confidence_buckets"]),
                json.dumps(summary["validation_report"]),
                summary["model_name"],
                summary["training_source_kind"],
            ),
        )
        analysis_id = int(cursor.lastrowid)
        conn.executemany(
            """
            INSERT INTO flows (
                analysis_id, row_index, predicted_label, verdict, confidence,
                severity, ground_truth, flow_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    analysis_id,
                    row["row_index"],
                    row["predicted_label"],
                    row["verdict"],
                    row["confidence"],
                    row["severity"],
                    row["ground_truth"],
                    row["flow_timestamp"],
                )
                for row in flow_rows
            ],
        )
        return analysis_id


def list_analyses(limit: int = 50) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, original_filename, created_at, total_flows, benign_count,
                   malicious_count, detection_rate, mean_confidence, label_agreement,
                   model_name, training_source_kind
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_analysis(analysis_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    return _analysis_from_row(row)


def list_flows(analysis_id: int, page: int, page_size: int, verdict: str, label: str) -> dict:
    filters = ["analysis_id = ?"]
    params: list = [analysis_id]
    if verdict:
        filters.append("verdict = ?")
        params.append(verdict)
    if label:
        filters.append("predicted_label = ?")
        params.append(label)
    where = " AND ".join(filters)
    offset = (page - 1) * page_size
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM flows WHERE {where}", params).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT row_index, predicted_label, verdict, confidence, severity,
                   ground_truth, flow_timestamp
            FROM flows
            WHERE {where}
            ORDER BY row_index ASC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()
    return {
        "page": page,
        "page_size": page_size,
        "total": int(total),
        "items": [dict(row) for row in rows],
    }


def export_flows(analysis_id: int) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT row_index, flow_timestamp, predicted_label, verdict, confidence,
                   severity, ground_truth
            FROM flows
            WHERE analysis_id = ?
            ORDER BY row_index ASC
            """,
            (analysis_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_alerts(limit: int) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT f.row_index, f.predicted_label, f.confidence, f.severity,
                   f.ground_truth, f.flow_timestamp, a.id AS analysis_id,
                   a.original_filename, a.created_at
            FROM flows f
            JOIN analyses a ON a.id = f.analysis_id
            WHERE f.verdict = 'MALICIOUS'
            ORDER BY f.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def dashboard_stats() -> dict:
    with connect() as conn:
        totals = conn.execute(
            """
            SELECT COALESCE(SUM(total_flows), 0) AS total_flows,
                   COALESCE(SUM(benign_count), 0) AS benign_count,
                   COALESCE(SUM(malicious_count), 0) AS malicious_count,
                   COUNT(*) AS analysis_count
            FROM analyses
            """
        ).fetchone()
        distributions = conn.execute("SELECT attack_distribution FROM analyses").fetchall()
        recent_alerts = conn.execute(
            """
            SELECT f.row_index, f.predicted_label, f.confidence, f.severity,
                   a.id AS analysis_id, a.original_filename, a.created_at
            FROM flows f
            JOIN analyses a ON a.id = f.analysis_id
            WHERE f.verdict = 'MALICIOUS'
            ORDER BY f.id DESC
            LIMIT 8
            """
        ).fetchall()
        recent_analyses = conn.execute(
            """
            SELECT id, original_filename, created_at, total_flows, benign_count,
                   malicious_count, detection_rate, model_name
            FROM analyses
            ORDER BY id DESC
            LIMIT 6
            """
        ).fetchall()

    combined: dict[str, int] = {}
    for row in distributions:
        parsed = json.loads(row["attack_distribution"])
        pairs = parsed.items() if isinstance(parsed, dict) else ((item["label"], item["count"]) for item in parsed)
        for label, count in pairs:
            combined[label] = combined.get(label, 0) + int(count)

    total_flows = int(totals["total_flows"])
    malicious = int(totals["malicious_count"])
    return {
        "total_flows": total_flows,
        "benign_count": int(totals["benign_count"]),
        "malicious_count": malicious,
        "analysis_count": int(totals["analysis_count"]),
        "detection_rate": (malicious / total_flows) if total_flows else 0.0,
        "attack_distribution": [
            {"label": label, "count": count}
            for label, count in sorted(combined.items(), key=lambda item: (-item[1], item[0]))
        ],
        "recent_alerts": [dict(row) for row in recent_alerts],
        "recent_analyses": [dict(row) for row in recent_analyses],
    }
