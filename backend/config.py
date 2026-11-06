"""Runtime paths and limits. Environment variables override defaults."""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"
MODEL_DIR = BACKEND_DIR / "models"
SAMPLE_CSV = DATA_DIR / "sample_traffic.csv"
MODEL_PATH = MODEL_DIR / "nids_bundle.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"
DB_PATH = DATA_DIR / "nids.db"


def load_env_file() -> None:
    """Load the project .env without adding a dependency. Existing vars win."""
    env_path = PROJECT_DIR / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()

HOST = os.getenv("NIDS_HOST", "127.0.0.1")
PORT = int(os.getenv("NIDS_PORT", "8000"))
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "NIDS_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
MAX_UPLOAD_MB = int(os.getenv("NIDS_MAX_UPLOAD_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_ROWS = int(os.getenv("NIDS_MAX_ROWS", "25000"))
MAX_COLUMNS = 256
CLI_MAX_BYTES = 200 * 1024 * 1024
RANDOM_STATE = 42
TEST_SIZE = 0.25
