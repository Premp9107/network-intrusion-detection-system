# Aegis NIDS

Aegis is an offline, AI-assisted network intrusion detection system for flow records. It trains a Random Forest and a Logistic Regression model, keeps the one with the higher held-out macro F1, and classifies uploaded CSV files through a FastAPI backend and a React dashboard.

This is a university and portfolio project. It analyzes files that already contain flow features. It does not capture packets, monitor a live interface, or block traffic.

## Problem statement

Security operations teams review large tables of network flows. Manual review does not scale, and a demo that only shows hardcoded alerts does not demonstrate detection. Aegis applies a reproducible scikit-learn pipeline to CIC-IDS2017-compatible columns, stores each run, and separates operational "flagged share" from the model's held-out precision, recall, and F1.

## Features

- Random Forest and Logistic Regression, compared on one stratified train/test split (`test_size=0.25`, `random_state=42`)
- Held-out accuracy, macro and weighted precision, recall, and F1, plus a confusion matrix and classification report
- Metrics are written by the training script from scikit-learn. The UI reads that file and does not invent scores
- Joblib bundle containing the selected model and the training-set imputer and scaler
- CSV upload with extension, size, encoding, schema, and numeric checks
- Benign versus malicious verdicts, attack category labels, and estimated class probabilities
- Dashboard, flow inspection, result export, sample download, and analysis history
- Health endpoint and interactive API docs

## Architecture

```
React dashboard  --HTTP /api-->  FastAPI
                                   |- CSV validation
                                   |- saved median imputer + standard scaler
                                   |- scikit-learn classifier
                                   |- SQLite (analyses, flows, alerts)
```

The frontend and backend are separate apps. Uploaded files are read in memory. The API never uses the client filename as a filesystem path and never executes an upload.

Preprocessing at prediction time is the preprocessor saved during training: column medians, then a standard scaler, both fit on the training split only.

## Technologies

- Backend: Python, FastAPI, pandas, NumPy, scikit-learn, Joblib, SQLite
- Frontend: React, Vite, JavaScript, Tailwind CSS, Recharts, Lucide

## Dataset

`backend/data/sample_traffic.csv` is a 1,200-row synthetic demonstration set (200 rows for each of BENIGN, DoS, DDoS, PortScan, Brute Force, and Web Attack). Classes overlap on purpose. The generator is not a packet simulator and it is not the CIC-IDS2017 corpus.

A compatible CSV must include these columns. Names are matched after trimming whitespace, ignoring case:

`Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd Packets`, `Total Length of Bwd Packets`, `Fwd Packet Length Mean`, `Bwd Packet Length Mean`, `Flow Bytes/s`, `Flow Packets/s`, `Flow IAT Mean`, `Fwd IAT Mean`, `Bwd IAT Mean`, `Fwd Packets/s`, `Bwd Packets/s`, `Packet Length Mean`, `Packet Length Std`, `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `ACK Flag Count`, `Down/Up Ratio`, `Average Packet Size`, `Init_Win_bytes_forward`, `Init_Win_bytes_backward`, `Active Mean`, `Idle Mean`

`Label` is required for training and optional for analysis. `Timestamp` is displayed when present. Other columns are ignored.

To train on a real CIC-IDS2017 extract, first cut it down to the columns above and at most 200 MB:

```python
import pandas as pd

needed = {
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd IAT Mean", "Bwd IAT Mean", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Mean",
    "Packet Length Std", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "ACK Flag Count", "Down/Up Ratio", "Average Packet Size", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "Active Mean", "Idle Mean", "Label",
}
frame = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
frame.columns = [column.strip() for column in frame.columns]
frame[list(needed)].head(20000).to_csv("subset.csv", index=False)
```

Scores on a real capture are only meaningful after you retrain on that data. The bundled model has only seen the synthetic file.

## Installation

From the project root:

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd frontend
npm install
```

macOS or Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
cd frontend
npm install
```

Copy `.env.example` to `.env` if you want to change the host, port, upload limit, or CORS origins. The defaults bind the API to `127.0.0.1:8000` and let the Vite dev server proxy `/api`.

## Train the model

From `backend`:

```powershell
python train.py
```

That regenerates the synthetic sample, fits both models, writes `backend/models/nids_bundle.joblib` and `backend/models/metrics.json`, and prints the held-out scores. To train on another compatible file:

```powershell
python train.py --data C:\path\to\subset.csv
```

The API also trains the bundled sample on startup if the model files are missing.

## Run the backend

From `backend`, with the virtual environment active:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Run the frontend

From `frontend`, in a second terminal:

```powershell
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173).

## API endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Process and model status. `live_capture` is always false |
| GET | `/api/model/metrics` | Held-out comparison, confusion matrix, classification report |
| GET | `/api/dashboard` | Aggregate counts from stored analyses |
| GET | `/api/sample` | Download the synthetic CSV |
| GET | `/api/analyses` | Analysis history |
| POST | `/api/analyses` | Upload a CSV and classify it |
| POST | `/api/analyses/sample` | Classify the bundled sample |
| GET | `/api/analyses/{id}` | One result summary |
| GET | `/api/analyses/{id}/flows` | Paginated flow decisions |
| GET | `/api/analyses/{id}/export` | Download decisions as CSV |
| GET | `/api/alerts` | Malicious decisions across runs |

Upload errors:

- `400` for a non-CSV extension, empty file, binary content, or a file that is not valid UTF-8 CSV
- `413` when the file is larger than 10 MB
- `422` when required columns are missing, non-numeric, or the row limit is exceeded

`confidence` on each flow is the maximum `predict_proba` value for the predicted class. It is a model estimate, not a calibrated certainty and not proof of an attack.

`detection_rate` is the share of flows in a file whose predicted class is not `BENIGN`. Model recall is reported only with the held-out test metrics.

## Screenshots

The running UI is a dark navy dashboard with cyan accents:

1. Dashboard — flow totals, flagged share, attack mix, and held-out F1
2. Traffic Analysis — confidence buckets and a per-flow estimate
3. Upload Dataset — CSV validation and the bundled sample
4. Detection Results — verdicts, categories, and CSV export
5. Model Performance — both models, confusion matrix, and classification report
6. Alert History — malicious decisions and earlier runs
7. About Project — scope and limitations

Capture these from the local app and place them in `docs/screenshots/` if you want images in the repository. They are not required to run the project.

## Checks

From `backend`, with dependencies installed:

```powershell
python self_check.py
```

The script retrains the sample, checks that prediction uses the saved training preprocessor, recomputes the stored test metrics with scikit-learn, and calls every API endpoint, including malformed, binary, traversal-named, and oversized uploads.

## Limitations

- Offline CSV scoring only. There is no packet capture or streaming sensor.
- The default model is trained on synthetic data. Do not quote its scores as CIC-IDS2017 performance.
- In-file label agreement can include rows the model trained on. Held-out metrics are on the Model Performance page.
- The negative class is the exact label `BENIGN`.
- Uploads are capped at 10 MB and 25,000 rows. Training files are capped at 200 MB.
- There is no authentication, multi-user separation, or encrypted model store. Keep the service on localhost.
- Probabilities are not calibrated.

## Future improvements

- Train and evaluate on an official CIC-IDS2017 subset, with class weighting for the real imbalance
- Probability calibration and a threshold chosen on a validation split
- Zeek or CICFlowMeter export as the file source, still without pretending the web app is a live sensor
- Authentication and a read-only demo mode before any non-local deployment
