"""Train both classifiers and save the stronger held-out model.

Examples:
    python train.py
    python train.py --data C:\\captures\\subset.csv
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import CLI_MAX_BYTES, SAMPLE_CSV
from pipeline import DatasetError, train_csv, train_default, write_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Aegis NIDS classifiers.")
    parser.add_argument(
        "--data",
        type=Path,
        help="CIC-IDS2017-compatible CSV. Omit this to regenerate and use the synthetic sample.",
    )
    args = parser.parse_args()
    try:
        if args.data is None:
            write_sample(SAMPLE_CSV)
            metrics = train_default()
        else:
            path = args.data.resolve()
            if not path.is_file():
                raise SystemExit(f"Training file not found: {path}")
            if path.stat().st_size > CLI_MAX_BYTES:
                raise SystemExit("Training CSV exceeds 200 MB. Export a smaller subset and retry.")
            kind = "synthetic_demonstration" if path == SAMPLE_CSV.resolve() else "external_csv"
            metrics = train_csv(path, kind)
    except DatasetError as exc:
        raise SystemExit(str(exc)) from exc

    selected = metrics["selected_model"]
    test = metrics["models"][selected]["test"]
    print(f"Selected model: {selected}")
    print(f"Held-out accuracy: {test['accuracy']:.4f}")
    print(f"Held-out precision (macro): {test['precision_macro']:.4f}")
    print(f"Held-out recall (macro): {test['recall_macro']:.4f}")
    print(f"Held-out F1 (macro): {test['f1_macro']:.4f}")
    print(f"Test rows: {metrics['n_test']}  Train rows: {metrics['n_train']}")
    print("Metrics written to backend/models/metrics.json")


if __name__ == "__main__":
    main()
