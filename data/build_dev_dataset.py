"""
Gera data/processed/dev_dataset.csv a partir dos exemplos em data/raw/dev_samples.py.
Executa o mesmo extrator usado em produção para garantir consistência.

Uso:
    PYTHONPATH=src python3 data/build_dev_dataset.py
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_review_gate.diff_parser import parse_unified_diff
from security_review_gate.features import extract_features

sys.path.insert(0, str(Path(__file__).parent / "raw"))
from dev_samples import SAMPLES

OUTPUT = Path(__file__).parent / "processed" / "dev_dataset.csv"


def build() -> None:
    rows = []
    for sample in SAMPLES:
        parsed = parse_unified_diff(sample["diff"])
        features = extract_features(parsed)
        row = {"id": sample["id"], "label": sample["label"], **features.to_dict()}
        rows.append(row)

    fieldnames = list(rows[0].keys())
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    positives = sum(r["label"] for r in rows)
    print(f"Escrito: {OUTPUT}")
    print(f"Total: {len(rows)} exemplos — {positives} positivos / {len(rows) - positives} negativos")


if __name__ == "__main__":
    build()
