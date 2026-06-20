"""Carrega e valida o dataset para treino e avaliação."""

import csv
from dataclasses import dataclass
from pathlib import Path

import numpy as np

FEATURE_COLS = [
    "files_changed",
    "lines_added",
    "lines_removed",
    "test_files_changed",
    "sensitive_paths",
    "infrastructure_files",
    "dependency_files",
    "binary_files",
    "auth_signals",
    "crypto_signals",
    "sql_signals",
    "command_signals",
    "input_signals",
    "secret_signals",
    "security_disable_signals",
]


@dataclass
class Dataset:
    X: np.ndarray
    y: np.ndarray
    feature_names: list[str]
    ids: list[str]


def load_dataset(path: str | Path) -> Dataset:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset não encontrado: {path}")

    ids, labels, rows = [], [], []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            missing = [c for c in FEATURE_COLS if c not in row]
            if missing:
                raise ValueError(f"Colunas ausentes: {missing}")
            ids.append(row["id"])
            labels.append(int(row["label"]))
            rows.append([float(row[c]) for c in FEATURE_COLS])

    if not rows:
        raise ValueError("Dataset vazio.")

    return Dataset(
        X=np.array(rows, dtype=np.float32),
        y=np.array(labels, dtype=np.int32),
        feature_names=FEATURE_COLS,
        ids=ids,
    )
