"""
Treina e avalia o modelo de priorização de revisão de segurança.

Dataset pequeno (dev): usa validação cruzada estratificada para métricas
mais estáveis do que um único split treino/teste.
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    average_precision_score,
    precision_recall_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .baseline import baseline_decision
from .dataset import Dataset, load_dataset
from .features import DiffFeatures

DEV_DATASET = Path(__file__).parent.parent.parent / "data" / "processed" / "dev_dataset.csv"
MODEL_OUT = Path(__file__).parent.parent.parent / "models" / "review_gate.joblib"
META_OUT = Path(__file__).parent.parent.parent / "models" / "metadata.json"


def _build_pipeline() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced")),
    ])


def _baseline_predictions(dataset: Dataset) -> np.ndarray:
    preds = []
    for row in dataset.X:
        features = DiffFeatures(**dict(zip(dataset.feature_names, (int(v) for v in row))))
        decision = baseline_decision(features)
        preds.append(1 if decision.level in ("medium", "high") else 0)
    return np.array(preds)


def _recall_at_top_k(y_true: np.ndarray, scores: np.ndarray, k: float = 0.10) -> float:
    n_top = max(1, int(len(scores) * k))
    top_idx = np.argsort(scores)[::-1][:n_top]
    positives_in_top = y_true[top_idx].sum()
    total_positives = y_true.sum()
    return float(positives_in_top / total_positives) if total_positives else 0.0


def train(dataset_path: Path = DEV_DATASET) -> None:
    dataset = load_dataset(dataset_path)
    n, n_pos = len(dataset.y), dataset.y.sum()
    print(f"Dataset: {n} exemplos — {n_pos} positivos / {n - n_pos} negativos")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    pipe = _build_pipeline()

    # probabilidades e predições via CV (cada exemplo é predito uma vez)
    prob_cv = cross_val_predict(pipe, dataset.X, dataset.y, cv=cv, method="predict_proba")[:, 1]
    pred_cv = (prob_cv >= 0.5).astype(int)

    pr_auc = average_precision_score(dataset.y, prob_cv)
    recall_top10 = _recall_at_top_k(dataset.y, prob_cv, k=0.10)

    print("\n── Modelo (validação cruzada 5-fold) ──────────────────")
    print(classification_report(dataset.y, pred_cv, target_names=["low", "high"], digits=3))
    print(f"PR-AUC:          {pr_auc:.3f}")
    print(f"Recall@Top10%:   {recall_top10:.3f}")

    # baseline para comparação
    baseline_pred = _baseline_predictions(dataset)
    baseline_pr_auc = average_precision_score(dataset.y, baseline_pred.astype(float))
    baseline_recall_top10 = _recall_at_top_k(dataset.y, baseline_pred.astype(float), k=0.10)

    print("\n── Baseline determinístico ────────────────────────────")
    print(classification_report(dataset.y, baseline_pred, target_names=["low", "high"], digits=3))
    print(f"PR-AUC:          {baseline_pr_auc:.3f}")
    print(f"Recall@Top10%:   {baseline_recall_top10:.3f}")

    # treina modelo final em todos os dados e salva
    pipe.fit(dataset.X, dataset.y)
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, MODEL_OUT)

    coef = pipe.named_steps["clf"].coef_[0]
    top_features = sorted(zip(dataset.feature_names, coef), key=lambda x: abs(x[1]), reverse=True)

    meta = {
        "dataset": str(dataset_path),
        "n_samples": int(n),
        "n_positives": int(n_pos),
        "features": dataset.feature_names,
        "evaluation": "5-fold stratified CV",
        "pr_auc_cv": round(pr_auc, 4),
        "recall_top10_cv": round(recall_top10, 4),
        "pr_auc_baseline": round(baseline_pr_auc, 4),
        "recall_top10_baseline": round(baseline_recall_top10, 4),
        "top_features": [{"feature": f, "coef": round(float(c), 4)} for f, c in top_features[:8]],
        "warning": "Métricas em dataset de desenvolvimento (25 exemplos). Não usar como referência de produção.",
    }
    META_OUT.write_text(json.dumps(meta, ensure_ascii=False, indent=2))

    print(f"\nModelo salvo: {MODEL_OUT}")
    print(f"Metadados:    {META_OUT}")
    print("\nPesos por feature (top 8):")
    for feat, coef_val in top_features[:8]:
        bar = "+" * int(abs(coef_val) * 3) if coef_val > 0 else "-" * int(abs(coef_val) * 3)
        print(f"  {feat:<30} {coef_val:+.3f}  {bar}")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEV_DATASET
    train(path)
