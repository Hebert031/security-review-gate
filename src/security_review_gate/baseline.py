from dataclasses import dataclass

from .features import DiffFeatures


@dataclass(frozen=True)
class ReviewDecision:
    score: int
    level: str
    signals: list[str]


def baseline_decision(features: DiffFeatures) -> ReviewDecision:
    """Calcula uma referência explicável; não confirma vulnerabilidades."""
    score = 0
    signals: list[str] = []

    weighted_signals = [
        (features.security_disable_signals, 30, "controle de segurança possivelmente desabilitado"),
        (features.secret_signals, 25, "possível material secreto adicionado"),
        (features.command_signals, 18, "execução dinâmica de comandos alterada"),
        (features.auth_signals, 15, "autenticação ou sessão alterada"),
        (features.sensitive_paths, 14, "arquivo sensível de segurança alterado"),
        (features.crypto_signals, 12, "código criptográfico alterado"),
        (features.sql_signals, 10, "acesso a dados ou SQL alterado"),
        (features.input_signals, 8, "tratamento de entrada não confiável alterado"),
        (features.infrastructure_files, 8, "infraestrutura ou CI/CD alterado"),
        (features.dependency_files, 7, "dependências alteradas"),
        (features.binary_files, 7, "arquivo binário não inspecionável alterado"),
    ]

    for count, weight, reason in weighted_signals:
        if count:
            score += min(2, count) * weight
            signals.append(reason)

    if features.files_changed >= 10 or features.lines_added + features.lines_removed >= 500:
        score += 10
        signals.append("mudança ampla, com maior superfície para revisão")

    if score and features.test_files_changed == 0:
        score += 8
        signals.append("nenhum arquivo de teste alterado")
    elif features.test_files_changed:
        score = max(0, score - 5)

    score = min(100, score)
    level = "high" if score >= 55 else "medium" if score >= 25 else "low"
    return ReviewDecision(score=score, level=level, signals=signals[:6])
