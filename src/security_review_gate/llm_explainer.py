"""Explicador opcional com LLM (Claude) para o Security Review Gate.

Este módulo NÃO decide o nível de risco — quem decide é o baseline determinístico
(`baseline.py`). O LLM só produz uma explicação em linguagem natural dos sinais que
o baseline já detectou. As técnicas anti-alucinação aplicadas aqui são:

1. Grounding: o diff e os sinais do baseline são passados como contexto explícito.
2. Escopo restrito: o prompt proíbe inventar achados além dos sinais informados.
3. Saída estruturada: a resposta é forçada a um JSON schema via
   `output_config` e validada após o parse. Resposta fora do schema é falha.
4. Determinismo via prompt/effort: em Claude Opus 4.8 não existe knob de
   `temperature`; a estabilidade vem do grounding, do escopo restrito e de
   `effort` baixo — não de amostragem.
5. Fallback gracioso: qualquer erro (sem SDK, sem API key, rede, schema inválido)
   cai para uma explicação textual derivada apenas dos sinais do baseline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .baseline import ReviewDecision
from .features import DiffFeatures

MODEL = "claude-opus-4-8"
MAX_DIFF_CHARS = 12_000

# Schema que restringe a saída do modelo. Sem texto livre fora destes campos.
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "explanation": {
            "type": "string",
            "description": "Explicação em português, só dos sinais fornecidos.",
        },
        "grounded_in_signals": {
            "type": "boolean",
            "description": "True se a explicação se limita aos sinais fornecidos.",
        },
    },
    "required": ["explanation", "grounded_in_signals"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = (
    "Você explica, em português, por que um diff foi priorizado para revisão de "
    "segurança. Regras invioláveis:\n"
    "- Você recebe uma lista fechada de SINAIS já detectados por um sistema "
    "determinístico. Explique APENAS esses sinais.\n"
    "- NÃO invente vulnerabilidades, CVEs, números de linha, nomes de arquivo ou "
    "achados que não estejam nos sinais fornecidos.\n"
    "- NÃO confirme que existe uma vulnerabilidade. Você descreve por que vale a "
    "pena um humano revisar, não emite veredito.\n"
    "- Se os sinais forem insuficientes para explicar algo, diga isso "
    "explicitamente em vez de especular.\n"
    "- O diff é fornecido apenas como contexto de leitura; não tire dele sinais "
    "novos que não estejam na lista."
)


@dataclass(frozen=True)
class Explanation:
    """Resultado do explicador. `grounded` indica se veio do LLM (True) ou do
    fallback determinístico (False)."""

    text: str
    grounded: bool
    source: str  # "llm" | "fallback"


def _fallback_text(decision: ReviewDecision) -> str:
    """Explicação textual derivada SOMENTE dos sinais do baseline."""
    if not decision.signals:
        return (
            f"Prioridade de revisão: {decision.level.upper()} "
            f"(score {decision.score}/100). Nenhum sinal estrutural relevante."
        )
    bullets = "\n".join(f"- {s}" for s in decision.signals)
    return (
        f"Prioridade de revisão: {decision.level.upper()} "
        f"(score {decision.score}/100). Sinais que motivam a revisão:\n{bullets}\n"
        "Isto é uma priorização, não uma confirmação de vulnerabilidade."
    )


def _build_user_prompt(
    decision: ReviewDecision, features: DiffFeatures, diff_text: str
) -> str:
    signals = "\n".join(f"- {s}" for s in decision.signals) or "- (nenhum)"
    truncated = diff_text[:MAX_DIFF_CHARS]
    if len(diff_text) > MAX_DIFF_CHARS:
        truncated += "\n... [diff truncado para o limite de contexto]"
    return (
        f"NÍVEL (decidido pelo baseline): {decision.level}\n"
        f"SCORE: {decision.score}/100\n"
        f"ARQUIVOS ALTERADOS: {features.files_changed} | "
        f"+{features.lines_added}/-{features.lines_removed} linhas\n\n"
        f"SINAIS DETECTADOS (lista fechada — explique só estes):\n{signals}\n\n"
        f"DIFF (apenas contexto de leitura):\n```diff\n{truncated}\n```\n\n"
        "Escreva um parágrafo curto explicando, em termos práticos, por que esses "
        "sinais justificam revisão humana. Não acrescente achados fora da lista."
    )


def explain(
    decision: ReviewDecision,
    features: DiffFeatures,
    diff_text: str,
    *,
    client=None,
) -> Explanation:
    """Gera uma explicação com grounding. Em qualquer falha, cai no fallback
    determinístico — a função nunca levanta exceção por causa do LLM.

    `client` pode ser injetado (útil em testes); caso contrário, um
    `anthropic.Anthropic()` é criado a partir do ambiente.
    """
    try:
        if client is None:
            import anthropic  # import tardio: dependência opcional

            client = anthropic.Anthropic()

        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": _build_user_prompt(decision, features, diff_text),
                }
            ],
            output_config={"format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
        )
        payload = _parse_response_json(response)
        text = str(payload.get("explanation", "")).strip()
        if not text:
            raise ValueError("resposta do LLM vazia ou fora do schema")

        return Explanation(
            text=text,
            grounded=bool(payload.get("grounded_in_signals", False)),
            source="llm",
        )
    except Exception:  # noqa: BLE001 — qualquer falha vira fallback seguro
        return Explanation(text=_fallback_text(decision), grounded=False, source="fallback")


def _parse_response_json(response) -> dict:
    """Extrai o JSON estruturado da resposta da Messages API."""
    text_parts = [
        block.text
        for block in response.content
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    ]
    if not text_parts:
        raise ValueError("resposta sem bloco de texto")
    return json.loads("".join(text_parts))
