"""Ferramentas do agente + guarda de allowlist.

GUARDA DE SEGURANCA: `http_request` so atinge hosts explicitamente autorizados.
Qualquer tentativa de tocar outro host e bloqueada e devolvida ao modelo como
erro. Isso mantem o agente confinado ao laboratorio (alvos locais).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

FLAG_RE = re.compile(r"flag\{[^}]{1,200}\}", re.I)


@dataclass
class ToolContext:
    allowed_hosts: set[str]
    session: requests.Session = field(default_factory=requests.Session)
    found_flag: str | None = None
    max_body_chars: int = 4000
    seen_text: str = ""  # acumula tudo que ja foi observado (grounding anti-alucinacao)


def _host_allowed(url: str, allowed: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {h.lower() for h in allowed}


def http_request(
    ctx: ToolContext,
    method: str = "GET",
    url: str = "",
    data: dict | None = None,
    headers: dict | None = None,
) -> dict:
    """Faz uma requisicao HTTP ao alvo. Cookies persistem entre chamadas."""
    if not _host_allowed(url, ctx.allowed_hosts):
        return {
            "error": "host bloqueado pela allowlist do laboratorio",
            "hosts_permitidos": sorted(ctx.allowed_hosts),
        }
    try:
        resp = ctx.session.request(
            method.upper(),
            url,
            data=data or None,
            headers=headers or None,
            timeout=15,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return {"error": f"falha na requisicao: {exc}"}

    ctx.seen_text += "\n" + resp.text  # registra o que foi observado (grounding)
    truncated = len(resp.text) > ctx.max_body_chars
    body = resp.text[: ctx.max_body_chars] + ("\n...[truncado]" if truncated else "")
    interesting = ("Content-Type", "Set-Cookie", "Location", "Server")
    return {
        "status": resp.status_code,
        "url_final": resp.url,
        "headers": {k: resp.headers[k] for k in interesting if k in resp.headers},
        "body": body,
    }


def submit_flag(ctx: ToolContext, flag: str = "") -> dict:
    """Declara a flag encontrada e encerra o desafio.

    Guarda anti-alucinacao: so aceita uma flag que REALMENTE apareceu em alguma
    resposta ja observada. Flag inventada e rejeitada — o agente tem que continuar
    investigando (ex: enumerar ids num IDOR) ate ver a flag de verdade.
    """
    match = FLAG_RE.search(flag or "")
    if not match:
        return {"ok": False, "message": "nao parece uma flag valida (formato flag{...})"}
    candidate = match.group(0)
    if candidate not in ctx.seen_text:
        return {
            "ok": False,
            "message": (
                "essa flag NAO apareceu em nenhuma resposta observada. Nao invente "
                "flags. Continue investigando o alvo ate ver flag{...} de verdade "
                "no corpo de uma resposta."
            ),
        }
    ctx.found_flag = candidate
    return {"ok": True, "message": "flag registrada"}


# Esquemas no formato function-calling (compativel com Ollama/OpenAI).
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Faz uma requisicao HTTP ao alvo do desafio. Use para explorar "
                "paginas, enviar formularios e testar injecoes. Cookies de sessao "
                "persistem automaticamente entre chamadas."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "url": {
                        "type": "string",
                        "description": "URL completa, ex: http://127.0.0.1:8000/login",
                    },
                    "data": {
                        "type": "object",
                        "description": "Campos de formulario (form-urlencoded), ex: {'username': \"' OR '1'='1\"}",
                    },
                    "headers": {"type": "object", "description": "Cabecalhos HTTP opcionais"},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_flag",
            "description": "Submete a flag (formato flag{...}) para encerrar o desafio.",
            "parameters": {
                "type": "object",
                "properties": {"flag": {"type": "string"}},
                "required": ["flag"],
            },
        },
    },
]

# Quais argumentos cada ferramenta aceita (filtra kwargs inesperados do modelo).
_ALLOWED_ARGS = {
    "http_request": {"method", "url", "data", "headers"},
    "submit_flag": {"flag"},
}


def dispatch(ctx: ToolContext, name: str, args: dict) -> dict:
    """Executa a ferramenta pelo nome, filtrando argumentos validos."""
    fns = {"http_request": http_request, "submit_flag": submit_flag}
    fn = fns.get(name)
    if fn is None:
        return {"error": f"ferramenta desconhecida: {name}"}
    clean = {k: v for k, v in (args or {}).items() if k in _ALLOWED_ARGS[name]}
    return fn(ctx, **clean)
