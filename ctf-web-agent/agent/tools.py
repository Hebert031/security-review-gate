"""Ferramentas do agente + guarda de allowlist.

GUARDA DE SEGURANCA: `http_request` so atinge hosts explicitamente autorizados.
Qualquer tentativa de tocar outro host e bloqueada e devolvida ao modelo como
erro. Isso mantem o agente confinado ao laboratorio (alvos locais).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

FLAG_RE = re.compile(r"flag\{[^}]{1,200}\}", re.I)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


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
        # Segue redirects MANUALMENTE, revalidando o allowlist a cada salto. Isso
        # imita uma defesa anti-SSRF de verdade: um open redirect nao basta para
        # alcancar um host bloqueado pelo cliente.
        resp = ctx.session.request(
            method.upper(),
            url,
            data=data or None,
            headers=headers or None,
            timeout=15,
            allow_redirects=False,
        )
        hops = 0
        while resp.is_redirect and hops < 5:
            nxt = requests.compat.urljoin(resp.url, resp.headers.get("Location", ""))
            if not _host_allowed(nxt, ctx.allowed_hosts):
                return {
                    "status": resp.status_code,
                    "url_final": resp.url,
                    "redirect_bloqueado": nxt,
                    "body": (
                        f"redirect para '{nxt}', cujo host esta FORA do allowlist do "
                        "laboratorio — nao seguido. (Seu proprio cliente nao alcanca "
                        "hosts internos so por causa de um open redirect.)"
                    ),
                }
            resp = ctx.session.request("GET", nxt, timeout=15, allow_redirects=False)
            hops += 1
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


def b64_decode(ctx: ToolContext, text: str = "") -> dict:
    """Decodifica base64/base64url (tolera falta de padding). Util para inspecionar
    cookies de sessao e outros valores codificados."""
    try:
        raw = _b64url_dec((text or "").strip())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"falha ao decodificar base64: {exc}"}
    return {"decoded": raw.decode("utf-8", "replace")}


def b64_encode(ctx: ToolContext, text: str = "") -> dict:
    """Codifica um texto em base64url (sem padding). Util para reempacotar um
    cookie/sessao depois de adultera-lo."""
    return {"encoded": _b64url((text or "").encode("utf-8"))}


def jwt_decode(ctx: ToolContext, token: str = "") -> dict:
    """Decodifica um JWT (sem verificar assinatura) e mostra header + payload."""
    parts = (token or "").split(".")
    if len(parts) < 2:
        return {"error": "nao parece um JWT (espera 3 partes separadas por ponto)"}
    try:
        header = json.loads(_b64url_dec(parts[0]))
        payload = json.loads(_b64url_dec(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        return {"error": f"falha ao decodificar: {exc}"}
    return {"header": header, "payload": payload}


def jwt_forge(ctx: ToolContext, payload: dict | None = None, alg: str = "none") -> dict:
    """Forja um JWT com o payload dado. Por padrao alg='none' (sem assinatura),
    util contra verificadores que aceitam tokens nao assinados."""
    if not isinstance(payload, dict) or not payload:
        return {"error": "informe 'payload' como objeto, ex: {'user':'admin','role':'admin'}"}
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = ""  # alg=none -> assinatura vazia
    token = f"{h}.{p}.{sig}"
    return {"token": token, "uso": "envie em header Authorization: Bearer <token>"}


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
            "name": "b64_decode",
            "description": (
                "Decodifica um valor base64/base64url para texto. Use para "
                "inspecionar o conteudo de um cookie de sessao ou token codificado."
            ),
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string", "description": "o valor base64"}},
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "b64_encode",
            "description": (
                "Codifica um texto em base64url (sem padding). Use para reempacotar "
                "um cookie/sessao depois de editar (ex: trocar role para admin)."
            ),
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string", "description": "o texto a codificar"}},
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "jwt_decode",
            "description": (
                "Decodifica um token JWT (sem verificar assinatura) e mostra o "
                "header e o payload. Use para inspecionar um token recebido e "
                "descobrir os campos (ex: role)."
            ),
            "parameters": {
                "type": "object",
                "properties": {"token": {"type": "string", "description": "o JWT (x.y.z)"}},
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "jwt_forge",
            "description": (
                "Forja um JWT com o payload que voce escolher, usando alg='none' "
                "(sem assinatura). Util quando o servidor aceita tokens nao "
                "assinados: forje {'role':'admin'} e use-o para escalar privilegio."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "claims do token, ex: {'user':'admin','role':'admin'}",
                    },
                    "alg": {"type": "string", "description": "algoritmo; use 'none'"},
                },
                "required": ["payload"],
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
    "b64_decode": {"text"},
    "b64_encode": {"text"},
    "jwt_decode": {"token"},
    "jwt_forge": {"payload", "alg"},
    "submit_flag": {"flag"},
}


def dispatch(ctx: ToolContext, name: str, args: dict) -> dict:
    """Executa a ferramenta pelo nome, filtrando argumentos validos."""
    fns = {
        "http_request": http_request,
        "b64_decode": b64_decode,
        "b64_encode": b64_encode,
        "jwt_decode": jwt_decode,
        "jwt_forge": jwt_forge,
        "submit_flag": submit_flag,
    }
    fn = fns.get(name)
    if fn is None:
        return {"error": f"ferramenta desconhecida: {name}"}
    clean = {k: v for k, v in (args or {}).items() if k in _ALLOWED_ARGS[name]}
    return fn(ctx, **clean)
