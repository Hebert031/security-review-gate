"""Loop ReAct: o LLM observa a resposta, raciocina e age via ferramentas
ate capturar a flag ou esgotar os passos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

import requests

from . import ui
from .llm import LLMClient
from .playbooks import SIGNALS
from .tools import ToolContext, TOOL_SCHEMAS, dispatch


STALL_LIMIT = 4  # passos seguidos sem acao antes de declarar o agente travado
CHAT_RETRIES = 2  # tentativas da chamada ao LLM antes de desistir do passo (timeout etc)


def _chat_with_retry(llm: LLMClient, messages: list[dict], on_event: Callable[[str], None]):
    """Chama o LLM tolerando falhas transitorias de rede (ex: ReadTimeout quando o
    modelo degenera numa geracao longa). Reerguer a excecao so apos esgotar."""
    for attempt in range(1, CHAT_RETRIES + 1):
        try:
            with ui.Spinner("consultando o modelo…"):
                return llm.chat(messages, TOOL_SCHEMAS)
        except requests.RequestException as exc:
            if attempt >= CHAT_RETRIES:
                raise
            on_event(ui.warn(f"modelo nao respondeu ({type(exc).__name__}); tentando de novo..."))


@dataclass
class AgentResult:
    success: bool
    flag: str | None
    steps: int

SYSTEM = (
    "Voce e um agente de seguranca ofensiva resolvendo um desafio CTF de Web em "
    "um laboratorio ISOLADO e AUTORIZADO. Objetivo unico: encontrar a flag, no "
    "formato flag{...}.\n"
    "\n"
    "METODO (loop): explore -> reconheca a tecnica pelos SINAIS -> peca a receita "
    "com playbook(<tecnica>) -> execute -> observe -> repita.\n"
    "\n"
    "Disciplina:\n"
    "- ADAPTE a tecnica ao alvo; nao aplique um roteiro cego. Primeiro entenda a "
    "estrutura do app (pagina inicial, formularios, parametros, rotas) com "
    "http_request, depois escolha o ataque que casa com o que voce VE.\n"
    "- Use o mapa de SINAIS abaixo para identificar a tecnica provavel. Em seguida "
    "chame a ferramenta playbook(<tecnica>) para receber a RECEITA concreta (payloads, "
    "como provar, como escalar). NAO adivinhe a mecanica de cabeca: peca o playbook.\n"
    "- Leia a pagina inicial em busca de DICAS: credenciais de demonstracao "
    "(ex: 'guest / guest'), caminhos internos e nomes (vhost, campo, variavel) "
    "costumam estar escritos no HTML/comentarios. Use-as.\n"
    "- Se um endpoint retorna 404 repetidamente, ele NAO existe neste alvo: pare de "
    "insistir e mude de tecnica. Repetir requisicao que ja falhou nao traz nada.\n"
    "- PERSISTENCIA: se um payload falhar, tente OUTRA variacao da MESMA tecnica "
    "(o playbook lista varias) antes de trocar de abordagem. Nunca repita exatamente "
    "a mesma requisicao que ja falhou.\n"
    "- Reuse a sessao: cookies de login persistem entre chamadas automaticamente.\n"
    "- URL-encode quando precisar (espaco, ;, &, |, aspas, <, > na querystring).\n"
    "- Leia o corpo das respostas com atencao; a flag costuma aparecer apos um login "
    "bem-sucedido ou ao acessar um recurso restrito.\n"
    "- NUNCA invente uma flag. So chame submit_flag com um texto flag{...} que "
    "apareceu LITERALMENTE no corpo de uma resposta que voce recebeu. Ao ver flag{...} "
    "numa resposta, chame submit_flag imediatamente.\n"
    "- Antes de cada acao, explique em uma frase curta o que vai tentar e por que.\n"
    "\n"
    + SIGNALS
)


def _fmt_args(args: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


def _to_tool_content(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False)[:4500]


def run_agent(
    llm: LLMClient,
    base_url: str,
    allowed_hosts: set[str],
    max_steps: int = 15,
    on_event: Callable[[str], None] = print,
) -> AgentResult:
    """Roda o agente contra `base_url`. Retorna o resultado (flag + passos)."""
    ctx = ToolContext(allowed_hosts=allowed_hosts)
    messages = [
        {"role": "system", "content": SYSTEM},
        {
            "role": "user",
            "content": (
                f"O desafio esta hospedado em {base_url}. Comece explorando a "
                "pagina inicial e capture a flag."
            ),
        },
    ]

    stalls = 0  # passos seguidos sem nenhuma chamada de ferramenta
    for step in range(1, max_steps + 1):
        try:
            resp = _chat_with_retry(llm, messages, on_event)
        except requests.RequestException as exc:
            # Timeout/erro de rede persistente no LLM: aborta SO esta tentativa
            # (a gincana segue; o ATTEMPTS do placar ainda da nova chance ao nivel).
            on_event(ui.warn(f"modelo indisponivel ({type(exc).__name__}); abortando a tentativa."))
            return AgentResult(success=False, flag=None, steps=step)

        if resp.content.strip():
            on_event(ui.step(step, resp.content.strip()))

        assistant_msg: dict = {"role": "assistant", "content": resp.content}
        if resp.tool_calls:
            assistant_msg["tool_calls"] = [
                {"function": {"name": tc["name"], "arguments": tc["arguments"]}}
                for tc in resp.tool_calls
            ]
        messages.append(assistant_msg)

        if not resp.tool_calls:
            # O modelo 7B as vezes degenera (cospe texto sem chamar ferramenta).
            # Aborta cedo em vez de queimar todos os passos a toa.
            stalls += 1
            if stalls >= STALL_LIMIT:
                on_event(ui.warn("agente travou (varios passos sem acao); abortando a tentativa."))
                return AgentResult(success=False, flag=None, steps=step)
            messages.append(
                {
                    "role": "user",
                    "content": "Aja agora: use http_request, ou submit_flag se ja tem a flag.",
                }
            )
            continue

        stalls = 0
        for tc in resp.tool_calls:
            name, args = tc["name"], tc["arguments"]
            on_event(ui.tool_call(name, _fmt_args(args)))
            result = dispatch(ctx, name, args)
            preview = (
                result.get("body")
                or result.get("playbook")
                or result.get("token")
                or result.get("decoded")
                or result.get("encoded")
                or result.get("payload")
                or result.get("message")
                or result.get("error", "")
            )
            on_event(ui.tool_result(str(preview)[:160].replace(chr(10), " ")))
            messages.append({"role": "tool", "content": _to_tool_content(result)})

            if name == "submit_flag" and ctx.found_flag:
                on_event(ui.flag_capture(ctx.found_flag, step))
                return AgentResult(success=True, flag=ctx.found_flag, steps=step)

    on_event(ui.color("\n❌ Limite de passos atingido sem capturar a flag.", ui.RED))
    return AgentResult(success=False, flag=None, steps=max_steps)
