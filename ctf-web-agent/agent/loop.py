"""Loop ReAct: o LLM observa a resposta, raciocina e age via ferramentas
ate capturar a flag ou esgotar os passos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from .llm import LLMClient
from .tools import ToolContext, TOOL_SCHEMAS, dispatch


STALL_LIMIT = 4  # passos seguidos sem acao antes de declarar o agente travado


@dataclass
class AgentResult:
    success: bool
    flag: str | None
    steps: int

SYSTEM = (
    "Voce e um agente de seguranca ofensiva resolvendo um desafio CTF de Web em "
    "um laboratorio ISOLADO e AUTORIZADO. Objetivo unico: encontrar a flag, no "
    "formato flag{...}.\n"
    "Diretrizes:\n"
    "- ADAPTE a tecnica ao alvo; nao aplique um roteiro cego. Primeiro entenda a "
    "estrutura do app, depois escolha o ataque que casa com o que voce VE.\n"
    "- Se um endpoint retorna 404 repetidamente, ele NAO existe neste alvo: pare de "
    "insistir nele e mude de tecnica. Repetir requisicao que ja falhou nao traz nada.\n"
    "- Sinais de tecnica: formulario de login que separa admin de comum -> tente SQLi "
    "para virar admin; URL com id -> IDOR; endpoint que busca URL -> SSRF.\n"
    "- Explore o alvo com http_request: pagina inicial, formularios, parametros, rotas.\n"
    "- Para login, a vulnerabilidade provavel e SQL injection. A query do servidor "
    "costuma ser: WHERE username='<input>' AND password='<input>'. Para burlar, seu "
    "payload precisa FECHAR a aspa e COMENTAR o resto da query com -- (dois tracos e "
    "um espaco), senao o AND password derruba a condicao.\n"
    "- Varie os payloads de SQLi no campo username, um por tentativa:\n"
    "    ' OR '1'='1' -- \n"
    "    admin' -- \n"
    "    ' OR 1=1 -- \n"
    "    ') OR ('1'='1' -- \n"
    "- Leia a pagina inicial em busca de DICAS: credenciais de demonstracao "
    "(ex: 'guest / guest') costumam estar escritas no HTML. Use-as para logar.\n"
    "- IDOR exige ORDEM: (1) primeiro faca login de verdade com credenciais validas "
    "para obter uma sessao; (2) SO DEPOIS acesse /conta?id=N e enumere ids.\n"
    "  Se uma resposta disser 'Faca login' ou der 401, voce NAO esta autenticado: "
    "volte e faca o login — NAO adianta trocar o id, o problema e a falta de sessao.\n"
    "- Apos logar, ENUMERE ids um por um (id=1, id=2, id=3...). O servidor pode "
    "devolver dados de OUTRO usuario sem checar permissao; a flag costuma estar na "
    "conta de MENOR id (o admin, id=1). So pare quando ver flag{...}.\n"
    "- Reuse a sessao: cookies de login persistem entre chamadas automaticamente.\n"
    "- SSRF: se houver um endpoint que busca uma URL para voce (ex: /fetch?url=...), "
    "use-o para acessar recursos INTERNOS do servidor que voce nao alcanca direto — "
    "ex: ?url=http://localhost:8080/flag ou enderecos de metadados internos. Procure "
    "na pagina dicas sobre servicos internos (host:porta e caminhos).\n"
    "- NUNCA invente uma flag. So chame submit_flag com um texto flag{...} que "
    "apareceu LITERALMENTE no corpo de uma resposta que voce recebeu. Se voce nao "
    "viu uma flag ainda, continue investigando — nao chute.\n"
    "- PERSISTENCIA: se um payload falhar, tente OUTRA variacao da MESMA tecnica "
    "antes de mudar de abordagem. Nunca repita exatamente a mesma requisicao que ja "
    "falhou; isso nao traz informacao nova.\n"
    "- Leia o corpo das respostas com atencao; a flag costuma aparecer no HTML apos "
    "um login bem-sucedido ou ao acessar um recurso de outro usuario.\n"
    "- Ao ver flag{...} numa resposta, chame submit_flag imediatamente.\n"
    "- Antes de cada acao, explique em uma frase curta o que vai tentar e por que."
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
        resp = llm.chat(messages, TOOL_SCHEMAS)

        if resp.content.strip():
            on_event(f"\n[passo {step}] 🤔 {resp.content.strip()}")

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
                on_event("\n⚠️  agente travou (varios passos sem acao); abortando a tentativa.")
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
            on_event(f"   ⚙️  {name}({_fmt_args(args)})")
            result = dispatch(ctx, name, args)
            preview = result.get("body", result.get("message", result.get("error", "")))
            on_event(f"      ↳ {str(preview)[:160].replace(chr(10), ' ')}")
            messages.append({"role": "tool", "content": _to_tool_content(result)})

            if name == "submit_flag" and ctx.found_flag:
                on_event(f"\n🏁 FLAG CAPTURADA: {ctx.found_flag}  (em {step} passos)")
                return AgentResult(success=True, flag=ctx.found_flag, steps=step)

    on_event("\n❌ Limite de passos atingido sem capturar a flag.")
    return AgentResult(success=False, flag=None, steps=max_steps)
