"""Loop ReAct: o LLM observa a resposta, raciocina e age via ferramentas
ate capturar a flag ou esgotar os passos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

import requests

from .llm import LLMClient
from .tools import ToolContext, TOOL_SCHEMAS, dispatch


STALL_LIMIT = 4  # passos seguidos sem acao antes de declarar o agente travado
CHAT_RETRIES = 2  # tentativas da chamada ao LLM antes de desistir do passo (timeout etc)


def _chat_with_retry(llm: LLMClient, messages: list[dict], on_event: Callable[[str], None]):
    """Chama o LLM tolerando falhas transitorias de rede (ex: ReadTimeout quando o
    modelo degenera numa geracao longa). Reerguer a excecao so apos esgotar."""
    for attempt in range(1, CHAT_RETRIES + 1):
        try:
            return llm.chat(messages, TOOL_SCHEMAS)
        except requests.RequestException as exc:
            if attempt >= CHAT_RETRIES:
                raise
            on_event(f"\n⚠️  modelo nao respondeu ({type(exc).__name__}); tentando de novo...")


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
    "para virar admin; URL com id -> IDOR; endpoint que busca URL -> SSRF; endpoint "
    "que roda um comando do sistema (ping, nslookup, etc) -> Command Injection; "
    "endpoint que serve/baixa um arquivo por nome (?file=, ?page=, ?doc=) -> Path "
    "Traversal/LFI; token JWT (3 partes x.y.z) + area que exige admin -> forja de JWT; "
    "endpoint que ECOA seu texto numa saudacao/mensagem (?name=, ?msg=) -> teste SSTI; "
    "cookie de sessao que e base64 de um JSON (sem assinatura) -> adultere o cookie; "
    "fetcher/preview de URL com allowlist + endpoint de redirect -> encadeie open "
    "redirect com SSRF.\n"
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
    "- COMMAND INJECTION: se um endpoint roda um comando do SO com um parametro seu "
    "(ex: /ping?host=...), o servidor costuma montar `ping -c1 <host>` no shell. "
    "Encadeie OUTRO comando para ler a flag, variando o separador por tentativa:\n"
    "    ?host=127.0.0.1; cat /flag\n"
    "    ?host=127.0.0.1 && cat /flag\n"
    "    ?host=127.0.0.1 | cat /flag\n"
    "    ?host=$(cat /flag)\n"
    "  A flag costuma estar em /flag; se nao souber o caminho, tente `ls` antes. "
    "Lembre de URL-encode quando precisar (espaco, ;, &, | em querystring).\n"
    "- PATH TRAVERSAL / LFI: se um endpoint serve um arquivo pelo nome (ex: "
    "/download?file=manual.txt), ele costuma ler de uma pasta fixa SEM confinar o "
    "caminho. Use ../ para escapar da pasta e ler arquivos de fora dela. Varie:\n"
    "    ?file=../../../../flag\n"
    "    ?file=/flag            (caminho absoluto direto)\n"
    "    ?file=../../../../etc/passwd\n"
    "  Leia a pagina inicial: ela costuma dizer ONDE a flag esta (ex: /flag na raiz). "
    "Suba ../ o suficiente para chegar na raiz antes do nome do arquivo.\n"
    "- JWT FORGE: se a app emite um token JWT (3 partes base64 separadas por ponto, "
    "x.y.z) e uma area (ex: /admin) exige role=admin, faca: (1) faca login para "
    "receber um token; (2) use jwt_decode para ver o payload (campos como role); "
    "(3) use jwt_forge com payload {'user':'admin','role':'admin'} (alg='none') para "
    "criar um token forjado; (4) refaca a requisicao a area protegida passando "
    "headers={'Authorization': 'Bearer <token_forjado>'}. Muitos verificadores "
    "aceitam alg=none sem checar a assinatura — e por isso que a forja funciona.\n"
    "- SSTI (Server-Side Template Injection): se um endpoint REFLETE seu texto numa "
    "saudacao/mensagem (ex: /hello?name=...), teste se ele renderiza um template. "
    "Primeiro PROVE com {{7*7}}: se a resposta vier '49' (e nao o texto literal "
    "'{{7*7}}'), e template e da pra injetar. Depois ESCALE para vazar a flag, "
    "variando por tentativa (lembre de URL-encode):\n"
    "    ?name={{7*7}}            (recon: confirma que e template)\n"
    "    ?name={{config}}         (vaza o objeto de config do app — costuma ter a flag)\n"
    "    ?name={{config['FLAG']}} (le um campo direto do config)\n"
    "  O objeto `config` (estilo Flask) geralmente carrega segredos e a flag.\n"
    "- COOKIE TAMPERING: se o servidor manda um cookie de sessao (header Set-Cookie, "
    "ex: sess=...) que e apenas base64 de um JSON SEM assinatura, voce controla a "
    "sessao. Faca: (1) pegue o valor do cookie na resposta; (2) use b64_decode para "
    "ver o JSON (campos como role); (3) edite role para 'admin' e use b64_encode no "
    "JSON novo; (4) refaca a requisicao a area restrita passando "
    "headers={'Cookie': 'sess=<valor_b64_forjado>'}. Como nao ha assinatura, o "
    "servidor confia no cookie adulterado.\n"
    "- OPEN REDIRECT + SSRF: um servico de preview/fetch busca URLs NO SERVIDOR, mas "
    "so aceita uma allowlist (ex: alvos /public ou /go do host publico). A flag fica "
    "num host INTERNO (ex: http://127.0.0.2:PORT/flag) que VOCE nao alcanca direto "
    "(o lab bloqueia: 'host bloqueado pela allowlist'). Existe um open redirect "
    "(/go?to=...) na allowlist. ENCADEIE: peca ao preview um alvo PERMITIDO (/go) que "
    "redireciona pro host interno — o fetcher do SERVIDOR segue o redirect e vaza a "
    "flag. Pedir /go direto NAO funciona (seu cliente tambem respeita a allowlist no "
    "redirect). Monte assim (URL-encode o target inteiro):\n"
    "    /preview?target=http://127.0.0.1:PORT/go?to=http://127.0.0.2:PORT/flag\n"
    "  A pagina inicial diz o endereco exato do recurso interno e os caminhos aceitos.\n"
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
        try:
            resp = _chat_with_retry(llm, messages, on_event)
        except requests.RequestException as exc:
            # Timeout/erro de rede persistente no LLM: aborta SO esta tentativa
            # (a gincana segue; o ATTEMPTS do placar ainda da nova chance ao nivel).
            on_event(f"\n⚠️  modelo indisponivel ({type(exc).__name__}); abortando a tentativa.")
            return AgentResult(success=False, flag=None, steps=step)

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
            preview = (
                result.get("body")
                or result.get("token")
                or result.get("decoded")
                or result.get("encoded")
                or result.get("payload")
                or result.get("message")
                or result.get("error", "")
            )
            on_event(f"      ↳ {str(preview)[:160].replace(chr(10), ' ')}")
            messages.append({"role": "tool", "content": _to_tool_content(result)})

            if name == "submit_flag" and ctx.found_flag:
                on_event(f"\n🏁 FLAG CAPTURADA: {ctx.found_flag}  (em {step} passos)")
                return AgentResult(success=True, flag=ctx.found_flag, steps=step)

    on_event("\n❌ Limite de passos atingido sem capturar a flag.")
    return AgentResult(success=False, flag=None, steps=max_steps)
