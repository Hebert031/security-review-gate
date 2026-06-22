"""Alvo CTF nivel 7 — SSTI (Server-Side Template Injection).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /hello monta uma
saudacao concatenando a entrada do usuario DENTRO do codigo-fonte do template
e so depois renderiza:

    template = "Ola, " + name + "!"     # <- entrada vai pro SOURCE do template
    render(template, contexto)          # <- e entao avaliada

Como o motor avalia expressoes {{ ... }}, qualquer {{...}} que o usuario mandar
em `name` e EXECUTADO no servidor. O recon classico e {{7*7}} -> 49 (prova que e
template, nao texto). A escalada e o vazamento famoso do Flask: {{config}} expoe
o objeto de configuracao do app — que aqui guarda a FLAG.

100% stdlib, isolado e deterministico. O eval roda com __builtins__ vazio (sem
acesso a os/open), entao o caminho previsto e o LEAK de `config`, nao RCE.
"""

import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{sst1_t3mpl4t3_1nj3ct10n_c0nf1g_l34k}"

# "config" do app, no estilo Flask. Fica acessivel dentro dos templates — e por
# isso {{config}} vaza tudo, inclusive a FLAG.
CONFIG = {
    "APP": "GreetService",
    "ENV": "prod",
    "DEBUG": False,
    "SECRET_KEY": "n0t-th3-fl4g-but-also-s3cr3t",
    "FLAG": FLAG,
}

_EXPR = re.compile(r"\{\{(.*?)\}\}")


def render(template: str, context: dict) -> str:
    """Motor de template ingenuo: avalia cada {{ expr }} contra o contexto.

    VULNERAVEL: usa eval(). Como a entrada do usuario e concatenada no `template`
    antes de renderizar, o usuario controla as expressoes avaliadas (SSTI).
    """
    def repl(match: re.Match) -> str:
        expr = match.group(1).strip()
        try:
            # __builtins__ vazio: limita a RCE, mas as variaveis do contexto
            # (como `config`) continuam acessiveis -> leak.
            return str(eval(expr, {"__builtins__": {}}, context))  # noqa: S307
        except Exception as exc:  # noqa: BLE001
            return f"[erro ao avaliar '{expr}': {exc}]"

    return _EXPR.sub(repl, template)


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>GreetService — Saudacoes Personalizadas</h1>
<p>Geramos uma saudacao pra voce. Passe seu nome em <code>/hello?name=SeuNome</code>.</p>
<pre>GET /hello?name=Maria   ->   Ola, Maria!</pre>
<p><i>Nota do dev (nao remover): a saudacao usa o MESMO motor de template do
resto do site. As variaveis do app (inclusive <code>config</code>) ficam
disponiveis no template. Sintaxe: <code>{{ expressao }}</code>. TODO: sanitizar
a entrada antes de renderizar.</i></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, HOME)
            return
        if parsed.path == "/hello":
            name = parse_qs(parsed.query).get("name", ["visitante"])[0]
            # BUG: a entrada vai direto pro SOURCE do template e e renderizada.
            template = "Ola, " + name + "!"
            saudacao = render(template, {"config": CONFIG})
            self._send(200, f"<h1>{saudacao}</h1><p>Volte sempre ao GreetService.</p>")
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8006"))
    print(f"Alvo CTF nivel 7 (SSTI) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
