"""Alvo CTF nivel 10 — Mass Assignment (atribuicao em massa / priv-esc no cadastro).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /register cria uma
conta a partir dos campos do formulario e — ERRO DE DESIGN — joga TODOS os campos
recebidos direto no objeto do usuario, sem uma allowlist. O front so manda
`username`/`password`, mas o backend tambem aceita um campo `role` que o cliente
NUNCA deveria poder definir. Mande `role=admin` no cadastro e a conta ja nasce
admin -> a resposta entrega a FLAG.

100% stdlib, isolado e deterministico. A correcao real seria aceitar apenas os
campos previstos (allowlist) e definir `role` no servidor, jamais a partir da
entrada do usuario.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{m4ss_4ss1gnm3nt_r0l3_fr0m_cl13nt}"

# Campos que o backend ingenuamente copia da requisicao pro usuario.
# BUG: `role` esta aqui — deveria ser definido so no servidor.
def build_user(form: dict) -> dict:
    user = {"role": "user"}  # padrao
    for key, values in form.items():
        user[key] = values[0]  # copia TUDO que veio no form (mass assignment)
    return user


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>DevHub — Crie sua conta</h1>
<p>Cadastre-se para acessar o painel.</p>
<form method="POST" action="/register">
  usuario: <input name="username"><br>
  senha: <input name="password" type="password"><br>
  <button>Cadastrar</button>
</form>
<p><i>Nota do dev (nao remover): o /register monta o usuario copiando os campos
do POST direto pro registro (TODO: trocar por uma allowlist de campos). Contas
comuns nascem com <code>role=user</code>; o painel admin exige
<code>role=admin</code>.</i></p>
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
        if urlparse(self.path).path == "/":
            self._send(200, HOME)
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/register":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        user = build_user(form)
        if user.get("role") == "admin":
            self._send(
                200,
                f"<h1>Conta admin criada!</h1><p>Bem-vindo, {user.get('username','?')} "
                f"(role=admin). Painel liberado: {FLAG}</p>",
            )
            return
        self._send(
            200,
            f"<h1>Conta criada</h1><p>Usuario '{user.get('username','?')}' com "
            f"role='{user.get('role')}'. O painel admin exige role='admin'.</p>",
        )


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8009"))
    print(f"Alvo CTF nivel 10 (mass assignment) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
