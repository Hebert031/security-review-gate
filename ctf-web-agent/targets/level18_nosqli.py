"""Alvo CTF nivel 18 — NoSQL Injection (auth bypass por operador do Mongo).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O /login monta uma "consulta"
no estilo MongoDB a partir dos campos do formulario, SEM tratar operadores. No
form-urlencoded, um campo como `password[$ne]=x` vira o filtro {"$ne": "x"}
("diferente de x") — que casa com QUALQUER senha. Assim, `username=admin` +
`password[$ne]=x` loga como admin sem saber a senha -> FLAG.

100% stdlib, isolado e deterministico (simula a semantica do Mongo: $ne, $gt).
A licao: nunca deixar a entrada do usuario virar operador da query; force tipos
(senha tem que ser string) e use queries parametrizadas.
"""

import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{n0sql_1nj3ct10n_n3_byp4ss}"

# "Banco" de usuarios. A senha real do admin e desconhecida pelo atacante.
USERS = {"admin": {"password": "S3nh4SuperSecreta!", "role": "admin"}}

_OP_KEY = re.compile(r"^(\w+)\[\$(\w+)\]$")  # ex: password[$ne]


def parse_query(form: dict) -> dict:
    """Converte o form num filtro estilo Mongo. BUG: aceita operadores do cliente."""
    query: dict = {}
    for key, values in form.items():
        m = _OP_KEY.match(key)
        if m:
            field, op = m.group(1), m.group(2)
            query.setdefault(field, {})["$" + op] = values[0]
        else:
            query[key] = values[0]
    return query


def match_user(query: dict) -> dict | None:
    """Avalia o filtro contra o USERS, com semantica ingenua de Mongo."""
    def field_matches(stored, cond) -> bool:
        if isinstance(cond, dict):  # operadores
            if "$ne" in cond and stored != cond["$ne"]:
                return True
            if "$gt" in cond and str(stored) > str(cond["$gt"]):
                return True
            return False
        return stored == cond  # igualdade simples

    for username, doc in USERS.items():
        rec = {"username": username, **doc}
        if all(field_matches(rec.get(f), c) for f, c in query.items()):
            return rec
    return None


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>MongoApp — Login</h1>
<form method="POST" action="/login">
  usuario: <input name="username"><br>
  senha: <input name="password" type="password"><br>
  <button>Entrar</button>
</form>
<p><i>Nota do dev (nao remover): o /login monta a query do Mongo direto a partir
dos campos do form (TODO: forcar tipos / nao aceitar operadores do cliente).
Operadores como <code>$ne</code> sao interpretados.</i></p>
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
        if urlparse(self.path).path != "/login":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        user = match_user(parse_query(form))
        if user and user.get("role") == "admin":
            self._send(200, f"<h1>Logado como {user['username']}</h1><p>{FLAG}</p>")
            return
        self._send(200, "<p>Credenciais invalidas.</p>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8017"))
    print(f"Alvo CTF nivel 18 (NoSQL injection) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
