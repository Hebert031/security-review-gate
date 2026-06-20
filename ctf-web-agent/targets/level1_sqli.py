"""Alvo CTF nivel 1 — SQL injection em formulario de login.

Ambiente de LABORATORIO. Este servico e vulneravel DE PROPOSITO: ele concatena
a entrada do usuario direto na query SQL. Serve apenas como alvo isolado para o
agente praticar. Roda so em 127.0.0.1.
"""

import os
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

FLAG = "flag{sql_1nj3ct10n_b00tstr4p}"


def init_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
    con.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [("admin", "S3cr3t-p4ss-x9z", "admin"), ("guest", "guest", "user")],
    )
    con.commit()
    return con


DB = init_db()

PAGE = """<!doctype html><html lang="pt-br"><body>
<h1>Mega Corp — Area Restrita</h1>
<p>Faca login para acessar o painel.</p>
<form method="POST" action="/login">
  usuario: <input name="username"><br>
  senha: <input name="password" type="password"><br>
  <button type="submit">Entrar</button>
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:  # silencia log padrao ruidoso
        pass

    def do_GET(self) -> None:
        if self.path in ("/", "/login"):
            self._send(200, PAGE)
        else:
            self._send(404, "<h1>404 — nao encontrado</h1>")

    def do_POST(self) -> None:
        if self.path != "/login":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw)
        user = form.get("username", [""])[0]
        pw = form.get("password", [""])[0]

        # VULNERAVEL DE PROPOSITO: entrada concatenada na query (SQL injection).
        query = (
            "SELECT username, role FROM users "
            f"WHERE username='{user}' AND password='{pw}'"
        )
        try:
            row = DB.execute(query).fetchone()
        except sqlite3.Error as exc:
            self._send(200, f"<p>Erro de SQL: {exc}</p>")
            return

        if row and row[1] == "admin":
            self._send(200, f"<h1>Bem-vindo, {row[0]}!</h1><p>Painel admin liberado. {FLAG}</p>")
        elif row:
            self._send(200, f"<h1>Bem-vindo, {row[0]}!</h1><p>Conta sem privilegio de admin.</p>")
        else:
            self._send(200, "<p>Credenciais invalidas.</p>")


if __name__ == "__main__":
    # 127.0.0.1 por padrao (seguro pra rodar local). No container, HOST=0.0.0.0
    # deixa o alvo alcancavel pelos outros servicos da rede isolada do compose.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"Alvo CTF nivel 1 (SQLi) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
