"""Alvo CTF nivel 2 — IDOR (Insecure Direct Object Reference).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. Apos o login (guest/guest), o
endpoint /conta?id=N devolve os dados da conta N SEM checar se a sessao atual e
dona daquela conta. Trocando o id para 1 (admin), qualquer usuario logado le a
flag. Roda so localmente.
"""

import os
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{1d0r_br0k3n_4cc3ss_c0ntr0l}"

# id -> dados da conta (a conta 1, do admin, guarda a flag na nota)
ACCOUNTS = {
    "1": {"user": "admin", "saldo": "R$ 1.000.000,00", "nota": FLAG},
    "2": {"user": "guest", "saldo": "R$ 12,50", "nota": "conta de demonstracao"},
}
# username -> (senha, id)
CREDS = {"guest": ("guest", "2"), "admin": ("S3cr3t-p4ss-x9z", "1")}
SESSIONS: dict[str, str] = {}  # token -> id do dono da sessao

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>Mega Bank — Internet Banking</h1>
<p>Acesse sua conta.</p>
<form method="POST" action="/login">
  usuario: <input name="username"><br>
  senha: <input name="password" type="password"><br>
  <button type="submit">Entrar</button>
</form>
<p>Conta de demonstracao: <b>guest / guest</b></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, set_cookie: str | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass

    def _session_owner(self) -> str | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie["session"].value if "session" in cookie else None
        return SESSIONS.get(token or "")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, HOME)
            return
        if parsed.path == "/conta":
            owner = self._session_owner()
            if owner is None:
                self._send(401, "<p>Faca login para ver contas.</p>")
                return
            account_id = parse_qs(parsed.query).get("id", [owner])[0]
            acc = ACCOUNTS.get(account_id)
            if not acc:
                self._send(404, "<p>Conta inexistente.</p>")
                return
            # VULNERAVEL: nao verifica se `owner` == `account_id` (IDOR).
            self._send(
                200,
                f"<h1>Conta #{account_id} — {acc['user']}</h1>"
                f"<p>Saldo: {acc['saldo']}</p><p>Nota: {acc['nota']}</p>",
            )
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")

    def do_POST(self) -> None:
        if self.path != "/login":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = form.get("username", [""])[0]
        pw = form.get("password", [""])[0]

        record = CREDS.get(user)
        if not record or record[0] != pw:
            self._send(200, "<p>Credenciais invalidas.</p>")
            return

        token = uuid.uuid4().hex
        SESSIONS[token] = record[1]
        self._send(
            200,
            f"<h1>Bem-vindo, {user}!</h1>"
            f"<p>Sua conta: <a href='/conta?id={record[1]}'>/conta?id={record[1]}</a></p>",
            set_cookie=f"session={token}; Path=/; HttpOnly",
        )


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8001"))
    print(f"Alvo CTF nivel 2 (IDOR) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
