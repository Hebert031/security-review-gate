"""Alvo CTF nivel 6 — JWT forge (auth bypass via alg=none).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. A API emite um JWT (assinado
com HS256) no login e protege /admin exigindo role=admin. O verificador, porem,
TEM UM BUG CLASSICO: quando o cabecalho do token diz alg="none", ele aceita o
token SEM checar a assinatura. Logo, da pra forjar um token {"role":"admin"}
com alg=none e entrar como admin sem saber o segredo.

100% stdlib (base64/hmac/hashlib), isolado e deterministico. O segredo HS256 e
forte e NUNCA vaza — o caminho previsto e a falha do alg=none, nao quebrar a
assinatura.
"""

import base64
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{jwt_4lg_n0n3_4dm1n_pwn3d}"
SECRET = b"sup3r-s3cr3t-hs256-key-nunca-vaza-9a3f"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def make_jwt(payload: dict, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none":
        sig = ""
    else:
        sig = _b64url(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify_jwt(token: str) -> dict | None:
    try:
        h_b64, p_b64, sig = token.split(".")
        header = json.loads(_b64url_dec(h_b64))
        payload = json.loads(_b64url_dec(p_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    alg = header.get("alg", "")
    # BUG VULNERAVEL: alg=none e aceito sem verificar assinatura nenhuma.
    if alg == "none":
        return payload
    if alg == "HS256":
        expected = _b64url(hmac.new(SECRET, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expected, sig):
            return payload
    return None


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>AdminAPI — Painel Corporativo</h1>
<p>Autentique-se para receber um <b>token JWT</b> e use-o no cabecalho
<code>Authorization: Bearer &lt;token&gt;</code>.</p>
<pre>POST /login   (form: username, password)   ex: guest / guest
GET  /admin   (Authorization: Bearer &lt;token&gt;)  -> exige role=admin</pre>
<p><i>Nota do dev (nao remover): o verificador de JWT ainda aceita tokens com
alg "none" sem checar assinatura. TODO de seguranca pendente.</i></p>
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
        if parsed.path == "/admin":
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            payload = verify_jwt(token) if token else None
            if not payload:
                self._send(401, "<p>Token ausente ou invalido. Faca login em /login.</p>")
                return
            if payload.get("role") == "admin":
                self._send(200, f"<h1>Painel Admin</h1><p>Bem-vindo, admin. {FLAG}</p>")
                return
            self._send(
                403,
                f"<p>Acesso negado. Seu token tem role='{payload.get('role')}'. "
                "O painel exige role='admin'.</p>",
            )
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/login":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = form.get("username", [""])[0] or "guest"
        # Qualquer credencial vira uma sessao de usuario comum (role=user).
        token = make_jwt({"user": user, "role": "user"})
        self._send(
            200,
            f"<h1>Login OK</h1><p>Token emitido para '{user}' (role=user):</p>"
            f"<pre>{token}</pre><p>Use em <code>Authorization: Bearer &lt;token&gt;</code>.</p>",
        )


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8005"))
    print(f"Alvo CTF nivel 6 (JWT forge) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
