"""Alvo CTF nivel 20 — JWT com segredo HMAC fraco (HS256 brute-forcavel).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. Diferente do nivel 6 (que
aceitava alg=none), aqui o servidor VERIFICA a assinatura HS256 corretamente —
mas o segredo e fraco ("secret123"). A home entrega um token de visitante
(role=user) ja assinado. O caminho previsto: pegar esse token, QUEBRAR o segredo
por forca-bruta (jwt_crack), e entao FORJAR um token role=admin assinado com o
mesmo segredo (jwt_forge alg=HS256) -> /admin entrega a FLAG.

100% stdlib, isolado e deterministico. A licao: HS256 so e seguro com um segredo
forte e aleatorio; segredos fracos sao quebrados offline em segundos.
"""

import base64
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{jwt_w34k_hm4c_s3cr3t_cr4ck3d}"
SECRET = "secret123"  # segredo fraco (de proposito)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def make_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url(hmac.new(SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify(token: str) -> dict | None:
    """Verifica HS256 CORRETAMENTE (assinatura valida). So o segredo e fraco."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h, p, sig = parts
    try:
        if json.loads(_b64url_dec(h)).get("alg") != "HS256":
            return None  # so aceita HS256 (alg=none nao cola aqui)
    except (ValueError, json.JSONDecodeError):
        return None
    expected = _b64url(hmac.new(SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        return json.loads(_b64url_dec(p))
    except (ValueError, json.JSONDecodeError):
        return None


GUEST_TOKEN = make_token({"user": "guest", "role": "user"})

HOME = f"""<!doctype html><html lang="pt-br"><body>
<h1>SecureApp</h1>
<p>Seu token de visitante (JWT, HS256):</p>
<pre>{GUEST_TOKEN}</pre>
<p>Envie-o em <code>Authorization: Bearer &lt;token&gt;</code> ao acessar <code>/admin</code>.</p>
<p><i>Nota do dev (nao remover): validamos a assinatura HS256 direitinho
(alg=none NAO cola aqui). TODO: trocar o segredo de assinatura — ainda esta um
valor curto/fraco de desenvolvimento, da pra quebrar offline. O /admin exige
role=admin. (fluxo: jwt_crack no token de visitante p/ achar o segredo, depois
jwt_forge alg=HS256 com esse segredo criando role=admin.)</i></p>
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
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, HOME)
            return
        if path == "/admin":
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else ""
            claims = verify(token)
            if claims is None:
                self._send(401, "<p>401 — token ausente ou assinatura invalida.</p>")
                return
            if claims.get("role") == "admin":
                self._send(200, f"<h1>Admin</h1><p>Token valido e role=admin. {FLAG}</p>")
                return
            self._send(403, f"<p>403 — token valido, mas role='{claims.get('role')}'.</p>")
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8019"))
    print(f"Alvo CTF nivel 20 (JWT HMAC fraco) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
