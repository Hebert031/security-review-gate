"""Alvo CTF nivel 8 — Cookie tampering (auth bypass por sessao client-side).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. Ao visitar a home, o app emite
um cookie de sessao `sess` que NAO e assinado nem criptografado: e apenas um JSON
{"user":..., "role":...} em base64url. O painel /painel confia 100% no que vier
no cookie. Logo, basta DECODIFICAR o cookie, trocar role para "admin", RECODIFICAR
e reenviar -> acesso de admin sem senha.

100% stdlib, isolado e deterministico. O erro de design e confiar num estado de
sessao que o cliente controla (deveria ser assinado, ex: HMAC, como um JWT real).
"""

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{c00k13_t4mp3r1ng_r0l3_4dm1n}"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def make_cookie(user: str = "guest", role: str = "user") -> str:
    return _b64url(json.dumps({"user": user, "role": role}, separators=(",", ":")).encode())


def read_session(cookie_header: str) -> dict | None:
    """Extrai e decodifica o cookie `sess` do header Cookie. Sem verificacao."""
    for part in (cookie_header or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.strip().split("=", 1)
        if k == "sess":
            try:
                return json.loads(_b64url_dec(v))
            except (ValueError, json.JSONDecodeError):
                return None
    return None


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>ClubVIP — Area de Membros</h1>
<p>Voce entrou como visitante. Emitimos um cookie de sessao <code>sess</code>.</p>
<pre>GET /painel   -> area restrita (exige um membro com role "admin")</pre>
<p><i>Nota do dev (nao remover): a sessao e so um JSON em base64 dentro do cookie
<code>sess</code> (sem assinatura — TODO: assinar com HMAC). O /painel apenas le
o campo <code>role</code> do cookie e confia nele.</i></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, set_cookie: str | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            # Emite um cookie de visitante (role=user) — o cliente pode adultera-lo.
            self._send(200, HOME, set_cookie=f"sess={make_cookie()}; Path=/")
            return
        if path == "/painel":
            sess = read_session(self.headers.get("Cookie", ""))
            if not sess:
                self._send(401, "<p>Sem cookie de sessao. Visite a home primeiro.</p>")
                return
            if sess.get("role") == "admin":
                self._send(
                    200, f"<h1>Painel VIP</h1><p>Bem-vindo, admin. {FLAG}</p>"
                )
                return
            self._send(
                403,
                f"<p>Acesso negado. Seu cookie diz role='{sess.get('role')}'. "
                "O painel exige role='admin'.</p>",
            )
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8007"))
    print(f"Alvo CTF nivel 8 (cookie tampering) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
