"""Alvo CTF nivel 11 — HTTP Verb Tampering (bypass de auth por metodo HTTP).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O /admin e "protegido" por uma
regra que so cobre o metodo GET (imite um proxy/.htaccess mal configurado:
"deny GET /admin"). O handler real, porem, responde a QUALQUER metodo. Logo,
trocar o verbo (POST, PUT, DELETE...) contorna a checagem e cai direto no
conteudo protegido -> FLAG.

100% stdlib, isolado e deterministico. A correcao real seria negar por padrao
(default-deny) para todos os metodos, nao apenas para o GET.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{http_v3rb_t4mp3r1ng_byp4ss}"

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>Ops Console</h1>
<p>Painel interno. A rota <code>/admin</code> e restrita.</p>
<p><i>Nota do dev (nao remover): a protecao do /admin foi configurada no proxy
como uma regra de <code>GET</code> (deny GET /admin). O app por tras responde a
metodos diversos. TODO: aplicar default-deny a todos os verbos.</i></p>
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

    def _admin_body(self) -> str:
        return f"<h1>Admin Console</h1><p>Acesso liberado. {FLAG}</p>"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, HOME)
            return
        if path == "/admin":
            # A "regra do proxy" so bloqueia GET.
            self._send(403, "<p>403 — GET /admin negado pela politica.</p>")
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")

    def _handle_other(self) -> None:
        if urlparse(self.path).path == "/admin":
            # Sem checagem para metodos != GET -> bypass.
            self._send(200, self._admin_body())
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")

    do_POST = _handle_other
    do_PUT = _handle_other
    do_DELETE = _handle_other


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8010"))
    print(f"Alvo CTF nivel 11 (verb tampering) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
