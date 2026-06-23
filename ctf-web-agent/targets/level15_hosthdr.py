"""Alvo CTF nivel 15 — Host Header Injection (bypass por vhost confiavel).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O painel admin mora num
"vhost interno" e a app decide se libera o /admin OLHANDO o header `Host` da
requisicao — que o cliente controla. Basta enviar `Host: admin.corp.local` para
ser roteado ao painel interno -> FLAG.

100% stdlib, isolado e deterministico. A licao: nunca tomar decisao de
seguranca/roteamento com base no header Host vindo do cliente.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{h0st_h34d3r_1nj3ct10n_vh0st}"
ADMIN_VHOST = "admin.corp.local"

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>Corp Portal</h1>
<p>Site publico. O painel admin fica num host interno separado.</p>
<p><i>Nota do dev (nao remover): roteamos por vhost. O painel admin so responde
quando o header <code>Host</code> e <code>admin.corp.local</code> (host interno).
TODO: nao confiar no Host enviado pelo cliente para liberar area restrita.</i></p>
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
        # BUG: roteia/autoriza pelo Host controlado pelo cliente.
        host = (self.headers.get("Host", "") or "").split(":")[0]
        if path == "/admin":
            if host == ADMIN_VHOST:
                self._send(200, f"<h1>Painel Admin Interno</h1><p>{FLAG}</p>")
                return
            self._send(
                403,
                f"<p>403 — /admin so atende o vhost interno '{ADMIN_VHOST}'. "
                f"Seu Host: '{host}'.</p>",
            )
            return
        if path == "/":
            self._send(200, HOME)
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8014"))
    print(f"Alvo CTF nivel 15 (host header) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
