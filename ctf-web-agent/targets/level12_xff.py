"""Alvo CTF nivel 12 — Trusted-header spoof (bypass de IP via X-Forwarded-For).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O /admin so deveria atender a
rede interna do escritorio (IP 10.0.0.5). Mas a app, atras de um proxy, decide
"de onde veio a requisicao" confiando CEGAMENTE no header X-Forwarded-For — que
o cliente controla. Basta enviar `X-Forwarded-For: 10.0.0.5` para se passar pela
maquina interna e liberar o painel -> FLAG.

100% stdlib, isolado e deterministico. A correcao real seria nunca confiar em
X-Forwarded-For vindo de fora; so o proxy de borda (confiavel) pode defini-lo.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{x_f0rw4rd3d_f0r_sp00f_1nt3rn4l}"
INTERNAL_IP = "10.0.0.5"

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>Intranet Acme</h1>
<p>Portal interno. O <code>/admin</code> e liberado apenas para a rede do escritorio.</p>
<p><i>Nota do dev (nao remover): rodamos atras de um proxy reverso; o app
identifica o IP de origem pelo header <code>X-Forwarded-For</code>. Acesso admin
liberado somente para o IP interno <code>10.0.0.5</code>. TODO: parar de confiar
em XFF vindo do cliente.</i></p>
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
            # BUG: confia no header controlado pelo cliente.
            client_ip = self.headers.get("X-Forwarded-For", "0.0.0.0").split(",")[0].strip()
            if client_ip == INTERNAL_IP:
                self._send(200, f"<h1>Admin interno</h1><p>Origem confiavel. {FLAG}</p>")
                return
            self._send(
                403,
                f"<p>Acesso negado. Origem detectada: {client_ip}. "
                f"O /admin so atende o IP interno {INTERNAL_IP}.</p>",
            )
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8011"))
    print(f"Alvo CTF nivel 12 (XFF spoof) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
