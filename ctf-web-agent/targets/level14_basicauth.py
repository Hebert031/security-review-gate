"""Alvo CTF nivel 14 — HTTP Basic Auth com credenciais padrao (broken auth).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O /admin responde 401 com
`WWW-Authenticate: Basic`, pedindo autenticacao HTTP Basic. As credenciais
padrao (admin:admin) nunca foram trocadas. O caminho previsto: montar
`admin:admin`, codificar em base64 e enviar no header
`Authorization: Basic YWRtaW46YWRtaW4=` -> FLAG.

100% stdlib, isolado e deterministico. Exercita b64_encode + header Authorization.
A licao: credenciais padrao + Basic Auth (base64 e codificacao, NAO criptografia)
sao um classico de broken authentication.
"""

import base64
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{b4s1c_4uth_d3f4ult_cr3ds_pwn3d}"
USER, PASSWORD = "admin", "admin"
EXPECTED = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>Roteador WebAdmin</h1>
<p>Interface de administracao do dispositivo. Acesse <code>/admin</code>.</p>
<p><i>Nota do dev (nao remover): o /admin usa HTTP Basic Auth. As credenciais de
fabrica (admin/admin) ainda nao foram trocadas. Lembrando: Basic Auth manda
usuario:senha apenas em base64 (codificacao, nao seguranca). TODO: trocar a
senha padrao.</i></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, auth_challenge: bool = False) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if auth_challenge:
            self.send_header("WWW-Authenticate", 'Basic realm="WebAdmin"')
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
            if auth == EXPECTED:
                self._send(200, f"<h1>WebAdmin</h1><p>Login OK. {FLAG}</p>")
                return
            self._send(
                401,
                "<p>401 — autenticacao necessaria (HTTP Basic).</p>",
                auth_challenge=True,
            )
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8013"))
    print(f"Alvo CTF nivel 14 (basic auth) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
