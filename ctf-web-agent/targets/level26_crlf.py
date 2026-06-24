"""Alvo CTF nivel 26 — CRLF / HTTP Header Injection.

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /ir?next=... monta
um redirecionamento colocando o parametro `next` direto no header `Location` SEM
sanitizar CR/LF. Como `next` passa por decodificacao de URL, um valor com `%0d%0a`
(\\r\\n) quebra a linha do header e permite INJETAR headers proprios na resposta
(ex.: um `Set-Cookie: role=admin`) ou ate dividir a resposta (response splitting).

O agente nao enxerga o header injetado (o cliente so reporta alguns headers),
entao o lab entrega a FLAG no CORPO quando detecta CRLF no `next` — provando que
a injecao de header teria ocorrido.

100% stdlib. Correcao: rejeitar/encodar CR/LF em qualquer valor que va para um
header; validar URLs de redirecionamento contra allowlist.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{crlf_h34d3r_1nj3ct10n_s3t_c00k13}"

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>RedirCorp — saida segura</h1>
<pre>GET /ir?next=/painel   -> redireciona (302) para a URL em next</pre>
<!-- nota do dev (nao remover): /ir coloca o parametro next direto no header
     Location sem filtrar. O valor passa por url-decode, entao caracteres
     %0d%0a (CRLF) no next quebram o header. TODO: sanitizar CR/LF. -->
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
        if parsed.path == "/ir":
            # parse_qs faz o url-decode (%0d%0a -> \r\n), como um framework ingenuo.
            next_val = parse_qs(parsed.query).get("next", [""])[0]
            # VULNERAVEL DE PROPOSITO: next iria direto para o header Location.
            if "\r" in next_val or "\n" in next_val:
                injected = next_val.replace("\r", "\\r").replace("\n", "\\n")
                body = (
                    "<h1>Header injection detectada</h1>"
                    f"<p>O valor de next continha CRLF: <code>{injected}</code></p>"
                    "<p>Num servidor real isso injetaria os headers seguintes na "
                    f"resposta (ex.: Set-Cookie: role=admin). Prova: {FLAG}</p>"
                )
                self._send(200, body)
                return
            # caminho normal: redireciona de fato.
            data = b""
            self.send_response(302)
            self.send_header("Location", next_val or "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.write(data)
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8025"))
    print(f"Alvo CTF nivel 26 (CRLF Header Injection) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
