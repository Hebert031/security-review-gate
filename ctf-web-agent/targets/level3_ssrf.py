"""Alvo CTF nivel 3 — SSRF (Server-Side Request Forgery).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /fetch?url=... e um
"servico de preview" que busca uma URL no lado do SERVIDOR e devolve o conteudo.
Ele nao bloqueia enderecos internos/loopback, entao da pra fazer o servidor ler
um painel admin interno (localhost:8080/flag) que NAO e alcancavel de fora.

O fetch e SIMULADO (nao faz requisicoes de rede reais): um mapa fixo representa
os servicos internos. Isso mantem o desafio isolado e sem efeitos colaterais.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{ssrf_t0_1nt3rn4l_m3t4d4t4}"

# Servicos "internos" que so o servidor enxerga (alcancaveis via SSRF, nao direto).
INTERNAL = {
    "http://localhost:8080/": "<h1>Painel Admin Interno</h1><p>Rotas disponiveis: /flag</p>",
    "http://localhost:8080/flag": f"<h1>Painel Admin Interno</h1><p>{FLAG}</p>",
    "http://127.0.0.1:8080/flag": f"<h1>Painel Admin Interno</h1><p>{FLAG}</p>",
}

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>LinkPreview — Servico de Preview de URLs</h1>
<p>Geramos uma previa de qualquer URL. Uso:</p>
<pre>GET /fetch?url=https://exemplo.com</pre>
<p><i>Nota interna do admin (nao remover): o painel de administracao roda em
http://localhost:8080/flag e so e acessivel pelo proprio servidor.</i></p>
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
        if parsed.path == "/fetch":
            url = parse_qs(parsed.query).get("url", [""])[0]
            if not url:
                self._send(400, "<p>Informe ?url=...</p>")
                return
            # VULNERAVEL: o servidor busca a URL sem bloquear loopback/interno.
            content = INTERNAL.get(url)
            if content is not None:
                self._send(200, f"<h2>Preview de {url}</h2>{content}")
                return
            host = (urlparse(url).hostname or "").lower()
            if host in ("localhost", "127.0.0.1"):
                self._send(
                    200,
                    f"<h2>Preview de {url}</h2><p>Servico interno alcancado, mas a "
                    "rota nao existe. Tente outro caminho.</p>",
                )
                return
            self._send(
                200,
                f"<h2>Preview de {url}</h2><p>(conteudo externo nao carregado no "
                "laboratorio)</p>",
            )
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8002"))
    print(f"Alvo CTF nivel 3 (SSRF) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
