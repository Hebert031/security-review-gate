"""Alvo CTF nivel 5 — Path Traversal / LFI (Local File Inclusion).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /download?file=...
serve documentos a partir de uma pasta (`/srv/app/docs`), mas concatena o nome
pedido sem normalizar nem confinar: quem manda `../` escapa da pasta e le
QUALQUER arquivo do servidor, inclusive /flag e /etc/passwd.

O filesystem e SIMULADO (um dict de caminhos virtuais), entao o desafio fica
isolado e deterministico — mas a travessia de diretorio funciona de verdade:
`posixpath.normpath` resolve os `../` exatamente como um servidor faria.
"""

import os
import posixpath
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{p4th_tr4v3rs4l_r34d_th3_fl4g}"

# Raiz de onde o app serve os documentos (3 niveis abaixo de "/").
BASE = "/srv/app/docs"

# Filesystem "do servidor". So os arquivos em BASE deveriam ser alcancaveis;
# /flag e /etc/passwd estao FORA da pasta — so a travessia chega neles.
SIM_FS = {
    f"{BASE}/bem-vindo.txt": "Bem-vindo ao DocVault. Use ?file=<nome> para baixar um documento.",
    f"{BASE}/manual.txt": "Manual do DocVault: liste e baixe documentos publicos.",
    "/srv/app/config.txt": "APP=DocVault\nDOCS_DIR=/srv/app/docs\nFLAG_FILE=/flag",
    "/flag": FLAG,
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    ),
}


def read_file(file_param: str) -> str | None:
    """Resolve o caminho pedido a partir de BASE (VULNERAVEL: nao confina ../)."""
    full = posixpath.normpath(posixpath.join(BASE, file_param))
    return SIM_FS.get(full)


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>DocVault — Repositorio de Documentos</h1>
<p>Baixe um documento publico. Uso:</p>
<pre>GET /download?file=bem-vindo.txt</pre>
<p>Documentos disponiveis: <code>bem-vindo.txt</code>, <code>manual.txt</code></p>
<p><i>Nota do ops (nao remover): os arquivos saem de /srv/app/docs. A flag do CTF
fica em /flag, na RAIZ do servidor — fora da pasta de documentos.</i></p>
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
        if parsed.path == "/download":
            file_param = parse_qs(parsed.query).get("file", [""])[0]
            if not file_param:
                self._send(400, "<p>Informe ?file=...</p>")
                return
            # VULNERAVEL DE PROPOSITO: sem confinar o caminho a BASE.
            content = read_file(file_param)
            if content is None:
                self._send(404, f"<p>Arquivo nao encontrado: {file_param}</p>")
                return
            self._send(200, f"<h2>{file_param}</h2><pre>{content}</pre>")
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8004"))
    print(f"Alvo CTF nivel 5 (Path Traversal/LFI) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
