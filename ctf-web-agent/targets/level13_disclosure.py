"""Alvo CTF nivel 13 — Sensitive file exposure (recon via robots.txt -> backup).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. A home nao revela nada, mas o
/robots.txt — por descuido — lista um caminho "secreto" no Disallow. Esse arquivo
de backup (.bak) ficou exposto no servidor e contem a FLAG. O caminho previsto:
ler /robots.txt -> notar o Disallow -> baixar o arquivo de backup.

100% stdlib, isolado e deterministico. A licao: "Disallow" no robots.txt NAO
protege nada (so pede pra crawlers nao indexarem); e backups jamais deveriam
ficar acessiveis via web.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{r0b0ts_d1s4ll0w_l34ks_th3_b4ckup}"

ROBOTS = "User-agent: *\nDisallow: /backup/db_dump.bak\n"

BACKUP = (
    "-- dump parcial do banco (NAO COMMITAR)\n"
    "users(id,user,role):\n"
    "  1,admin,admin\n"
    "  2,maria,user\n"
    f"app_secrets(flag): {FLAG}\n"
)

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>Loja Pixel</h1>
<p>Bem-vindo a Loja Pixel. Nada de interessante por aqui.</p>
<p><i>Nota do dev (nao remover): lembrar de revisar o que esta exposto na raiz
do site antes do lancamento (ver arquivos de metadados de crawler). TODO:
remover backups antigos do servidor.</i></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
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
        if path == "/robots.txt":
            self._send(200, ROBOTS, ctype="text/plain; charset=utf-8")
            return
        if path == "/backup/db_dump.bak":
            self._send(200, BACKUP, ctype="text/plain; charset=utf-8")
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8012"))
    print(f"Alvo CTF nivel 13 (sensitive file exposure) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
