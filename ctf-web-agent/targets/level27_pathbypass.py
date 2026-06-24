"""Alvo CTF nivel 27 — Auth bypass por normalizacao de path.

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O controle de acesso bloqueia
o acesso ao painel admin comparando o path EXATO `/admin` (403). Mas o roteamento
que serve o conteudo NORMALIZA o path (resolve `.`/`..`, `//`, %2e, barra final).
Assim, qualquer variante que normalize para `/admin` mas nao seja a string literal
`/admin` passa pelo bloqueio e serve a area admin.

Variantes que funcionam: `/admin/`, `//admin`, `/./admin`, `/%2e/admin`.

100% stdlib, deterministico. Causa-raiz: decidir autorizacao sobre a string crua
e servir o recurso sobre a string normalizada — defesas devem normalizar ANTES de
autorizar (e usar o mesmo path canonico nos dois lugares).
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlparse

FLAG = "flag{p4th_n0rm4l1z4t10n_403_byp4ss}"


def normalize(path: str) -> str:
    """Canonicaliza o path: url-decode + resolve '', '.', '..' e '//'."""
    p = unquote(path)
    segs: list[str] = []
    for s in p.split("/"):
        if s in ("", "."):
            continue
        if s == "..":
            if segs:
                segs.pop()
            continue
        segs.append(s)
    return "/" + "/".join(segs)


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>PainelCorp</h1>
<pre>GET /admin   -> area administrativa (restrita)</pre>
<!-- nota do dev (nao remover): o middleware de auth bloqueia exatamente o
     path "/admin" (403). O roteador que serve a pagina, porem, normaliza o
     path antes (resolve ., .., // e %2e). TODO: normalizar ANTES de autorizar. -->
</body></html>"""

ADMIN_PAGE = (
    "<!doctype html><html lang='pt-br'><body>"
    "<h1>Area administrativa</h1>"
    f"<p>Bem-vindo, admin. Voce contornou o controle de acesso. {FLAG}</p>"
    "</body></html>"
)


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
        raw = urlparse(self.path).path
        if raw == "/":
            self._send(200, HOME)
            return

        # VULNERAVEL DE PROPOSITO: autoriza sobre a string CRUA...
        if raw == "/admin":
            self._send(403, "<h1>403 — acesso negado ao /admin</h1>")
            return
        # ...mas serve sobre a string NORMALIZADA.
        if normalize(raw) == "/admin":
            self._send(200, ADMIN_PAGE)
            return

        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8026"))
    print(f"Alvo CTF nivel 27 (Path normalization bypass) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
