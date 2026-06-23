"""Alvo CTF nivel 17 — Verbose error / debug leak (vazamento por stack trace).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /api/saldo espera
um parametro `id` numerico e faz `int(id)`. Como o app esta em MODO DEBUG, quando
algo quebra ele responde uma pagina de erro detalhada que despeja o estado interno
— inclusive o dicionario de configuracao do app, onde mora a FLAG. Basta enviar
um `id` nao-numerico (ex: ?id=abc) para disparar a excecao e ler o vazamento.

100% stdlib, isolado e deterministico. A licao: paginas de debug/erro verboso em
producao vazam segredos; capturar e logar o erro, e responder algo generico.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{v3rb0s3_3rr0r_d3bug_l34k}"

APP_CONFIG = {
    "service": "WalletAPI",
    "debug": True,
    "db_dsn": "postgres://wallet:s3nh4@db/wallet",
    "FLAG": FLAG,
}

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>WalletAPI</h1>
<p>Consulte saldo em <code>/api/saldo?id=NUMERO</code>.</p>
<pre>GET /api/saldo?id=1  -> {"id":1,"saldo":...}</pre>
<p><i>Nota do dev (nao remover): a API esta em modo DEBUG (paginas de erro
detalhadas ligadas). TODO: desligar debug antes de ir pra producao.</i></p>
</body></html>"""


def debug_error_page(exc: Exception) -> str:
    """Pagina de erro 'de debug': despeja a config interna do app (vaza segredos)."""
    cfg = "\n".join(f"  {k} = {v!r}" for k, v in APP_CONFIG.items())
    return (
        "<h1>500 — Internal Server Error (DEBUG)</h1>"
        f"<p>Excecao: <b>{type(exc).__name__}: {exc}</b></p>"
        "<h2>Application config (debug dump)</h2>"
        f"<pre>{cfg}</pre>"
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
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, HOME)
            return
        if parsed.path == "/api/saldo":
            raw = parse_qs(parsed.query).get("id", ["1"])[0]
            try:
                uid = int(raw)  # quebra se nao for numerico -> pagina de debug
            except Exception as exc:  # noqa: BLE001
                self._send(500, debug_error_page(exc))
                return
            self._send(200, f'{{"id":{uid},"saldo":0}}')
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8016"))
    print(f"Alvo CTF nivel 17 (verbose error) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
