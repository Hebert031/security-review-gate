"""Alvo CTF nivel 22 — Upload irrestrito -> execucao de codigo (RCE).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O app tem um sistema de
"plugins": voce envia um arquivo .py por upload (multipart) e o servidor EXECUTA
o conteudo no lado servidor, devolvendo a saida. Como nao ha restricao nenhuma,
isso e RCE direto. O contexto de execucao expoe a variavel <code>SECRET</code>
(onde mora a FLAG): basta enviar um plugin que faca <code>print(SECRET)</code>.

100% stdlib, isolado e deterministico (roda no container do laboratorio). A licao:
nunca executar/interpretar arquivos enviados por usuarios; valide tipo, armazene
fora da raiz web e jamais de eval/exec/include no conteudo.
"""

import contextlib
import io
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{f1l3_upl04d_t0_rc3_pwn3d}"
SECRET = FLAG  # disponivel no contexto de execucao do plugin


def extract_upload(body: bytes, boundary: str) -> str | None:
    """Extrai o conteudo do primeiro 'part' de arquivo de um multipart/form-data."""
    delim = ("--" + boundary).encode()
    for part in body.split(delim):
        head, sep, rest = part.partition(b"\r\n\r\n")
        if sep and b"filename=" in head:
            return rest.rsplit(b"\r\n", 1)[0].decode("utf-8", "replace")
    return None


def run_plugin(code: str) -> str:
    """EXECUTA o plugin enviado (RCE de proposito) e captura a saida."""
    ns = {
        "SECRET": SECRET,
        "__builtins__": {"print": print, "len": len, "range": range, "str": str},
    }
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(code, ns)  # noqa: S102 — vulneravel DE PROPOSITO
    return buf.getvalue()


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>PluginHub</h1>
<p>Faca upload de um plugin <code>.py</code> (campo <code>plugin</code>) em
<code>POST /upload</code> (multipart). O servidor executa e devolve a saida.</p>
<p><i>Nota do dev (nao remover): plugins sao executados no servidor (TODO: por
num sandbox de verdade). O ambiente de execucao expoe a variavel
<code>SECRET</code> da config para os plugins.</i></p>
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
        if urlparse(self.path).path == "/":
            self._send(200, HOME)
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/upload":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        ctype = self.headers.get("Content-Type", "")
        if "boundary=" not in ctype:
            self._send(400, "<p>envie multipart/form-data com um arquivo.</p>")
            return
        boundary = ctype.split("boundary=", 1)[1].strip()
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        code = extract_upload(body, boundary)
        if code is None:
            self._send(400, "<p>nenhum arquivo encontrado no upload.</p>")
            return
        try:
            output = run_plugin(code)
        except Exception as exc:  # noqa: BLE001
            self._send(200, f"<h1>Plugin executado (com erro)</h1><pre>{type(exc).__name__}: {exc}</pre>")
            return
        self._send(200, f"<h1>Plugin executado</h1><p>Saida:</p><pre>{output}</pre>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8021"))
    print(f"Alvo CTF nivel 22 (upload RCE) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
