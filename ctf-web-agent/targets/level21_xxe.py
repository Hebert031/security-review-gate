"""Alvo CTF nivel 21 — XXE (XML External Entity).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O /parse recebe um XML CRU no
corpo e o processa com RESOLUCAO DE ENTIDADES EXTERNAS ligada. Definindo uma
entidade externa que aponta para um arquivo do servidor, o conteudo do arquivo e
injetado na resposta. O arquivo secreto fica em <code>file:///flag</code> e
contem a FLAG. Payload classico:

    <?xml version="1.0"?>
    <!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
    <comment>&xxe;</comment>

A app devolve "Comentario: &lt;conteudo do arquivo&gt;" -> FLAG.

Implementacao didatica e SIMPLIFICADA (parser por regex, "filesystem" virtual em
memoria — NAO le o disco real). A licao: desligue a resolucao de entidades
externas (DTD) no seu parser XML.
"""

import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{xxe_3xt3rn4l_3nt1ty_f1l3_r34d}"

# "Filesystem" virtual: o que uma entidade SYSTEM consegue ler.
VFILES = {
    "file:///flag": FLAG,
    "/flag": FLAG,
    "file:///etc/hostname": "ctf-lab",
}

_ENTITY_SYS = re.compile(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>')
_ENTITY_LIT = re.compile(r'<!ENTITY\s+(\w+)\s+"([^"]*)"\s*>')
_COMMENT = re.compile(r"<comment>(.*?)</comment>", re.S)


def parse_xml(xml: str) -> str:
    """Resolve entidades (inclusive externas) e devolve o texto do <comment>."""
    entities: dict[str, str] = {}
    for name, uri in _ENTITY_SYS.findall(xml):
        entities[name] = VFILES.get(uri, f"[arquivo nao encontrado: {uri}]")  # XXE!
    for name, lit in _ENTITY_LIT.findall(xml):
        entities.setdefault(name, lit)

    m = _COMMENT.search(xml)
    content = m.group(1) if m else ""
    for name, value in entities.items():
        content = content.replace(f"&{name};", value)
    return content.strip()


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>XML Comment Box</h1>
<p>Envie um comentario em XML (POST <code>/parse</code>, corpo XML):</p>
<pre>&lt;comment&gt;Ola!&lt;/comment&gt;</pre>
<p><i>Nota do dev (nao remover): nosso parser XML processa DTD e entidades
externas (TODO: desabilitar — risco de XXE). Arquivos internos do servico ficam
sob <code>file:///</code> (ex.: ha um <code>file:///flag</code> de teste).</i></p>
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
        if urlparse(self.path).path != "/parse":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0))
        xml = self.rfile.read(length).decode("utf-8", "replace")
        try:
            content = parse_xml(xml)
        except Exception as exc:  # noqa: BLE001
            self._send(400, f"<p>XML invalido: {exc}</p>")
            return
        self._send(200, f"<h1>Comentario recebido</h1><p>{content}</p>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8020"))
    print(f"Alvo CTF nivel 21 (XXE) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
