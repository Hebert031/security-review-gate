"""Alvo CTF nivel 19 — GraphQL introspection (campo escondido exposto pelo schema).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. O endpoint /graphql atende
queries (via ?query=... ou corpo). A INTROSPECTION ficou ligada em producao,
entao a query introspectiva `{__schema{...}}` revela TODOS os campos do tipo
Query — inclusive um campo administrativo escondido chamado `secretFlag`, que
nao aparece em lugar nenhum da UI. Depois e so consulta-lo: `{ secretFlag }`
-> FLAG.

Implementacao didatica e SIMPLIFICADA (sem parser GraphQL real): detecta
`__schema`/`__type` para listar o schema e `secretFlag` para resolver o campo.
A licao: desligue introspection em producao; ela mapeia toda a sua API (campos
ocultos inclusive) para um atacante.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{gr4phql_1ntr0sp3ct10n_h1dd3n_f13ld}"

SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {
                    "name": "Query",
                    "fields": [
                        {"name": "me", "type": "User"},
                        {"name": "products", "type": "[Product]"},
                        # campo administrativo escondido (nao aparece na UI):
                        {"name": "secretFlag", "type": "String"},
                    ],
                },
                {"name": "User", "fields": [{"name": "id"}, {"name": "name"}]},
            ],
        }
    }
}

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>ShopGraph API</h1>
<p>API GraphQL em <code>/graphql</code>. Ex: <code>/graphql?query={me{name}}</code></p>
<p><i>Nota do dev (nao remover): introspection continua LIGADA (TODO: desligar em
producao). Lembrando que <code>{__schema{types{name fields{name}}}}</code> lista
todos os campos disponiveis, mesmo os que nao colocamos na interface.</i></p>
</body></html>"""


def resolve(query: str) -> dict:
    q = query or ""
    if "__schema" in q or "__type" in q:
        return SCHEMA
    if "secretFlag" in q:
        return {"data": {"secretFlag": FLAG}}
    if "me" in q:
        return {"data": {"me": {"name": "guest"}}}
    return {"errors": [{"message": "campo desconhecido"}]}


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, obj: dict) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, code: int, body: str) -> None:
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
            self._send_html(200, HOME)
            return
        if parsed.path == "/graphql":
            query = parse_qs(parsed.query).get("query", [""])[0]
            self._send_json(200, resolve(query))
            return
        self._send_html(404, "<h1>404 — nao encontrado</h1>")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/graphql":
            self._send_html(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        # aceita {"query":"..."} (JSON) ou query=... (form)
        query = ""
        try:
            query = json.loads(raw).get("query", "")
        except (ValueError, AttributeError):
            query = parse_qs(raw).get("query", [""])[0]
        self._send_json(200, resolve(query))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8018"))
    print(f"Alvo CTF nivel 19 (GraphQL introspection) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
