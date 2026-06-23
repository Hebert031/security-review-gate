"""Alvo CTF nivel 16 — Business logic (manipulacao de quantidade/preco).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. A loja tem um item premium que
custa mais do que o seu saldo. O /checkout calcula `total = preco * qtd` e so
confere se `total <= saldo` — sem validar que `qtd` e POSITIVA. Mandando uma
quantidade NEGATIVA, o total fica <= 0 ("cabe" no saldo) e a compra do item
premium e aprovada -> FLAG.

100% stdlib, isolado e deterministico. A licao: falhas de logica de negocio
(valores negativos, limites nao checados) nao aparecem em scanners de injecao —
sempre validar invariantes (qtd > 0).
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "flag{bus1n3ss_l0g1c_n3g4t1v3_qty}"
SALDO = 100
PRECO_PREMIUM = 999  # bem acima do saldo

HOME = """<!doctype html><html lang="pt-br"><body>
<h1>GadgetShop</h1>
<p>Seu saldo: R$100. Item premium "Acesso VIP": R$999.</p>
<form method="POST" action="/checkout">
  item: <input name="item" value="premium"><br>
  quantidade: <input name="qtd" value="1"><br>
  <button>Comprar</button>
</form>
<p><i>Nota do dev (nao remover): o /checkout aprova a compra quando
<code>preco*qtd &lt;= saldo</code>. TODO: validar que a quantidade e positiva
antes de cobrar (ta aceitando qualquer inteiro).</i></p>
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
        if urlparse(self.path).path != "/checkout":
            self._send(404, "<h1>404 — nao encontrado</h1>")
            return
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        item = form.get("item", ["?"])[0]
        try:
            qtd = int(form.get("qtd", ["1"])[0])
        except ValueError:
            self._send(400, "<p>quantidade invalida.</p>")
            return
        total = PRECO_PREMIUM * qtd
        # BUG: nao valida qtd > 0; total negativo "cabe" no saldo.
        if item == "premium" and total <= SALDO:
            self._send(
                200,
                f"<h1>Compra aprovada!</h1><p>Acesso VIP liberado (total=R${total}). {FLAG}</p>",
            )
            return
        self._send(
            200,
            f"<p>Compra recusada. total=R${total} excede o saldo R${SALDO}.</p>",
        )


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8015"))
    print(f"Alvo CTF nivel 16 (business logic) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
