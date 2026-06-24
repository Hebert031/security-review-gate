"""Alvo CTF nivel 24 — Insecure Deserialization (desserializacao insegura).

Ambiente de LABORATORIO, vulneravel DE PROPOSITO. A home emite um cookie `prefs`
com as "preferencias" do usuario em base64. O painel DESSERIALIZA esse cookie
chamando `eval()` no conteudo decodificado — ou seja, executa codigo Python que
o CLIENTE controla. Isso e desserializacao insegura (CWE-502): o atacante envia
uma expressao e ela roda dentro do escopo do app (acesso a variaveis, e RCE).

Para capturar a flag basta enviar um `prefs` cujo conteudo, ao ser eval-ado,
devolva o segredo: a variavel `FLAG` esta no escopo do eval. Ex.: prefs = base64
da string `FLAG`. (Pickle teria o mesmo problema; aqui usamos eval por ser o
caso resolvivel sem opcodes binarios.)

100% stdlib, isolado e deterministico. Correcao: NUNCA desserialize dado nao
confiavel com eval/pickle/yaml.load; use formatos de dados puros (json) e
valide o schema.
"""

import base64
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

FLAG = "flag{1ns3cur3_d3s3r14l1z4t10n_eval_rc3}"
VERSION = "1.0"


def _b64dec(seg: str) -> bytes:
    seg = seg.strip()
    try:  # tolera base64 e base64url, com ou sem padding
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:
        return base64.b64decode(seg + "=" * (-len(seg) % 4))


def make_prefs(expr: str = "{'tema': 'claro'}") -> str:
    return base64.urlsafe_b64encode(expr.encode()).rstrip(b"=").decode()


def read_prefs_cookie(cookie_header: str) -> str | None:
    for part in (cookie_header or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.strip().split("=", 1)
        if k == "prefs":
            return v
    return None


HOME = """<!doctype html><html lang="pt-br"><body>
<h1>PrefApp — suas preferencias</h1>
<p>Emitimos um cookie <code>prefs</code> com suas preferencias serializadas.</p>
<pre>GET /painel   -> aplica suas preferencias e mostra o resultado</pre>
<!-- nota do dev (nao remover): /painel desserializa o cookie prefs com
     resultado = eval(base64decode(prefs)). No escopo do eval existem as
     variaveis FLAG e VERSION. TODO: trocar eval por json.loads. -->
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, set_cookie: str | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            # emite um prefs benigno de exemplo
            self._send(200, HOME, set_cookie=f"prefs={make_prefs()}; Path=/")
            return
        if path == "/painel":
            raw = read_prefs_cookie(self.headers.get("Cookie", ""))
            if not raw:
                self._send(200, "<p>Sem cookie prefs. Visite / primeiro.</p>")
                return
            try:
                payload = _b64dec(raw).decode("utf-8", "replace")
                # VULNERAVEL DE PROPOSITO: eval em dado controlado pelo cliente.
                resultado = eval(payload, {"FLAG": FLAG, "VERSION": VERSION})  # noqa: S307
            except Exception as exc:  # noqa: BLE001
                self._send(200, f"<p>Erro ao aplicar preferencias: {exc}</p>")
                return
            self._send(200, f"<h1>Preferencias aplicadas</h1><p>resultado: {resultado}</p>")
            return
        self._send(404, "<h1>404 — nao encontrado</h1>")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8023"))
    print(f"Alvo CTF nivel 24 (Insecure Deserialization) em http://{host}:{port}  — Ctrl+C para parar")
    HTTPServer((host, port), Handler).serve_forever()
