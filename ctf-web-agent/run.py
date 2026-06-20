"""Runner: lanca o agente de IA contra um alvo CTF local.

Pre-requisitos:
  1. Ollama rodando com um modelo que faca tool calling (ex: qwen2.5:7b-instruct)
  2. O alvo no ar:  python3 targets/level1_sqli.py

Uso:
  python3 run.py --target http://127.0.0.1:8000 --expected-flag 'flag{...}'
"""

import argparse
import os
from urllib.parse import urlparse

from agent.llm import OllamaClient
from agent.loop import run_agent


def main() -> None:
    parser = argparse.ArgumentParser(description="Agente de IA que resolve CTFs de Web.")
    parser.add_argument("--target", default=os.environ.get("TARGET", "http://127.0.0.1:8000"))
    parser.add_argument("--model", default=os.environ.get("MODEL", "qwen2.5:7b-instruct"))
    parser.add_argument("--ollama-host", default=None, help="ex: http://ollama:11434")
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--no-pull", action="store_true", help="nao baixar o modelo se faltar")
    parser.add_argument("--expected-flag", default=None, help="valida a captura se informado")
    args = parser.parse_args()

    host = urlparse(args.target).hostname or "127.0.0.1"
    allowed = {host, "127.0.0.1", "localhost"}

    llm = OllamaClient(model=args.model, host=args.ollama_host)
    print(f"🎯 alvo: {args.target}  |  🧠 {args.model} @ {llm.host}  |  🔒 hosts: {sorted(allowed)}")
    llm.wait_until_ready()
    if not args.no_pull:
        llm.ensure_model()

    result = run_agent(llm, args.target, allowed_hosts=allowed, max_steps=args.max_steps)

    if args.expected_flag:
        ok = result.flag == args.expected_flag
        print("\n✅ CORRETO! a IA resolveu o desafio." if ok else "\n⚠️  flag diferente da esperada.")


if __name__ == "__main__":
    main()
