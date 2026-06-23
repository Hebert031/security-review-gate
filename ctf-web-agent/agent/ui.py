"""Camada de apresentacao do terminal: cores ANSI, banner, caixas por nivel,
spinner animado enquanto o LLM pensa e comemoracao da flag.

REGRA DE OURO: efeitos so quando a saida e um TERMINAL de verdade. Em pipe,
arquivo (os runs em background) ou com NO_COLOR, tudo cai para texto limpo —
identico ao comportamento antigo. Assim logs salvos e greps nao quebram.
"""

from __future__ import annotations

import itertools
import os
import sys
import threading
import time


def _enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001
        return False


FANCY = _enabled()


def _c(code: str) -> str:
    return code if FANCY else ""


RESET = _c("\033[0m")
BOLD = _c("\033[1m")
DIM = _c("\033[2m")
RED = _c("\033[31m")
GREEN = _c("\033[32m")
YELLOW = _c("\033[33m")
BLUE = _c("\033[34m")
MAGENTA = _c("\033[35m")
CYAN = _c("\033[36m")
GREY = _c("\033[90m")


def color(s: str, *codes: str) -> str:
    if not FANCY or not codes:
        return s
    return "".join(codes) + s + RESET


BANNER = r"""
  ____ _____ _____   __        _______ ____
 / ___|_   _|  ___|  \ \      / / ____| __ )
| |     | | | |_      \ \ /\ / /|  _| |  _ \
| |___  | | |  _|      \ V  V / | |___| |_) |
 \____| |_| |_|         \_/\_/  |_____|____/
"""

# Mascote: a capivara da "Capibara Security".
CAPIBARA = r"""
            .-~~~~~~~-.
          .'  o     o  '.
         /      ___      \
        |      ( ᴥ )      |       CAPIBARA  SECURITY
         \      '-'      /        ──  by Hebert Ribeiro  ──
          '-._______.-'
          //  |   |  \\
         (_) (_) (_) (_)
"""


def banner(model: str, host: str, repeat: int) -> str:
    """Cabecalho de abertura da gincana (com a mascote e o autor)."""
    if FANCY:
        head = color(BANNER, CYAN, BOLD) + color(CAPIBARA, YELLOW)
    else:
        head = "=== CTF WEB AGENT — Capibara Security · by Hebert Ribeiro ==="
    info = (
        f"🧠 modelo: {color(model, BOLD)}  @  {color(host, GREY)}"
        f"   |   repeticoes: {repeat}"
    )
    return f"{head}\n{info}"


def level_header(title: str, base: str, attempt: int, attempts: int) -> str:
    """Caixa de titulo do nivel (sem emoji dentro das bordas p/ alinhar certo)."""
    info = f"try {attempt}/{attempts}" if attempts > 1 else ""
    if not FANCY:
        suffix = "" if attempts == 1 else f"  (tentativa {attempt}/{attempts})"
        return f"\n{'='*64}\n🎯 {title}  ({base}){suffix}\n{'='*64}"

    left = f"─ {title} "
    right = f" {info} ─" if info else "─"
    mid = f" alvo  {base}"
    inner = max(len(left) + len(right), len(mid), 52)
    pad_top = "─" * (inner - len(left) - len(right))
    pad_mid = " " * (inner - len(mid))
    C = CYAN
    top = color("┌", C) + color(left, C, BOLD) + color(pad_top + right + "┐", C)
    midl = color("│", C) + color(mid, GREY) + pad_mid + color("│", C)
    bot = color("└" + "─" * inner + "┘", C)
    return f"\n{top}\n{midl}\n{bot}"


def step(n: int, text: str) -> str:
    tag = color(f"[passo {n}]", DIM, BOLD)
    return f"\n{tag} 🤔 {color(text, CYAN)}"


def tool_call(name: str, args: str) -> str:
    return "   " + color("⚙️  " + name + "(" + args + ")", YELLOW)


def tool_result(preview: str) -> str:
    return "      " + color("↳ " + preview, GREY)


def warn(text: str) -> str:
    return color(f"\n⚠️  {text}", YELLOW)


def flag_capture(flag: str, steps: int) -> str:
    plain = f"🏁 FLAG CAPTURADA: {flag}  (em {steps} passos)"
    if not FANCY:
        return "\n" + plain
    art = color("   🏁  F L A G   C A P T U R A D A  🏁", GREEN, BOLD)
    sub = color(f"        ✓ {flag}  ·  {steps} passos", GREEN)
    return "\n" + art + "\n" + sub + "\n" + color(plain, GREEN, DIM)


def bar(value: float, vmax: float, width: int = 8) -> str:
    """Barrinha proporcional (placar). Sem cor fora de TTY."""
    if vmax <= 0:
        filled = 0
    else:
        filled = max(1, round(width * value / vmax)) if value > 0 else 0
    s = "▇" * filled + "░" * (width - filled)
    return color(s, CYAN)


class Spinner:
    """Spinner Braille transitorio enquanto algo demora (ex: chamada ao LLM).

    Inerte (no-op) fora de TTY: nao escreve nada, nao atrapalha pipe/arquivo.
    """

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, text: str) -> None:
        self.text = text
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start = 0.0

    def __enter__(self) -> "Spinner":
        if FANCY:
            self._start = time.time()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def _run(self) -> None:
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            el = time.time() - self._start
            sys.stdout.write(
                f"\r{CYAN}{frame}{RESET} {self.text} {DIM}{el:5.1f}s{RESET}  "
            )
            sys.stdout.flush()
            time.sleep(0.1)

    def __exit__(self, *exc) -> None:
        if FANCY and self._thread:
            self._stop.set()
            self._thread.join()
            sys.stdout.write("\r\033[K")  # limpa a linha do spinner
            sys.stdout.flush()
