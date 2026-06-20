"""Camada de LLM trocavel (provider-agnostic).

O resto do agente so conhece a interface `LLMClient`. Hoje a implementacao e
Ollama local (sem API key), mas plugar OpenAI/Groq/etc e so escrever outra
classe com o mesmo metodo `chat`.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Protocol

import requests

DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[dict] = field(default_factory=list)  # [{"name", "arguments"}]


class LLMClient(Protocol):
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse: ...


class OllamaClient:
    """Cliente para a API REST local do Ollama (/api/chat com tool calling)."""

    def __init__(
        self,
        model: str = "qwen2.5:7b-instruct",
        host: str | None = None,
        timeout: int = 180,
        temperature: float = 0.2,
    ) -> None:
        self.model = model
        self.host = (host or DEFAULT_HOST).rstrip("/")
        self.timeout = timeout
        self.temperature = temperature

    def wait_until_ready(self, attempts: int = 60, delay: float = 2.0) -> None:
        """Espera o servidor Ollama responder (util ao subir junto no compose)."""
        for i in range(attempts):
            try:
                requests.get(f"{self.host}/api/tags", timeout=5).raise_for_status()
                return
            except requests.RequestException:
                if i == 0:
                    print(f"⏳ aguardando Ollama em {self.host} ...")
                time.sleep(delay)
        raise RuntimeError(f"Ollama nao respondeu em {self.host}")

    def ensure_model(self) -> None:
        """Garante que o modelo esta baixado; puxa via /api/pull se faltar."""
        tags = requests.get(f"{self.host}/api/tags", timeout=10).json().get("models", [])
        if any(m.get("name", "").startswith(self.model) for m in tags):
            return
        print(f"⬇️  baixando modelo {self.model} (so na primeira vez)...")
        with requests.post(
            f"{self.host}/api/pull",
            json={"model": self.model, "stream": True},
            stream=True,
            timeout=None,
        ) as resp:
            resp.raise_for_status()
            last = ""
            for line in resp.iter_lines():
                if not line:
                    continue
                status = json.loads(line).get("status", "")
                if status and status != last:
                    print(f"   {status}")
                    last = status

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        resp = requests.post(
            f"{self.host}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "stream": False,
                "options": {"temperature": self.temperature},
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        msg = resp.json().get("message", {}) or {}

        tool_calls: list[dict] = []
        for call in msg.get("tool_calls") or []:
            fn = call.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append({"name": fn.get("name", ""), "arguments": args or {}})

        return LLMResponse(content=msg.get("content", "") or "", tool_calls=tool_calls)
