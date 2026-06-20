# CTF Web Agent

Uma IA autônoma que resolve desafios de **CTF de Web**. Recebe a URL de um
desafio e a meta ("ache a flag") e hackeia sozinha num loop ReAct: observa a
resposta HTTP → raciocina → escolhe a próxima ação, até capturar a `flag{...}`.

> ⚠️ Ambiente de laboratório autorizado. O agente só atinge hosts numa
> **allowlist** (por padrão `127.0.0.1`/`localhost`). Os alvos em `targets/`
> são vulneráveis de propósito e rodam só localmente. Não use contra sistemas
> de terceiros sem autorização.

## Arquitetura

```
Claude/Qwen (cérebro)  →  http_request() / submit_flag()  →  alvo local vulnerável
   loop ReAct                 guarda de allowlist               sandbox isolado
```

- `agent/llm.py` — camada de LLM **trocável** (hoje: Ollama local, sem API key).
- `agent/tools.py` — ferramentas + guarda de allowlist (host fora da lista = bloqueado).
- `agent/loop.py` — loop ReAct que liga cérebro e ferramentas.
- `targets/` — desafios vulneráveis de propósito (nível 1: SQL injection).
- `run.py` — lança o agente contra um alvo.
- `smoke_test.py` — valida alvo + ferramentas **sem LLM**.

## Opção A — Docker (recomendado, reproduzível)

Sobe **ollama + alvo + agente** numa rede isolada. O alvo nem publica porta no
host, e o modelo é baixado automaticamente na primeira vez.

```bash
cd ctf-web-agent

# sobe tudo e mostra o agente resolvendo (a 1ª vez baixa imagens + modelo)
docker compose up --build

# (opcional) modelo menor/mais rápido em CPU
MODEL=qwen2.5:3b-instruct docker compose up --build

# limpar containers, rede e cache de modelos
docker compose down -v
```

A primeira execução demora (baixa a imagem do Ollama e o modelo ~4–5 GB). As
seguintes são rápidas — o modelo fica cacheado no volume `ollama_models`.

> GPU: o `docker-compose.yml` já reserva a NVIDIA (toolkit detectado no host).
> Se der erro de GPU, comente o bloco `deploy:` do serviço `ollama` para rodar
> em CPU.

## Opção B — Local (sem Docker)

Pré-requisitos: **Ollama** + Python 3.11 com `requests`.

```bash
# instala o Ollama e baixa um modelo bom em tool calling
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct

# 1) valida a fundação — NÃO precisa de Ollama
python3 smoke_test.py

# 2) sobe o alvo vulnerável (deixe rodando num terminal)
python3 targets/level1_sqli.py

# 3) solte o agente contra o alvo (em outro terminal)
python3 run.py --target http://127.0.0.1:8000 \
               --expected-flag 'flag{sql_1nj3ct10n_b00tstr4p}'
```

### Flags úteis do `run.py`

| Flag | Padrão | Para quê |
|---|---|---|
| `--target` | `http://127.0.0.1:8000` | URL do desafio |
| `--model` | `qwen2.5:7b-instruct` | modelo do Ollama |
| `--ollama-host` | `http://localhost:11434` | onde o Ollama está |
| `--max-steps` | `15` | teto de ações do agente |
| `--no-pull` | — | não baixar o modelo se faltar |
| `--expected-flag` | — | valida a captura ao final |

## Roadmap

- [x] Nível 1 — SQL injection (bypass de login)
- [ ] Nível 2 — IDOR (acesso a recurso de outro usuário)
- [ ] Nível 3 — SSRF
- [ ] Placar / cronômetro (quantos passos a IA levou)
- [ ] Plugar outros LLMs (Groq, OpenAI) na mesma interface
