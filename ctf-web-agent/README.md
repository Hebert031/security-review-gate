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

- `agent/llm.py` — camada de LLM **trocável** (Ollama local **ou remoto**;
  suporta token Bearer via `OLLAMA_TOKEN`).
- `agent/tools.py` — ferramentas (`http_request` com `data`/`headers`/`body`
  cru/`files` multipart, `b64_decode`, `b64_encode`, `jwt_decode`, `jwt_forge`
  (none/HS256), `jwt_crack`, `submit_flag`) + guarda de allowlist (host fora da
  lista = bloqueado).
- `agent/loop.py` — loop ReAct que liga cérebro e ferramentas.
- `targets/` — **22 desafios** vulneráveis de propósito (SQLi, IDOR, SSRF, cmd
  injection, LFI, JWT, SSTI, cookie tampering, open redirect+SSRF, mass
  assignment, verb tampering, XFF/Host spoof, file exposure, basic auth,
  business logic, verbose error, NoSQLi, GraphQL, JWT HMAC fraco, XXE,
  upload→RCE). Detalhamento técnico de cada um em **`docs/ATAQUES.md`**.
- `scoreboard.py` — sobe a gincana inteira, cronometra cada nível e ranqueia.
- `run.py` — lança o agente contra um alvo.
- `smoke_test.py` / `smoke_new.py` — validam alvos + ferramentas **sem LLM**.

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

## Gincana completa (placar)

Sobe os 22 alvos como subprocessos locais e ranqueia a IA por passos e tempo.
Só o Ollama precisa estar de pé.

```bash
python3 scoreboard.py                 # roda os 22 níveis
ONLY=4 python3 scoreboard.py          # só o nível 4
ONLY=10,15,20 python3 scoreboard.py   # níveis selecionados
REPEAT=3 python3 scoreboard.py        # 3 tentativas por nível, mede a taxa de acerto
MODEL=qwen2.5:3b-instruct python3 scoreboard.py
```

## Backend remoto (RunPod) com token

Dá pra rodar o LLM num pod com GPU no **RunPod** em vez do Ollama local — os
alvos CTF continuam locais (127.0.0.1). O `run_model.sh` troca o backend e o
`endpoint.sh` guarda a URL num lugar só.

```bash
./endpoint.sh https://SEU_POD-8080.proxy.runpod.net   # define o pod (1 lugar só)
./run_model.sh local       # LLM no Ollama local
./run_model.sh runpod      # LLM no pod (padrão)
ONLY=15,20 ./run_model.sh runpod
```

**Protegendo o pod com token.** Por padrão a API do Ollama fica aberta. O
template em **`infra/runpod/`** sobe uma imagem que já põe um **gate de token**
(Caddy na 8080 exige `Authorization: Bearer <token>`) na frente do Ollama:

- Imagem pronta: `hebertribeiro31/ollama-glm-token:latest` (público).
- No RunPod: exponha **só a 8080**, volume em `/root/.ollama` (cache do modelo),
  env `OLLAMA_MODELS=glm-4.7-flash:latest`. Deixe `OLLAMA_TOKEN` em branco para
  o pod **gerar** um token a cada boot (impresso no log) ou fixe um.
- Na sua máquina, guarde o token em `secrets/ollama_token` (gitignored) — o
  `chat.sh`/`run_model.sh` o enviam automaticamente.

Passo a passo de build/push e configuração do template: **`infra/runpod/README.md`**.
(Para proteger um pod **já existente** sem rebuildar, use `proteger.sh`.)

## Roadmap

- [x] Nível 1 — SQL injection (bypass de login)
- [x] Nível 2 — IDOR (acesso a recurso de outro usuário)
- [x] Nível 3 — SSRF (acesso a serviço interno)
- [x] Nível 4 — Command injection (`/ping?host=` → shell do servidor)
- [x] Nível 5 — Path traversal / LFI (`/download?file=../../../../flag`)
- [x] Nível 6 — JWT forge (auth bypass via `alg=none`)
- [x] Nível 7 — SSTI (`/hello?name={{7*7}}` → vaza `{{config}}` com a flag)
- [x] Nível 8 — Cookie tampering (sessão base64 sem assinatura → `role=admin`)
- [x] Nível 9 — Open redirect + SSRF (preview com allowlist burlada via `/go?to=`)
- [x] Nível 10 — Mass assignment (`role=admin` no cadastro)
- [x] Nível 11 — HTTP verb tampering (regra só cobre GET)
- [x] Nível 12 — Trusted header spoof (`X-Forwarded-For` interno)
- [x] Nível 13 — Sensitive file exposure (`robots.txt` → backup)
- [x] Nível 14 — Basic Auth com credenciais padrão
- [x] Nível 15 — Host header injection (vhost interno)
- [x] Nível 16 — Business logic (quantidade negativa)
- [x] Nível 17 — Verbose error / debug leak
- [x] Nível 18 — NoSQL injection (`password[$ne]=`)
- [x] Nível 19 — GraphQL introspection (campo escondido)
- [x] Nível 20 — JWT HMAC fraco (`jwt_crack` → forja HS256)
- [x] Nível 21 — XXE (entidade externa `file:///flag`)
- [x] Nível 22 — Upload irrestrito → RCE
- [x] Placar / cronômetro (quantos passos a IA levou)
- [x] Backend remoto (RunPod) + token Bearer + template Docker
- [ ] Arena de modelos (3B vs 7B vs 14B lado a lado)
- [ ] Plugar outros LLMs (Groq, OpenAI) na mesma interface
