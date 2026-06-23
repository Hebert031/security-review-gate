# Template RunPod — Ollama (GPU NVIDIA) + token Bearer

Imagem que sobe sozinha: Ollama usando a GPU do pod, baixa o(s) modelo(s) GLM e
expõe **apenas a porta 8080 protegida por `Authorization: Bearer <token>`**
(Caddy na frente). Substitui o `proteger.sh` manual — já vem protegido de boot.

```
cliente  ->  :8080 (Caddy, exige Bearer)  ->  127.0.0.1:11434 (Ollama / GPU)
```

## 1. Build e push da imagem

Precisa de uma conta num registry (Docker Hub, GHCR, etc.). Exemplo Docker Hub:

```bash
cd infra/runpod
docker build -t SEU_USUARIO/ollama-glm-token:latest .
docker push SEU_USUARIO/ollama-glm-token:latest
```

> O build não precisa de GPU; o uso de GPU acontece no RunPod, em runtime.

## 2. Criar o template no RunPod

Em **Templates → New Template**:

- **Container Image:** `SEU_USUARIO/ollama-glm-token:latest`
- **Container Disk:** ~20 GB (modelo + sistema).
- **Volume (recomendado):** monte um volume em **`/root/.ollama`** — assim os
  modelos baixados **persistem** entre reinícios (não rebaixa toda vez).
- **Expose HTTP Ports:** `8080`  ← **só essa**. **NÃO** exponha a 11434.
- **Environment Variables:**
  | Nome | Valor | Para quê |
  |------|-------|----------|
  | `OLLAMA_TOKEN` | um hex fixo (ex.: `openssl rand -hex 32`) | token **estável** entre reinícios |
  | `OLLAMA_MODELS` | `glm-4.7-flash:latest` | modelo(s) a baixar (vírgula p/ vários) |

  > Se **não** definir `OLLAMA_TOKEN`, o entrypoint gera um a cada boot e o
  > imprime no log do pod (muda toda vez — menos prático).

- **GPU:** escolha uma NVIDIA (ex.: RTX 2000/3000/4000, A-series…). O Ollama
  detecta e usa a GPU automaticamente (runtime CUDA já está na imagem base).

## 3. Usar no agent (sua máquina)

```bash
./endpoint.sh https://SEU_POD-8080.proxy.runpod.net
mkdir -p secrets && echo "SEU_OLLAMA_TOKEN" > secrets/ollama_token   # gitignored
./run_model.sh runpod
```

`chat.sh` e `run_model.sh` leem o token de `secrets/ollama_token`
automaticamente (ou da env `OLLAMA_TOKEN`).

## 4. Conferir

```bash
URL=https://SEU_POD-8080.proxy.runpod.net
curl -s -o /dev/null -w "%{http_code}\n" "$URL/api/tags"                          # 401
curl -s -o /dev/null -w "%{http_code}\n" "$URL/api/tags" -H "Authorization: Bearer SEU_TOKEN"  # 200
```

## Notas

- **Vários modelos:** `OLLAMA_MODELS="glm-4.7-flash:latest,glm4:9b,glm4:latest"`.
- **Cold start:** sem volume, o 1º boot baixa o modelo (alguns GB) — leva uns
  minutos. Com volume em `/root/.ollama`, só na primeira vez.
- **Segurança:** o token nunca vai pro repositório (fica em env do RunPod e em
  `secrets/` local, gitignorado). Garanta que **só a 8080** está exposta.
