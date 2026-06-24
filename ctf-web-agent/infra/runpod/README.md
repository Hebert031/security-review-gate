# Template RunPod — Ollama (GPU NVIDIA) + token via header X-Ollama-Token

Imagem que sobe sozinha: Ollama usando a GPU do pod, baixa o(s) modelo(s) GLM e
expõe **apenas a porta 8080 protegida pelo header `X-Ollama-Token: <token>`**
(Caddy na frente). Substitui o `proteger.sh` manual — já vem protegido de boot.

```
cliente  ->  :8080 (Caddy, exige X-Ollama-Token)  ->  127.0.0.1:11434 (Ollama / GPU)
```

> **Por que `X-Ollama-Token` e não `Authorization: Bearer`?** O proxy público do
> RunPod (`*.proxy.runpod.net`) intercepta o header `Authorization` e devolve
> **403** antes de chegar no pod. Um header próprio passa intacto até o Caddy.
>
> **Por que o Caddy reescreve o `Host`?** O Ollama recusa requisições com
> `Host` != localhost (403). Pela URL pública o Host vira `*.proxy.runpod.net`,
> então o `reverse_proxy` faz `header_up Host {upstream_hostport}`.

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
  modelos baixados **e o token** persistem entre reinícios (não rebaixa nem
  troca o token toda vez).
- **Expose HTTP Ports:** `8080`  ← **só essa**. **NÃO** exponha a 11434.
- **Environment Variables:**
  | Nome | Valor | Para quê |
  |------|-------|----------|
  | `OLLAMA_TOKEN` | um hex fixo (ex.: `openssl rand -hex 32`) | token **estável**; deve ser igual ao `secrets/ollama_token` local |
  | `OLLAMA_MODELS` | `glm-4.7-flash:latest` | modelo(s) a baixar (vírgula p/ vários) |

  > **Resolução do token (entrypoint), do mais forte ao mais fraco:**
  > 1. env `OLLAMA_TOKEN` (fonte da verdade — defina = ao seu secrets);
  > 2. arquivo persistido em `/root/.ollama/ollama_token` (estável entre boots);
  > 3. gera um novo e persiste (só se não houver nenhum dos dois).
  >
  > O token efetivo sempre aparece no log do pod e fica em
  > `/root/.ollama/ollama_token` (dá pra **consultar** lá).

- **GPU:** escolha uma NVIDIA (ex.: RTX 2000/3000/4000, A-series…). O Ollama
  detecta e usa a GPU automaticamente (runtime CUDA já está na imagem base).

## 3. Usar no agent (sua máquina)

```bash
./endpoint.sh https://SEU_POD-8080.proxy.runpod.net
mkdir -p secrets && echo "SEU_OLLAMA_TOKEN" > secrets/ollama_token   # gitignored
./run_model.sh runpod
```

`chat.sh` e `run_model.sh` leem o token de `secrets/ollama_token`
automaticamente (ou da env `OLLAMA_TOKEN`) e o enviam no header `X-Ollama-Token`.

## 4. Conferir

```bash
URL=https://SEU_POD-8080.proxy.runpod.net
curl -s -o /dev/null -w "%{http_code}\n" "$URL/api/tags"                                  # 401
curl -s -o /dev/null -w "%{http_code}\n" "$URL/api/tags" -H "X-Ollama-Token: SEU_TOKEN"   # 200
```

## Notas

- **Vários modelos:** `OLLAMA_MODELS="glm-4.7-flash:latest,glm4:9b,glm4:latest"`.
- **Cold start:** sem volume, o 1º boot baixa o modelo (alguns GB) — leva uns
  minutos. Com volume em `/root/.ollama`, só na primeira vez.
- **Rotacionar token:** mude o env `OLLAMA_TOKEN` (e o `secrets/ollama_token`),
  ou apague `/root/.ollama/ollama_token` e reinicie para gerar um novo.
- **Segurança:** o token nunca vai pro repositório (fica em env do RunPod e em
  `secrets/` local, gitignorado). **Nunca** cole o token em paste público
  (termbin/pastebin etc.). Garanta que **só a 8080** está exposta.
