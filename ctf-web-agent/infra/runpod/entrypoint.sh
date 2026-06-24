#!/usr/bin/env bash
#
# Entrypoint do template RunPod: Ollama interno + Caddy com token na porta 8080.
# Fluxo: cliente -> :8080 (Caddy, exige X-Ollama-Token) -> 127.0.0.1:11434 (Ollama/GPU).
set -euo pipefail

MODELS="${OLLAMA_MODELS:-glm-4.7-flash:latest}"     # lista separada por virgula
PROXY_PORT="${PROXY_PORT:-8080}"
OLLAMA_PORT="${OLLAMA_INTERNAL_PORT:-11434}"
# Arquivo onde o token fica persistido (no volume /root/.ollama => sobrevive a reinicios).
TOKEN_FILE="${OLLAMA_TOKEN_FILE:-/root/.ollama/ollama_token}"

# --- Token: resolve em 3 niveis, do mais forte ao mais fraco:
#   1) env OLLAMA_TOKEN   -> fonte da verdade (defina = ao seu secrets/ollama_token)
#   2) arquivo persistido -> estavel entre reinicios mesmo sem env
#   3) gera um novo       -> e persiste no arquivo para os proximos boots
mkdir -p "$(dirname "$TOKEN_FILE")"
if [[ -n "${OLLAMA_TOKEN:-}" ]]; then
  echo "$OLLAMA_TOKEN" > "$TOKEN_FILE"
  echo "==> Token: usando OLLAMA_TOKEN do ambiente (persistido em $TOKEN_FILE)."
elif [[ -s "$TOKEN_FILE" ]]; then
  OLLAMA_TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  echo "==> Token: reutilizando o persistido em $TOKEN_FILE."
else
  OLLAMA_TOKEN="$(openssl rand -hex 32)"
  echo "$OLLAMA_TOKEN" > "$TOKEN_FILE"
  echo "================================================================"
  echo " OLLAMA_TOKEN nao definido e sem token persistido — gerei um novo."
  echo " (defina OLLAMA_TOKEN nas envs do RunPod para fixar via secrets.)"
  echo "================================================================"
fi
chmod 600 "$TOKEN_FILE" 2>/dev/null || true
echo "==> TOKEN DE ACESSO (use no agent: OLLAMA_TOKEN=...):"
echo
echo "    ${OLLAMA_TOKEN}"
echo

# --- 1. Ollama interno (so localhost; a GPU NVIDIA e detectada pela base).
export OLLAMA_HOST="127.0.0.1:${OLLAMA_PORT}"
echo "==> Subindo o Ollama em 127.0.0.1:${OLLAMA_PORT} ..."
ollama serve >/var/log/ollama.log 2>&1 &

echo "==> Aguardando o Ollama responder ..."
until curl -sf "127.0.0.1:${OLLAMA_PORT}/api/tags" >/dev/null 2>&1; do sleep 1; done
echo "    Ollama pronto."

# --- 2. Baixar modelo(s). Com volume em /root/.ollama, so baixa na 1a vez.
IFS=',' read -ra LIST <<< "$MODELS"
for m in "${LIST[@]}"; do
  m="$(echo "$m" | xargs)"   # trim
  [[ -z "$m" ]] && continue
  echo "==> ollama pull ${m}"
  ollama pull "$m"
done

# --- 3. Caddyfile: gate de token na porta publica.
# Gate por header CUSTOMIZADO X-Ollama-Token (NAO Authorization): o proxy do
# RunPod intercepta o header Authorization e devolve 403 antes de chegar aqui.
# header_up Host: o Ollama recusa requisicoes com Host != localhost (403). Pela
# URL publica o Host vira *.proxy.runpod.net; reescrevemos para o upstream local.
cat > /etc/caddy/Caddyfile <<EOF
:${PROXY_PORT} {
	@noauth {
		not header X-Ollama-Token "${OLLAMA_TOKEN}"
	}
	respond @noauth "Unauthorized" 401

	reverse_proxy 127.0.0.1:${OLLAMA_PORT} {
		header_up Host {upstream_hostport}
	}
}
EOF
echo "==> Caddy escutando na porta ${PROXY_PORT} (exige header X-Ollama-Token)."

# --- 4. Caddy em foreground = PID principal do container (mantem o pod vivo).
exec caddy run --config /etc/caddy/Caddyfile
