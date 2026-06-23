#!/usr/bin/env bash
#
# Entrypoint do template RunPod: Ollama interno + Caddy com token na porta 8080.
# Fluxo: cliente -> :8080 (Caddy, exige Bearer) -> 127.0.0.1:11434 (Ollama/GPU).
set -euo pipefail

MODELS="${OLLAMA_MODELS:-glm-4.7-flash:latest}"     # lista separada por virgula
PROXY_PORT="${PROXY_PORT:-8080}"
OLLAMA_PORT="${OLLAMA_INTERNAL_PORT:-11434}"

# --- Token: usa OLLAMA_TOKEN do ambiente (estavel entre reinicios) ou gera um.
if [[ -z "${OLLAMA_TOKEN:-}" ]]; then
  OLLAMA_TOKEN="$(openssl rand -hex 32)"
  echo "================================================================"
  echo " OLLAMA_TOKEN nao foi definido no template — gerei um agora."
  echo " (defina OLLAMA_TOKEN nas envs do RunPod para um token FIXO.)"
  echo "================================================================"
fi
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
cat > /etc/caddy/Caddyfile <<EOF
:${PROXY_PORT} {
    @noauth {
        not header Authorization "Bearer ${OLLAMA_TOKEN}"
    }
    respond @noauth "Unauthorized" 401

    reverse_proxy 127.0.0.1:${OLLAMA_PORT}
}
EOF
echo "==> Caddy escutando na porta ${PROXY_PORT} (exige Bearer token)."

# --- 4. Caddy em foreground = PID principal do container (mantem o pod vivo).
exec caddy run --config /etc/caddy/Caddyfile
