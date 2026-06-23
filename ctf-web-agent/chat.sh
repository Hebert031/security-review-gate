#!/usr/bin/env bash
# Troca simples com o Ollama remoto (RunPod).
# Uso: ./chat.sh "sua pergunta aqui"
set -euo pipefail
cd "$(dirname "$0")"

# Endpoint: env OLLAMA_HOST > arquivo .endpoint > padrao
FILE_HOST="$(cat .endpoint 2>/dev/null || echo https://ca96oj7hww47qu-11434.proxy.runpod.net)"
HOST="${OLLAMA_HOST:-$FILE_HOST}"
MODEL="${OLLAMA_MODEL:-glm-4.7-flash:latest}"
PROMPT="${*:-Diga ola em uma frase.}"

curl -s -m 120 "$HOST/api/chat" -d "$(jq -n \
  --arg m "$MODEL" --arg p "$PROMPT" \
  '{model:$m, stream:false, messages:[{role:"user", content:$p}]}')" \
  | jq -r '.message.content'
