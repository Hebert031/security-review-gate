#!/usr/bin/env bash
# Roda a gincana trocando FACIL entre o Ollama LOCAL e um Ollama no RUNPOD,
# e entre modelos. So o LLM muda de lugar; os alvos CTF seguem locais.
#
# Uso:
#   ./run_model.sh local                  # qwen2.5:7b no seu Ollama local
#   ./run_model.sh runpod                 # glm4:9b no pod do RunPod
#   MODEL=glm4:9b ONLY=1 ./run_model.sh runpod     # so o nivel 1
#   ONLY=8,9 ./run_model.sh runpod                 # niveis 8 e 9
#   ATTEMPTS=1 ./run_model.sh runpod               # confiabilidade crua
#   RUNPOD_URL=https://outro-pod-11434.proxy.runpod.net ./run_model.sh runpod
#
# Variaveis: MODEL, ONLY, ATTEMPTS, RUNPOD_URL
set -euo pipefail
cd "$(dirname "$0")"

# URL do pod RunPod: env RUNPOD_URL > arquivo .endpoint (use ./endpoint.sh) > padrao
FILE_URL="$(cat .endpoint 2>/dev/null || echo https://ca96oj7hww47qu-11434.proxy.runpod.net)"
RUNPOD_URL="${RUNPOD_URL:-$FILE_URL}"

BACKEND="${1:-runpod}"
case "$BACKEND" in
  local)
    HOST="http://ollama:11434"; DEPS=();        MODEL="${MODEL:-qwen2.5:7b-instruct}" ;;
  runpod)
    HOST="$RUNPOD_URL";         DEPS=(--no-deps); MODEL="${MODEL:-glm-4.7-flash:latest}" ;;
  *)
    echo "uso: $0 [local|runpod]   (vars: MODEL, ONLY, ATTEMPTS, RUNPOD_URL)"; exit 1 ;;
esac

ENVS=(-e OLLAMA_HOST="$HOST" -e MODEL="$MODEL")
[[ -n "${ONLY:-}" ]]         && ENVS+=(-e ONLY="$ONLY")
[[ -n "${ATTEMPTS:-}" ]]     && ENVS+=(-e ATTEMPTS="$ATTEMPTS")
# Token Bearer (pod protegido pelo proteger.sh). Sem ele, nada muda.
[[ -n "${OLLAMA_TOKEN:-}" ]] && ENVS+=(-e OLLAMA_TOKEN="$OLLAMA_TOKEN")

echo "▶ backend=$BACKEND  host=$HOST  model=$MODEL  only=${ONLY:-todos}  attempts=${ATTEMPTS:-2}"
exec docker compose run --rm "${DEPS[@]}" "${ENVS[@]}" agent
