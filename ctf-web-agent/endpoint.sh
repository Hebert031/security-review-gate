#!/usr/bin/env bash
# Mostra ou troca a URL do Ollama remoto (RunPod) usada por chat.sh e run_model.sh.
#
# Uso:
#   ./endpoint.sh                 # mostra a URL atual
#   ./endpoint.sh <url>           # define uma URL nova
#   ./endpoint.sh ca96oj7hww47qu  # so o ID do pod (monta a URL :11434 sozinho)
set -euo pipefail
cd "$(dirname "$0")"

FILE=".endpoint"
DEFAULT="https://ca96oj7hww47qu-11434.proxy.runpod.net"

if [[ $# -eq 0 ]]; then
  if [[ -f "$FILE" ]]; then
    echo "endpoint atual: $(cat "$FILE")"
  else
    echo "endpoint atual: $DEFAULT  (padrao, sem $FILE)"
  fi
  exit 0
fi

arg="$1"
# Se passar so o ID do pod (sem http nem ponto), monta a URL completa.
if [[ "$arg" != http* && "$arg" != *.* ]]; then
  url="https://${arg}-11434.proxy.runpod.net"
else
  url="$arg"
fi

echo "$url" > "$FILE"
echo "endpoint salvo em $FILE: $url"
