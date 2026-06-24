#!/usr/bin/env bash
#
# Protege a API do Ollama no RunPod com um token Bearer via Caddy (porta 8080).
# O Ollama continua na 11434 (interno); o Caddy atende na 8080 exigindo o token.
# Fluxo: Proxy RunPod :8080 -> Caddy (exige token) -> Ollama (127.0.0.1:11434)
#
# COMO USAR (dentro do pod):
#   1. chmod +x proteger.sh
#   2. ./proteger.sh
#   3. Guarde o token impresso.
#   4. No painel do RunPod: EXPONHA a porta 8080 e REMOVA a 11434 da exposicao
#      (senao a 11434 continua aberta SEM token e fura a protecao).
#   5. No agent: aponte o endpoint para a URL -8080 e use OLLAMA_TOKEN.
set -euo pipefail

PROXY_PORT=8080       # porta do Caddy (a que voce expoe no RunPod)
OLLAMA_PORT=11434     # porta do Ollama (interna)

echo "==> Gerando token de acesso..."
TOKEN=$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | xxd -p -c32)
echo "    Token gerado (GUARDE EM LOCAL SEGURO):"
echo
echo "    $TOKEN"
echo

echo "==> Instalando Caddy..."
apt-get update -qq
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg >/dev/null
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
apt-get update -qq
apt-get install -y -qq caddy >/dev/null
echo "    Caddy instalado."

echo "==> Garantindo o Ollama escutando na ${OLLAMA_PORT} (localhost)..."
echo "    (o Ollama padrao ja escuta em 127.0.0.1:${OLLAMA_PORT} — nao mexemos nele)"

echo "==> Escrevendo Caddyfile (Caddy atende a porta ${PROXY_PORT})..."
mkdir -p /etc/caddy
# Gate por header CUSTOMIZADO X-Ollama-Token (NAO Authorization): o proxy do
# RunPod intercepta o header Authorization e devolve 403 antes de chegar aqui.
cat > /etc/caddy/Caddyfile <<EOF
:${PROXY_PORT} {
    @noauth {
        not header X-Ollama-Token "${TOKEN}"
    }
    respond @noauth "Unauthorized" 401

    reverse_proxy 127.0.0.1:${OLLAMA_PORT}
}
EOF
echo "    /etc/caddy/Caddyfile pronto."

echo "==> Subindo o Caddy em background na porta ${PROXY_PORT}..."
pkill -f "caddy run" 2>/dev/null || true
sleep 1
nohup caddy run --config /etc/caddy/Caddyfile > /var/log/caddy.log 2>&1 &
sleep 2
echo "    Caddy rodando na porta ${PROXY_PORT}. Logs em /var/log/caddy.log"

echo "==> Auto-teste dentro do pod..."
echo -n "    sem token (quer 401): "; curl -s -o /dev/null -w "%{http_code}\n" "127.0.0.1:${PROXY_PORT}/api/tags"
echo -n "    com token (quer 200): "; curl -s -o /dev/null -w "%{http_code}\n" "127.0.0.1:${PROXY_PORT}/api/tags" -H "X-Ollama-Token: ${TOKEN}"

echo
echo "==============================================================="
echo " PRONTO!"
echo "==============================================================="
echo " 1. No RunPod: EXPONHA a porta ${PROXY_PORT} e REMOVA a ${OLLAMA_PORT}"
echo "    (a 11434 exposta continua SEM token — tem que tirar)."
echo
echo " 2. Teste de fora do pod:"
echo "    curl https://SEU_POD-${PROXY_PORT}.proxy.runpod.net/api/tags \\"
echo "      -H \"X-Ollama-Token: ${TOKEN}\""
echo
echo " 3. No agent (sua maquina):"
echo "    ./endpoint.sh https://SEU_POD-${PROXY_PORT}.proxy.runpod.net"
echo "    export OLLAMA_TOKEN=${TOKEN}"
echo "    ./run_model.sh runpod"
echo "==============================================================="
