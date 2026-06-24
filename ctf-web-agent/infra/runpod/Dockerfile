# Template RunPod: Ollama (GPU NVIDIA) + gate de token via Caddy (header X-Ollama-Token).
#
# Base = imagem oficial do Ollama (ja traz o runtime CUDA; usa a GPU do pod
# automaticamente quando ha uma). Em cima dela instalamos o Caddy e trocamos o
# entrypoint para: subir o Ollama interno, baixar o(s) modelo(s) e expor so a
# porta 8080 protegida pelo header X-Ollama-Token (o proxy do RunPod derruba
# Authorization, por isso header proprio).
FROM ollama/ollama:latest

# Caddy + utilitarios (curl/openssl ja ajudam no entrypoint).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl openssl gnupg debian-keyring debian-archive-keyring apt-transport-https ca-certificates \
 && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
 && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null \
 && apt-get update \
 && apt-get install -y --no-install-recommends caddy \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/caddy

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Defaults (sobrescreva no template do RunPod via env).
ENV OLLAMA_MODELS="glm-4.7-flash:latest" \
    PROXY_PORT=8080 \
    OLLAMA_INTERNAL_PORT=11434

# A imagem base define ENTRYPOINT ["/bin/ollama"]; trocamos pelo nosso.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Porta exposta: SO a 8080 (protegida). Nao exponha a 11434.
EXPOSE 8080
