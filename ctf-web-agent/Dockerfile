FROM python:3.12-slim

WORKDIR /app

# Dependencias primeiro (cache de camada)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Roda como usuario sem privilegio (defesa em profundidade)
RUN useradd --create-home runner
USER runner

CMD ["python3", "run.py"]
