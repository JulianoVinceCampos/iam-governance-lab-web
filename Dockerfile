# Container do iam-governance-lab.
# Serve a API e o dashboard em 0.0.0.0:8000. O estado vive num arquivo SQLite sob /data
# (monte um volume para sobreviver a restart). O YAML em /app/data é o seed.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IAMGOV_DATA_DIR=/app/data \
    IAMGOV_DB_PATH=/data/iamgov.db

WORKDIR /app

# Instala o pacote primeiro (melhor cache de layer).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# O seed YAML não faz parte do wheel; copie explicitamente.
COPY data ./data

RUN mkdir -p /data && useradd --create-home --uid 10001 app && chown -R app /data /app
USER app

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=4).status==200 else 1)"

CMD ["uvicorn", "iamgov.api:app", "--host", "0.0.0.0", "--port", "8000"]
