FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY run.py .

ENV PYTHONUNBUFFERED=1 \
    GHOSTINDEX_HOST=0.0.0.0 \
    GHOSTINDEX_PORT=8787 \
    GHOSTINDEX_KEEP_ADMIN=true

EXPOSE 8787
VOLUME ["/app/data"]

CMD ["python", "-c", "import uvicorn; from app.config import get_settings; s=get_settings(); uvicorn.run('app.main:app', host=s.host, port=s.port)"]
