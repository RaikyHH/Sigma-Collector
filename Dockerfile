# Dockerfile for Sigma Rule Collector

# --- Base Stage ---
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


# --- Builder Stage ---
FROM base AS builder

WORKDIR /app
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# --- Final Stage ---
FROM base

RUN adduser --system --group appuser

# NEU: Das Skript wird an einen festen Ort für den Quellcode kopiert.
WORKDIR /usr/src/app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY sigma-collector.py .
RUN chown -R appuser:appuser /usr/src/app

RUN mkdir /data && chown appuser:appuser /data
WORKDIR /data

USER appuser



CMD ["python", "/usr/src/app/sigma-collector.py"]
