FROM python:3.12-slim

# System deps: curl is used by the container healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

COPY . /app

# Run as a non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && chmod +x /app/start.sh \
    && chown -R appuser:appuser /app
USER appuser

# 8000 backend, 8501 frontend (compose), 7860 all-in-one (Hugging Face Spaces).
EXPOSE 8000 8501 7860

# Default: run both services in one container (used by Hugging Face Spaces).
# docker-compose overrides this with a per-service command.
CMD ["/app/start.sh"]
