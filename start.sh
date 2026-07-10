#!/usr/bin/env bash
# All-in-one entrypoint: runs the FastAPI backend and the Streamlit frontend in
# one container (used by Hugging Face Spaces, which exposes a single port).
# docker-compose overrides this to run each service separately.
set -euo pipefail

# Start the FastAPI backend in the background on the internal port.
uvicorn threatlens_ai.backend.main:app --host 0.0.0.0 --port 8000 &

# Wait for the backend to become healthy so the first page load succeeds.
for _ in $(seq 1 30); do
    if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Start the Streamlit frontend in the foreground on the public port.
# Hugging Face Spaces uses 7860 by default; PORT is honored if the platform sets it.
exec streamlit run threatlens_ai/frontend/app.py \
    --server.port "${PORT:-7860}" \
    --server.address 0.0.0.0 \
    --server.headless true
