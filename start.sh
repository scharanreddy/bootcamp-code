#!/usr/bin/env bash
# All-in-one entrypoint: runs the FastAPI backend and the Streamlit frontend in
# one container (used by Hugging Face Spaces, which exposes a single port).
# docker-compose overrides this to run each service separately.
set -euo pipefail

# Run from the project root so the packages resolve, and use `python -m` so the
# current directory is on sys.path (no editable install needed in the image).
cd /app

# Start the FastAPI backend in the background on the internal port.
python -m uvicorn threatlens_ai.backend.main:app --host 0.0.0.0 --port 8000 &

# Wait for the backend to become healthy so the first page load succeeds.
for _ in $(seq 1 30); do
    if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Start the Streamlit frontend in the foreground on the public port.
# Hugging Face Spaces uses 7860 by default; PORT is honored if the platform sets it.
exec python -m streamlit run threatlens_ai/frontend/app.py \
    --server.port "${PORT:-7860}" \
    --server.address 0.0.0.0 \
    --server.headless true
