# ThreatLens AI

ThreatLens AI is a scaffolded threat intelligence platform with a FastAPI backend, Streamlit frontend, and LangGraph-based agent orchestration.

## Features

- FastAPI backend for API endpoints
- Streamlit frontend for interactive UI
- LangGraph agent orchestration shell
- Production-ready Docker and Compose support
- Python 3.12 compatible

## Project Structure

- `threatlens_ai/` - main application package
- `threatlens_ai/backend/` - FastAPI backend code
- `threatlens_ai/frontend/` - Streamlit application
- `threatlens_ai/agent/` - LangGraph orchestration placeholders
- `threatlens_ai/models/` - shared domain models and schemas
- `threatlens_ai/utils/` - shared utilities

## Setup

1. Create a virtual environment with Python 3.12

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Copy environment variables

```bash
cp .env.example .env
```

## Running Locally

### Backend

```bash
uvicorn threatlens_ai.backend.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
streamlit run threatlens_ai.frontend.app --server.port 8501
```

## Docker

```bash
docker-compose up --build
```

## Notes

This repository is scaffolded with placeholders for business logic. Implement actual threat analysis, orchestration, and UI flow in the corresponding modules.
