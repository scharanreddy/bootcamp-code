FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8000
EXPOSE 8501

CMD ["uvicorn", "threatlens_ai.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
