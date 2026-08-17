FROM python:3.12-slim

# Distroless-like: minimal system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy models for PII detection
RUN python -m spacy download pt_core_news_sm && \
    python -m spacy download en_core_web_sm

COPY app ./app

# Run as non-root user
RUN useradd -r -u 1001 appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
