# Multi-stage Docker build for Hoax Threat Detection System

# Stage 1: Builder
FROM python:3.9-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --user --no-cache-dir -r requirements.txt

# Download NLP models
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download en_core_web_lg && \
    python -m nltk.downloader punkt stopwords vader_lexicon averaged_perceptron_tagger

# Stage 2: Runtime
FROM python:3.9-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data/models

# Set environment variables
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Expose ports
EXPOSE 8000 8501 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/ || exit 1

# Default command
CMD ["python", "main.py", "--mode", "both"]