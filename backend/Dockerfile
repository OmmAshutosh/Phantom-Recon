# Multi-stage Dockerfile for PHANTOM RECON v2.1 Backend
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    PHANTOM_DB_PATH=/data/phantom.db \
    PHANTOM_OUTPUT_DIR=/data/output

WORKDIR /app

# Install system dependencies needed for compiling extensions and network recon
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libxml2-dev \
    libxslt1-dev \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code, modules, configs, and wordlists
COPY . .

# Create volume mount directory for persistent SQLite database and reports
RUN mkdir -p /data/output && chmod -R 777 /data

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT}/api/health || exit 1

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
