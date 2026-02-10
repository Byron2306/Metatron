# Seraph AI Defense System - Backend Dockerfile
# ==============================================
# FastAPI backend with security tools and CCE Worker

FROM python:3.11-slim

LABEL maintainer="Seraph AI Team"
LABEL description="Seraph AI Defense System Backend"
LABEL version="5.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    # WireGuard tools
    wireguard-tools \
    # Network tools
    nmap \
    tcpdump \
    # Process tools
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /var/lib/seraph-ai/vpn \
    && mkdir -p /app/scripts \
    && mkdir -p /app/playbooks \
    && mkdir -p /app/services \
    && chmod -R 755 /app

# Copy playbooks if they exist
COPY playbooks/ /app/playbooks/ 2>/dev/null || true

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/api/health || exit 1

# Run the application with CCE Worker
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
