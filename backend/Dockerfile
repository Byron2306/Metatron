# Anti-AI Defense System - Backend Dockerfile
# ============================================
# FastAPI backend with all security tools

FROM python:3.11-slim

LABEL maintainer="Anti-AI Defense Team"
LABEL description="Anti-AI Defense System Backend"

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
    # For memory forensics
    volatility3 || true \
    # Network tools
    nmap \
    tcpdump \
    # Container security
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
RUN mkdir -p /var/lib/anti-ai-defense/vpn \
    && mkdir -p /app/scripts \
    && mkdir -p /app/playbooks \
    && chmod -R 755 /app

# Copy playbooks
COPY playbooks/ /app/playbooks/

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/api/health || exit 1

# Run the application
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
