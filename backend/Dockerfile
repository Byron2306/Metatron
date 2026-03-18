# syntax=docker/dockerfile:1.7
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
    ca-certificates \
    gnupg \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libffi-dev \
    libssl-dev \
    git \
    # WireGuard tools
    wireguard-tools \
    iproute2 \
    iptables \
    openresolv \
    # Detection/forensics tooling
    suricata \
    yara \
    jq \
    # Compression/dev libs useful for Volatility builds
    liblzma-dev \
    zlib1g-dev \
    # Network tools
    nmap \
    tcpdump \
    # Process tools
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy binary
RUN set -eux; \
        TRIVY_VERSION="0.69.3"; \
        ARCH="$(dpkg --print-architecture)"; \
        case "$ARCH" in \
            amd64) TRIVY_ARCH="64bit" ;; \
            arm64) TRIVY_ARCH="ARM64" ;; \
            *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
        esac; \
        wget -qO /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
        tar -xzf /tmp/trivy.tar.gz -C /tmp trivy; \
        mv /tmp/trivy /usr/local/bin/trivy; \
        chmod +x /usr/local/bin/trivy; \
        rm -f /tmp/trivy.tar.gz

# Create app directory
WORKDIR /app

# Ensure backend package modules are on Python path so imports like
# `from routers.*` work when running `uvicorn backend.server:app`.
ENV PYTHONPATH=/app/backend:/app

# Copy requirements and install Python dependencies
# When building from the repository root context, the requirements file is at backend/requirements.txt
COPY backend/requirements.txt requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# Install Volatility 3 for memory analysis.  AVML is handy but
# the Python package isn't available on PyPI and cloning from GitHub
# can fail in restricted networks, so we omit it here; the code
# already handles its absence gracefully.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir volatility3

# Install liboqs and Python bindings for production quantum mode
RUN set -eux; \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs; \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON; \
    cmake --build /tmp/liboqs/build; \
    cmake --install /tmp/liboqs/build; \
    ldconfig; \
    pip install liboqs-python; \
    rm -rf /tmp/liboqs

# Copy application code
# When building from the repository root context, copy the `backend` directory into the image
COPY backend/ backend/

# Create necessary directories
RUN mkdir -p /var/lib/seraph-ai/vpn \
    && mkdir -p /app/scripts \
    && mkdir -p /app/playbooks \
    && mkdir -p /app/services \
    && chmod -R 755 /app

# Expose port
EXPOSE 8001

# Health check - use a simple port check with a slightly longer timeout
HEALTHCHECK --interval=30s --timeout=20s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8001/api/health || exit 1
# NOTE: the earlier 10s timeout was being exceeded during heavy background work
# (network scans, threat intel updates) which caused the container to be marked
# unhealthy even though the service was still operating.  The longer timeout
# makes the check more tolerant until the underlying issue can be optimized.

# Run the application with CCE Worker
CMD ["uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8001"]
