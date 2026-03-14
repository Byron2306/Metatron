FROM python:3.11-slim

LABEL maintainer="Seraph AI Team"
LABEL description="Lightweight Volatility 3 helper image"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    liblzma-dev \
    zlib1g-dev \
    git \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/volatility

# Install volatility3.  We could also add AVML from GitHub but
# many environments block git operations; install it manually later
# if needed.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir volatility3

# Keep container alive to allow exec into it for ad-hoc runs
CMD ["tail", "-f", "/dev/null"]
