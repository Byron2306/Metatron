FROM python:3.11-slim

# Install system dependencies for scanning and VPN
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Container management
    docker.io \
    curl \
    # Network / LAN discovery
    nmap \
    iproute2 \
    net-tools \
    arp-scan \
    iputils-ping \
    # WiFi scanning
    iw \
    wireless-tools \
    # Bluetooth scanning
    bluez \
    bluetooth \
    # WireGuard VPN
    wireguard-tools \
    # Security / malware scanning
    yara \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir flask flask-cors requests psutil yara-python

# Copy unified_agent package
COPY unified_agent/ /app/unified_agent/

WORKDIR /app/unified_agent/ui/web

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "5000"]
