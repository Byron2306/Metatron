# Anti-AI Defense System - Deployment Guide

## Quick Start with Docker Compose

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Linux server with kernel 5.6+ (for WireGuard)
- 4GB+ RAM recommended
- Ports: 80, 443, 3000, 8001, 27017, 51820/udp

### 1. Clone and Configure

```bash
# Clone the repository
git clone https://github.com/your-org/anti-ai-defense.git
cd anti-ai-defense

# Copy and edit environment file
cp .env.example .env
nano .env
```

### 2. Configure Environment Variables

Edit `.env` with your settings:

```bash
# REQUIRED: Change the JWT secret
JWT_SECRET=your-very-long-random-secret-key-at-least-32-characters

# REQUIRED: Your server's public domain/IP for VPN
VPN_SERVER_ENDPOINT=your-server.example.com

# Optional: Elasticsearch for advanced analytics
ELASTICSEARCH_URL=https://your-elastic.example.com:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your-password
```

### 3. Deploy

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 4. Access the Application

- **Web UI**: http://your-server:3000
- **API**: http://your-server:8001/api
- **VPN**: your-server:51820/udp

### 5. Initial Setup

1. Open the web UI and register an admin account
2. Go to Settings to configure notifications
3. Download and deploy agents to endpoints

---

## VPN Setup

### Server Configuration

The WireGuard VPN server starts automatically. To manage peers:

```bash
# View server status
docker exec anti-ai-wireguard wg show

# View peer configs
docker exec anti-ai-wireguard ls /config/peer*

# Get peer config QR code
docker exec anti-ai-wireguard cat /config/peer1/peer1.conf
```

### Client Configuration

1. In the Web UI, go to **VPN** page
2. Click **Add Peer** to create a new peer config
3. Download the `.conf` file
4. Import into WireGuard client:
   - **Windows/Mac**: WireGuard app → Import tunnel
   - **Linux**: `wg-quick up /path/to/peer.conf`
   - **Mobile**: WireGuard app → Scan QR code

---

## Agent Deployment

### Download Agent

From the Web UI:
1. Go to **Agents** page
2. Click **Download Agent** dropdown
3. Choose **Advanced Agent** (recommended)

### Install on Endpoints

```bash
# Install dependencies
pip install psutil requests websocket-client

# Run agent with server connection
python advanced_agent.py --connect --api-url https://your-server.example.com
```

### Agent Features
- Real-time WebSocket connection for commands
- Process monitoring and threat detection
- Browser extension scanning
- Credential theft detection
- Persistence mechanism scanning
- CLI command telemetry for AI detection

### Run as Service (Linux)

```bash
# Create systemd service
sudo cat > /etc/systemd/system/anti-ai-agent.service << 'EOF'
[Unit]
Description=Anti-AI Defense Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/anti-ai-agent
ExecStart=/usr/bin/python3 advanced_agent.py --connect --api-url https://your-server.example.com
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl enable anti-ai-agent
sudo systemctl start anti-ai-agent
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Docker Host                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 anti-ai-network                           │   │
│  │                                                           │   │
│  │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐  │   │
│  │  │ Frontend│   │ Backend │   │ MongoDB │   │WireGuard│  │   │
│  │  │  :3000  │◄─►│  :8001  │◄─►│ :27017  │   │ :51820  │  │   │
│  │  │  React  │   │ FastAPI │   │         │   │   VPN   │  │   │
│  │  └─────────┘   └─────────┘   └─────────┘   └─────────┘  │   │
│  │       │              │                            │      │   │
│  └───────┼──────────────┼────────────────────────────┼──────┘   │
│          │              │                            │          │
└──────────┼──────────────┼────────────────────────────┼──────────┘
           │              │                            │
           ▼              ▼                            ▼
       Users          Agents                     VPN Clients
       (Web)        (WebSocket)                  (WireGuard)
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | React web application |
| Backend | 8001 | FastAPI REST API + WebSocket |
| MongoDB | 27017 | Database |
| WireGuard | 51820/udp | VPN server |

---

## Maintenance

### Backup Database

```bash
# Backup MongoDB
docker exec anti-ai-mongodb mongodump --out /backup
docker cp anti-ai-mongodb:/backup ./backup-$(date +%Y%m%d)

# Restore
docker cp ./backup anti-ai-mongodb:/restore
docker exec anti-ai-mongodb mongorestore /restore
```

### Update Services

```bash
# Pull latest images
docker-compose pull

# Rebuild and restart
docker-compose up -d --build
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
```

---

## Troubleshooting

### VPN Not Working

```bash
# Check WireGuard status
docker exec anti-ai-wireguard wg show

# Check kernel modules
lsmod | grep wireguard

# Enable IP forwarding (host)
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### Backend Issues

```bash
# Check health
curl http://localhost:8001/api/health

# View logs
docker-compose logs backend

# Restart service
docker-compose restart backend
```

### Database Connection

```bash
# Test MongoDB
docker exec anti-ai-mongodb mongosh --eval "db.stats()"

# Check connection from backend
docker-compose logs backend | grep -i mongo
```

---

## Security Recommendations

1. **Change JWT Secret**: Use a strong, random 64+ character secret
2. **Enable HTTPS**: Use nginx with SSL certificates
3. **Firewall**: Only expose necessary ports
4. **Updates**: Regularly update Docker images
5. **Monitoring**: Set up alerts for critical events
6. **Backup**: Regular database backups
7. **VPN**: Use VPN for all agent connections in production

---

## Support

- GitHub Issues: [Report bugs](https://github.com/your-org/anti-ai-defense/issues)
- Documentation: [Full docs](https://docs.your-org.com)
