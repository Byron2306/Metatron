# Seraph AI Defense System

<p align="center">
  <img src="https://customer-assets.emergentagent.com/job_securityshield-17/artifacts/4jbqdhyd_ChatGPT%20Image%20Feb%2010%2C%202026%2C%2009_07_51%20AM.png" alt="Seraph AI Logo" width="200"/>
</p>

<p align="center">
  <strong>Ultimate Agentic Anti-AI Agent Defense System</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#deployment">Deployment</a>
</p>

---

## Overview

Seraph AI is an enterprise-grade, proactive cybersecurity defense platform that combines autonomous threat detection, AI-powered analysis, and automated remediation. Built on a zero-trust architecture with post-quantum cryptography readiness, Seraph AI provides comprehensive protection against advanced persistent threats, AI-driven attacks, and sophisticated adversaries.

### Key Capabilities

- **Swarm Defense**: Auto-deploy lightweight defender agents across your entire network
- **AI Threat Intelligence**: AATL (Autonomous Agent Threat Layer) with MITRE ATT&CK mapping
- **Zero-Trust Architecture**: mTLS, cryptographic identity, policy-based enforcement
- **Post-Quantum Ready**: KYBER/DILITHIUM encryption with liboqs integration
- **Advanced Services**: MCP Server, Vector Memory, VNS, Quantum Security, AI Reasoning

---

## Features

### 🛡️ Core Security

| Feature | Description |
|---------|-------------|
| **Unified Agent** | Single powerful agent for desktops and mobile with process monitoring, network scanning, and aggressive auto-remediation |
| **Aggressive Auto-Kill** | Automatically terminates CRITICAL and HIGH severity threats without human intervention |
| **Network Scanning** | Port, WiFi, and Bluetooth scanning integrated into agent monitoring |
| **USB Device Monitoring** | Detects and alerts on unauthorized USB device connections |
| **SIEM Integration** | Built-in Elasticsearch integration for centralized logging |

### 🧠 AI-Powered Analysis

| Feature | Description |
|---------|-------------|
| **AATL/AATR** | Autonomous Agent Threat Layer with AI Threat Registry |
| **Local AI Reasoning** | Ollama integration for on-premise threat analysis |
| **MITRE ATT&CK Mapping** | 37+ techniques mapped with automated classification |
| **Threat Classification** | Credential theft, ransomware, C2, lateral movement, exfiltration detection |
| **Risk Scoring** | 0-100 risk scores with severity assessment |

### 🔐 Enterprise Security Layer

| Service | Description |
|---------|-------------|
| **Identity Service** | Agent cryptographic identity with attestation |
| **Policy Engine** | PDP/PEP for action gates and rate limits |
| **Token Broker** | Vault-like service for scoped capability tokens |
| **Tool Gateway** | Governed CLI execution with allowlisting |
| **Telemetry Chain** | Tamper-evident, signed telemetry storage |

### 🚀 Advanced Services

| Service | Description |
|---------|-------------|
| **MCP Server** | Model Context Protocol for governed tool execution |
| **Vector Memory** | MongoDB-backed semantic search (128-dim embeddings) |
| **VNS** | Virtual Network Sensor for independent network truth |
| **Quantum Security** | Post-quantum cryptography (Kyber/Dilithium) |
| **AI Reasoning** | Local LLM integration via Ollama |
| **Cuckoo Sandbox** | Full VM-based malware analysis |
| **VNS Alerts** | Slack/Email notifications for threats |
| **Tactical Heatmap** | Visual threat prioritization |

### 📊 Visualization & Reporting

- **Tactical Heatmap**: AI-prioritized threat visualization
- **Network Topology Map**: Live network visualization with threat indicators
- **Command Center**: Real-time C2 dashboard with swarm control
- **PDF Reports**: Enhanced threat intelligence reports with charts
- **Slack/Email Alerts**: Automated VNS alerting pipeline

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       SERAPH AI PLATFORM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Frontend   │  │   Backend    │  │   MongoDB    │           │
│  │    (React)   │  │   (FastAPI)  │  │   (Atlas)    │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                  │                   │
│         └────────────────┼──────────────────┘                   │
│                          │                                       │
├──────────────────────────┼───────────────────────────────────────┤
│  ENTERPRISE SECURITY LAYER                                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │Identity │ │ Policy  │ │ Token   │ │  Tool   │ │Telemetry│   │
│  │Service  │ │ Engine  │ │ Broker  │ │ Gateway │ │ Chain   │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
├──────────────────────────────────────────────────────────────────┤
│  ADVANCED SERVICES                                               │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │   MCP   │ │ Vector  │ │   VNS   │ │Quantum  │ │   AI    │   │
│  │ Server  │ │ Memory  │ │         │ │Security │ │Reasoning│   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                            │
│  │ Cuckoo  │ │  VNS    │ │Tactical │                            │
│  │ Sandbox │ │ Alerts  │ │ Heatmap │                            │
│  └─────────┘ └─────────┘ └─────────┘                            │
├──────────────────────────────────────────────────────────────────┤
│  UNIFIED AGENT (Deployed Network-Wide)                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Seraph Defender v7 (Desktop/Server/Mobile)                 ││
│  │  - Process Monitoring    - Network Scanning                  ││
│  │  - USB Detection         - SIEM Integration                 ││
│  │  - Auto-Kill Defense     - VPN Auto-Config                  ││
│  │  - Local Dashboard       - VNS Sync                         ││
│  │  - AI Analysis Sync      - Quantum Ready                    ││
│  └─────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- Python 3.11+
- Node.js 18+
- MongoDB Atlas account (or local MongoDB)
- Optional: Ollama for local AI reasoning
- Optional: liboqs for production quantum crypto
- Optional: Cuckoo Sandbox for malware analysis

### Backend Setup

```bash
cd /app/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# For production quantum crypto
pip install liboqs-python

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

### Frontend Setup

```bash
cd /app/frontend

# Install dependencies
yarn install

# Configure environment
cp .env.example .env
# Edit .env with your backend URL
```

### Agent Deployment

```bash
# Download unified agent
cd /app/scripts

# For desktop/server deployment
python seraph_defender_v7.py --api-url https://your-server.com

# The agent will:
# - Monitor processes and network
# - Sync with VNS for flow analysis
# - Send threats to AI for analysis
# - Auto-kill high-severity threats
# - Serve local dashboard on port 8765
```

---

## Configuration

### Environment Variables

#### Backend (.env)

```env
# Database
MONGO_URL=mongodb+srv://user:pass@cluster.mongodb.net
DB_NAME=seraph_ai

# Security
JWT_SECRET=your-secret-key-min-32-chars

# Cuckoo Sandbox (Optional)
CUCKOO_API_URL=http://sandbox.local:8090
CUCKOO_API_TOKEN=your-token
CUCKOO_API_VERSION=2  # or 3 for Cuckoo 3.x

# Ollama AI (Optional)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral

# VNS Alerts (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@yourdomain.com
SMTP_PASSWORD=app-password
ALERT_EMAIL_FROM=seraph@alerts.local
ALERT_EMAIL_TO=security@yourdomain.com
ALERT_MIN_SEVERITY=high
ALERT_COOLDOWN_MINUTES=5
```

#### Frontend (.env)

```env
REACT_APP_BACKEND_URL=https://your-api.com
```

---

## API Reference

### Authentication

All API endpoints require JWT authentication:

```bash
# Login
curl -X POST /api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"pass"}'

# Use token
curl -X GET /api/threats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/threats` | List threats |
| GET | `/api/alerts` | List alerts |
| GET | `/api/agents` | List connected agents |

### Advanced Services

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/advanced/dashboard` | Combined advanced dashboard |
| GET | `/api/advanced/mcp/tools` | List MCP tools |
| POST | `/api/advanced/mcp/execute` | Execute MCP tool |
| POST | `/api/advanced/memory/store` | Store to vector memory |
| POST | `/api/advanced/memory/search` | Semantic search |
| POST | `/api/advanced/vns/flow` | Record network flow |
| GET | `/api/advanced/vns/beacons` | Get C2 beacon detections |
| POST | `/api/advanced/ai/analyze` | AI threat analysis |
| POST | `/api/advanced/ai/query` | AI security query |
| POST | `/api/advanced/ai/ollama/configure` | Configure Ollama |
| POST | `/api/advanced/quantum/keypair/kyber` | Generate Kyber keypair |
| POST | `/api/advanced/quantum/keypair/dilithium` | Generate Dilithium keypair |
| GET | `/api/advanced/sandbox/status` | Cuckoo sandbox status |
| POST | `/api/advanced/sandbox/submit/file` | Submit file to sandbox |
| POST | `/api/advanced/alerts/configure` | Configure VNS alerts |
| POST | `/api/advanced/alerts/test` | Send test alert |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/threat-intelligence` | Generate PDF report |
| POST | `/api/reports/ai-summary` | Generate AI summary |

---

## Agent Reference

### Seraph Defender v7

The unified desktop/server/mobile agent provides comprehensive endpoint protection.

#### Features

- **Process Monitoring**: Real-time process detection with threat scoring
- **Network Scanning**: Port, WiFi, Bluetooth discovery
- **USB Monitoring**: Device detection and blocking
- **Auto-Kill**: Automatic termination of high-severity threats
- **SIEM Integration**: Elasticsearch log forwarding
- **VPN Auto-Config**: WireGuard split-tunnel setup
- **VNS Sync**: Sends flows to Virtual Network Sensor
- **AI Analysis Sync**: Sends threats to AI for enhanced analysis
- **Local Dashboard**: Web UI on port 8765

#### Local Dashboard Tabs

1. **Overview**: System status, threat counts, health metrics
2. **Processes**: Running processes with risk scoring
3. **Network**: Port scan results, active connections
4. **WiFi**: Detected wireless networks
5. **Bluetooth**: Nearby Bluetooth devices
6. **USB**: Connected USB devices
7. **AI Detection**: AATL threat classifications
8. **Advanced Services**: MCP, VNS, Quantum, AI status
9. **All Events**: Complete event log

---

## Deployment

### Production Checklist

- [ ] Configure MongoDB Atlas with proper network access
- [ ] Set strong JWT_SECRET (32+ characters)
- [ ] Enable HTTPS/TLS for all communications
- [ ] Configure Slack/Email alerts for VNS
- [ ] Deploy agents to all endpoints
- [ ] Set up Cuckoo sandbox for malware analysis (optional)
- [ ] Install Ollama for local AI (optional)
- [ ] Install liboqs for production quantum crypto (optional)

### Ollama Setup (for AI Reasoning)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended model
ollama pull mistral

# Start Ollama service
ollama serve

# Configure in Seraph UI or via API
curl -X POST /api/advanced/ai/ollama/configure \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"base_url":"http://localhost:11434","model":"mistral"}'
```

### liboqs Setup (for Production Quantum Crypto)

```bash
# Install liboqs Python bindings
pip install liboqs-python

# Verify installation
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"

# Seraph will automatically use production mode when liboqs is available
```

### Cuckoo Sandbox Setup

```bash
# Install Cuckoo (follow official docs)
# Configure in .env:
CUCKOO_API_URL=http://sandbox.local:8090
CUCKOO_API_TOKEN=your-api-token
CUCKOO_API_VERSION=2  # or 3

# Without Cuckoo, Seraph falls back to static analysis
```

---

## Security Considerations

### Zero-Trust Principles

1. **Never Trust, Always Verify**: All agents must authenticate
2. **Least Privilege**: Capability tokens are scoped and short-lived
3. **Defense in Depth**: Multiple layers of protection
4. **Assume Breach**: Tamper-evident logging, canary triggers

### Cryptographic Standards

- **Key Encapsulation**: KYBER-768 (NIST selected)
- **Digital Signatures**: DILITHIUM-3 (NIST selected)
- **Hashing**: SHA3-256 (quantum-resistant)
- **Classical Fallback**: AES-256-GCM + RSA-4096

### Data Classification

| Level | Description | Storage |
|-------|-------------|---------|
| SECRET | Credentials, private keys | Encrypted vault |
| CONFIDENTIAL | Telemetry, reports | MongoDB encrypted |
| INTERNAL | Operational logs | Tamper-evident chain |
| PUBLIC | System status | Standard storage |

---

## Troubleshooting

### Common Issues

**Agent not connecting:**
```bash
# Check API URL
echo $REACT_APP_BACKEND_URL

# Test connectivity
curl -s https://your-server.com/api/health
```

**Ollama not responding:**
```bash
# Check Ollama status
curl -s http://localhost:11434/api/tags

# Restart Ollama
systemctl restart ollama
```

**VNS Alerts not sending:**
```bash
# Test alert
curl -X POST /api/advanced/alerts/test \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel":"all"}'
```

### Logs

```bash
# Backend logs
tail -f /var/log/supervisor/backend.err.log

# Agent logs
# Check ~/.seraph/defender.log
```

---

## Version History

- **v6.0.0** (Mar 2026): Advanced Services - MCP, Vector Memory, VNS, Quantum, AI Reasoning, Cuckoo Sandbox, VNS Alerts, Tactical Heatmap
- **v5.9.0** (Feb 2026): Enterprise Security Layer, Aggressive Auto-Kill, SIEM, USB, Sandbox
- **v5.8.0** (Feb 2026): Network Infrastructure Scanning, Split-Tunnel VPN
- **v5.7.0** (Feb 2026): Advanced Agent Detection, Browser Extension
- **v5.6.0** (Feb 2026): Auto-Kill Defense, Command Center, Network Threat Map
- **v5.5.0** (Feb 2026): UI Branding Overhaul, Deploy All Fix
- **v5.4.0** (Feb 2026): Real Network Scanner, Mobile Agent Support
- **v5.3.0** (Feb 2026): AI Threat Intelligence Layer (AATL/AATR)
- **v5.2.0** (Feb 2026): Swarm Auto-Deployment, Real Telemetry

---

## License

Proprietary - Emergent Labs

---

## Support

- **Documentation**: This README
- **Issues**: GitHub Issues
- **Email**: security@seraph.ai

---

<p align="center">
  <strong>Seraph AI</strong> - Protecting the Future, Today
</p>
