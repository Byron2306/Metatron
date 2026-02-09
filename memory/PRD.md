# Anti-AI Defense System - Product Requirements Document

## Overview
The Ultimate Agentic Anti-AI Agent Defense System - a comprehensive cybersecurity platform designed to counter malicious AI agents and advanced malware.

## Version History
- **v1.0.0**: Initial dashboard with simulated threats
- **v2.0.0**: Real network scanning, local agent, notifications
- **v3.0.0**: Backend refactoring + 4 enterprise security features
- **v3.1.0**: Frontend pages for all 6 enterprise features + Enhanced installer
- **v3.2.0**: SOAR Playbook Engine + Bug fixes (CURRENT - Feb 2026)

## v3.2 New Features (Feb 2026)

### 1. SOAR Playbook Engine ✅
- **5 Pre-configured Playbooks**: Malware, Ransomware, IOC Match, Suspicious Process, Honeypot
- **10 Available Actions**: Block IP, Kill Process, Quarantine File, Send Alert, Isolate Endpoint, Collect Forensics, Disable User, Scan Endpoint, Update Firewall, Create Ticket
- **8 Trigger Types**: Threat Detected, Malware Found, Ransomware Detected, Suspicious Process, IOC Match, Honeypot Triggered, Anomaly Detected, Manual
- **Execution Tracking**: Full history with step-by-step results

### 2. Bug Fixes ✅
- Fixed Settings page crash (frontend expected nested structure, backend returned flat)
- Fixed Quarantine page crash (frontend expected {entries: []}, backend returned [])

### 3. New UI Page ✅
- **SOAR Page**: Visual playbook management with toggle switches, execution buttons, and history

## Credentials Required for Full Functionality

| Service | Credential | How to Get |
|---------|-----------|------------|
| **Slack** | Webhook URL | api.slack.com/apps → Create App → Incoming Webhooks → Add to Workspace |
| **SendGrid** | API Key | sendgrid.com → Settings → API Keys → Create (starts with `SG.`) |
| **Twilio** | Account SID, Auth Token, Phone | twilio.com → Console Dashboard |
| **Elasticsearch** | URL + API Key | elastic.co/cloud → Create Deployment → Security → API Key |
| **OpenClaw** | API Key + Gateway URL | From your OpenClaw provider |

## v3.1 Features (Completed)

### 1. Complete UI for All Enterprise Features ✅
- **Threat Intelligence Page**: IOC lookup, feed stats, real-time search
- **Ransomware Protection Page**: Canary management, protected folders
- **Container Security Page**: Trivy scanning, runtime monitoring
- **VPN Integration Page**: WireGuard management, peer configuration
- **Threat Correlation Page**: Automated threat correlation engine
- **EDR & Memory Forensics Page**: Process tree, FIM, USB control

### 2. Navigation Integration ✅
- Added 6 new navigation items to sidebar
- Updated App.js with routes for all new pages
- All pages accessible after login

### 3. Enhanced Local Agent Installer ✅
- **Better Windows Support**: Auto-detection of winget/chocolatey/scoop
- **WireGuard Installation**: Cross-platform installation support
- **Trivy Installation**: Container scanner installation
- **Volatility 3 Installation**: Memory forensics framework
- **Improved UX**: Automatic browser opening for manual downloads

## Architecture (v3.2)

### Frontend Structure (21 Pages)
```
/app/frontend/src/pages/
├── DashboardPage.jsx          # Main dashboard
├── AIDetectionPage.jsx        # AI threat detection
├── AlertsPage.jsx             # Alert management
├── ThreatsPage.jsx            # Threat listing
├── NetworkTopologyPage.jsx    # Network visualization
├── ThreatHuntingPage.jsx      # Threat hunting
├── HoneypotsPage.jsx          # Honeypot management
├── ReportsPage.jsx            # PDF reports
├── AgentsPage.jsx             # Local agent management
├── QuarantinePage.jsx         # File quarantine
├── SettingsPage.jsx           # Configuration
├── ThreatResponsePage.jsx     # Auto-response rules
├── TimelinePage.jsx           # Threat timeline
├── AuditLogPage.jsx           # Audit logs
├── ThreatIntelPage.jsx        # Threat intelligence
├── RansomwarePage.jsx         # Ransomware protection
├── ContainerSecurityPage.jsx  # Container security
├── VPNPage.jsx                # VPN management
├── CorrelationPage.jsx        # Threat correlation
├── EDRPage.jsx                # EDR & Memory Forensics
└── SOARPage.jsx               # NEW: SOAR Playbooks
```

### Backend Structure (24 Router Modules)
```
/app/backend/
├── server.py                    # Main FastAPI app (200 lines)
├── routers/
│   ├── auth.py                  # Authentication
│   ├── threats.py               # Threat management
│   ├── alerts.py                # Alert management
│   ├── ai_analysis.py           # AI-powered analysis
│   ├── dashboard.py             # Dashboard stats
│   ├── network.py               # Network topology
│   ├── hunting.py               # Threat hunting
│   ├── honeypots.py             # Honeypot management
│   ├── reports.py               # PDF reports
│   ├── agents.py                # Local agent management
│   ├── quarantine.py            # File quarantine
│   ├── settings.py              # Notification settings
│   ├── response.py              # Threat response
│   ├── audit.py                 # Audit logging
│   ├── timeline.py              # Threat timeline
│   ├── websocket.py             # WebSocket management
│   ├── openclaw.py              # OpenClaw AI config
│   ├── threat_intel.py          # NEW: Threat intelligence
│   ├── ransomware.py            # NEW: Ransomware protection
│   ├── containers.py            # NEW: Container security
│   ├── vpn.py                   # NEW: VPN integration
│   ├── correlation.py           # NEW: Threat correlation
│   ├── edr.py                   # NEW: EDR & Memory Forensics
│   └── soar.py                  # NEW: SOAR Playbooks
├── soar_engine.py               # NEW: SOAR service
├── threat_intel.py              # Threat feed service
├── ransomware_protection.py     # Ransomware service
├── container_security.py        # Container/Trivy service
├── vpn_integration.py           # WireGuard service
├── threat_correlation.py        # Threat correlation service
├── edr_service.py               # EDR service
└── ... (existing services)
```

## API Endpoints (v3.1 Additions)

### Threat Correlation
- `GET /api/correlation/stats` - Correlation statistics
- `GET /api/correlation/history` - Correlation history
- `POST /api/correlation/all-active` - Correlate all active threats
- `POST /api/correlation/settings` - Update correlation settings
- `GET /api/correlation/auto-actions` - List automated actions

### EDR & Memory Forensics
- `GET /api/edr/status` - EDR system status
- `GET /api/edr/telemetry` - System telemetry
- `GET /api/edr/process-tree` - Process hierarchy
- `POST /api/edr/fim/baseline` - Create file baseline
- `POST /api/edr/fim/check` - Check file integrity
- `POST /api/edr/fim/monitor` - Add path to monitoring
- `GET /api/edr/usb/devices` - List USB devices
- `POST /api/edr/usb/allow` - Allow USB device
- `POST /api/edr/usb/block` - Block USB device

## v3.0 API Endpoints

### Threat Intelligence
- `GET /api/threat-intel/stats` - Get feed statistics
- `POST /api/threat-intel/check` - Check single IOC
- `POST /api/threat-intel/check-bulk` - Check multiple IOCs
- `POST /api/threat-intel/update` - Refresh feeds
- `GET /api/threat-intel/feeds` - Get feed status
- `GET /api/threat-intel/matches/recent` - Recent matches

### Ransomware Protection
- `GET /api/ransomware/status` - Protection status
- `POST /api/ransomware/start` - Start protection
- `POST /api/ransomware/stop` - Stop protection
- `POST /api/ransomware/canaries/deploy` - Deploy canary files
- `GET /api/ransomware/canaries` - List canaries
- `POST /api/ransomware/canaries/check` - Check canary integrity
- `GET /api/ransomware/protected-folders` - List protected folders
- `POST /api/ransomware/protected-folders` - Add protected folder

### Container Security
- `GET /api/containers/stats` - Container security stats
- `GET /api/containers` - Running containers
- `GET /api/containers/{id}/security` - Container security check
- `POST /api/containers/scan` - Scan image
- `POST /api/containers/scan-all` - Scan all images
- `GET /api/containers/scans/history` - Scan history

### VPN Integration
- `GET /api/vpn/status` - VPN server status
- `POST /api/vpn/initialize` - Initialize WireGuard
- `POST /api/vpn/start` - Start VPN server
- `POST /api/vpn/stop` - Stop VPN server
- `GET /api/vpn/peers` - List VPN peers
- `POST /api/vpn/peers` - Add peer
- `GET /api/vpn/peers/{id}/config` - Get peer config file
- `DELETE /api/vpn/peers/{id}` - Remove peer
- `GET /api/vpn/kill-switch` - Kill switch status
- `POST /api/vpn/kill-switch/enable` - Enable kill switch
- `POST /api/vpn/kill-switch/disable` - Disable kill switch

## What's Working
- ✅ All 23 API router modules
- ✅ All 20 frontend pages
- ✅ Threat Intelligence with ~20.5k indicators
- ✅ Ransomware canary deployment
- ✅ Container security endpoints (Trivy integration ready)
- ✅ VPN endpoints (WireGuard integration ready)
- ✅ Threat Correlation engine with auto-actions
- ✅ EDR with process tree, FIM, USB control
- ✅ Enhanced local agent installer
- ✅ All previous v2.0 features

## Configuration Notes

### Threat Intelligence
- Feeds auto-update every 6 hours
- AlienVault OTX requires API key (optional)
- Set `OTX_API_KEY` for OTX integration

### Container Security
- Requires Trivy installed on agent
- Install: `apt install trivy` or `brew install trivy`

### VPN Integration
- Requires WireGuard installed on server
- Install: `apt install wireguard`
- Server endpoint configured via `VPN_SERVER_ENDPOINT`

## Comparison: Standard AV vs This System

| Feature | Standard AV | This System |
|---------|------------|-------------|
| Signature detection | ✅ | ✅ (YARA + feeds) |
| Behavioral analysis | ✅ | ✅ |
| Network protection | ✅ | ✅ (Suricata) |
| Ransomware protection | ✅ | ✅ (Canaries + behavioral) |
| Container security | ❌ | ✅ (Trivy + Falco) |
| Threat intelligence | ⚠️ Limited | ✅ (20k+ IOCs) |
| AI-powered analysis | ❌ | ✅ (GPT) |
| VPN integration | ❌ | ✅ (WireGuard) |
| Agentic response | ❌ | ✅ (Auto-block, auto-kill) |
| Centralized dashboard | ⚠️ Basic | ✅ (Full SOC) |

## Backlog / Future Features

### P1 - High Priority
- [x] Frontend pages for new v3.0 features ✅
- [x] Memory forensics (Volatility integration) ✅ (installer ready)
- [x] EDR capabilities (process trees, FIM) ✅

### P2 - Medium Priority
- [ ] SOAR playbook engine
- [ ] Honey tokens and honey credentials
- [ ] Browser isolation
- [ ] Kibana dashboard integration

### P3 - Future
- [ ] Zero Trust architecture
- [ ] ML-based threat prediction
- [ ] Sandbox/VM-based analysis (Cuckoo)
