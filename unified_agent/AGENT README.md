# Metatron Unified Security Agent

A comprehensive, cross-platform security agent system that provides unified threat detection, monitoring, and response capabilities across Windows, Linux, macOS, Android, and iOS platforms.

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗   ██╗
║     ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║   ██║
║     ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║   ██║
║     ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║   ╚═╝
║     ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██╗
║     ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
║                                                                  ║
║                    UNIFIED SECURITY AGENT v1.0                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

## Features

### 🔍 **Comprehensive Monitoring**
- **Network Scanning**: Detects devices, open ports, and network traffic
- **Process Monitoring**: Tracks running processes and suspicious activities
- **File System Monitoring**: Watches for file changes and unauthorized access
- **Wireless Scanning**: Bluetooth and Wi-Fi network detection
- **System Resource Monitoring**: CPU, memory, and disk usage tracking

### 🛡️ **Threat Detection**
- **Real-time Analysis**: Continuous monitoring with configurable intervals
- **Anomaly Detection**: Identifies unusual system behavior
- **Malware Prevention**: Blocks known malicious patterns
- **Intrusion Detection**: Monitors for unauthorized access attempts

### 📱 **Cross-Platform Support**
- **Windows**: Native Win32 application with system tray integration
- **Linux**: GTK-based desktop application
- **macOS**: Native SwiftUI application with macOS integration
- **Android**: Native Kotlin Jetpack Compose application
- **iOS**: Native SwiftUI application with iOS integration

### 🚀 **Auto-Deployment**
- **Network Discovery**: Automatically detects devices on the network
- **Wireless Deployment**: Deploys agents to discovered devices
- **Platform Detection**: Identifies device types and capabilities
- **Remote Installation**: Automated agent installation and configuration

### 🖥️ **Central Management**
- **Web Dashboard**: RESTful API for agent management
- **Real-time Monitoring**: Live status updates from all agents
- **Alert Management**: Centralized alert handling and response
- **Configuration Management**: Remote agent configuration updates

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Metatron Server                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 REST API (FastAPI)                  │    │
│  │  • Agent Registration & Management                  │    │
│  │  • Alert Processing & Response                      │    │
│  │  • Deployment Coordination                         │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Auto-Deployment System                 │    │
│  │  • Network Device Discovery                        │    │
│  │  • Platform Detection                              │    │
│  │  • Remote Agent Installation                       │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
          ┌─────────▼──┐  ┌──────▼─────┐  ┌───▼─────────┐
          │   Windows  │  │   Linux    │  │   macOS     │
          │   Agent     │  │   Agent    │  │   Agent     │
          │             │  │            │  │             │
          │ • Tkinter   │  │ • Tkinter  │  │ • SwiftUI   │
          │ • Win32 API │  │ • GTK      │  │ • macOS API │
          └─────────────┘  └────────────┘  └─────────────┘
                    │            │            │
          ┌─────────▼──┐  ┌──────▼─────┐  ┌───▼─────────┐
          │  Android    │  │    iOS     │  │   Other     │
          │   Agent      │  │   Agent    │  │  Platforms  │
          │              │  │            │  │             │
          │ • Jetpack    │  │ • SwiftUI  │  │ • Future    │
          │   Compose    │  │ • iOS API  │  │   Support   │
          └─────────────┘  └─────────────┘  └─────────────┘
```

## Quick Start

### Prerequisites

- **Python 3.8+**
- **Git**
- **Platform-specific build tools** (see platform sections)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/metatron-agent.git
   cd metatron-agent
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Build the system:**
   ```bash
   # Build all platforms
   ./unified_agent/build.sh

   # Or build specific platforms
   ./unified_agent/build.sh --platform windows linux macos
   ```

4. **Start the server:**
   ```bash
   python unified_agent/server_api.py
   ```

5. **Deploy agents:**
   ```bash
   python unified_agent/auto_deployment.py
   ```

## Platform-Specific Setup

### Windows Agent

**Requirements:**
- Windows 10/11
- Python 3.8+ (for building)
- PyInstaller
- NSIS (optional, for installer creation)

**Building:**
```bash
./unified_agent/build.sh --platform windows
```

**Running:**
```bash
# From dist/windows/
MetatronAgent.exe
```

### Linux Agent

**Requirements:**
- Linux distribution with GTK support
- Python 3.8+
- PyInstaller
- dpkg (optional, for .deb creation)

**Building:**
```bash
./unified_agent/build.sh --platform linux
```

**Running:**
```bash
# From dist/linux/
./MetatronAgent
```

### macOS Agent

**Requirements:**
- macOS 10.15+
- Xcode Command Line Tools
- Swift 5.0+
- Python 3.8+ (for building)

**Building:**
```bash
./unified_agent/build.sh --platform macos
```

**Running:**
```bash
# From dist/macos/
./MetatronAgent
```

### Android Agent

**Requirements:**
- Android Studio
- Android SDK
- JDK 11+
- Gradle

**Building:**
```bash
./unified_agent/build.sh --platform android
```

**Installation:**
```bash
adb install unified_agent/dist/android/app-debug.apk
```

### iOS Agent

**Requirements:**
- macOS with Xcode
- iOS Simulator or physical device
- Apple Developer Account (for distribution)

**Building:**
```bash
./unified_agent/build.sh --platform ios
```

## API Documentation

### Server API Endpoints

#### Agent Management
- `POST /agents/register` - Register a new agent
- `GET /agents` - List all agents
- `GET /agents/{agent_id}` - Get agent details
- `DELETE /agents/{agent_id}` - Unregister agent
- `POST /agents/{agent_id}/heartbeat` - Agent heartbeat
- `POST /agents/{agent_id}/command` - Send command to agent

#### Alert Management
- `GET /alerts` - List alerts
- `PUT /alerts/{alert_id}/acknowledge` - Acknowledge alert

#### Deployment Management
- `POST /deployments` - Create deployment
- `GET /deployments` - List deployments
- `GET /deployments/{deployment_id}` - Get deployment details

#### System Management
- `GET /config` - Get server configuration
- `PUT /config` - Update server configuration
- `GET /stats` - Get system statistics

### Agent API

Agents communicate with the server via HTTP/HTTPS:

```python
import requests

# Agent registration
response = requests.post('http://server:8001/agents/register', json={
    'agent_id': 'unique-agent-id',
    'platform': 'windows',
    'hostname': 'DESKTOP-123',
    'ip_address': '192.168.1.100',
    'version': '1.0.0',
    'capabilities': ['network_scan', 'process_monitor']
})

# Heartbeat
response = requests.post(f'http://server:8001/agents/{agent_id}/heartbeat', json={
    'agent_id': agent_id,
    'status': 'online',
    'cpu_usage': 45.2,
    'memory_usage': 67.8,
    'alerts': []
})
```

## Configuration

### Server Configuration

Create `unified_agent/server_config.json`:

```json
{
  "host": "0.0.0.0",
  "port": 8001,
  "heartbeat_interval": 60,
  "alert_thresholds": {
    "cpu_usage": 90,
    "memory_usage": 90,
    "network_connections": 100
  },
  "monitoring_enabled": true,
  "supported_platforms": ["windows", "linux", "macos", "android", "ios"],
  "auto_deployment": true,
  "network_range": "192.168.1.0/24"
}
```

### Agent Configuration

Each agent can be configured via the server API or local config files:

```json
{
  "server_url": "http://server:8001",
  "agent_name": "Windows-Desktop-001",
  "update_interval": 30,
  "heartbeat_interval": 60,
  "monitoring_options": {
    "network_scanning": true,
    "process_monitoring": true,
    "file_scanning": true,
    "wireless_scanning": true,
    "bluetooth_scanning": true
  }
}
```

## Auto-Deployment

The auto-deployment system automatically discovers and deploys agents to network devices:

### Configuration

Create `unified_agent/auto_deployment_config.json`:

```json
{
  "network_range": "192.168.1.0/24",
  "deployment_port": 8002,
  "scan_interval": 30,
  "auto_deploy": true,
  "supported_platforms": ["windows", "linux", "macos", "android"],
  "server_url": "http://localhost:8001",
  "agent_version": "1.0.0"
}
```

### Usage

```bash
# Start auto-deployment
python unified_agent/auto_deployment.py

# The system will:
# 1. Scan the network for devices
# 2. Identify device platforms
# 3. Deploy appropriate agents
# 4. Register agents with the server
```

## Monitoring & Alerts

### Alert Types

- **Network Alerts**: Unauthorized connections, port scans
- **Process Alerts**: Suspicious processes, high CPU usage
- **File Alerts**: Unauthorized file access, modifications
- **System Alerts**: High resource usage, offline agents

### Alert Response

Alerts are processed through the server API and can trigger:

- Email notifications
- SMS alerts
- Automated responses
- Dashboard updates

## Development

### Project Structure

```
unified_agent/
├── core/                    # Shared agent core
│   ├── agent.py            # Main agent logic
│   └── config.py           # Configuration management
├── ui/                     # Platform-specific UIs
│   ├── windows/            # Windows Tkinter app
│   ├── linux/              # Linux Tkinter app
│   ├── macos/              # macOS SwiftUI app
│   ├── android/            # Android Jetpack Compose
│   └── ios/                # iOS SwiftUI app
├── server_api.py           # FastAPI server
├── auto_deployment.py      # Auto-deployment system
├── build.sh               # Build script
└── requirements.txt       # Python dependencies
```

### Adding New Features

1. **Core Features**: Add to `unified_agent/core/`
2. **UI Features**: Update platform-specific UI files
3. **API Features**: Add endpoints to `server_api.py`
4. **Build Updates**: Modify `build.sh` for new platforms

### Testing

```bash
# Run server tests
python -m pytest tests/

# Test agent communication
python test_agent_connection.py

# Test auto-deployment
python test_deployment.py
```

## Security

### Agent Authentication

- Agents use unique IDs and tokens for authentication
- All communication is encrypted (HTTPS recommended)
- Heartbeat validation prevents spoofing

### Data Protection

- Sensitive data is encrypted at rest
- Network traffic is monitored for anomalies
- Access controls prevent unauthorized configuration changes

### Best Practices

- Regular security updates
- Network segmentation
- Least privilege access
- Regular backup of configuration and logs

## Troubleshooting

### Common Issues

**Agent won't connect to server:**
- Check server URL and port
- Verify firewall settings
- Check agent logs

**Auto-deployment fails:**
- Verify network permissions
- Check device discovery settings
- Review deployment logs

**High resource usage:**
- Adjust monitoring intervals
- Review alert thresholds
- Check for memory leaks

### Logs

- **Server logs**: `server_api.log`
- **Deployment logs**: `auto_deployment.log`
- **Agent logs**: Platform-specific log files

### Support

- **Documentation**: This README and inline code comments
- **Logs**: Check log files for detailed error information
- **Configuration**: Verify all config files are valid JSON

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

### Code Style

- Python: PEP 8
- Swift: Swift API Design Guidelines
- Kotlin: Kotlin Coding Conventions
- Bash: Google Shell Style Guide

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Roadmap

### Version 1.1
- Advanced threat intelligence integration
- Machine learning-based anomaly detection
- Enhanced mobile device management

### Version 1.2
- Cloud deployment support
- Kubernetes integration
- Advanced reporting and analytics

### Version 2.0
- AI-powered threat response
- Zero-trust architecture
- Multi-cloud support

---

**Metatron Security** - Unified Protection for the Digital Age