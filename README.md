# Network Scanner MCP

Environmental awareness for the AGI cluster through network device discovery, port scanning, and service detection.

```
   ╭──────────────────────────────────────╮
   │  PIXEL'S NETWORK AWARENESS           │
   │                                      │
   │  "I can see everything on the        │
   │   network now - all devices,         │
   │   services, and cluster health!"     │
   ╰──────────────────────────────────────╯
```

## Features

### Device Discovery
- **ARP Network Scanning**: Discover all devices on the local network
- **MAC Vendor Lookup**: Identify device manufacturers
- **Hostname Resolution**: Resolve device hostnames via reverse DNS
- **Device History**: Track when devices first/last appeared
- **Anomaly Detection**: Alert when unknown devices join

### Port Scanning & Service Detection
- **Port Scanning**: Scan specific ports or common service ports
- **Service Fingerprinting**: Identify services by port and banner
- **Quick Scan Mode**: Fast scan of common ports (22, 80, 443, etc.)
- **Full Port Scan**: Comprehensive scan of ports 1-1024
- **Banner Grabbing**: Capture service banners for identification

### Cluster Monitoring
- **Cluster Node Status**: Monitor AGI cluster node connectivity
- **Health Checks**: Ping-based reachability testing with latency
- **Alert Daemon**: Continuous monitoring with voice and cluster alerts
- **Node Recovery Detection**: Alerts when nodes come back online

### Alerting
- **Voice Alerts**: TTS alerts via edge-tts
- **Node-Chat Integration**: Broadcast alerts to cluster nodes
- **Alert History**: Persistent alert log with history

## Installation

```bash
cd ${AGENTIC_SYSTEM_PATH:-/opt/agentic}/mcp-servers/network-scanner-mcp
source ${AGENTIC_SYSTEM_PATH:-/opt/agentic}/.venv/bin/activate

# Install the package
pip install -e .

# For development (includes tests)
pip install -e ".[dev]"

# Install system dependencies (Fedora)
sudo dnf install arp-scan

# For voice alerts (optional)
pip install edge-tts
sudo dnf install mpv
```

## Configuration

### MCP Server Configuration

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "network-scanner": {
      "command": "${AGENTIC_SYSTEM_PATH:-/opt/agentic}/.venv/bin/python",
      "args": ["-m", "network_scanner_mcp.server"],
      "cwd": "${AGENTIC_SYSTEM_PATH:-/opt/agentic}/mcp-servers/network-scanner-mcp/src"
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_SCANNER_DATA_DIR` | `$AGENTIC_SYSTEM_PATH/databases/network-scanner` | Data storage directory |
| `NETWORK_INTERFACE` | Auto-detected | Network interface to use |
| `DEFAULT_SCAN_SUBNET` | Auto-detected | Default subnet for scans |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_TO_FILE` | `false` | Enable file logging |
| `CLUSTER_NODES_JSON` | None | JSON string of cluster nodes |

### Alert Daemon Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL_SECONDS` | `300` | Seconds between scans |
| `VOICE_ALERTS_ENABLED` | `true` | Enable voice alerts |
| `NODE_CHAT_ALERTS_ENABLED` | `true` | Enable cluster alerts |
| `ALERT_ON_NEW_DEVICES` | `true` | Alert on new device detection |
| `ALERT_ON_CLUSTER_NODE_DOWN` | `true` | Alert when cluster nodes go offline |
| `TTS_VOICE` | `en-IE-EmilyNeural` | Voice for TTS alerts |
| `MAX_ALERT_HISTORY` | `1000` | Maximum alerts to retain |

### Cluster Nodes Configuration

Create `cluster_nodes.json` in the data directory:

```json
{
  "192.0.2.146": {
    "name": "orchestrator",
    "role": "orchestrator",
    "type": "cluster_node"
  },
  "192.0.2.196": {
    "name": "builder",
    "role": "builder",
    "type": "cluster_node"
  },
  "192.0.2.233": {
    "name": "researcher",
    "role": "researcher",
    "type": "cluster_node"
  }
}
```

Or set via environment variable:
```bash
export CLUSTER_NODES_JSON='{"192.0.2.146": {"name": "orchestrator", "role": "orchestrator"}}'
```

## MCP Tools

### Device Discovery

| Tool | Description |
|------|-------------|
| `scan_network(subnet?, resolve_names?)` | ARP scan for all devices on subnet |
| `detect_new_devices()` | Find only new devices since last scan |
| `get_unknown_devices()` | List unidentified devices |

### Device Information

| Tool | Description |
|------|-------------|
| `get_device_info(identifier)` | Details about device (by IP or MAC) |
| `get_device_history(mac?)` | Historical data for devices |
| `mark_device_known(mac, label, device_type)` | Label a device as trusted |
| `remove_device_known(mac)` | Remove device from known list |

### Network Topology

| Tool | Description |
|------|-------------|
| `get_network_topology()` | Full topology with categorization |

### Port Scanning

| Tool | Description |
|------|-------------|
| `scan_device_ports(target, ports?, quick?)` | Scan ports on specific device |
| `discover_services()` | Quick scan all devices for services |

### Cluster Monitoring

| Tool | Description |
|------|-------------|
| `get_cluster_nodes()` | Status of configured cluster nodes |
| `check_cluster_health()` | Ping all nodes and report health |

### Utilities

| Tool | Description |
|------|-------------|
| `ping_device(target, count?)` | Ping device for reachability |
| `resolve_device_hostname(target)` | Resolve hostname via DNS |
| `get_scanner_status()` | Get scanner status and configuration |
| `export_for_security_scan()` | Export IPs for security-scanner-mcp |

## Usage Examples

### Basic Network Discovery

```python
# Scan the network
scan_network()

# Scan with hostname resolution
scan_network(resolve_names=True)

# Check for new devices
detect_new_devices()

# Find unknown devices
get_unknown_devices()
```

### Device Management

```python
# Mark your phone as known
mark_device_known(
    mac="00:00:00:00:00:63",
    label="Marc's iPhone",
    device_type="trusted"
)

# Get device details
get_device_info("192.0.2.217")
get_device_info("00:00:00:00:00:63")

# View device history
get_device_history()
```

### Port Scanning

```python
# Quick port scan (common ports)
scan_device_ports("192.0.2.217", quick=True)

# Scan specific ports
scan_device_ports("192.0.2.217", ports="22,80,443,8080")

# Full port scan (1-1024)
scan_device_ports("192.0.2.217", ports="all")

# Discover services on all devices
discover_services()
```

### Cluster Monitoring

```python
# Check cluster node status
get_cluster_nodes()

# Full health check with latency
check_cluster_health()
```

### Network Topology

```python
# Get full network topology
topology = get_network_topology()

# Returns categorized lists:
# - cluster_nodes: Configured cluster nodes
# - known_devices: Devices marked as trusted
# - unknown_devices: Unidentified devices
```

## Alert Daemon

The alert daemon provides continuous network monitoring with alerts.

### Running the Daemon

```bash
# Run directly
python -m network_scanner_mcp.alert_daemon

# Or use the installed script
network-scanner-daemon
```

### Systemd Service

Install as a systemd service:

```bash
sudo cp network-scanner-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable network-scanner-daemon
sudo systemctl start network-scanner-daemon
```

Check status:
```bash
sudo systemctl status network-scanner-daemon
journalctl -u network-scanner-daemon -f
```

### Alert Types

| Type | Trigger | Priority |
|------|---------|----------|
| `new_device` | Unknown device detected | High |
| `node_offline` | Cluster node unreachable | Critical |
| `node_recovered` | Cluster node back online | Normal |

## Data Storage

All data is stored in the configured data directory (default: `${AGENTIC_SYSTEM_PATH:-/opt/agentic}/databases/network-scanner/`):

| File | Description |
|------|-------------|
| `device_history.json` | All discovered devices with metadata |
| `known_devices.json` | Devices marked as known/trusted |
| `cluster_nodes.json` | Cluster node configuration |
| `alert_history.json` | Alert log (last 1000 alerts) |
| `pending_alerts.json` | Queued alerts for delivery |
| `server.log` | MCP server logs (if enabled) |
| `alert_daemon.log` | Alert daemon logs |

## Integration

### Enhanced Memory MCP
Device discoveries can be stored in enhanced-memory for pattern analysis and learning.

### Node-Chat MCP
Alerts are broadcast to cluster nodes via node-chat when enabled.

### Security Scanner MCP
Use `export_for_security_scan()` to get IP lists for vulnerability scanning with security-scanner-mcp.

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=network_scanner_mcp --cov-report=html

# Run specific test file
pytest tests/test_utils.py -v
```

### Code Structure

```
src/network_scanner_mcp/
├── __init__.py       # Package exports
├── server.py         # MCP server with tools
├── scanner.py        # Scanning functionality
├── alert_daemon.py   # Continuous monitoring daemon
└── utils.py          # Shared utilities
```

## Requirements

- Python 3.10+
- Root/sudo access for ARP scanning
- Network interface access

### System Dependencies

- `arp-scan` - Required for ARP scanning
- `edge-tts` - Optional for voice alerts
- `mpv` - Optional for audio playback

## Changelog

### v0.2.0

- Added port scanning and service detection
- Added hostname resolution
- Implemented proper node-chat integration
- Refactored with shared utilities module
- Added comprehensive type hints
- Added thread-safe device registry
- Removed unused dependencies
- Added unit tests
- Fixed data format inconsistencies
- Auto-detect network interface

### v0.1.0

- Initial release
- ARP scanning
- Device history tracking
- Basic cluster monitoring
- Alert daemon

---

*Part of the AGI Agentic System - Environmental Awareness Component*
