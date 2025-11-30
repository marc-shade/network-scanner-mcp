# Network Scanner MCP

Environmental awareness for the AGI cluster through network device discovery and monitoring.

```
   ╭──────────────────────────────────────╮
   │  🐕 PIXEL'S NETWORK AWARENESS 🐕     │
   │                                      │
   │  "I can see everything on the        │
   │   network now - not just the         │
   │   cluster nodes!"                    │
   ╰──────────────────────────────────────╯
```

## Features

- **ARP Network Scanning**: Discover all devices on the local network
- **MAC Vendor Lookup**: Identify device manufacturers
- **Device History**: Track when devices first/last appeared
- **Anomaly Detection**: Alert when unknown devices join
- **Cluster Node Status**: Monitor AGI cluster node connectivity
- **Device Labeling**: Mark devices as known/trusted

## Installation

```bash
cd ${AGENTIC_SYSTEM_PATH:-/opt/agentic}/mcp-servers/network-scanner-mcp
source ${AGENTIC_SYSTEM_PATH:-/opt/agentic}/.venv/bin/activate
pip install -e .

# Install system dependencies (Fedora)
sudo dnf install arp-scan nmap
```

## Configuration

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

## Tools

| Tool | Description |
|------|-------------|
| `scan_network` | ARP scan for all devices on subnet |
| `get_network_topology` | Full topology with categorization |
| `get_device_info` | Details about specific device (by IP or MAC) |
| `detect_new_devices` | Find only new devices since last scan |
| `mark_device_known` | Label a device as trusted |
| `get_cluster_nodes` | Status of AGI cluster nodes |
| `get_device_history` | Historical data for devices |
| `get_unknown_devices` | List unidentified devices |

## Usage Examples

```python
# Scan the network
scan_network()

# Check cluster node status
get_cluster_nodes()

# Find unknown devices
get_unknown_devices()

# Mark your phone as known
mark_device_known(mac="00:00:00:00:00:63", label="Marc's iPhone")
```

## Data Storage

- Device history: `${AGENTIC_SYSTEM_PATH:-/opt/agentic}/databases/network-scanner/device_history.json`
- Known devices: `${AGENTIC_SYSTEM_PATH:-/opt/agentic}/databases/network-scanner/known_devices.json`

## Integration

### Enhanced Memory
Stores device discoveries for pattern analysis and learning.

### Node Chat
Broadcasts alerts to cluster when new devices are detected.

### Security Scanner
Feeds discovered IPs to Nuclei for vulnerability scanning.

## Requirements

- Python 3.10+
- Root access for ARP scanning (or arp-scan with sudo)
- Network interface access

## Cluster Nodes (Configurable)

Cluster nodes are loaded from configuration:
- Environment variable `CLUSTER_NODES_JSON`
- Configuration file `~/.claude/cluster-nodes.json`

Default node roles:
| Role | Description |
|------|-------------|
| orchestrator | Coordination, monitoring, routing |
| builder | Compilation, testing, containers |
| files | File storage and management |
| coordinator | Multi-node coordination |
| inference | AI inference and GPU workloads |

---

*Part of the AGI Security Projects Roadmap*
