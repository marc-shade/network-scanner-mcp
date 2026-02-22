
# Network Scanner MCP![network_scanner_mcp](https://github.com/user-attachments/assets/4b4e2262-7dd0-44c0-9f13-11d835bfd3bf)


[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Network discovery and port scanning for infrastructure mapping.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

Environmental awareness for the AGI cluster through network device discovery, port scanning, and service detection.

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

### Defense & Federal Compliance

#### SCAP Compliance Output
- **XCCDF 1.2**: Generates Extensible Configuration Checklist Description Format results per NIST SP 800-126 Rev. 3
- **OVAL 5.11**: Produces Open Vulnerability and Assessment Language definitions for automated assessment
- **CPE 2.3**: Common Platform Enumeration for asset identification with vendor/product/version resolution
- **CCE References**: Common Configuration Enumeration identifiers linked to check results

#### CIS Benchmark Checking
- Unused high-risk ports detection (telnet, FTP, rlogin, etc.)
- Default credential detection via banner analysis
- TLS 1.2+ enforcement verification (per NIST SP 800-52 Rev. 2)
- SNMP community string brute-force testing (SNMPv2c packet construction)
- SSH configuration audit (protocol version, server currency)
- NTP synchronization verification (UDP NTP client probe)
- Syslog forwarding configuration check
- Access control list posture assessment
- Each check returns: benchmark_id, title, description, level (L1/L2), status, rationale, remediation

#### NIST CSF Asset Inventory
- **ID.AM-1**: Physical devices and systems inventoried with type classification
- **ID.AM-2**: Software platforms and applications catalogued from port/banner data
- **ID.AM-3**: Organizational data flows mapped (direction, encryption status)
- **ID.AM-4**: External information systems identified via RFC 1918 boundary analysis
- **ID.AM-5**: Resources prioritized by classification (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED) and risk score
- Multi-factor risk scoring: exposure (30%), criticality (25%), vulnerability (25%), patch status (20%)

#### Zero Trust Architecture Assessment (NIST SP 800-207 + DISA ZTA)
- **Pillar 1 - Identity**: Authentication strength, MFA indicators, centralized identity services
- **Pillar 2 - Device**: Inventory completeness, device health, endpoint management coverage
- **Pillar 3 - Network**: Micro-segmentation, encrypted transport ratio, lateral movement risk
- **Pillar 4 - Application**: HTTPS coverage, API security, web application posture
- **Pillar 5 - Data**: Database exposure, data-in-transit encryption, storage security
- Maturity scoring per CISA ZT Maturity Model: TRADITIONAL / ADVANCED / OPTIMAL
- DoD ZTA Reference Architecture alignment assessment
- OMB M-22-09 Federal Zero Trust Strategy gap analysis
- Phased transformation roadmap generation

#### NIST SP 800-53 Rev. 5 Control Mapping
- Maps findings to: CA-7, CM-8, RA-5, SC-7, SI-4, PM-5, AC-17
- Control satisfaction assessment: satisfied / partially_satisfied / not_satisfied
- FIPS 199 baseline coverage (LOW / MODERATE / HIGH)
- POA&M generation with severity-based SLAs (30/90/180 days)
- Phased remediation milestones per NIST SP 800-37 Rev. 2

#### Multi-Framework Vulnerability Scoring
- **CVSS v3.1**: Complete base, temporal, and environmental score computation per FIRST specification
- **SSVC**: Stakeholder-Specific Vulnerability Categorization using CISA decision tree (Track/Track*/Attend/Act)
- **KEV**: Known Exploited Vulnerabilities cross-reference with ransomware indicators
- **Mission Impact**: Defense-grade impact assessment considering service criticality and asset classification
- Composite priority scoring combining all frameworks

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

### Defense & Federal Compliance

| Tool | Description |
|------|-------------|
| `network_scap_report(target?)` | Generate SCAP-compliant results (XCCDF, OVAL, CPE) |
| `network_cis_check(target, known_services?)` | Run CIS benchmark assessment |
| `network_asset_inventory()` | NIST CSF-aligned asset inventory with risk scoring |
| `network_zero_trust_assess()` | Zero Trust posture assessment (NIST 800-207/DISA ZTA) |
| `network_compliance_map(include_cis?)` | Map findings to NIST 800-53 controls |
| `network_vuln_prioritize(vulns_json)` | Defense-grade vulnerability prioritization (CVSS+SSVC+KEV) |
| `network_generate_poam()` | Generate Plan of Action & Milestones |

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
├── __init__.py                  # Package exports
├── server.py                    # MCP server with tools
├── scanner.py                   # Scanning functionality
├── alert_daemon.py              # Continuous monitoring daemon
├── utils.py                     # Shared utilities
└── compliance/                  # Defense & federal compliance
    ├── __init__.py              # Compliance module exports
    ├── scap_output.py           # SCAP output (XCCDF, OVAL, CPE)
    ├── cis_benchmarks.py        # CIS Benchmark checking
    ├── nist_csf_inventory.py    # NIST CSF asset inventory
    ├── zero_trust.py            # Zero Trust assessment (800-207)
    ├── nist_800_53.py           # NIST 800-53 control mapping + POA&M
    └── vuln_scoring.py          # CVSS v3.1, SSVC, KEV scoring
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

### v0.3.0

- Added SCAP-compliant output (XCCDF 1.2, OVAL 5.11, CPE 2.3)
- Added CIS Benchmark checking with 8 network device hardening checks
- Added NIST CSF asset inventory (ID.AM-1 through ID.AM-5) with risk scoring
- Added Zero Trust Architecture assessment (NIST 800-207, DISA ZTA, CISA ZT Maturity Model)
- Added NIST SP 800-53 Rev. 5 control mapping (7 control families)
- Added POA&M generation per NIST SP 800-37 Rev. 2
- Added multi-framework vulnerability scoring (CVSS v3.1, SSVC, KEV, mission impact)
- 7 new MCP tools for defense and federal compliance
- Asset classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
- DoD ZTA Reference Architecture and OMB M-22-09 alignment

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
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
