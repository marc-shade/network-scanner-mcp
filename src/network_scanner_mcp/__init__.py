"""
Network Scanner MCP - Environmental awareness for the AGI cluster.

This package provides network scanning and monitoring capabilities:
- ARP scanning for device discovery
- Port scanning and service detection
- Hostname resolution
- Cluster node monitoring
- Alert daemon for continuous monitoring
- Integration with node-chat MCP for cluster alerts

Requires: arp-scan (system package), edge-tts (for voice alerts)

Example usage:
    # As MCP server
    network-scanner-mcp

    # As alert daemon
    network-scanner-daemon

    # Programmatic usage
    from network_scanner_mcp.scanner import arp_scan, scan_ports
    from network_scanner_mcp.utils import load_cluster_nodes
"""

__version__ = "0.2.0"
__author__ = "AGI System"

from .utils import (
    ClusterNodeConfig,
    DeviceInfo,
    ScanResult,
    detect_network_interface,
    detect_local_subnet,
    get_data_dir,
    load_cluster_nodes,
    normalize_mac,
    setup_logging,
)

from .scanner import (
    arp_scan,
    scan_ports,
    quick_port_scan,
    resolve_hostname,
    resolve_hostnames,
    ping_host,
    ping_hosts,
    full_device_scan,
    discover_network,
    COMMON_PORTS,
    SERVICE_PORTS,
)

__all__ = [
    # Version
    "__version__",
    # Types
    "ClusterNodeConfig",
    "DeviceInfo",
    "ScanResult",
    # Utils
    "detect_network_interface",
    "detect_local_subnet",
    "get_data_dir",
    "load_cluster_nodes",
    "normalize_mac",
    "setup_logging",
    # Scanner
    "arp_scan",
    "scan_ports",
    "quick_port_scan",
    "resolve_hostname",
    "resolve_hostnames",
    "ping_host",
    "ping_hosts",
    "full_device_scan",
    "discover_network",
    "COMMON_PORTS",
    "SERVICE_PORTS",
]
