#!/usr/bin/env python3
"""
Network Scanner MCP Server

Provides environmental awareness for the AGI cluster by:
- Discovering all devices on the network via ARP scanning
- Identifying devices by MAC address vendor lookup
- Tracking device history and detecting new/rogue devices
- Port scanning and service detection
- Hostname resolution
- Cluster node monitoring
- Alerting the cluster via node-chat when network changes occur
- Storing device knowledge in enhanced-memory

Requires root/sudo for raw packet operations (arp-scan).
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Optional

from fastmcp import FastMCP

from .utils import (
    ClusterNodeConfig,
    DeviceInfo,
    detect_network_interface,
    detect_local_subnet,
    get_cluster_node_display_name,
    get_config_value,
    get_data_dir,
    get_timestamp,
    load_cluster_nodes,
    load_json_file,
    normalize_mac,
    save_json_file,
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

# =============================================================================
# Configuration
# =============================================================================

# Set up logging
logger = setup_logging(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    log_file=get_data_dir() / "server.log" if get_config_value("LOG_TO_FILE", False, bool) else None,
)

# Data paths
DATA_DIR = get_data_dir()
DEVICE_HISTORY_FILE = DATA_DIR / "device_history.json"
KNOWN_DEVICES_FILE = DATA_DIR / "known_devices.json"
CLUSTER_CONFIG_FILE = DATA_DIR / "cluster_nodes.json"

# Load cluster nodes configuration
CLUSTER_NODES: dict[str, ClusterNodeConfig] = load_cluster_nodes(CLUSTER_CONFIG_FILE)

# Initialize FastMCP server
mcp = FastMCP("network-scanner")

# Detect network interface
INTERFACE = detect_network_interface()
logger.info(f"Using network interface: {INTERFACE}")

# =============================================================================
# Global State (Thread-Safe)
# =============================================================================

class DeviceRegistry:
    """Thread-safe device registry for storing device history and known devices."""

    def __init__(self):
        self._lock = Lock()
        self._device_history: dict[str, DeviceInfo] = {}
        self._known_devices: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        """Load data from disk."""
        with self._lock:
            self._device_history = load_json_file(DEVICE_HISTORY_FILE)
            self._known_devices = load_json_file(KNOWN_DEVICES_FILE)
            logger.info(f"Loaded {len(self._device_history)} devices, {len(self._known_devices)} known")

    def _save_history(self) -> None:
        """Save device history to disk."""
        save_json_file(DEVICE_HISTORY_FILE, self._device_history)

    def _save_known(self) -> None:
        """Save known devices to disk."""
        save_json_file(KNOWN_DEVICES_FILE, self._known_devices)

    def get_device(self, mac: str) -> Optional[DeviceInfo]:
        """Get device by MAC address."""
        mac = normalize_mac(mac)
        with self._lock:
            return self._device_history.get(mac)

    def get_device_by_ip(self, ip: str) -> Optional[DeviceInfo]:
        """Get device by IP address."""
        with self._lock:
            for mac, device in self._device_history.items():
                if device.get("ip") == ip:
                    return device
        return None

    def update_device(self, mac: str, device_data: dict) -> tuple[bool, DeviceInfo]:
        """
        Update or add a device to the registry.

        Returns:
            Tuple of (is_new, device_info)
        """
        mac = normalize_mac(mac)
        timestamp = get_timestamp()
        is_new = False

        with self._lock:
            if mac in self._device_history:
                # Update existing device
                self._device_history[mac]["last_seen"] = timestamp
                self._device_history[mac]["ip"] = device_data.get("ip", self._device_history[mac].get("ip"))
                self._device_history[mac]["seen_count"] = self._device_history[mac].get("seen_count", 0) + 1

                # Update additional fields if provided
                for field in ["vendor", "hostname", "ports", "services"]:
                    if field in device_data and device_data[field]:
                        self._device_history[mac][field] = device_data[field]
            else:
                # New device
                is_new = True
                ip = device_data.get("ip", "Unknown")
                self._device_history[mac] = {
                    "mac": mac,
                    "ip": ip,
                    "vendor": device_data.get("vendor", "Unknown"),
                    "hostname": device_data.get("hostname"),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "seen_count": 1,
                    "is_known": mac in self._known_devices,
                    "is_cluster_node": ip in CLUSTER_NODES,
                    "ports": device_data.get("ports", []),
                    "services": device_data.get("services", []),
                }

            device = self._device_history[mac].copy()
            self._save_history()

        return (is_new, device)

    def mark_known(self, mac: str, label: str, device_type: str = "trusted") -> bool:
        """Mark a device as known/trusted."""
        mac = normalize_mac(mac)

        with self._lock:
            self._known_devices[mac] = {
                "label": label,
                "type": device_type,
                "added": get_timestamp(),
            }

            if mac in self._device_history:
                self._device_history[mac]["is_known"] = True
                self._save_history()

            self._save_known()

        logger.info(f"Marked {mac} as known: {label}")
        return True

    def remove_known(self, mac: str) -> bool:
        """Remove a device from known list."""
        mac = normalize_mac(mac)

        with self._lock:
            if mac in self._known_devices:
                del self._known_devices[mac]

                if mac in self._device_history:
                    self._device_history[mac]["is_known"] = False
                    self._save_history()

                self._save_known()
                return True

        return False

    def get_all_devices(self) -> dict[str, DeviceInfo]:
        """Get all devices."""
        with self._lock:
            return self._device_history.copy()

    def get_known_devices(self) -> dict[str, dict]:
        """Get all known devices."""
        with self._lock:
            return self._known_devices.copy()

    def is_known(self, mac: str) -> bool:
        """Check if a device is known."""
        mac = normalize_mac(mac)
        with self._lock:
            return mac in self._known_devices

    def get_unknown_macs(self) -> set[str]:
        """Get MACs of unknown devices."""
        with self._lock:
            all_macs = set(self._device_history.keys())
            known_macs = set(self._known_devices.keys())
            cluster_ips = set(CLUSTER_NODES.keys())
            cluster_macs = {
                mac for mac, dev in self._device_history.items()
                if dev.get("ip") in cluster_ips
            }
            return all_macs - known_macs - cluster_macs


# Initialize global registry
registry = DeviceRegistry()


# =============================================================================
# MCP Tools - Device Discovery
# =============================================================================

@mcp.tool()
async def scan_network(
    subnet: Optional[str] = None,
    resolve_names: bool = True,
) -> str:
    """
    Scan the local network for all connected devices using ARP.

    Args:
        subnet: Subnet to scan (e.g., "192.0.2.44/24"). Auto-detected if not specified.
        resolve_names: Whether to resolve hostnames for discovered devices.

    Returns:
        JSON with discovered devices including IP, MAC, vendor, and hostname.
    """
    logger.info(f"Starting network scan (subnet={subnet}, resolve_names={resolve_names})")

    # Perform ARP scan
    devices = await arp_scan(subnet, INTERFACE)

    if not devices:
        return json.dumps({
            "success": False,
            "error": "No devices found or scan failed",
            "interface": INTERFACE,
        })

    # Resolve hostnames if requested
    if resolve_names:
        ips = [d["ip"] for d in devices]
        hostname_map = await resolve_hostnames(ips)
        for device in devices:
            device["hostname"] = hostname_map.get(device["ip"])

    # Update registry and track new devices
    new_devices = []
    for device in devices:
        is_new, updated = registry.update_device(
            device["mac"],
            {
                "ip": device["ip"],
                "vendor": device["vendor"],
                "hostname": device.get("hostname"),
            }
        )
        if is_new:
            new_devices.append(updated)

    result = {
        "success": True,
        "interface": INTERFACE,
        "total_devices": len(devices),
        "new_devices_count": len(new_devices),
        "new_devices": new_devices,
        "devices": devices,
        "message": f"Found {len(devices)} devices, {len(new_devices)} new",
    }

    logger.info(f"Scan complete: {len(devices)} devices, {len(new_devices)} new")
    return json.dumps(result, indent=2)


@mcp.tool()
async def detect_new_devices() -> str:
    """
    Scan network and return only newly discovered devices since last scan.

    Returns:
        JSON with list of new devices only.
    """
    devices = await arp_scan(interface=INTERFACE)

    new_devices = []
    for device in devices:
        is_new, updated = registry.update_device(
            device["mac"],
            {"ip": device["ip"], "vendor": device["vendor"]}
        )
        if is_new:
            new_devices.append(updated)

    return json.dumps({
        "success": True,
        "new_devices": new_devices,
        "count": len(new_devices),
        "message": f"Detected {len(new_devices)} new device(s)",
    }, indent=2)


@mcp.tool()
async def get_unknown_devices() -> str:
    """
    Get list of all unknown/unverified devices on the network.

    Returns:
        JSON with list of unknown devices.
    """
    all_devices = registry.get_all_devices()
    unknown_macs = registry.get_unknown_macs()

    unknown_devices = [
        all_devices[mac]
        for mac in unknown_macs
        if mac in all_devices
    ]

    # Sort by last seen (most recent first)
    unknown_devices.sort(
        key=lambda d: d.get("last_seen", ""),
        reverse=True
    )

    return json.dumps({
        "success": True,
        "unknown_devices": unknown_devices,
        "count": len(unknown_devices),
        "message": f"Found {len(unknown_devices)} unknown device(s)",
    }, indent=2)


# =============================================================================
# MCP Tools - Device Information
# =============================================================================

@mcp.tool()
async def get_device_info(identifier: str) -> str:
    """
    Get detailed information about a specific device by IP or MAC address.

    Args:
        identifier: IP address or MAC address of the device.

    Returns:
        JSON with device details including history, ports, and services.
    """
    identifier = identifier.upper()

    # Try MAC first
    device = registry.get_device(identifier)

    # Try IP if not found
    if device is None:
        device = registry.get_device_by_ip(identifier)

    if device is None:
        return json.dumps({
            "success": False,
            "error": f"Device not found: {identifier}"
        })

    # Add cluster info if applicable
    if device.get("ip") in CLUSTER_NODES:
        device["cluster_info"] = CLUSTER_NODES[device["ip"]]

    return json.dumps({"success": True, "device": device}, indent=2)


@mcp.tool()
async def get_device_history(mac: Optional[str] = None) -> str:
    """
    Get full device history including first seen, last seen, and visit counts.

    Args:
        mac: Optional MAC address to filter by. Returns all devices if not specified.

    Returns:
        JSON with device history.
    """
    if mac:
        mac = normalize_mac(mac)
        device = registry.get_device(mac)
        if device:
            return json.dumps({"success": True, "device": device}, indent=2)
        return json.dumps({"success": False, "error": f"Device not found: {mac}"})

    all_devices = registry.get_all_devices()
    return json.dumps({
        "success": True,
        "device_history": all_devices,
        "total_devices": len(all_devices),
    }, indent=2)


@mcp.tool()
async def mark_device_known(
    mac: str,
    label: str,
    device_type: str = "trusted",
) -> str:
    """
    Mark a device as known/trusted with a label.

    Args:
        mac: MAC address of the device.
        label: Friendly label for the device (e.g., "Living Room TV").
        device_type: Device type - "trusted", "iot", "guest", or "infrastructure".

    Returns:
        JSON confirmation.
    """
    valid_types = ["trusted", "iot", "guest", "infrastructure"]
    if device_type not in valid_types:
        return json.dumps({
            "success": False,
            "error": f"Invalid device_type. Must be one of: {valid_types}"
        })

    registry.mark_known(mac, label, device_type)

    return json.dumps({
        "success": True,
        "message": f"Marked {mac} as known: {label} ({device_type})"
    })


@mcp.tool()
async def remove_device_known(mac: str) -> str:
    """
    Remove a device from the known/trusted list.

    Args:
        mac: MAC address of the device.

    Returns:
        JSON confirmation.
    """
    if registry.remove_known(mac):
        return json.dumps({
            "success": True,
            "message": f"Removed {mac} from known devices"
        })

    return json.dumps({
        "success": False,
        "error": f"Device not found in known list: {mac}"
    })


# =============================================================================
# MCP Tools - Network Topology
# =============================================================================

@mcp.tool()
async def get_network_topology() -> str:
    """
    Get the full network topology including cluster nodes, known devices, and unknown devices.

    Returns:
        JSON with categorized device lists and topology statistics.
    """
    all_devices = registry.get_all_devices()
    known_devices = registry.get_known_devices()

    topology = {
        "cluster_nodes": [],
        "known_devices": [],
        "unknown_devices": [],
        "total_devices": len(all_devices),
        "last_scan": None,
        "interface": INTERFACE,
    }

    for mac, device in all_devices.items():
        device_info = {
            "mac": mac,
            "ip": device.get("ip", "Unknown"),
            "vendor": device.get("vendor", "Unknown"),
            "hostname": device.get("hostname"),
            "first_seen": device.get("first_seen"),
            "last_seen": device.get("last_seen"),
            "seen_count": device.get("seen_count", 0),
            "services": device.get("services", []),
        }

        # Track latest scan time
        if device.get("last_seen"):
            if not topology["last_scan"] or device["last_seen"] > topology["last_scan"]:
                topology["last_scan"] = device["last_seen"]

        ip = device.get("ip", "")

        # Categorize device
        if ip in CLUSTER_NODES:
            node_config = CLUSTER_NODES[ip]
            device_info["node_name"] = node_config["name"]
            device_info["node_role"] = node_config["role"]
            topology["cluster_nodes"].append(device_info)
        elif mac in known_devices:
            device_info["label"] = known_devices[mac].get("label", "Known Device")
            device_info["device_type"] = known_devices[mac].get("type", "trusted")
            topology["known_devices"].append(device_info)
        else:
            topology["unknown_devices"].append(device_info)

    # Sort lists
    topology["cluster_nodes"].sort(key=lambda x: x.get("node_name", ""))
    topology["known_devices"].sort(key=lambda x: x.get("label", ""))
    topology["unknown_devices"].sort(key=lambda x: x.get("last_seen", ""), reverse=True)

    return json.dumps({"success": True, "topology": topology}, indent=2)


# =============================================================================
# MCP Tools - Cluster Monitoring
# =============================================================================

@mcp.tool()
async def get_cluster_nodes() -> str:
    """
    Get status of known cluster nodes on the network.

    Returns:
        JSON with cluster node status including online/offline.
    """
    all_devices = registry.get_all_devices()

    # Build IP to MAC mapping from history
    ip_to_mac = {
        dev.get("ip"): mac
        for mac, dev in all_devices.items()
        if dev.get("ip")
    }

    cluster_status = []

    for ip, config in CLUSTER_NODES.items():
        mac = ip_to_mac.get(ip)
        device = all_devices.get(mac) if mac else None

        node_info = {
            "name": config["name"],
            "role": config["role"],
            "ip": ip,
            "mac": mac,
            "vendor": device.get("vendor") if device else None,
            "last_seen": device.get("last_seen") if device else None,
            "online": device is not None and device.get("last_seen") is not None,
        }

        # Check if recently seen (within last 10 minutes)
        if device and device.get("last_seen"):
            from .utils import is_recent
            node_info["recently_active"] = is_recent(device["last_seen"], 600)
        else:
            node_info["recently_active"] = False

        cluster_status.append(node_info)

    # Sort by name
    cluster_status.sort(key=lambda x: x["name"])

    online_count = sum(1 for n in cluster_status if n["online"])

    return json.dumps({
        "success": True,
        "cluster_nodes": cluster_status,
        "online_count": online_count,
        "total_nodes": len(cluster_status),
        "message": f"{online_count}/{len(cluster_status)} cluster nodes online",
    }, indent=2)


@mcp.tool()
async def check_cluster_health() -> str:
    """
    Perform a comprehensive health check on all cluster nodes.

    Pings all configured cluster nodes and reports their status.

    Returns:
        JSON with cluster health report including latency.
    """
    if not CLUSTER_NODES:
        return json.dumps({
            "success": False,
            "error": "No cluster nodes configured"
        })

    ips = list(CLUSTER_NODES.keys())
    results = []

    for ip in ips:
        config = CLUSTER_NODES[ip]
        is_up, latency = await ping_host(ip)

        results.append({
            "name": config["name"],
            "role": config["role"],
            "ip": ip,
            "reachable": is_up,
            "latency_ms": latency,
            "status": "healthy" if is_up else "unreachable",
        })

    # Classify health
    healthy = [r for r in results if r["reachable"]]
    unhealthy = [r for r in results if not r["reachable"]]

    overall_status = "healthy"
    if len(unhealthy) > 0:
        overall_status = "degraded"
    if len(healthy) == 0:
        overall_status = "critical"

    return json.dumps({
        "success": True,
        "overall_status": overall_status,
        "healthy_nodes": len(healthy),
        "unhealthy_nodes": len(unhealthy),
        "nodes": results,
        "message": f"Cluster health: {overall_status} ({len(healthy)}/{len(results)} nodes up)",
    }, indent=2)


# =============================================================================
# MCP Tools - Port Scanning
# =============================================================================

@mcp.tool()
async def scan_device_ports(
    target: str,
    ports: Optional[str] = None,
    quick: bool = True,
) -> str:
    """
    Scan ports on a specific device.

    Args:
        target: IP address or MAC address of target device.
        ports: Comma-separated list of ports or "all" for 1-1024. Uses common ports if not specified.
        quick: Use quick scan mode (faster, fewer ports). Ignored if ports specified.

    Returns:
        JSON with open ports and detected services.
    """
    # Resolve target to IP
    target = target.upper()
    ip = target

    if ":" in target:  # Looks like MAC
        device = registry.get_device(target)
        if device:
            ip = device.get("ip")
        if not ip:
            return json.dumps({
                "success": False,
                "error": f"Could not find IP for MAC: {target}"
            })

    # Parse port list
    port_list = None
    if ports:
        if ports.lower() == "all":
            port_list = list(range(1, 1025))
        else:
            try:
                port_list = [int(p.strip()) for p in ports.split(",")]
            except ValueError:
                return json.dumps({
                    "success": False,
                    "error": "Invalid port format. Use comma-separated numbers or 'all'."
                })

    # Perform scan
    logger.info(f"Port scanning {ip}")

    if port_list:
        results = await scan_ports(ip, port_list)
    elif quick:
        results = await quick_port_scan(ip)
    else:
        results = await scan_ports(ip, COMMON_PORTS)

    open_ports = [r for r in results if r.state == "open"]

    # Update device record with discovered services
    device = registry.get_device_by_ip(ip)
    if device:
        services = [p.service for p in open_ports if p.service != "unknown"]
        registry.update_device(
            device["mac"],
            {
                "ip": ip,
                "ports": [{"port": p.port, "service": p.service, "state": p.state} for p in results],
                "services": services,
            }
        )

    return json.dumps({
        "success": True,
        "target": ip,
        "ports_scanned": len(results),
        "open_ports": [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "banner": p.banner,
                "response_time_ms": p.response_time_ms,
            }
            for p in open_ports
        ],
        "services_detected": [p.service for p in open_ports if p.service != "unknown"],
        "message": f"Found {len(open_ports)} open ports on {ip}",
    }, indent=2)


@mcp.tool()
async def discover_services() -> str:
    """
    Discover services running on all known devices in the network.

    Performs quick port scan on all devices in history.

    Returns:
        JSON with services discovered per device.
    """
    all_devices = registry.get_all_devices()

    if not all_devices:
        return json.dumps({
            "success": False,
            "error": "No devices in history. Run scan_network first."
        })

    results = []

    for mac, device in all_devices.items():
        ip = device.get("ip")
        if not ip:
            continue

        open_ports = await quick_port_scan(ip)

        if open_ports:
            services = [p.service for p in open_ports if p.service != "unknown"]

            # Update device record
            registry.update_device(
                mac,
                {
                    "ip": ip,
                    "ports": [{"port": p.port, "service": p.service} for p in open_ports],
                    "services": services,
                }
            )

            results.append({
                "mac": mac,
                "ip": ip,
                "hostname": device.get("hostname"),
                "vendor": device.get("vendor"),
                "open_ports": [p.port for p in open_ports],
                "services": services,
            })

    return json.dumps({
        "success": True,
        "devices_scanned": len(all_devices),
        "devices_with_services": len(results),
        "results": results,
        "message": f"Discovered services on {len(results)} devices",
    }, indent=2)


# =============================================================================
# MCP Tools - Utilities
# =============================================================================

@mcp.tool()
async def ping_device(target: str, count: int = 3) -> str:
    """
    Ping a device to check reachability and latency.

    Args:
        target: IP address or MAC address of target device.
        count: Number of ping packets to send.

    Returns:
        JSON with ping results.
    """
    # Resolve target to IP
    ip = target

    if ":" in target.upper():  # MAC address
        device = registry.get_device(target.upper())
        if device:
            ip = device.get("ip")
        if not ip:
            return json.dumps({
                "success": False,
                "error": f"Could not find IP for MAC: {target}"
            })

    is_reachable, latency = await ping_host(ip, count=count)

    return json.dumps({
        "success": True,
        "target": ip,
        "reachable": is_reachable,
        "latency_ms": latency,
        "status": "up" if is_reachable else "down",
    }, indent=2)


@mcp.tool()
async def resolve_device_hostname(target: str) -> str:
    """
    Resolve hostname for a device via reverse DNS.

    Args:
        target: IP address of the device.

    Returns:
        JSON with hostname resolution result.
    """
    hostname = await resolve_hostname(target)

    # Update device if in history
    device = registry.get_device_by_ip(target)
    if device and hostname:
        registry.update_device(device["mac"], {"ip": target, "hostname": hostname})

    return json.dumps({
        "success": True,
        "ip": target,
        "hostname": hostname,
        "resolved": hostname is not None,
    }, indent=2)


@mcp.tool()
async def get_scanner_status() -> str:
    """
    Get current status of the network scanner.

    Returns:
        JSON with scanner status including interface, data stats, and configuration.
    """
    all_devices = registry.get_all_devices()
    known_devices = registry.get_known_devices()

    return json.dumps({
        "success": True,
        "status": {
            "interface": INTERFACE,
            "data_dir": str(DATA_DIR),
            "total_devices_tracked": len(all_devices),
            "known_devices": len(known_devices),
            "cluster_nodes_configured": len(CLUSTER_NODES),
            "cluster_node_ips": list(CLUSTER_NODES.keys()),
        },
        "configuration": {
            "log_level": os.environ.get("LOG_LEVEL", "INFO"),
            "default_subnet": detect_local_subnet(),
        },
    }, indent=2)


# =============================================================================
# MCP Tools - Integration with Other MCPs
# =============================================================================

@mcp.tool()
async def export_for_security_scan() -> str:
    """
    Export discovered devices for security scanning integration.

    Returns IP addresses in a format suitable for security-scanner-mcp.

    Returns:
        JSON with IP list and device metadata for security scanning.
    """
    all_devices = registry.get_all_devices()

    # Build list of IPs with metadata
    targets = []
    for mac, device in all_devices.items():
        ip = device.get("ip")
        if ip:
            targets.append({
                "ip": ip,
                "mac": mac,
                "vendor": device.get("vendor"),
                "hostname": device.get("hostname"),
                "is_cluster_node": ip in CLUSTER_NODES,
                "services": device.get("services", []),
            })

    return json.dumps({
        "success": True,
        "total_targets": len(targets),
        "targets": targets,
        "ip_list": [t["ip"] for t in targets],
        "cluster_ips": list(CLUSTER_NODES.keys()),
        "message": f"Exported {len(targets)} targets for security scanning",
    }, indent=2)


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Entry point for the MCP server."""
    logger.info("Starting Network Scanner MCP Server")
    logger.info(f"Interface: {INTERFACE}")
    logger.info(f"Data directory: {DATA_DIR}")
    logger.info(f"Cluster nodes configured: {len(CLUSTER_NODES)}")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
