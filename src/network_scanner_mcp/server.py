#!/usr/bin/env python3
"""
Network Scanner MCP Server

Provides environmental awareness for the AGI cluster by:
- Discovering all devices on the network via ARP scanning
- Identifying devices by MAC address vendor lookup
- Tracking device history and detecting new/rogue devices
- Alerting the cluster via node-chat when network changes occur
- Storing device knowledge in enhanced-memory

Requires root/sudo for raw packet operations (arp-scan).
"""

import asyncio
import json
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP
import os

# Data storage path
DATA_DIR = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "/mnt/agentic-system"), "databases/network-scanner"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEVICE_HISTORY_FILE = DATA_DIR / "device_history.json"
KNOWN_DEVICES_FILE = DATA_DIR / "known_devices.json"

# Known cluster nodes for reference
CLUSTER_NODES = {
    "192.168.1.79": {"name": "mac-studio", "role": "orchestrator", "type": "cluster_node"},  # TODO: Move to config/env var
    "192.168.1.87": {"name": "macpro51", "role": "builder", "type": "cluster_node"},  # TODO: Move to config/env var
    "192.168.1.183": {"name": "macpro51-alt", "role": "builder", "type": "cluster_node"},  # TODO: Move to config/env var
    "192.168.1.233": {"name": "mac-mini", "role": "files", "type": "cluster_node"},  # TODO: Move to config/env var
    "192.168.1.55": {"name": "macbook-air-m3", "role": "coordinator", "type": "cluster_node"},  # TODO: Move to config/env var
    "192.168.1.186": {"name": "completeu-server", "role": "inference", "type": "cluster_node"},  # TODO: Move to config/env var
}

# Initialize FastMCP server
mcp = FastMCP("network-scanner")


def _detect_interface() -> str:
    """Detect the primary network interface."""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        if default_gateway:
            return default_gateway[1]
    except Exception:
        pass

    # Fallback to common interface names
    for iface in ["enp20s0", "enp19s0", "enp6s0", "eth0", "en0", "wlan0", "wlp2s0", "wls5"]:
        if Path(f"/sys/class/net/{iface}").exists():
            return iface
    return "eth0"


def _load_json_file(filepath: Path) -> dict:
    """Load JSON from file."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return {}


def _save_json_file(filepath: Path, data: dict):
    """Save JSON to file."""
    filepath.write_text(json.dumps(data, indent=2))


# Global state
INTERFACE = _detect_interface()
device_history = _load_json_file(DEVICE_HISTORY_FILE)
known_devices = _load_json_file(KNOWN_DEVICES_FILE)


async def _scan_arp(subnet: Optional[str] = None) -> list[dict]:
    """Perform ARP scan using arp-scan."""
    if subnet is None:
        # Auto-detect subnet
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            subnet = "192.168.1.0/24"  # TODO: Move to config/env var

    devices = []
    timestamp = datetime.now().isoformat()

    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet", "-I", INTERFACE],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2 and "." in parts[0]:
                    ip = parts[0].strip()
                    mac = parts[1].strip().upper()
                    vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "scan_time": timestamp,
                    })
    except Exception as e:
        return [{"error": str(e)}]

    return devices


def _update_device_history(devices: list[dict]) -> dict:
    """Update device history and detect new devices."""
    global device_history
    new_devices = []
    updated_count = 0

    for device in devices:
        if "error" in device:
            continue
        mac = device["mac"]

        if mac in device_history:
            device_history[mac]["last_seen"] = device["scan_time"]
            device_history[mac]["ip"] = device["ip"]
            device_history[mac]["seen_count"] = device_history[mac].get("seen_count", 0) + 1
            updated_count += 1
        else:
            device_history[mac] = {
                "mac": mac,
                "ip": device["ip"],
                "vendor": device["vendor"],
                "first_seen": device["scan_time"],
                "last_seen": device["scan_time"],
                "seen_count": 1,
                "is_known": mac in known_devices,
                "is_cluster_node": device["ip"] in CLUSTER_NODES,
            }
            new_devices.append(device)

    _save_json_file(DEVICE_HISTORY_FILE, device_history)

    return {
        "total_devices": len(devices),
        "new_devices": new_devices,
        "updated_devices": updated_count,
    }


@mcp.tool()
async def scan_network(subnet: Optional[str] = None) -> str:
    """
    Scan the local network for all connected devices using ARP.

    Args:
        subnet: Subnet to scan (e.g., 192.168.1.0/24). Defaults to local subnet.  # TODO: Move to config/env var

    Returns:
        JSON with discovered devices including IP, MAC, and vendor.
    """
    devices = await _scan_arp(subnet)
    result = _update_device_history(devices)

    return json.dumps({
        "success": True,
        "interface": INTERFACE,
        "scan_result": result,
        "devices": devices,
        "message": f"Found {result['total_devices']} devices, {len(result['new_devices'])} new",
    }, indent=2)


@mcp.tool()
async def get_network_topology() -> str:
    """
    Get the full network topology including cluster nodes, known devices, and unknown devices.

    Returns:
        JSON with categorized device lists.
    """
    topology = {
        "cluster_nodes": [],
        "known_devices": [],
        "unknown_devices": [],
        "total_devices": len(device_history),
        "last_scan": None,
    }

    for mac, device in device_history.items():
        device_info = {
            "mac": mac,
            "ip": device.get("ip", "Unknown"),
            "vendor": device.get("vendor", "Unknown"),
            "first_seen": device.get("first_seen"),
            "last_seen": device.get("last_seen"),
            "seen_count": device.get("seen_count", 0),
        }

        if device.get("last_seen"):
            if not topology["last_scan"] or device["last_seen"] > topology["last_scan"]:
                topology["last_scan"] = device["last_seen"]

        if device.get("ip") in CLUSTER_NODES:
            device_info["node_name"] = CLUSTER_NODES[device["ip"]]["name"]
            device_info["node_role"] = CLUSTER_NODES[device["ip"]]["role"]
            topology["cluster_nodes"].append(device_info)
        elif device.get("is_known") or mac in known_devices:
            device_info["label"] = known_devices.get(mac, {}).get("label", "Known Device")
            topology["known_devices"].append(device_info)
        else:
            topology["unknown_devices"].append(device_info)

    return json.dumps({"success": True, "topology": topology}, indent=2)


@mcp.tool()
async def get_device_info(identifier: str) -> str:
    """
    Get detailed information about a specific device by IP or MAC address.

    Args:
        identifier: IP address or MAC address of the device.

    Returns:
        JSON with device details.
    """
    identifier = identifier.upper()

    for mac, device in device_history.items():
        if mac == identifier or device.get("ip") == identifier:
            if device.get("ip") in CLUSTER_NODES:
                device["cluster_info"] = CLUSTER_NODES[device["ip"]]
            return json.dumps({"success": True, "device": device}, indent=2)

    return json.dumps({"success": False, "error": f"Device not found: {identifier}"})


@mcp.tool()
async def detect_new_devices() -> str:
    """
    Scan network and return only newly discovered devices since last scan.

    Returns:
        JSON with list of new devices.
    """
    devices = await _scan_arp()
    result = _update_device_history(devices)

    return json.dumps({
        "success": True,
        "new_devices": result["new_devices"],
        "count": len(result["new_devices"]),
        "message": f"Detected {len(result['new_devices'])} new device(s)",
    }, indent=2)


@mcp.tool()
async def mark_device_known(mac: str, label: str, device_type: str = "trusted") -> str:
    """
    Mark a device as known/trusted with a label.

    Args:
        mac: MAC address of the device.
        label: Friendly label for the device (e.g., 'Living Room TV').
        device_type: Device type - trusted, iot, or guest.

    Returns:
        JSON confirmation.
    """
    global known_devices, device_history
    mac = mac.upper()

    known_devices[mac] = {
        "label": label,
        "type": device_type,
        "added": datetime.now().isoformat(),
    }

    if mac in device_history:
        device_history[mac]["is_known"] = True

    _save_json_file(KNOWN_DEVICES_FILE, known_devices)
    _save_json_file(DEVICE_HISTORY_FILE, device_history)

    return json.dumps({"success": True, "message": f"Marked {mac} as known: {label}"})


@mcp.tool()
async def get_cluster_nodes() -> str:
    """
    Get status of known cluster nodes on the network.

    Returns:
        JSON with cluster node status including online/offline.
    """
    topology = json.loads(await get_network_topology())
    cluster_status = []

    for node in topology["topology"]["cluster_nodes"]:
        cluster_status.append({
            "name": node.get("node_name"),
            "role": node.get("node_role"),
            "ip": node.get("ip"),
            "mac": node.get("mac"),
            "last_seen": node.get("last_seen"),
            "online": node.get("last_seen") is not None,
        })

    # Add any cluster nodes not seen
    seen_ips = {n["ip"] for n in cluster_status}
    for ip, info in CLUSTER_NODES.items():
        if ip not in seen_ips:
            cluster_status.append({
                "name": info["name"],
                "role": info["role"],
                "ip": ip,
                "mac": None,
                "last_seen": None,
                "online": False,
            })

    return json.dumps({
        "success": True,
        "cluster_nodes": cluster_status,
        "online_count": sum(1 for n in cluster_status if n["online"]),
        "total_nodes": len(cluster_status),
    }, indent=2)


@mcp.tool()
async def get_device_history(mac: Optional[str] = None) -> str:
    """
    Get full device history including first seen, last seen, and visit counts.

    Args:
        mac: Optional MAC address to filter by.

    Returns:
        JSON with device history.
    """
    if mac:
        mac = mac.upper()
        device = device_history.get(mac)
        if device:
            return json.dumps({"success": True, "device": device}, indent=2)
        return json.dumps({"success": False, "error": f"Device not found: {mac}"})

    return json.dumps({
        "success": True,
        "device_history": device_history,
        "total_devices": len(device_history),
    }, indent=2)


@mcp.tool()
async def get_unknown_devices() -> str:
    """
    Get list of all unknown/unverified devices on the network.

    Returns:
        JSON with list of unknown devices.
    """
    topology = json.loads(await get_network_topology())
    return json.dumps({
        "success": True,
        "unknown_devices": topology["topology"]["unknown_devices"],
        "count": len(topology["topology"]["unknown_devices"]),
        "message": f"Found {len(topology['topology']['unknown_devices'])} unknown device(s)",
    }, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
