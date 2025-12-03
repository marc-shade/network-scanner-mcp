#!/usr/bin/env python3
"""
Network Scanner Alert Daemon

Monitors network for new devices and cluster node status changes.
Sends alerts via:
- Voice synthesis (edge-tts)
- Node-chat MCP (cluster broadcast)
- Log files

Run as standalone: python -m network_scanner_mcp.alert_daemon
Or install as systemd service for continuous monitoring.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

from .utils import (
    ClusterNodeConfig,
    get_config_value,
    get_data_dir,
    get_timestamp,
    load_cluster_nodes,
    load_json_file,
    normalize_mac,
    save_json_file,
    setup_logging,
    detect_network_interface,
)
from .scanner import arp_scan, ping_hosts

# =============================================================================
# Configuration
# =============================================================================

# Configurable settings via environment
SCAN_INTERVAL_SECONDS = get_config_value("SCAN_INTERVAL_SECONDS", 300, int)
VOICE_ALERTS_ENABLED = get_config_value("VOICE_ALERTS_ENABLED", True, bool)
NODE_CHAT_ALERTS_ENABLED = get_config_value("NODE_CHAT_ALERTS_ENABLED", True, bool)
ALERT_ON_NEW_DEVICES = get_config_value("ALERT_ON_NEW_DEVICES", True, bool)
ALERT_ON_CLUSTER_NODE_DOWN = get_config_value("ALERT_ON_CLUSTER_NODE_DOWN", True, bool)
MAX_ALERT_HISTORY = get_config_value("MAX_ALERT_HISTORY", 1000, int)

# Voice settings
VOICE_NAME = get_config_value("TTS_VOICE", "en-IE-EmilyNeural", str)

# Node-chat settings
NODE_CHAT_SOCKET = get_config_value("NODE_CHAT_SOCKET", "/tmp/node-chat-mcp.sock", str)
NODE_CHAT_HTTP_URL = get_config_value("NODE_CHAT_HTTP_URL", "http://localhost:8765", str)

# Paths
DATA_DIR = get_data_dir()
ALERT_LOG = DATA_DIR / "alert_history.json"
KNOWN_DEVICES_FILE = DATA_DIR / "known_devices.json"

# Set up logging
logger = setup_logging(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    log_file=DATA_DIR / "alert_daemon.log",
)

# Network interface (auto-detected)
INTERFACE = detect_network_interface()

# Load cluster nodes configuration
CLUSTER_CONFIG_FILE = DATA_DIR / "cluster_nodes.json"
CLUSTER_NODES: dict[str, ClusterNodeConfig] = load_cluster_nodes(CLUSTER_CONFIG_FILE)


# =============================================================================
# Alert Types
# =============================================================================

class AlertType:
    """Alert type constants."""
    NEW_DEVICE = "new_device"
    NODE_OFFLINE = "node_offline"
    NODE_RECOVERED = "node_recovered"
    MULTIPLE_NEW_DEVICES = "multiple_new_devices"
    UNKNOWN_DEVICE_DETECTED = "unknown_device_detected"
    CLUSTER_DEGRADED = "cluster_degraded"
    CLUSTER_HEALTHY = "cluster_healthy"


# =============================================================================
# Alert History
# =============================================================================

class AlertHistory:
    """Manages alert history with persistence."""

    def __init__(self, filepath: Path, max_entries: int = 1000):
        self.filepath = filepath
        self.max_entries = max_entries
        self._history: dict = load_json_file(filepath, {"alerts": []})

    def add(self, alert_type: str, message: str, data: Optional[dict] = None) -> dict:
        """Add an alert to history."""
        alert = {
            "id": len(self._history.get("alerts", [])) + 1,
            "timestamp": get_timestamp(),
            "type": alert_type,
            "message": message,
            "data": data or {},
        }

        if "alerts" not in self._history:
            self._history["alerts"] = []

        self._history["alerts"].append(alert)

        # Trim to max entries
        if len(self._history["alerts"]) > self.max_entries:
            self._history["alerts"] = self._history["alerts"][-self.max_entries:]

        # Save to disk
        save_json_file(self.filepath, self._history)

        return alert

    def get_recent(self, count: int = 10) -> list[dict]:
        """Get recent alerts."""
        alerts = self._history.get("alerts", [])
        return alerts[-count:] if alerts else []

    def get_by_type(self, alert_type: str, count: int = 10) -> list[dict]:
        """Get alerts by type."""
        alerts = [
            a for a in self._history.get("alerts", [])
            if a.get("type") == alert_type
        ]
        return alerts[-count:] if alerts else []


# Initialize alert history
alert_history = AlertHistory(ALERT_LOG, MAX_ALERT_HISTORY)


# =============================================================================
# Voice Alerts
# =============================================================================

async def speak_alert(message: str, priority: str = "normal") -> bool:
    """
    Send voice alert using edge-tts.

    Args:
        message: Message to speak
        priority: Alert priority ("low", "normal", "high", "critical")

    Returns:
        True if successful
    """
    if not VOICE_ALERTS_ENABLED:
        logger.debug("Voice alerts disabled")
        return False

    try:
        # Adjust voice based on priority
        rate = "+0%"
        if priority == "high":
            rate = "+10%"
        elif priority == "critical":
            rate = "+20%"

        # Generate TTS audio
        output_file = Path("/tmp/network_alert.mp3")

        process = await asyncio.create_subprocess_exec(
            "edge-tts",
            "--voice", VOICE_NAME,
            "--rate", rate,
            "--text", message,
            "--write-media", str(output_file),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        _, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

        if process.returncode != 0:
            logger.error(f"edge-tts failed: {stderr.decode()}")
            return False

        # Play audio
        play_process = await asyncio.create_subprocess_exec(
            "mpv",
            "--no-terminal",
            "--really-quiet",
            str(output_file),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        await asyncio.wait_for(play_process.wait(), timeout=30)

        logger.info(f"[VOICE] {message}")
        return True

    except FileNotFoundError as e:
        logger.warning(f"Voice alert tool not found: {e}")
        return False
    except asyncio.TimeoutError:
        logger.warning("Voice alert timed out")
        return False
    except Exception as e:
        logger.error(f"Voice alert error: {e}")
        return False


# =============================================================================
# Node-Chat Integration
# =============================================================================

async def send_node_chat_alert(
    message: str,
    alert_type: str,
    data: Optional[dict] = None,
    priority: str = "normal",
) -> bool:
    """
    Send alert to cluster via node-chat MCP.

    Tries multiple methods:
    1. Direct socket connection
    2. HTTP API
    3. Database queue (fallback)

    Args:
        message: Alert message
        alert_type: Type of alert
        data: Additional alert data
        priority: Alert priority

    Returns:
        True if any delivery method succeeded
    """
    if not NODE_CHAT_ALERTS_ENABLED:
        logger.debug("Node-chat alerts disabled")
        return False

    alert_payload = {
        "type": "network_alert",
        "alert_type": alert_type,
        "message": message,
        "priority": priority,
        "timestamp": get_timestamp(),
        "source": "network-scanner-daemon",
        "data": data or {},
    }

    # Method 1: Try HTTP API
    if aiohttp:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{NODE_CHAT_HTTP_URL}/broadcast",
                    json=alert_payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    if response.status == 200:
                        logger.info(f"[NODE-CHAT] Alert sent via HTTP: {message}")
                        return True
                    else:
                        logger.debug(f"Node-chat HTTP returned {response.status}")
        except Exception as e:
            logger.debug(f"Node-chat HTTP failed: {e}")

    # Method 2: Try Unix socket
    socket_path = Path(NODE_CHAT_SOCKET)
    if socket_path.exists():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(socket_path)),
                timeout=5,
            )

            # Send JSON-RPC style message
            request = json.dumps({
                "jsonrpc": "2.0",
                "method": "broadcast_to_cluster",
                "params": {"message": message, "priority": priority},
                "id": 1,
            }) + "\n"

            writer.write(request.encode())
            await writer.drain()

            # Read response
            response = await asyncio.wait_for(reader.readline(), timeout=5)

            writer.close()
            await writer.wait_closed()

            if response:
                logger.info(f"[NODE-CHAT] Alert sent via socket: {message}")
                return True

        except Exception as e:
            logger.debug(f"Node-chat socket failed: {e}")

    # Method 3: Write to database queue for later delivery
    try:
        queue_file = DATA_DIR / "pending_alerts.json"
        pending = load_json_file(queue_file, {"alerts": []})
        pending["alerts"].append(alert_payload)

        # Keep last 100 pending alerts
        pending["alerts"] = pending["alerts"][-100:]
        save_json_file(queue_file, pending)

        logger.info(f"[NODE-CHAT] Alert queued for delivery: {message}")
        return True

    except Exception as e:
        logger.error(f"Failed to queue alert: {e}")

    return False


# =============================================================================
# Network Monitoring
# =============================================================================

async def scan_network() -> list[dict]:
    """
    Perform network scan.

    Returns:
        List of discovered devices
    """
    try:
        devices = await arp_scan(interface=INTERFACE)
        logger.debug(f"Scan found {len(devices)} devices")
        return devices
    except Exception as e:
        logger.error(f"Network scan error: {e}")
        return []


def load_known_devices() -> set[str]:
    """Load set of known device MAC addresses."""
    known = load_json_file(KNOWN_DEVICES_FILE, {})

    # Handle both formats:
    # Format 1: {"MAC": {...}}
    # Format 2: {"devices": {"MAC": {...}}}
    if "devices" in known:
        return set(normalize_mac(mac) for mac in known["devices"].keys())

    # Assume direct MAC->info mapping
    return set(normalize_mac(mac) for mac in known.keys())


async def check_cluster_nodes(discovered_ips: set[str]) -> tuple[list, list]:
    """
    Check cluster node status.

    Args:
        discovered_ips: Set of IPs found in scan

    Returns:
        Tuple of (online_nodes, offline_nodes)
    """
    online = []
    offline = []

    for ip, config in CLUSTER_NODES.items():
        node_info = (ip, config["name"], config["role"])

        if ip in discovered_ips:
            online.append(node_info)
        else:
            # Double-check with ping
            reachable = await ping_host_simple(ip)
            if reachable:
                online.append(node_info)
            else:
                offline.append(node_info)

    return online, offline


async def ping_host_simple(ip: str, timeout: float = 2.0) -> bool:
    """Simple ping check."""
    try:
        process = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", str(int(timeout)), ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(process.wait(), timeout=timeout + 1)
        return process.returncode == 0
    except Exception:
        return False


# =============================================================================
# Alert Generation
# =============================================================================

async def process_new_device(device: dict) -> None:
    """Process and alert on new device detection."""
    ip = device.get("ip", "Unknown")
    mac = device.get("mac", "Unknown")
    vendor = device.get("vendor", "Unknown")

    message = f"New device detected: {ip}, MAC {mac}, vendor: {vendor}"
    voice_message = f"New device detected! IP address {ip}, {vendor}"

    logger.warning(f"[NEW DEVICE] {message}")

    # Log alert
    alert_history.add(
        AlertType.NEW_DEVICE,
        message,
        {"ip": ip, "mac": mac, "vendor": vendor}
    )

    # Send alerts concurrently
    await asyncio.gather(
        speak_alert(voice_message, priority="high"),
        send_node_chat_alert(message, AlertType.NEW_DEVICE, device, priority="high"),
        return_exceptions=True,
    )


async def process_node_offline(ip: str, name: str, role: str) -> None:
    """Process and alert on cluster node going offline."""
    message = f"Cluster node offline: {name} ({role}) at {ip}"
    voice_message = f"Warning! Cluster node {name} is offline!"

    logger.error(f"[CLUSTER] {message}")

    alert_history.add(
        AlertType.NODE_OFFLINE,
        message,
        {"ip": ip, "name": name, "role": role}
    )

    await asyncio.gather(
        speak_alert(voice_message, priority="critical"),
        send_node_chat_alert(message, AlertType.NODE_OFFLINE, {"ip": ip, "name": name, "role": role}, priority="critical"),
        return_exceptions=True,
    )


async def process_node_recovered(ip: str, name: str, role: str) -> None:
    """Process and alert on cluster node recovery."""
    message = f"Cluster node recovered: {name} ({role}) at {ip}"
    voice_message = f"Good news! Cluster node {name} is back online!"

    logger.info(f"[CLUSTER] {message}")

    alert_history.add(
        AlertType.NODE_RECOVERED,
        message,
        {"ip": ip, "name": name, "role": role}
    )

    await asyncio.gather(
        speak_alert(voice_message, priority="normal"),
        send_node_chat_alert(message, AlertType.NODE_RECOVERED, {"ip": ip, "name": name, "role": role}, priority="normal"),
        return_exceptions=True,
    )


# =============================================================================
# Main Monitor Loop
# =============================================================================

async def monitor_loop() -> None:
    """Main monitoring loop."""
    logger.info("=" * 60)
    logger.info("Network Scanner Alert Daemon Starting")
    logger.info("=" * 60)
    logger.info(f"Interface: {INTERFACE}")
    logger.info(f"Scan interval: {SCAN_INTERVAL_SECONDS}s")
    logger.info(f"Voice alerts: {VOICE_ALERTS_ENABLED}")
    logger.info(f"Node-chat alerts: {NODE_CHAT_ALERTS_ENABLED}")
    logger.info(f"Alert on new devices: {ALERT_ON_NEW_DEVICES}")
    logger.info(f"Alert on node down: {ALERT_ON_CLUSTER_NODE_DOWN}")
    logger.info(f"Cluster nodes configured: {len(CLUSTER_NODES)}")
    logger.info("=" * 60)

    # Track state across scans
    last_offline_nodes: set[str] = set()
    seen_macs: set[str] = set()

    # Initialize seen_macs from history
    device_history_file = DATA_DIR / "device_history.json"
    if device_history_file.exists():
        history = load_json_file(device_history_file, {})
        seen_macs = set(normalize_mac(mac) for mac in history.keys())
        logger.info(f"Loaded {len(seen_macs)} known MAC addresses from history")

    # Initial scan
    iteration = 0

    while True:
        iteration += 1
        scan_time = datetime.now().isoformat()

        try:
            logger.info(f"\n[SCAN #{iteration}] {scan_time} - Scanning network...")

            # Perform network scan
            devices = await scan_network()

            if not devices:
                logger.warning("No devices found in scan")
                await asyncio.sleep(SCAN_INTERVAL_SECONDS)
                continue

            logger.info(f"[SCAN] Found {len(devices)} devices")

            # Build sets for comparison
            current_ips = {d["ip"] for d in devices}
            current_macs = {normalize_mac(d["mac"]) for d in devices}
            known_macs = load_known_devices()

            # Check for new devices
            if ALERT_ON_NEW_DEVICES:
                for device in devices:
                    mac = normalize_mac(device["mac"])

                    # New device = not seen before AND not in known list AND not a cluster node
                    if mac not in seen_macs and mac not in known_macs:
                        ip = device.get("ip", "")

                        # Skip if it's a cluster node
                        if ip in CLUSTER_NODES:
                            logger.debug(f"Skipping new MAC for cluster node: {ip}")
                            continue

                        await process_new_device(device)

                # Update seen MACs
                seen_macs.update(current_macs)

            # Check cluster nodes
            if ALERT_ON_CLUSTER_NODE_DOWN and CLUSTER_NODES:
                online_nodes, offline_nodes = await check_cluster_nodes(current_ips)
                offline_ips = {ip for ip, _, _ in offline_nodes}

                # Newly offline nodes
                newly_offline = offline_ips - last_offline_nodes
                for ip, name, role in offline_nodes:
                    if ip in newly_offline:
                        await process_node_offline(ip, name, role)

                # Recovered nodes
                recovered = last_offline_nodes - offline_ips
                for ip in recovered:
                    if ip in CLUSTER_NODES:
                        config = CLUSTER_NODES[ip]
                        await process_node_recovered(ip, config["name"], config["role"])

                last_offline_nodes = offline_ips

                logger.info(f"[CLUSTER] Online: {len(online_nodes)}, Offline: {len(offline_nodes)}")

        except Exception as e:
            logger.error(f"Monitor loop error: {e}", exc_info=True)

        # Wait for next scan
        logger.debug(f"Sleeping for {SCAN_INTERVAL_SECONDS}s")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)


# =============================================================================
# Entry Point
# =============================================================================

def main() -> None:
    """Entry point for the alert daemon."""
    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(monitor_loop())
    except KeyboardInterrupt:
        logger.info("\n[DAEMON] Shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Daemon crashed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
