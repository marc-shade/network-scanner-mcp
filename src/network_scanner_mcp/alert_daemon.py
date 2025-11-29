#!/usr/bin/env python3
"""
Network Scanner Alert Daemon
Monitors network for new devices and alerts via voice/node-chat.

Run as: python alert_daemon.py
Or install as systemd service for continuous monitoring.
"""

import asyncio
import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import aiohttp

# Configuration
SCAN_INTERVAL_SECONDS = 300  # 5 minutes
VOICE_ALERTS_ENABLED = True
NODE_CHAT_ALERTS_ENABLED = True
ALERT_ON_NEW_DEVICES = True
ALERT_ON_CLUSTER_NODE_DOWN = True

# Paths
DATA_DIR = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "/mnt/agentic-system"), "mcp-servers/network-scanner-mcp/data"))
ALERT_LOG = DATA_DIR / "alert_history.json"
KNOWN_DEVICES_FILE = DATA_DIR / "known_devices.json"

# Voice MCP endpoint (if running as HTTP)
VOICE_MCP_SOCKET = "/tmp/voice-mode.sock"

# Cluster nodes to monitor
CLUSTER_NODES = {
    "192.168.1.79": "mac-studio (orchestrator)",  # TODO: Move to config/env var
    "192.168.1.87": "macpro51 (builder)",  # TODO: Move to config/env var
    "192.168.1.183": "macpro51-alt (builder)",  # TODO: Move to config/env var
    "192.168.1.233": "mac-mini (files)",  # TODO: Move to config/env var
    "192.168.1.55": "macbook-air-m3 (coordinator)",  # TODO: Move to config/env var
    "192.168.1.186": "completeu-server (inference)",  # TODO: Move to config/env var
}


def load_json(path: Path) -> dict:
    """Load JSON file or return empty dict."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except:
            return {}
    return {}


def save_json(path: Path, data: dict):
    """Save data to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


async def speak_alert(message: str):
    """Send voice alert via voice-mode MCP."""
    if not VOICE_ALERTS_ENABLED:
        return

    try:
        # Try calling voice-mode directly via subprocess
        # This works because we can invoke the MCP tool from Python
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c",
            f"""
import asyncio
import json
import subprocess

# Use edge-tts directly for simplicity
async def speak():
    proc = await asyncio.create_subprocess_exec(
        'edge-tts', '--voice', 'en-IE-EmilyNeural',
        '--text', '''{message.replace("'", "\\'")}''',
        '--write-media', '/tmp/alert.mp3',
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await proc.wait()

    # Play with mpv
    proc = await asyncio.create_subprocess_exec(
        'mpv', '--no-terminal', '/tmp/alert.mp3',
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await proc.wait()

asyncio.run(speak())
""",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await process.wait()
        print(f"[VOICE] {message}")
    except Exception as e:
        print(f"[VOICE ERROR] {e}")


async def send_node_chat_alert(message: str):
    """Send alert to cluster via node-chat MCP."""
    if not NODE_CHAT_ALERTS_ENABLED:
        return

    try:
        # Broadcast to cluster nodes
        print(f"[NODE-CHAT] {message}")
        # TODO: Implement actual node-chat integration
    except Exception as e:
        print(f"[NODE-CHAT ERROR] {e}")


async def scan_network() -> list:
    """Run ARP scan and return list of devices."""
    try:
        # Run arp-scan
        process = await asyncio.create_subprocess_exec(
            'sudo', 'arp-scan', '-l', '-I', 'enp20s0', '-q',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()

        devices = []
        for line in stdout.decode().strip().split('\n'):
            if line and '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    devices.append({
                        'ip': parts[0],
                        'mac': parts[1].upper(),
                        'vendor': parts[2] if len(parts) > 2 else 'Unknown'
                    })
        return devices
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        return []


async def check_cluster_nodes(devices: list) -> tuple[list, list]:
    """Check which cluster nodes are online/offline."""
    online_ips = {d['ip'] for d in devices}

    online_nodes = []
    offline_nodes = []

    for ip, name in CLUSTER_NODES.items():
        if ip in online_ips:
            online_nodes.append((ip, name))
        else:
            offline_nodes.append((ip, name))

    return online_nodes, offline_nodes


async def detect_new_devices(devices: list) -> list:
    """Compare scan results with known devices, return new ones."""
    known = load_json(KNOWN_DEVICES_FILE)
    known_macs = set(known.get('devices', {}).keys())

    new_devices = []
    for device in devices:
        mac = device['mac']
        if mac not in known_macs:
            new_devices.append(device)

    return new_devices


async def log_alert(alert_type: str, message: str, data: dict = None):
    """Log alert to history file."""
    history = load_json(ALERT_LOG)
    if 'alerts' not in history:
        history['alerts'] = []

    history['alerts'].append({
        'timestamp': datetime.now().isoformat(),
        'type': alert_type,
        'message': message,
        'data': data or {}
    })

    # Keep last 1000 alerts
    history['alerts'] = history['alerts'][-1000:]
    save_json(ALERT_LOG, history)


async def monitor_loop():
    """Main monitoring loop."""
    print(f"[DAEMON] Network Scanner Alert Daemon starting...")
    print(f"[DAEMON] Scan interval: {SCAN_INTERVAL_SECONDS}s")
    print(f"[DAEMON] Voice alerts: {VOICE_ALERTS_ENABLED}")
    print(f"[DAEMON] Node-chat alerts: {NODE_CHAT_ALERTS_ENABLED}")

    last_offline_nodes = set()

    while True:
        try:
            print(f"\n[SCAN] {datetime.now().isoformat()} - Scanning network...")
            devices = await scan_network()
            print(f"[SCAN] Found {len(devices)} devices")

            # Check for new devices
            if ALERT_ON_NEW_DEVICES:
                new_devices = await detect_new_devices(devices)
                if new_devices:
                    for device in new_devices:
                        msg = f"Alert! New device detected on network: {device['ip']}, MAC {device['mac']}, vendor {device['vendor']}"
                        print(f"[NEW DEVICE] {msg}")
                        await log_alert('new_device', msg, device)
                        await speak_alert(f"New device detected! IP {device['ip']}, {device['vendor']}")
                        await send_node_chat_alert(msg)

            # Check cluster nodes
            if ALERT_ON_CLUSTER_NODE_DOWN:
                online_nodes, offline_nodes = await check_cluster_nodes(devices)
                offline_set = {ip for ip, _ in offline_nodes}

                # Alert on newly offline nodes
                newly_offline = offline_set - last_offline_nodes
                for ip, name in offline_nodes:
                    if ip in newly_offline:
                        msg = f"Cluster node offline: {name} at {ip}"
                        print(f"[CLUSTER] {msg}")
                        await log_alert('node_offline', msg, {'ip': ip, 'name': name})
                        await speak_alert(f"Warning! Cluster node {name.split()[0]} is offline!")
                        await send_node_chat_alert(msg)

                # Log recovered nodes
                recovered = last_offline_nodes - offline_set
                for ip in recovered:
                    name = CLUSTER_NODES.get(ip, 'Unknown')
                    msg = f"Cluster node recovered: {name} at {ip}"
                    print(f"[CLUSTER] {msg}")
                    await log_alert('node_recovered', msg, {'ip': ip, 'name': name})
                    await speak_alert(f"Good news! Cluster node {name.split()[0]} is back online!")

                last_offline_nodes = offline_set
                print(f"[CLUSTER] Online: {len(online_nodes)}, Offline: {len(offline_nodes)}")

        except Exception as e:
            print(f"[ERROR] Monitor loop error: {e}")

        await asyncio.sleep(SCAN_INTERVAL_SECONDS)


def main():
    """Entry point."""
    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Run the monitor
    try:
        asyncio.run(monitor_loop())
    except KeyboardInterrupt:
        print("\n[DAEMON] Shutting down...")


if __name__ == "__main__":
    main()
