"""
Shared utilities for Network Scanner MCP.

This module consolidates common functionality used across the MCP server
and alert daemon to avoid code duplication and ensure consistency.
"""

import json
import logging
import os
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TypedDict

# Configure module logger
logger = logging.getLogger("network-scanner")


# =============================================================================
# Type Definitions
# =============================================================================

class DeviceInfo(TypedDict, total=False):
    """Type definition for a network device."""
    mac: str
    ip: str
    vendor: str
    hostname: Optional[str]
    first_seen: str
    last_seen: str
    seen_count: int
    is_known: bool
    is_cluster_node: bool
    ports: list[dict]
    services: list[str]


class ClusterNodeConfig(TypedDict, total=False):
    """Type definition for cluster node configuration."""
    name: str
    role: str
    type: str
    description: Optional[str]


class ScanResult(TypedDict):
    """Type definition for scan results."""
    ip: str
    mac: str
    vendor: str
    scan_time: str
    hostname: Optional[str]


# =============================================================================
# Configuration
# =============================================================================

def get_data_dir() -> Path:
    """
    Get the data directory for network scanner storage.

    Priority:
    1. NETWORK_SCANNER_DATA_DIR environment variable
    2. $AGENTIC_SYSTEM_PATH/databases/network-scanner
    3. ~/databases/network-scanner

    Returns:
        Path to the data directory (created if not exists)
    """
    data_dir = Path(os.environ.get(
        "NETWORK_SCANNER_DATA_DIR",
        os.path.join(
            os.environ.get("AGENTIC_SYSTEM_PATH", str(Path.home())),
            "databases/network-scanner"
        )
    ))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_config_value(key: str, default: Any = None, cast_type: type = str) -> Any:
    """
    Get a configuration value from environment with type casting.

    Args:
        key: Environment variable name
        default: Default value if not set
        cast_type: Type to cast the value to (str, int, float, bool)

    Returns:
        Configuration value cast to the specified type
    """
    value = os.environ.get(key)
    if value is None:
        return default

    if cast_type == bool:
        return value.lower() in ("true", "1", "yes", "on")

    try:
        return cast_type(value)
    except (ValueError, TypeError):
        logger.warning(f"Failed to cast {key}={value} to {cast_type}, using default: {default}")
        return default


# =============================================================================
# Cluster Node Configuration
# =============================================================================

def load_cluster_nodes(config_file: Optional[Path] = None) -> dict[str, ClusterNodeConfig]:
    """
    Load cluster node configuration from file or environment.

    Configuration sources (in priority order):
    1. CLUSTER_NODES_JSON environment variable (JSON string)
    2. cluster_nodes.json file in data directory
    3. Default hardcoded cluster nodes (if DEFAULT_CLUSTER_NODES is set)
    4. Empty dict (no predefined cluster nodes)

    The function normalizes all configuration formats to:
    {"ip": {"name": "...", "role": "...", "type": "cluster_node"}}

    Args:
        config_file: Optional path to cluster config file

    Returns:
        Dictionary mapping IP addresses to ClusterNodeConfig
    """
    # Try environment variable first
    env_config = os.environ.get("CLUSTER_NODES_JSON")
    if env_config:
        try:
            raw_config = json.loads(env_config)
            return _normalize_cluster_config(raw_config)
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid CLUSTER_NODES_JSON: {e}")

    # Try config file
    if config_file is None:
        config_file = get_data_dir() / "cluster_nodes.json"

    if config_file.exists():
        try:
            raw_config = json.loads(config_file.read_text())
            return _normalize_cluster_config(raw_config)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load cluster config from {config_file}: {e}")

    # Return empty - no predefined cluster nodes
    logger.info("No cluster nodes configured")
    return {}


def _normalize_cluster_config(raw_config: dict) -> dict[str, ClusterNodeConfig]:
    """
    Normalize cluster configuration to standard format.

    Handles both formats:
    - Simple: {"ip": "name (role)"}
    - Full: {"ip": {"name": "...", "role": "...", "type": "..."}}

    Args:
        raw_config: Raw configuration dictionary

    Returns:
        Normalized configuration dictionary
    """
    normalized = {}

    for ip, info in raw_config.items():
        if isinstance(info, str):
            # Parse "name (role)" format
            match = re.match(r"^(.+?)\s*\((.+?)\)$", info)
            if match:
                normalized[ip] = {
                    "name": match.group(1).strip(),
                    "role": match.group(2).strip(),
                    "type": "cluster_node"
                }
            else:
                normalized[ip] = {
                    "name": info,
                    "role": "node",
                    "type": "cluster_node"
                }
        elif isinstance(info, dict):
            normalized[ip] = {
                "name": info.get("name", "unknown"),
                "role": info.get("role", "node"),
                "type": info.get("type", "cluster_node"),
                "description": info.get("description")
            }

    return normalized


def get_cluster_node_display_name(ip: str, cluster_nodes: dict[str, ClusterNodeConfig]) -> str:
    """
    Get a display-friendly name for a cluster node.

    Args:
        ip: IP address of the node
        cluster_nodes: Cluster nodes configuration

    Returns:
        Display name like "node-1 (orchestrator)" or the IP if not found
    """
    if ip in cluster_nodes:
        node = cluster_nodes[ip]
        return f"{node['name']} ({node['role']})"
    return ip


# =============================================================================
# Network Interface Detection
# =============================================================================

def detect_network_interface() -> str:
    """
    Detect the primary network interface.

    Detection methods (in priority order):
    1. NETWORK_INTERFACE environment variable
    2. netifaces default gateway interface
    3. First active interface from /sys/class/net
    4. Fallback to "eth0"

    Returns:
        Network interface name (e.g., "eth0", "enp20s0")
    """
    # Check environment override
    env_interface = os.environ.get("NETWORK_INTERFACE")
    if env_interface:
        logger.info(f"Using interface from environment: {env_interface}")
        return env_interface

    # Try netifaces
    try:
        import netifaces
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        if default_gateway:
            interface = default_gateway[1]
            logger.info(f"Detected interface via netifaces: {interface}")
            return interface
    except Exception as e:
        logger.debug(f"netifaces detection failed: {e}")

    # Scan /sys/class/net for active interfaces
    net_path = Path("/sys/class/net")
    if net_path.exists():
        for iface in net_path.iterdir():
            # Skip loopback and virtual interfaces
            if iface.name.startswith(("lo", "docker", "br-", "veth", "virbr")):
                continue

            # Check if interface is up
            operstate = iface / "operstate"
            if operstate.exists():
                state = operstate.read_text().strip()
                if state == "up":
                    logger.info(f"Detected active interface: {iface.name}")
                    return iface.name

    # Fallback
    fallback = "eth0"
    logger.warning(f"Could not detect interface, using fallback: {fallback}")
    return fallback


def detect_local_subnet() -> str:
    """
    Detect the local subnet for scanning.

    Returns:
        Subnet in CIDR notation (e.g., "192.0.2.44/24")
    """
    # Check environment override
    env_subnet = os.environ.get("DEFAULT_SCAN_SUBNET")
    if env_subnet:
        return env_subnet

    try:
        # Connect to external server to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception as e:
        logger.warning(f"Subnet detection failed: {e}, using default")
        return "192.0.2.44/24"


# =============================================================================
# JSON File Operations
# =============================================================================

def load_json_file(filepath: Path, default: Optional[dict] = None) -> dict:
    """
    Load JSON data from file with error handling.

    Args:
        filepath: Path to JSON file
        default: Default value if file doesn't exist or is invalid

    Returns:
        Parsed JSON data or default value
    """
    if default is None:
        default = {}

    if not filepath.exists():
        return default

    try:
        content = filepath.read_text()
        if not content.strip():
            return default
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filepath}: {e}")
        return default
    except IOError as e:
        logger.error(f"Failed to read {filepath}: {e}")
        return default


def save_json_file(filepath: Path, data: dict, indent: int = 2) -> bool:
    """
    Save JSON data to file with error handling.

    Args:
        filepath: Path to JSON file
        data: Data to save
        indent: JSON indentation level

    Returns:
        True if successful, False otherwise
    """
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(data, indent=indent, default=str))
        return True
    except IOError as e:
        logger.error(f"Failed to write {filepath}: {e}")
        return False


# =============================================================================
# MAC Address Utilities
# =============================================================================

def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to uppercase colon-separated format.

    Args:
        mac: MAC address in any format

    Returns:
        Normalized MAC address (e.g., "00:00:00:00:00:63")
    """
    # Remove all separators and convert to uppercase
    clean = re.sub(r'[^a-fA-F0-9]', '', mac).upper()

    if len(clean) != 12:
        logger.warning(f"Invalid MAC address: {mac}")
        return mac.upper()

    # Format with colons
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def get_mac_vendor(mac: str) -> str:
    """
    Get vendor name from MAC address OUI.

    This is a placeholder - can be enhanced with mac-vendor-lookup library
    or an online API if needed.

    Args:
        mac: MAC address

    Returns:
        Vendor name or "Unknown"
    """
    # OUI prefix (first 3 octets)
    # This could be expanded with a local OUI database
    try:
        from mac_vendor_lookup import MacLookup
        lookup = MacLookup()
        return lookup.lookup(mac)
    except Exception:
        return "Unknown"


# =============================================================================
# Timestamp Utilities
# =============================================================================

def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse ISO format timestamp string.

    Args:
        timestamp_str: ISO format timestamp

    Returns:
        datetime object or None if invalid
    """
    try:
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, TypeError):
        return None


def is_recent(timestamp_str: str, max_age_seconds: int = 300) -> bool:
    """
    Check if a timestamp is within the recent past.

    Args:
        timestamp_str: ISO format timestamp
        max_age_seconds: Maximum age in seconds to be considered recent

    Returns:
        True if timestamp is within max_age_seconds of now
    """
    ts = parse_timestamp(timestamp_str)
    if ts is None:
        return False

    age = (datetime.now() - ts).total_seconds()
    return 0 <= age <= max_age_seconds


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Set up logging for the network scanner.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file to write logs to
        format_string: Custom format string

    Returns:
        Configured logger
    """
    if format_string is None:
        format_string = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # Get log level from environment or parameter
    env_level = os.environ.get("LOG_LEVEL", level).upper()
    numeric_level = getattr(logging, env_level, logging.INFO)

    # Configure root logger for this module
    logger = logging.getLogger("network-scanner")
    logger.setLevel(numeric_level)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(format_string))
        logger.addHandler(file_handler)

    return logger
