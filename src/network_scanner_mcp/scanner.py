"""
Network Scanner Module - Core scanning functionality.

Provides various network scanning capabilities:
- ARP scanning for device discovery
- Port scanning for service detection
- Hostname resolution
- Service fingerprinting
- Bandwidth monitoring (passive)

All scanning operations are async for non-blocking execution.
"""

import asyncio
import logging
import re
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .utils import (
    ScanResult,
    detect_network_interface,
    detect_local_subnet,
    get_timestamp,
    normalize_mac,
)

logger = logging.getLogger("network-scanner")


# =============================================================================
# Configuration Constants
# =============================================================================

# Default timeout values (can be overridden via environment)
ARP_SCAN_TIMEOUT = 30  # seconds
PORT_SCAN_TIMEOUT = 2  # seconds per port
HOSTNAME_LOOKUP_TIMEOUT = 1  # seconds

# Common ports for quick scans
COMMON_PORTS = [
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    445,   # SMB
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP Proxy
    8443,  # HTTPS Alt
]

# Well-known service ports
SERVICE_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "smtp-submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5901: "vnc-1",
    6379: "redis",
    6333: "qdrant",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    11434: "ollama",
    27017: "mongodb",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PortScanResult:
    """Result of a port scan."""
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = "unknown"
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None


@dataclass
class DeviceScanResult:
    """Complete scan result for a device."""
    ip: str
    mac: str
    vendor: str
    scan_time: str
    hostname: Optional[str] = None
    ports: list[PortScanResult] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    os_guess: Optional[str] = None
    is_reachable: bool = True

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "scan_time": self.scan_time,
            "hostname": self.hostname,
            "ports": [
                {
                    "port": p.port,
                    "state": p.state,
                    "service": p.service,
                    "banner": p.banner,
                    "response_time_ms": p.response_time_ms,
                }
                for p in self.ports
            ],
            "services": self.services,
            "os_guess": self.os_guess,
            "is_reachable": self.is_reachable,
        }


# =============================================================================
# ARP Scanning
# =============================================================================

async def arp_scan(
    subnet: Optional[str] = None,
    interface: Optional[str] = None,
    timeout: int = ARP_SCAN_TIMEOUT,
) -> list[ScanResult]:
    """
    Perform ARP scan to discover devices on the network.

    Uses arp-scan utility for reliable layer-2 discovery.

    Args:
        subnet: Subnet to scan (e.g., "192.0.2.44/24"). Auto-detected if None.
        interface: Network interface to use. Auto-detected if None.
        timeout: Scan timeout in seconds.

    Returns:
        List of discovered devices with IP, MAC, and vendor.
    """
    if interface is None:
        interface = detect_network_interface()

    if subnet is None:
        subnet = detect_local_subnet()

    timestamp = get_timestamp()
    devices: list[ScanResult] = []

    try:
        # Run arp-scan
        cmd = ["sudo", "arp-scan", "--localnet", "-I", interface, "-q"]
        logger.debug(f"Running: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning(f"ARP scan timed out after {timeout}s")
            return devices

        if process.returncode != 0:
            error = stderr.decode().strip()
            logger.error(f"arp-scan failed: {error}")
            return devices

        # Parse output
        for line in stdout.decode().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 2 and "." in parts[0]:
                ip = parts[0].strip()
                mac = normalize_mac(parts[1].strip())
                vendor = parts[2].strip() if len(parts) > 2 else "Unknown"

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "scan_time": timestamp,
                    "hostname": None,  # Will be resolved separately
                })

        logger.info(f"ARP scan found {len(devices)} devices")

    except FileNotFoundError:
        logger.error("arp-scan not found. Install with: sudo dnf install arp-scan")
    except PermissionError:
        logger.error("arp-scan requires root privileges. Run with sudo.")
    except Exception as e:
        logger.error(f"ARP scan error: {e}")

    return devices


# =============================================================================
# Port Scanning
# =============================================================================

async def scan_port(
    ip: str,
    port: int,
    timeout: float = PORT_SCAN_TIMEOUT,
    grab_banner: bool = True,
) -> PortScanResult:
    """
    Scan a single port on a host.

    Args:
        ip: Target IP address
        port: Port number to scan
        timeout: Connection timeout in seconds
        grab_banner: Whether to attempt banner grabbing

    Returns:
        PortScanResult with port state and optional banner
    """
    service = SERVICE_PORTS.get(port, "unknown")
    result = PortScanResult(port=port, state="closed", service=service)

    start_time = datetime.now()

    try:
        # Create connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )

        result.state = "open"
        result.response_time_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Attempt banner grab
        if grab_banner:
            try:
                # Send a probe for HTTP
                if port in (80, 8080, 8443):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()

                # Read response with timeout
                banner_data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=1.0
                )

                if banner_data:
                    # Clean up banner
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                    result.banner = banner[:256]  # Limit banner length

                    # Try to identify service from banner
                    result.service = _identify_service(port, banner)

            except (asyncio.TimeoutError, Exception):
                pass

        writer.close()
        await writer.wait_closed()

    except asyncio.TimeoutError:
        result.state = "filtered"
    except ConnectionRefusedError:
        result.state = "closed"
    except OSError:
        result.state = "filtered"
    except Exception as e:
        logger.debug(f"Port scan {ip}:{port} error: {e}")
        result.state = "filtered"

    return result


async def scan_ports(
    ip: str,
    ports: Optional[list[int]] = None,
    timeout: float = PORT_SCAN_TIMEOUT,
    concurrency: int = 50,
) -> list[PortScanResult]:
    """
    Scan multiple ports on a host concurrently.

    Args:
        ip: Target IP address
        ports: List of ports to scan. Uses COMMON_PORTS if None.
        timeout: Per-port timeout in seconds
        concurrency: Maximum concurrent port scans

    Returns:
        List of PortScanResult for all scanned ports
    """
    if ports is None:
        ports = COMMON_PORTS

    logger.debug(f"Scanning {len(ports)} ports on {ip}")

    # Use semaphore to limit concurrency
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_with_limit(port: int) -> PortScanResult:
        async with semaphore:
            return await scan_port(ip, port, timeout)

    # Scan all ports concurrently
    tasks = [scan_with_limit(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    scan_results = []
    for r in results:
        if isinstance(r, PortScanResult):
            scan_results.append(r)
        elif isinstance(r, Exception):
            logger.debug(f"Port scan exception: {r}")

    # Sort by port number
    scan_results.sort(key=lambda x: x.port)

    open_ports = [r for r in scan_results if r.state == "open"]
    logger.info(f"Found {len(open_ports)} open ports on {ip}")

    return scan_results


async def quick_port_scan(
    ip: str,
    timeout: float = 1.0,
) -> list[PortScanResult]:
    """
    Perform a quick scan of common service ports.

    Args:
        ip: Target IP address
        timeout: Per-port timeout (shorter for quick scan)

    Returns:
        List of open ports only
    """
    results = await scan_ports(ip, COMMON_PORTS, timeout=timeout)
    return [r for r in results if r.state == "open"]


def _identify_service(port: int, banner: str) -> str:
    """
    Identify service from port and banner.

    Args:
        port: Port number
        banner: Service banner (if available)

    Returns:
        Identified service name
    """
    banner_lower = banner.lower()

    # Web server identification (check these first as they may not include "http")
    if "nginx" in banner_lower:
        return "nginx"
    if "apache" in banner_lower:
        return "apache"
    if "iis" in banner_lower:
        return "iis"

    # HTTP/HTTPS indicators
    if "http" in banner_lower or banner.startswith("HTTP/"):
        return "http"

    # SSH indicators
    if "ssh" in banner_lower or "openssh" in banner_lower:
        return "ssh"

    # Database indicators
    if "mysql" in banner_lower:
        return "mysql"
    if "postgresql" in banner_lower:
        return "postgresql"
    if "redis" in banner_lower:
        return "redis"
    if "mongodb" in banner_lower:
        return "mongodb"

    # Other services
    if "smtp" in banner_lower:
        return "smtp"
    if "ftp" in banner_lower:
        return "ftp"
    if "smb" in banner_lower:
        return "smb"

    # Fall back to port-based identification
    return SERVICE_PORTS.get(port, "unknown")


# =============================================================================
# Hostname Resolution
# =============================================================================

async def resolve_hostname(
    ip: str,
    timeout: float = HOSTNAME_LOOKUP_TIMEOUT,
) -> Optional[str]:
    """
    Resolve IP address to hostname via reverse DNS.

    Args:
        ip: IP address to resolve
        timeout: Lookup timeout in seconds

    Returns:
        Hostname or None if resolution fails
    """
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                socket.gethostbyaddr,
                ip
            ),
            timeout=timeout
        )
        return result[0]
    except (socket.herror, socket.gaierror, asyncio.TimeoutError):
        return None
    except Exception as e:
        logger.debug(f"Hostname resolution failed for {ip}: {e}")
        return None


async def resolve_hostnames(
    ips: list[str],
    timeout: float = HOSTNAME_LOOKUP_TIMEOUT,
    concurrency: int = 20,
) -> dict[str, Optional[str]]:
    """
    Resolve multiple IP addresses to hostnames concurrently.

    Args:
        ips: List of IP addresses
        timeout: Per-lookup timeout
        concurrency: Maximum concurrent lookups

    Returns:
        Dictionary mapping IP to hostname (or None)
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def resolve_with_limit(ip: str) -> tuple[str, Optional[str]]:
        async with semaphore:
            hostname = await resolve_hostname(ip, timeout)
            return (ip, hostname)

    tasks = [resolve_with_limit(ip) for ip in ips]
    results = await asyncio.gather(*tasks)

    return dict(results)


# =============================================================================
# ICMP Ping
# =============================================================================

async def ping_host(
    ip: str,
    count: int = 1,
    timeout: float = 2.0,
) -> tuple[bool, Optional[float]]:
    """
    Ping a host to check reachability.

    Args:
        ip: Target IP address
        count: Number of ping packets
        timeout: Ping timeout in seconds

    Returns:
        Tuple of (is_reachable, average_latency_ms)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "ping", "-c", str(count), "-W", str(int(timeout)), ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        stdout, _ = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout + 1
        )

        if process.returncode == 0:
            # Parse average latency from ping output
            output = stdout.decode()
            match = re.search(r'avg[^=]*=\s*([\d.]+)', output)
            if match:
                return (True, float(match.group(1)))
            return (True, None)

        return (False, None)

    except (asyncio.TimeoutError, Exception):
        return (False, None)


async def ping_hosts(
    ips: list[str],
    timeout: float = 2.0,
    concurrency: int = 50,
) -> dict[str, bool]:
    """
    Ping multiple hosts concurrently.

    Args:
        ips: List of IP addresses
        timeout: Per-host timeout
        concurrency: Maximum concurrent pings

    Returns:
        Dictionary mapping IP to reachability status
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def ping_with_limit(ip: str) -> tuple[str, bool]:
        async with semaphore:
            is_up, _ = await ping_host(ip, timeout=timeout)
            return (ip, is_up)

    tasks = [ping_with_limit(ip) for ip in ips]
    results = await asyncio.gather(*tasks)

    return dict(results)


# =============================================================================
# Full Device Scan
# =============================================================================

async def full_device_scan(
    ip: str,
    mac: str,
    vendor: str = "Unknown",
    scan_ports: bool = True,
    resolve_hostname: bool = True,
    port_list: Optional[list[int]] = None,
) -> DeviceScanResult:
    """
    Perform a comprehensive scan of a single device.

    Args:
        ip: Device IP address
        mac: Device MAC address
        vendor: Vendor name (from ARP)
        scan_ports: Whether to perform port scanning
        resolve_hostname: Whether to resolve hostname
        port_list: Custom port list (uses COMMON_PORTS if None)

    Returns:
        Complete device scan result
    """
    from .scanner import resolve_hostname as _resolve_hostname, scan_ports as _scan_ports

    timestamp = get_timestamp()
    result = DeviceScanResult(
        ip=ip,
        mac=normalize_mac(mac),
        vendor=vendor,
        scan_time=timestamp,
    )

    # Parallel tasks
    tasks = []

    if resolve_hostname:
        tasks.append(_resolve_hostname(ip))

    if scan_ports:
        ports = port_list or COMMON_PORTS
        tasks.append(_scan_ports(ip, ports))

    # Execute parallel tasks
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)

        idx = 0
        if resolve_hostname:
            if isinstance(results[idx], str) or results[idx] is None:
                result.hostname = results[idx]
            idx += 1

        if scan_ports:
            if isinstance(results[idx], list):
                result.ports = results[idx]
                result.services = [
                    p.service for p in result.ports
                    if p.state == "open" and p.service != "unknown"
                ]

    return result


# =============================================================================
# Network Discovery (Combined)
# =============================================================================

async def discover_network(
    subnet: Optional[str] = None,
    interface: Optional[str] = None,
    scan_ports: bool = False,
    resolve_hostnames: bool = True,
) -> list[DeviceScanResult]:
    """
    Discover all devices on the network with optional detailed scanning.

    Args:
        subnet: Subnet to scan (auto-detected if None)
        interface: Network interface (auto-detected if None)
        scan_ports: Whether to scan ports on discovered devices
        resolve_hostnames: Whether to resolve hostnames

    Returns:
        List of device scan results
    """
    # Step 1: ARP scan
    devices = await arp_scan(subnet, interface)

    if not devices:
        logger.warning("No devices found in ARP scan")
        return []

    results: list[DeviceScanResult] = []

    # Step 2: Resolve hostnames (if requested)
    hostname_map = {}
    if resolve_hostnames:
        ips = [d["ip"] for d in devices]
        hostname_map = await resolve_hostnames(ips)

    # Step 3: Build results
    for device in devices:
        result = DeviceScanResult(
            ip=device["ip"],
            mac=device["mac"],
            vendor=device["vendor"],
            scan_time=device["scan_time"],
            hostname=hostname_map.get(device["ip"]),
        )

        # Step 4: Port scan (if requested)
        if scan_ports:
            port_results = await scan_ports(device["ip"])
            result.ports = port_results
            result.services = [
                p.service for p in port_results
                if p.state == "open" and p.service != "unknown"
            ]

        results.append(result)

    logger.info(f"Network discovery complete: {len(results)} devices")
    return results
