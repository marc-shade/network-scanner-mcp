"""Tests for network scanning functionality."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from network_scanner_mcp.scanner import (
    arp_scan,
    scan_port,
    scan_ports,
    quick_port_scan,
    resolve_hostname,
    resolve_hostnames,
    ping_host,
    ping_hosts,
    full_device_scan,
    discover_network,
    PortScanResult,
    DeviceScanResult,
    COMMON_PORTS,
    SERVICE_PORTS,
    _identify_service,
)


class TestARPScanning:
    """Tests for ARP scanning functionality."""

    @pytest.mark.asyncio
    async def test_arp_scan_success(self, mock_network_interface):
        """Test successful ARP scan."""
        mock_output = b"""192.0.2.102\t00:00:00:00:00:63\tApple, Inc.
192.0.2.138\t00:00:00:00:00:1B\tSamsung Electronics Co.,Ltd
192.0.2.143\t00:00:00:00:00:8D\tApple, Inc."""

        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_exec.return_value = mock_process

            results = await arp_scan(interface="eth0")

            assert len(results) == 3
            assert results[0]["ip"] == "192.0.2.102"
            assert results[0]["mac"] == "00:00:00:00:00:63"
            assert results[0]["vendor"] == "Apple, Inc."
            assert results[1]["ip"] == "192.0.2.138"
            assert results[2]["mac"] == "00:00:00:00:00:8D"

    @pytest.mark.asyncio
    async def test_arp_scan_timeout(self, mock_network_interface):
        """Test ARP scan timeout handling."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                side_effect=asyncio.TimeoutError()
            )
            mock_process.kill = MagicMock()
            mock_process.wait = AsyncMock()
            mock_exec.return_value = mock_process

            results = await arp_scan(interface="eth0", timeout=1)

            assert results == []
            mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_arp_scan_failure(self, mock_network_interface):
        """Test ARP scan command failure."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(b"", b"Permission denied"))
            mock_exec.return_value = mock_process

            results = await arp_scan(interface="eth0")

            assert results == []

    @pytest.mark.asyncio
    async def test_arp_scan_no_devices(self, mock_network_interface):
        """Test ARP scan with no devices found."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_process

            results = await arp_scan(interface="eth0")

            assert results == []

    @pytest.mark.asyncio
    async def test_arp_scan_auto_detect_interface(self):
        """Test ARP scan with auto-detected interface."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_process

            results = await arp_scan(interface=None)

            # Should still attempt scan with detected interface
            mock_exec.assert_called_once()


class TestPortScanning:
    """Tests for port scanning functionality."""

    @pytest.mark.asyncio
    async def test_scan_port_open(self):
        """Test scanning an open port."""
        with patch('asyncio.open_connection') as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)

            result = await scan_port("192.0.2.102", 80, grab_banner=False)

            assert result.port == 80
            assert result.state == "open"
            assert result.service == "http"
            assert result.response_time_ms is not None

    @pytest.mark.asyncio
    async def test_scan_port_closed(self):
        """Test scanning a closed port."""
        with patch('asyncio.open_connection', side_effect=ConnectionRefusedError()):
            result = await scan_port("192.0.2.102", 9999)

            assert result.port == 9999
            assert result.state == "closed"

    @pytest.mark.asyncio
    async def test_scan_port_filtered(self):
        """Test scanning a filtered port (timeout)."""
        with patch('asyncio.open_connection', side_effect=asyncio.TimeoutError()):
            result = await scan_port("192.0.2.102", 443, timeout=0.1)

            assert result.port == 443
            assert result.state == "filtered"

    @pytest.mark.asyncio
    async def test_scan_port_with_banner(self):
        """Test port scan with banner grabbing."""
        mock_banner = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"

        with patch('asyncio.open_connection') as mock_conn:
            mock_reader = AsyncMock()
            mock_reader.read = AsyncMock(return_value=mock_banner)
            mock_writer = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)

            result = await scan_port("192.0.2.102", 80, grab_banner=True)

            assert result.state == "open"
            assert result.banner is not None
            assert "nginx" in result.banner.lower()
            assert result.service == "nginx"

    @pytest.mark.asyncio
    async def test_scan_ports_multiple(self):
        """Test scanning multiple ports."""
        ports_to_scan = [22, 80, 443]

        with patch('network_scanner_mcp.scanner.scan_port') as mock_scan:
            mock_scan.side_effect = [
                PortScanResult(port=22, state="open", service="ssh"),
                PortScanResult(port=80, state="open", service="http"),
                PortScanResult(port=443, state="closed", service="https"),
            ]

            results = await scan_ports("192.0.2.102", ports_to_scan)

            assert len(results) == 3
            assert results[0].port == 22
            assert results[0].state == "open"
            assert results[1].port == 80
            assert results[2].state == "closed"

    @pytest.mark.asyncio
    async def test_scan_ports_default_ports(self):
        """Test scanning with default common ports."""
        with patch('network_scanner_mcp.scanner.scan_port') as mock_scan:
            mock_scan.return_value = PortScanResult(port=80, state="closed", service="http")

            results = await scan_ports("192.0.2.102")

            # Should scan COMMON_PORTS
            assert mock_scan.call_count == len(COMMON_PORTS)

    @pytest.mark.asyncio
    async def test_quick_port_scan(self):
        """Test quick port scan returns only open ports."""
        with patch('network_scanner_mcp.scanner.scan_ports') as mock_scan:
            mock_scan.return_value = [
                PortScanResult(port=22, state="open", service="ssh"),
                PortScanResult(port=80, state="closed", service="http"),
                PortScanResult(port=443, state="open", service="https"),
            ]

            results = await quick_port_scan("192.0.2.102")

            assert len(results) == 2
            assert all(r.state == "open" for r in results)
            assert results[0].port == 22
            assert results[1].port == 443

    def test_identify_service_from_banner(self):
        """Test service identification from banner."""
        # Web servers
        assert _identify_service(80, "Server: nginx/1.18.0") == "nginx"
        assert _identify_service(80, "Server: Apache/2.4.41") == "apache"
        assert _identify_service(8080, "Microsoft-IIS/10.0") == "iis"

        # SSH
        assert _identify_service(22, "SSH-2.0-OpenSSH_8.2p1") == "ssh"

        # Databases
        assert _identify_service(3306, "MySQL Server 8.0") == "mysql"
        assert _identify_service(5432, "PostgreSQL 13.3") == "postgresql"
        assert _identify_service(6379, "Redis 6.2.6") == "redis"

        # HTTP
        assert _identify_service(80, "HTTP/1.1 200 OK") == "http"

        # Unknown
        assert _identify_service(9999, "Custom Service") == "unknown"

    def test_identify_service_from_port_only(self):
        """Test service identification from port number only."""
        assert _identify_service(22, "") == "ssh"
        assert _identify_service(80, "") == "http"
        assert _identify_service(443, "") == "https"
        assert _identify_service(3306, "") == "mysql"
        assert _identify_service(9999, "") == "unknown"


class TestHostnameResolution:
    """Tests for hostname resolution."""

    @pytest.mark.asyncio
    async def test_resolve_hostname_success(self):
        """Test successful hostname resolution."""
        with patch('socket.gethostbyaddr', return_value=("example.com", [], ["192.0.2.102"])):
            result = await resolve_hostname("192.0.2.102")

            assert result == "example.com"

    @pytest.mark.asyncio
    async def test_resolve_hostname_failure(self):
        """Test failed hostname resolution."""
        with patch('socket.gethostbyaddr', side_effect=Exception("DNS error")):
            result = await resolve_hostname("192.0.2.102")

            assert result is None

    @pytest.mark.asyncio
    async def test_resolve_hostname_timeout(self):
        """Test hostname resolution timeout."""
        async def slow_lookup(*args):
            await asyncio.sleep(10)
            return ("example.com", [], [])

        with patch('socket.gethostbyaddr', side_effect=slow_lookup):
            result = await resolve_hostname("192.0.2.102", timeout=0.1)

            assert result is None

    @pytest.mark.asyncio
    async def test_resolve_hostnames_multiple(self):
        """Test resolving multiple hostnames."""
        def mock_lookup(ip):
            hostnames = {
                "192.0.2.102": ("host1.local", [], []),
                "192.0.2.138": ("host2.local", [], []),
                "192.0.2.143": ("host3.local", [], []),
            }
            if ip in hostnames:
                return hostnames[ip]
            raise Exception("Not found")

        with patch('socket.gethostbyaddr', side_effect=mock_lookup):
            ips = ["192.0.2.102", "192.0.2.138", "192.0.2.143"]
            results = await resolve_hostnames(ips)

            assert len(results) == 3
            assert results["192.0.2.102"] == "host1.local"
            assert results["192.0.2.138"] == "host2.local"
            assert results["192.0.2.143"] == "host3.local"


class TestPingFunctionality:
    """Tests for ping functionality."""

    @pytest.mark.asyncio
    async def test_ping_host_success(self):
        """Test successful ping."""
        mock_output = b"PING 192.0.2.102: 56 data bytes\nrtt min/avg/max = 1.2/1.5/1.8 ms"

        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_exec.return_value = mock_process

            is_up, latency = await ping_host("192.0.2.102")

            assert is_up is True
            assert latency == 1.5

    @pytest.mark.asyncio
    async def test_ping_host_down(self):
        """Test ping to unreachable host."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_process

            is_up, latency = await ping_host("192.0.2.200")

            assert is_up is False
            assert latency is None

    @pytest.mark.asyncio
    async def test_ping_host_timeout(self):
        """Test ping timeout."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_exec.return_value = mock_process

            is_up, latency = await ping_host("192.0.2.102", timeout=0.1)

            assert is_up is False
            assert latency is None

    @pytest.mark.asyncio
    async def test_ping_hosts_multiple(self):
        """Test pinging multiple hosts."""
        with patch('network_scanner_mcp.scanner.ping_host') as mock_ping:
            mock_ping.side_effect = [
                (True, 1.5),
                (False, None),
                (True, 2.3),
            ]

            ips = ["192.0.2.102", "192.0.2.200", "192.0.2.143"]
            results = await ping_hosts(ips)

            assert len(results) == 3
            assert results["192.0.2.102"] is True
            assert results["192.0.2.200"] is False
            assert results["192.0.2.143"] is True


class TestFullDeviceScan:
    """Tests for comprehensive device scanning."""

    @pytest.mark.asyncio
    async def test_full_device_scan_complete(self):
        """Test full device scan with all features."""
        with patch('network_scanner_mcp.scanner.resolve_hostname') as mock_resolve, \
             patch('network_scanner_mcp.scanner.scan_ports') as mock_scan:

            mock_resolve.return_value = "test-host.local"
            mock_scan.return_value = [
                PortScanResult(port=22, state="open", service="ssh"),
                PortScanResult(port=80, state="open", service="http"),
            ]

            result = await full_device_scan(
                ip="192.0.2.102",
                mac="00:00:00:00:00:63",
                vendor="Apple, Inc.",
                do_port_scan=True,
                do_hostname_lookup=True,
            )

            assert result.ip == "192.0.2.102"
            assert result.mac == "00:00:00:00:00:63"
            assert result.vendor == "Apple, Inc."
            assert result.hostname == "test-host.local"
            assert len(result.ports) == 2
            assert "ssh" in result.services
            assert "http" in result.services

    @pytest.mark.asyncio
    async def test_full_device_scan_minimal(self):
        """Test full device scan with minimal options."""
        result = await full_device_scan(
            ip="192.0.2.102",
            mac="00:00:00:00:00:63",
            do_port_scan=False,
            do_hostname_lookup=False,
        )

        assert result.ip == "192.0.2.102"
        assert result.hostname is None
        assert len(result.ports) == 0
        assert len(result.services) == 0

    @pytest.mark.asyncio
    async def test_full_device_scan_custom_ports(self):
        """Test full device scan with custom port list."""
        with patch('network_scanner_mcp.scanner.scan_ports') as mock_scan:
            mock_scan.return_value = [
                PortScanResult(port=8080, state="open", service="http-proxy"),
            ]

            result = await full_device_scan(
                ip="192.0.2.102",
                mac="00:00:00:00:00:63",
                do_port_scan=True,
                do_hostname_lookup=False,
                port_list=[8080, 8443],
            )

            mock_scan.assert_called_once_with("192.0.2.102", [8080, 8443])


class TestNetworkDiscovery:
    """Tests for network discovery."""

    @pytest.mark.asyncio
    async def test_discover_network_basic(self):
        """Test basic network discovery."""
        mock_arp_results = [
            {"ip": "192.0.2.102", "mac": "00:00:00:00:00:63", "vendor": "Apple", "scan_time": "2024-01-15T12:00:00", "hostname": None},
            {"ip": "192.0.2.138", "mac": "00:00:00:00:00:1B", "vendor": "Samsung", "scan_time": "2024-01-15T12:00:00", "hostname": None},
        ]

        with patch('network_scanner_mcp.scanner.arp_scan') as mock_arp, \
             patch('network_scanner_mcp.scanner.resolve_hostnames') as mock_resolve:

            mock_arp.return_value = mock_arp_results
            mock_resolve.return_value = {
                "192.0.2.102": "host1.local",
                "192.0.2.138": "host2.local",
            }

            results = await discover_network(include_hostnames=True, include_ports=False)

            assert len(results) == 2
            assert results[0].ip == "192.0.2.102"
            assert results[0].hostname == "host1.local"
            assert results[1].ip == "192.0.2.138"
            assert results[1].hostname == "host2.local"

    @pytest.mark.asyncio
    async def test_discover_network_with_ports(self):
        """Test network discovery with port scanning."""
        mock_arp_results = [
            {"ip": "192.0.2.102", "mac": "00:00:00:00:00:63", "vendor": "Apple", "scan_time": "2024-01-15T12:00:00", "hostname": None},
        ]

        with patch('network_scanner_mcp.scanner.arp_scan') as mock_arp, \
             patch('network_scanner_mcp.scanner.scan_ports') as mock_scan:

            mock_arp.return_value = mock_arp_results
            mock_scan.return_value = [
                PortScanResult(port=22, state="open", service="ssh"),
            ]

            results = await discover_network(include_ports=True, include_hostnames=False)

            assert len(results) == 1
            assert len(results[0].ports) == 1
            assert "ssh" in results[0].services

    @pytest.mark.asyncio
    async def test_discover_network_empty(self):
        """Test network discovery with no devices found."""
        with patch('network_scanner_mcp.scanner.arp_scan') as mock_arp:
            mock_arp.return_value = []

            results = await discover_network()

            assert results == []


class TestDataClasses:
    """Tests for data classes."""

    def test_port_scan_result_creation(self):
        """Test PortScanResult creation."""
        result = PortScanResult(
            port=80,
            state="open",
            service="http",
            banner="HTTP/1.1 200 OK",
            response_time_ms=15.3
        )

        assert result.port == 80
        assert result.state == "open"
        assert result.service == "http"
        assert result.banner == "HTTP/1.1 200 OK"
        assert result.response_time_ms == 15.3

    def test_device_scan_result_to_dict(self):
        """Test DeviceScanResult conversion to dictionary."""
        result = DeviceScanResult(
            ip="192.0.2.102",
            mac="00:00:00:00:00:63",
            vendor="Apple, Inc.",
            scan_time="2024-01-15T12:00:00",
            hostname="test-host.local",
            ports=[
                PortScanResult(port=22, state="open", service="ssh"),
            ],
            services=["ssh"],
            is_reachable=True
        )

        result_dict = result.to_dict()

        assert result_dict["ip"] == "192.0.2.102"
        assert result_dict["mac"] == "00:00:00:00:00:63"
        assert result_dict["hostname"] == "test-host.local"
        assert len(result_dict["ports"]) == 1
        assert result_dict["ports"][0]["port"] == 22
        assert "ssh" in result_dict["services"]
        assert result_dict["is_reachable"] is True
