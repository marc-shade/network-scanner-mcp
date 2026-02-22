"""Tests for MCP tool endpoints in network_scanner_mcp.server."""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from network_scanner_mcp import server
from network_scanner_mcp.scanner import PortScanResult


class TestScanNetworkTool:
    """Tests for scan_network MCP tool."""

    @pytest.mark.asyncio
    async def test_scan_network_success(self, mock_registry, mock_arp_scan_success):
        """Test successful network scan."""
        with patch('network_scanner_mcp.server.arp_scan') as mock_arp, \
             patch('network_scanner_mcp.server.resolve_hostnames') as mock_resolve:

            mock_arp.return_value = mock_arp_scan_success
            mock_resolve.return_value = {
                "192.0.2.102": "host1.local",
                "192.0.2.138": "host2.local",
            }

            result = await server.scan_network.fn(resolve_names=True)
            data = json.loads(result)

            assert data["success"] is True
            assert data["total_devices"] == 3
            assert len(data["devices"]) == 3
            assert data["devices"][0]["hostname"] == "host1.local"

    @pytest.mark.asyncio
    async def test_scan_network_no_devices(self, mock_registry):
        """Test network scan with no devices found."""
        with patch('network_scanner_mcp.server.arp_scan') as mock_arp:
            mock_arp.return_value = []

            result = await server.scan_network.fn()
            data = json.loads(result)

            assert data["success"] is False
            assert "No devices found" in data["error"]

    @pytest.mark.asyncio
    async def test_scan_network_no_hostname_resolution(self, mock_registry, mock_arp_scan_success):
        """Test network scan without hostname resolution."""
        with patch('network_scanner_mcp.server.arp_scan') as mock_arp, \
             patch('network_scanner_mcp.server.resolve_hostnames') as mock_resolve:

            mock_arp.return_value = mock_arp_scan_success

            result = await server.scan_network.fn(resolve_names=False)
            data = json.loads(result)

            assert data["success"] is True
            mock_resolve.assert_not_called()

    @pytest.mark.asyncio
    async def test_scan_network_custom_subnet(self, mock_registry, mock_arp_scan_success):
        """Test network scan with custom subnet."""
        with patch('network_scanner_mcp.server.arp_scan') as mock_arp:
            mock_arp.return_value = mock_arp_scan_success

            result = await server.scan_network.fn(subnet="10.0.0.0/24")
            data = json.loads(result)

            assert data["success"] is True
            mock_arp.assert_called_once()


class TestDetectNewDevicesTool:
    """Tests for detect_new_devices MCP tool."""

    @pytest.mark.asyncio
    async def test_detect_new_devices_found(self, mock_registry):
        """Test detecting new devices."""
        new_device = {
            "mac": "FF:FF:FF:FF:FF:FF",
            "ip": "192.0.2.250",
            "vendor": "New Vendor",
            "is_known": False
        }

        mock_registry.update_device.return_value = (True, new_device)

        with patch('network_scanner_mcp.server.arp_scan') as mock_arp:
            mock_arp.return_value = [
                {"ip": "192.0.2.250", "mac": "FF:FF:FF:FF:FF:FF", "vendor": "New Vendor"}
            ]

            result = await server.detect_new_devices.fn()
            data = json.loads(result)

            assert data["success"] is True
            assert data["count"] == 1
            assert len(data["new_devices"]) == 1

    @pytest.mark.asyncio
    async def test_detect_new_devices_none_found(self, mock_registry):
        """Test when no new devices are found."""
        mock_registry.update_device.return_value = (False, {})

        with patch('network_scanner_mcp.server.arp_scan') as mock_arp:
            mock_arp.return_value = [
                {"ip": "192.0.2.102", "mac": "00:00:00:00:00:63", "vendor": "Apple"}
            ]

            result = await server.detect_new_devices.fn()
            data = json.loads(result)

            assert data["success"] is True
            assert data["count"] == 0


class TestGetUnknownDevicesTool:
    """Tests for get_unknown_devices MCP tool."""

    @pytest.mark.asyncio
    async def test_get_unknown_devices(self, mock_registry, sample_device_history):
        """Test retrieving unknown devices."""
        mock_registry.get_unknown_macs.return_value = {"00:00:00:00:00:63"}

        result = await server.get_unknown_devices.fn()
        data = json.loads(result)

        assert data["success"] is True
        assert data["count"] == 1
        assert len(data["unknown_devices"]) == 1
        assert data["unknown_devices"][0]["mac"] == "00:00:00:00:00:63"

    @pytest.mark.asyncio
    async def test_get_unknown_devices_empty(self, mock_registry):
        """Test when no unknown devices exist."""
        mock_registry.get_unknown_macs.return_value = set()
        mock_registry.get_all_devices.return_value = {}

        result = await server.get_unknown_devices.fn()
        data = json.loads(result)

        assert data["success"] is True
        assert data["count"] == 0


class TestGetDeviceInfoTool:
    """Tests for get_device_info MCP tool."""

    @pytest.mark.asyncio
    async def test_get_device_info_by_mac(self, mock_registry, sample_device_history):
        """Test getting device info by MAC address."""
        result = await server.get_device_info.fn("00:00:00:00:00:63")
        data = json.loads(result)

        assert data["success"] is True
        assert data["device"]["mac"] == "00:00:00:00:00:63"
        assert data["device"]["ip"] == "192.0.2.217"

    @pytest.mark.asyncio
    async def test_get_device_info_by_ip(self, mock_registry, sample_device_history):
        """Test getting device info by IP address."""
        result = await server.get_device_info.fn("192.0.2.217")
        data = json.loads(result)

        assert data["success"] is True
        assert data["device"]["ip"] == "192.0.2.217"

    @pytest.mark.asyncio
    async def test_get_device_info_not_found(self, mock_registry):
        """Test getting info for non-existent device."""
        mock_registry.get_device.return_value = None
        mock_registry.get_device_by_ip.return_value = None

        result = await server.get_device_info.fn("FF:FF:FF:FF:FF:FF")
        data = json.loads(result)

        assert data["success"] is False
        assert "not found" in data["error"]

    @pytest.mark.asyncio
    async def test_get_device_info_cluster_node(self, mock_registry, sample_cluster_nodes):
        """Test getting info for a cluster node includes cluster info."""
        cluster_device = {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.0.2.143",
            "vendor": "Apple",
        }
        mock_registry.get_device.return_value = cluster_device

        result = await server.get_device_info.fn("AA:BB:CC:DD:EE:FF")
        data = json.loads(result)

        assert data["success"] is True
        assert "cluster_info" in data["device"]
        assert data["device"]["cluster_info"]["name"] == "orchestrator"


class TestMarkDeviceKnownTool:
    """Tests for mark_device_known MCP tool."""

    @pytest.mark.asyncio
    async def test_mark_device_known_valid(self, mock_registry):
        """Test marking a device as known."""
        result = await server.mark_device_known.fn(
            "00:00:00:00:00:63",
            "My Laptop",
            "trusted"
        )
        data = json.loads(result)

        assert data["success"] is True
        mock_registry.mark_known.assert_called_once_with(
            "00:00:00:00:00:63",
            "My Laptop",
            "trusted"
        )

    @pytest.mark.asyncio
    async def test_mark_device_known_invalid_type(self, mock_registry):
        """Test marking device with invalid type."""
        result = await server.mark_device_known.fn(
            "00:00:00:00:00:63",
            "Device",
            "invalid_type"
        )
        data = json.loads(result)

        assert data["success"] is False
        assert "Invalid device_type" in data["error"]

    @pytest.mark.asyncio
    async def test_mark_device_known_iot_type(self, mock_registry):
        """Test marking device as IoT type."""
        result = await server.mark_device_known.fn(
            "00:00:00:00:00:63",
            "Smart Light",
            "iot"
        )
        data = json.loads(result)

        assert data["success"] is True
        mock_registry.mark_known.assert_called_with(
            "00:00:00:00:00:63",
            "Smart Light",
            "iot"
        )


class TestRemoveDeviceKnownTool:
    """Tests for remove_device_known MCP tool."""

    @pytest.mark.asyncio
    async def test_remove_device_known_success(self, mock_registry):
        """Test removing a device from known list."""
        mock_registry.remove_known.return_value = True

        result = await server.remove_device_known.fn("00:00:00:00:00:1B")
        data = json.loads(result)

        assert data["success"] is True
        mock_registry.remove_known.assert_called_once_with("00:00:00:00:00:1B")

    @pytest.mark.asyncio
    async def test_remove_device_known_not_found(self, mock_registry):
        """Test removing device not in known list."""
        mock_registry.remove_known.return_value = False

        result = await server.remove_device_known.fn("FF:FF:FF:FF:FF:FF")
        data = json.loads(result)

        assert data["success"] is False
        assert "not found" in data["error"]


class TestGetNetworkTopologyTool:
    """Tests for get_network_topology MCP tool."""

    @pytest.mark.asyncio
    async def test_get_network_topology(self, mock_registry, sample_device_history, sample_cluster_nodes):
        """Test getting complete network topology."""
        # Setup cluster node
        cluster_device = {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.0.2.143",
            "vendor": "Apple",
            "hostname": "orchestrator.local",
            "first_seen": "2024-01-01T12:00:00",
            "last_seen": "2024-01-15T12:00:00",
            "seen_count": 100,
            "services": ["ssh"],
        }

        all_devices = sample_device_history.copy()
        all_devices["AA:BB:CC:DD:EE:FF"] = cluster_device
        mock_registry.get_all_devices.return_value = all_devices

        result = await server.get_network_topology.fn()
        data = json.loads(result)

        assert data["success"] is True
        topology = data["topology"]
        assert "cluster_nodes" in topology
        assert "known_devices" in topology
        assert "unknown_devices" in topology
        assert topology["total_devices"] == 3
        assert len(topology["cluster_nodes"]) == 1
        assert topology["cluster_nodes"][0]["node_name"] == "orchestrator"


class TestPortScanningTools:
    """Tests for port scanning MCP tools."""

    @pytest.mark.asyncio
    async def test_scan_device_ports_by_ip(self, mock_registry):
        """Test scanning ports by IP address (quick mode by default)."""
        with patch('network_scanner_mcp.server.quick_port_scan') as mock_scan:
            mock_scan.return_value = [
                PortScanResult(port=22, state="open", service="ssh", response_time_ms=15.3),
                PortScanResult(port=80, state="open", service="http", response_time_ms=20.1),
            ]

            result = await server.scan_device_ports.fn("192.0.2.102")
            data = json.loads(result)

            assert data["success"] is True
            assert data["target"] == "192.0.2.102"
            assert len(data["open_ports"]) == 2
            assert data["open_ports"][0]["port"] == 22
            assert "ssh" in data["services_detected"]

    @pytest.mark.asyncio
    async def test_scan_device_ports_by_mac(self, mock_registry, sample_device_history):
        """Test scanning ports by MAC address (quick mode by default)."""
        with patch('network_scanner_mcp.server.quick_port_scan') as mock_scan:
            mock_scan.return_value = [
                PortScanResult(port=443, state="open", service="https"),
            ]

            result = await server.scan_device_ports.fn("00:00:00:00:00:63")
            data = json.loads(result)

            assert data["success"] is True
            assert data["target"] == "192.0.2.217"  # Resolved from MAC

    @pytest.mark.asyncio
    async def test_scan_device_ports_custom_ports(self, mock_registry):
        """Test scanning custom port list."""
        with patch('network_scanner_mcp.server.scan_ports') as mock_scan:
            mock_scan.return_value = [
                PortScanResult(port=8080, state="open", service="http-proxy"),
            ]

            result = await server.scan_device_ports.fn("192.0.2.102", ports="8080,8443")
            data = json.loads(result)

            assert data["success"] is True
            mock_scan.assert_called_once()
            call_args = mock_scan.call_args
            assert 8080 in call_args[0][1]
            assert 8443 in call_args[0][1]

    @pytest.mark.asyncio
    async def test_scan_device_ports_all(self, mock_registry):
        """Test scanning all ports (1-1024)."""
        with patch('network_scanner_mcp.server.scan_ports') as mock_scan:
            mock_scan.return_value = []

            result = await server.scan_device_ports.fn("192.0.2.102", ports="all")
            data = json.loads(result)

            assert data["success"] is True
            # Should scan ports 1-1024
            call_args = mock_scan.call_args
            assert len(call_args[0][1]) == 1024

    @pytest.mark.asyncio
    async def test_discover_services(self, mock_registry, sample_device_history):
        """Test discovering services on all devices."""
        with patch('network_scanner_mcp.server.quick_port_scan') as mock_scan:
            mock_scan.return_value = [
                PortScanResult(port=22, state="open", service="ssh"),
                PortScanResult(port=80, state="open", service="http"),
            ]

            result = await server.discover_services.fn()
            data = json.loads(result)

            assert data["success"] is True
            assert data["devices_scanned"] == 2
            assert len(data["results"]) > 0


class TestClusterMonitoringTools:
    """Tests for cluster monitoring MCP tools."""

    @pytest.mark.asyncio
    async def test_get_cluster_nodes(self, mock_registry, sample_cluster_nodes, sample_device_history):
        """Test getting cluster node status."""
        # Add cluster node to device history
        cluster_device = {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.0.2.143",
            "vendor": "Apple",
            "last_seen": "2024-01-15T12:00:00",
        }
        all_devices = sample_device_history.copy()
        all_devices["AA:BB:CC:DD:EE:FF"] = cluster_device
        mock_registry.get_all_devices.return_value = all_devices

        result = await server.get_cluster_nodes.fn()
        data = json.loads(result)

        assert data["success"] is True
        assert len(data["cluster_nodes"]) == 3
        assert data["online_count"] == 1  # Only orchestrator has last_seen

    @pytest.mark.asyncio
    async def test_check_cluster_health(self, mock_registry, sample_cluster_nodes):
        """Test cluster health check."""
        with patch('network_scanner_mcp.server.ping_host') as mock_ping:
            mock_ping.side_effect = [
                (True, 1.5),   # orchestrator up
                (False, None), # builder down
                (True, 2.3),   # researcher up
            ]

            result = await server.check_cluster_health.fn()
            data = json.loads(result)

            assert data["success"] is True
            assert data["overall_status"] == "degraded"  # Not all nodes up
            assert data["healthy_nodes"] == 2
            assert data["unhealthy_nodes"] == 1


class TestUtilityTools:
    """Tests for utility MCP tools."""

    @pytest.mark.asyncio
    async def test_ping_device_by_ip(self, mock_registry):
        """Test pinging a device by IP."""
        with patch('network_scanner_mcp.server.ping_host') as mock_ping:
            mock_ping.return_value = (True, 15.3)

            result = await server.ping_device.fn("192.0.2.102")
            data = json.loads(result)

            assert data["success"] is True
            assert data["reachable"] is True
            assert data["latency_ms"] == 15.3
            assert data["status"] == "up"

    @pytest.mark.asyncio
    async def test_ping_device_by_mac(self, mock_registry, sample_device_history):
        """Test pinging a device by MAC address."""
        with patch('network_scanner_mcp.server.ping_host') as mock_ping:
            mock_ping.return_value = (True, 20.1)

            result = await server.ping_device.fn("00:00:00:00:00:63")
            data = json.loads(result)

            assert data["success"] is True
            assert data["target"] == "192.0.2.217"  # Resolved from MAC

    @pytest.mark.asyncio
    async def test_resolve_device_hostname(self, mock_registry):
        """Test resolving device hostname."""
        with patch('network_scanner_mcp.server.resolve_hostname') as mock_resolve:
            mock_resolve.return_value = "test-host.local"

            result = await server.resolve_device_hostname.fn("192.0.2.102")
            data = json.loads(result)

            assert data["success"] is True
            assert data["hostname"] == "test-host.local"
            assert data["resolved"] is True

    @pytest.mark.asyncio
    async def test_get_scanner_status(self, mock_registry, sample_device_history):
        """Test getting scanner status."""
        result = await server.get_scanner_status.fn()
        data = json.loads(result)

        assert data["success"] is True
        assert "status" in data
        assert "interface" in data["status"]
        assert "total_devices_tracked" in data["status"]
        assert "configuration" in data

    @pytest.mark.asyncio
    async def test_export_for_security_scan(self, mock_registry, sample_device_history, sample_cluster_nodes):
        """Test exporting device list for security scanning."""
        result = await server.export_for_security_scan.fn()
        data = json.loads(result)

        assert data["success"] is True
        assert "targets" in data
        assert "ip_list" in data
        assert len(data["targets"]) == 2
        assert data["cluster_ips"] == list(sample_cluster_nodes.keys())
