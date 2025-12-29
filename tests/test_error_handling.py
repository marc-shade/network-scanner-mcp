"""Tests for error handling and edge cases."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from network_scanner_mcp import server
from network_scanner_mcp.scanner import (
    arp_scan,
    scan_port,
    resolve_hostname,
    ping_host,
)
from network_scanner_mcp.utils import (
    load_json_file,
    save_json_file,
    normalize_mac,
    detect_network_interface,
    load_cluster_nodes,
)


class TestScannerErrorHandling:
    """Tests for scanner error handling."""

    @pytest.mark.asyncio
    async def test_arp_scan_permission_denied(self):
        """Test ARP scan handles permission errors."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_exec.side_effect = PermissionError("Permission denied")

            # Should not raise, should return empty list
            result = await arp_scan(interface="eth0")

            assert result == []

    @pytest.mark.asyncio
    async def test_arp_scan_command_not_found(self):
        """Test ARP scan handles missing command."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_exec.side_effect = FileNotFoundError("arp-scan not found")

            result = await arp_scan(interface="eth0")

            assert result == []

    @pytest.mark.asyncio
    async def test_arp_scan_malformed_output(self):
        """Test ARP scan handles malformed output."""
        mock_output = b"""This is not valid output
        Some random text
        Not a proper ARP response"""

        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_exec.return_value = mock_process

            result = await arp_scan(interface="eth0")

            # Should handle gracefully, return empty or skip bad lines
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_port_scan_network_unreachable(self):
        """Test port scan handles network unreachable."""
        with patch('asyncio.open_connection', side_effect=OSError("Network unreachable")):
            result = await scan_port("192.0.2.102", 80)

            assert result.state == "filtered"

    @pytest.mark.asyncio
    async def test_port_scan_invalid_banner(self):
        """Test port scan handles invalid/binary banner data."""
        invalid_banner = b"\x00\x01\x02\xFF\xFE\xFD"  # Binary data

        with patch('asyncio.open_connection') as mock_conn:
            mock_reader = AsyncMock()
            mock_reader.read = AsyncMock(return_value=invalid_banner)
            mock_writer = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)

            result = await scan_port("192.0.2.102", 80, grab_banner=True)

            # Should handle binary data without crashing
            assert result.state == "open"
            # Banner may be None or contain decoded bytes
            assert isinstance(result.banner, (str, type(None)))

    @pytest.mark.asyncio
    async def test_hostname_resolution_invalid_ip(self):
        """Test hostname resolution with invalid IP."""
        result = await resolve_hostname("not.a.valid.ip")

        assert result is None

    @pytest.mark.asyncio
    async def test_ping_host_exception(self):
        """Test ping handles unexpected exceptions."""
        with patch('asyncio.create_subprocess_exec', side_effect=Exception("Unexpected error")):
            is_up, latency = await ping_host("192.0.2.102")

            assert is_up is False
            assert latency is None


class TestDeviceRegistryErrorHandling:
    """Tests for DeviceRegistry error handling."""

    def test_registry_corrupted_history_file(self, tmp_path, monkeypatch):
        """Test registry handles corrupted history file."""
        data_dir = tmp_path / "network-scanner"
        data_dir.mkdir()

        # Create corrupted JSON file
        history_file = data_dir / "device_history.json"
        history_file.write_text("{invalid json content")

        monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(data_dir))

        # Should not crash, should initialize with empty registry
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()
            assert len(registry.get_all_devices()) == 0

    def test_registry_missing_files(self, tmp_path, monkeypatch):
        """Test registry handles missing data files gracefully."""
        data_dir = tmp_path / "network-scanner"
        data_dir.mkdir()

        monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(data_dir))

        # Should initialize without errors
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()
            assert isinstance(registry.get_all_devices(), dict)
            assert isinstance(registry.get_known_devices(), dict)

    def test_registry_invalid_mac_address(self, mock_data_dir):
        """Test registry handles invalid MAC addresses."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()

            # Should normalize or handle gracefully
            is_new, device = registry.update_device("invalid-mac", {"ip": "192.0.2.1"})

            # May normalize or use as-is
            assert device is not None
            assert "ip" in device


class TestMCPToolsErrorHandling:
    """Tests for MCP tool error handling."""

    @pytest.fixture
    def mock_registry_error(self):
        """Mock registry that raises errors."""
        mock_reg = MagicMock()
        mock_reg.get_all_devices.return_value = {}
        mock_reg.get_known_devices.return_value = {}
        mock_reg.get_device.return_value = None
        mock_reg.get_device_by_ip.return_value = None

        with patch.object(server, 'registry', mock_reg), \
             patch.object(server, 'CLUSTER_NODES', {}):
            yield mock_reg

    @pytest.mark.asyncio
    async def test_scan_device_ports_invalid_mac(self, mock_registry_error):
        """Test port scanning with invalid MAC."""
        result = await server.scan_device_ports.fn("invalid:mac:address")
        data = json.loads(result)

        assert data["success"] is False
        assert "Could not find IP" in data["error"]

    @pytest.mark.asyncio
    async def test_scan_device_ports_invalid_port_format(self, mock_registry_error):
        """Test port scanning with invalid port format."""
        result = await server.scan_device_ports.fn("192.0.2.102", ports="not,valid,ports")
        data = json.loads(result)

        assert data["success"] is False
        assert "Invalid port format" in data["error"]

    @pytest.mark.asyncio
    async def test_get_device_history_invalid_mac(self, mock_registry_error):
        """Test getting history for non-existent device."""
        result = await server.get_device_history.fn("FF:FF:FF:FF:FF:FF")
        data = json.loads(result)

        assert data["success"] is False
        assert "not found" in data["error"]

    @pytest.mark.asyncio
    async def test_ping_device_mac_without_ip(self, mock_registry_error):
        """Test ping with MAC that has no known IP."""
        result = await server.ping_device.fn("FF:FF:FF:FF:FF:FF")
        data = json.loads(result)

        assert data["success"] is False
        assert "Could not find IP" in data["error"]

    @pytest.mark.asyncio
    async def test_check_cluster_health_no_nodes(self):
        """Test cluster health check with no configured nodes."""
        with patch.object(server, 'CLUSTER_NODES', {}):
            result = await server.check_cluster_health.fn()
            data = json.loads(result)

            assert data["success"] is False
            assert "No cluster nodes" in data["error"]

    @pytest.mark.asyncio
    async def test_discover_services_no_devices(self, mock_registry_error):
        """Test service discovery with no devices in history."""
        result = await server.discover_services.fn()
        data = json.loads(result)

        assert data["success"] is False
        assert "No devices in history" in data["error"]


class TestUtilsErrorHandling:
    """Tests for utility function error handling."""

    def test_load_json_file_permission_denied(self, tmp_path):
        """Test loading file without read permission."""
        test_file = tmp_path / "protected.json"
        test_file.write_text('{"test": "data"}')
        test_file.chmod(0o000)

        try:
            result = load_json_file(test_file, default={"error": True})

            # Should return default on permission error
            assert result == {"error": True}
        finally:
            test_file.chmod(0o644)  # Restore permissions for cleanup

    def test_save_json_file_permission_denied(self, tmp_path):
        """Test saving file to protected directory."""
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        protected_dir.chmod(0o444)  # Read-only

        test_file = protected_dir / "test.json"

        try:
            result = save_json_file(test_file, {"test": "data"})

            # Should return False on permission error
            assert result is False
        finally:
            protected_dir.chmod(0o755)  # Restore permissions for cleanup

    def test_normalize_mac_empty_string(self):
        """Test MAC normalization with empty string."""
        result = normalize_mac("")

        # Should return empty or handle gracefully
        assert isinstance(result, str)

    def test_normalize_mac_very_long_string(self):
        """Test MAC normalization with excessively long input."""
        long_mac = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55"

        result = normalize_mac(long_mac)

        # Should handle gracefully
        assert isinstance(result, str)

    def test_detect_network_interface_no_interfaces(self, monkeypatch):
        """Test interface detection when no interfaces available."""
        monkeypatch.delenv("NETWORK_INTERFACE", raising=False)

        with patch('pathlib.Path.exists', return_value=False):
            result = detect_network_interface()

            # Should fall back to default
            assert result == "eth0"

    def test_load_cluster_nodes_invalid_json_env(self, monkeypatch):
        """Test loading cluster nodes with invalid JSON in environment."""
        monkeypatch.setenv("CLUSTER_NODES_JSON", "{invalid json")

        result = load_cluster_nodes()

        # Should handle gracefully and return empty
        assert result == {}


class TestConcurrencyAndRaceConditions:
    """Tests for concurrent access and race conditions."""

    @pytest.mark.asyncio
    async def test_concurrent_device_updates(self, mock_data_dir):
        """Test concurrent updates to same device."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()

            async def update_device():
                for i in range(10):
                    registry.update_device("AA:BB:CC:DD:EE:FF", {
                        "ip": f"192.0.2.{i}",
                        "vendor": "Test"
                    })
                    await asyncio.sleep(0.001)

            # Run concurrent updates
            await asyncio.gather(*[update_device() for _ in range(5)])

            # Should have consistent state
            device = registry.get_device("AA:BB:CC:DD:EE:FF")
            assert device is not None
            assert device["seen_count"] == 50  # 10 updates * 5 tasks

    @pytest.mark.asyncio
    async def test_concurrent_file_operations(self, tmp_path):
        """Test concurrent file read/write operations."""
        test_file = tmp_path / "test.json"
        test_file.write_text('{"counter": 0}')

        async def read_write():
            for _ in range(5):
                data = load_json_file(test_file, default={})
                data["counter"] = data.get("counter", 0) + 1
                save_json_file(test_file, data)
                await asyncio.sleep(0.001)

        # Run concurrent operations
        await asyncio.gather(*[read_write() for _ in range(3)])

        # File should still be valid JSON
        final_data = load_json_file(test_file)
        assert isinstance(final_data, dict)
        assert "counter" in final_data


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_scan_network_single_device(self, mock_registry):
        """Test network scan with exactly one device."""
        with patch('network_scanner_mcp.server.arp_scan') as mock_arp:
            mock_arp.return_value = [
                {"ip": "192.0.2.1", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Test", "scan_time": "2024-01-15T12:00:00", "hostname": None}
            ]

            result = await server.scan_network.fn(resolve_names=False)
            data = json.loads(result)

            assert data["success"] is True
            assert data["total_devices"] == 1

    @pytest.mark.asyncio
    async def test_port_scan_port_zero(self):
        """Test scanning port 0 (invalid port)."""
        with patch('asyncio.open_connection', side_effect=ConnectionRefusedError()):
            result = await scan_port("192.0.2.1", 0)

            assert result.port == 0
            assert result.state in ["closed", "filtered"]

    @pytest.mark.asyncio
    async def test_port_scan_port_65535(self):
        """Test scanning highest valid port."""
        with patch('asyncio.open_connection', side_effect=ConnectionRefusedError()):
            result = await scan_port("192.0.2.1", 65535)

            assert result.port == 65535
            assert result.state in ["closed", "filtered"]

    def test_device_registry_max_devices(self, mock_data_dir):
        """Test registry with large number of devices."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()

            # Add 1000 devices
            for i in range(1000):
                mac = f"AA:BB:CC:DD:EE:{i:02X}"
                registry.update_device(mac, {
                    "ip": f"192.168.{i // 256}.{i % 256}",
                    "vendor": f"Vendor{i}"
                })

            all_devices = registry.get_all_devices()
            assert len(all_devices) == 1000

    def test_normalize_mac_unicode(self):
        """Test MAC normalization with unicode characters."""
        # Should handle or reject gracefully
        result = normalize_mac("αα:ββ:cc:dd:ee:ff")

        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_resolve_hostname_ipv6(self):
        """Test hostname resolution with IPv6 address."""
        # May not be supported, should handle gracefully
        result = await resolve_hostname("2001:db8::1")

        # Either resolves or returns None
        assert result is None or isinstance(result, str)

    @pytest.mark.asyncio
    async def test_ping_localhost(self):
        """Test pinging localhost (should always succeed)."""
        is_up, latency = await ping_host("127.0.0.1", count=1)

        assert is_up is True
        assert latency is not None or latency == 0


class TestDataIntegrity:
    """Tests for data integrity and consistency."""

    def test_device_timestamps_chronological(self, mock_data_dir):
        """Test that first_seen is before or equal to last_seen."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()

            is_new, device = registry.update_device("AA:BB:CC:DD:EE:FF", {
                "ip": "192.0.2.1",
                "vendor": "Test"
            })

            assert device["first_seen"] <= device["last_seen"]

            # Update again
            is_new, device = registry.update_device("AA:BB:CC:DD:EE:FF", {
                "ip": "192.0.2.1",
                "vendor": "Test"
            })

            assert device["first_seen"] <= device["last_seen"]

    def test_seen_count_increments(self, mock_data_dir):
        """Test that seen_count increments correctly."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()

            for i in range(1, 11):
                is_new, device = registry.update_device("AA:BB:CC:DD:EE:FF", {
                    "ip": "192.0.2.1"
                })
                assert device["seen_count"] == i

    def test_mac_consistency(self, mock_data_dir):
        """Test MAC addresses remain consistent across updates."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            registry = server.DeviceRegistry()

            # Add with different formats
            registry.update_device("aa:bb:cc:dd:ee:ff", {"ip": "192.0.2.1"})
            registry.update_device("AA-BB-CC-DD-EE-FF", {"ip": "192.0.2.2"})
            registry.update_device("AABBCCDDEEFF", {"ip": "192.0.2.3"})

            # All should be same device
            all_devices = registry.get_all_devices()
            assert len(all_devices) == 1

            # MAC should be normalized
            normalized = normalize_mac("aa:bb:cc:dd:ee:ff")
            assert normalized in all_devices
