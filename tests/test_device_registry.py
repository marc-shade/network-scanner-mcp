"""Tests for DeviceRegistry in network_scanner_mcp.server."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

# Import after sys.path modification in conftest
from network_scanner_mcp.server import DeviceRegistry
from network_scanner_mcp.utils import normalize_mac


class TestDeviceRegistry:
    """Tests for thread-safe device registry."""

    @pytest.fixture
    def registry(self, mock_data_dir):
        """Create a fresh DeviceRegistry for each test."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', {}):
            return DeviceRegistry()

    @pytest.fixture
    def registry_with_data(self, populated_data_dir, sample_cluster_nodes):
        """Create a DeviceRegistry with pre-populated data."""
        with patch('network_scanner_mcp.server.CLUSTER_NODES', sample_cluster_nodes):
            return DeviceRegistry()

    def test_registry_initialization(self, registry):
        """Test DeviceRegistry initializes empty."""
        all_devices = registry.get_all_devices()
        known_devices = registry.get_known_devices()

        assert isinstance(all_devices, dict)
        assert isinstance(known_devices, dict)

    def test_registry_loads_existing_data(self, registry_with_data):
        """Test DeviceRegistry loads existing data from disk."""
        all_devices = registry_with_data.get_all_devices()
        known_devices = registry_with_data.get_known_devices()

        assert len(all_devices) == 2
        assert "00:00:00:00:00:63" in all_devices
        assert "00:00:00:00:00:1B" in all_devices
        assert len(known_devices) == 1
        assert "00:00:00:00:00:1B" in known_devices

    def test_update_device_new(self, registry):
        """Test adding a new device to registry."""
        device_data = {
            "ip": "192.0.2.102",
            "vendor": "Apple, Inc.",
            "hostname": "test-host"
        }

        is_new, device = registry.update_device("00:00:00:00:00:63", device_data)

        assert is_new is True
        assert device["mac"] == "00:00:00:00:00:63"
        assert device["ip"] == "192.0.2.102"
        assert device["vendor"] == "Apple, Inc."
        assert device["hostname"] == "test-host"
        assert device["seen_count"] == 1
        assert device["is_known"] is False

    def test_update_device_existing(self, registry_with_data):
        """Test updating an existing device."""
        mac = "00:00:00:00:00:63"
        original = registry_with_data.get_device(mac)
        original_count = original["seen_count"]

        device_data = {
            "ip": "192.0.2.217",
            "vendor": "Test Vendor",
        }

        is_new, device = registry_with_data.update_device(mac, device_data)

        assert is_new is False
        assert device["seen_count"] == original_count + 1
        assert device["ip"] == "192.0.2.217"

    def test_update_device_preserves_fields(self, registry_with_data):
        """Test updating device preserves existing fields."""
        mac = "00:00:00:00:00:63"

        device_data = {
            "ip": "192.0.2.217",
            "ports": [{"port": 22, "service": "ssh"}],
            "services": ["ssh"]
        }

        is_new, device = registry_with_data.update_device(mac, device_data)

        assert device["ports"] == [{"port": 22, "service": "ssh"}]
        assert device["services"] == ["ssh"]
        assert "first_seen" in device
        assert "last_seen" in device

    def test_get_device_by_mac(self, registry_with_data):
        """Test retrieving device by MAC address."""
        device = registry_with_data.get_device("00:00:00:00:00:63")

        assert device is not None
        assert device["mac"] == "00:00:00:00:00:63"
        assert device["ip"] == "192.0.2.217"

    def test_get_device_by_mac_not_found(self, registry):
        """Test retrieving non-existent device by MAC."""
        device = registry.get_device("FF:FF:FF:FF:FF:FF")

        assert device is None

    def test_get_device_by_ip(self, registry_with_data):
        """Test retrieving device by IP address."""
        device = registry_with_data.get_device_by_ip("192.0.2.217")

        assert device is not None
        assert device["ip"] == "192.0.2.217"
        assert device["mac"] == "00:00:00:00:00:63"

    def test_get_device_by_ip_not_found(self, registry):
        """Test retrieving non-existent device by IP."""
        device = registry.get_device_by_ip("10.0.0.1")

        assert device is None

    def test_mark_device_known(self, registry_with_data):
        """Test marking a device as known."""
        mac = "00:00:00:00:00:63"

        result = registry_with_data.mark_known(mac, "My Laptop", "trusted")

        assert result is True
        assert registry_with_data.is_known(mac)

        device = registry_with_data.get_device(mac)
        assert device["is_known"] is True

        known = registry_with_data.get_known_devices()
        assert mac in known
        assert known[mac]["label"] == "My Laptop"
        assert known[mac]["type"] == "trusted"

    def test_mark_device_known_different_types(self, registry):
        """Test marking devices with different types."""
        registry.update_device("AA:BB:CC:DD:EE:01", {"ip": "192.0.2.1"})
        registry.update_device("AA:BB:CC:DD:EE:02", {"ip": "192.0.2.2"})
        registry.update_device("AA:BB:CC:DD:EE:03", {"ip": "192.0.2.3"})

        registry.mark_known("AA:BB:CC:DD:EE:01", "Laptop", "trusted")
        registry.mark_known("AA:BB:CC:DD:EE:02", "Smart Light", "iot")
        registry.mark_known("AA:BB:CC:DD:EE:03", "Guest Phone", "guest")

        known = registry.get_known_devices()
        assert known["AA:BB:CC:DD:EE:01"]["type"] == "trusted"
        assert known["AA:BB:CC:DD:EE:02"]["type"] == "iot"
        assert known["AA:BB:CC:DD:EE:03"]["type"] == "guest"

    def test_remove_device_known(self, registry_with_data):
        """Test removing a device from known list."""
        mac = "00:00:00:00:00:1B"

        assert registry_with_data.is_known(mac)

        result = registry_with_data.remove_known(mac)

        assert result is True
        assert not registry_with_data.is_known(mac)

        device = registry_with_data.get_device(mac)
        assert device["is_known"] is False

    def test_remove_device_known_not_in_list(self, registry):
        """Test removing device not in known list."""
        result = registry.remove_known("FF:FF:FF:FF:FF:FF")

        assert result is False

    def test_is_known_true(self, registry_with_data):
        """Test is_known returns True for known device."""
        assert registry_with_data.is_known("00:00:00:00:00:1B") is True

    def test_is_known_false(self, registry_with_data):
        """Test is_known returns False for unknown device."""
        assert registry_with_data.is_known("00:00:00:00:00:63") is False

    def test_get_unknown_macs(self, registry_with_data):
        """Test getting list of unknown device MACs."""
        unknown = registry_with_data.get_unknown_macs()

        assert isinstance(unknown, set)
        assert "00:00:00:00:00:63" in unknown
        assert "00:00:00:00:00:1B" not in unknown  # This is known

    def test_get_unknown_macs_excludes_cluster(self, mock_data_dir):
        """Test unknown MACs excludes cluster nodes."""
        cluster_nodes = {
            "192.0.2.143": {
                "name": "orchestrator",
                "role": "orchestrator",
                "type": "cluster_node"
            }
        }

        with patch('network_scanner_mcp.server.CLUSTER_NODES', cluster_nodes):
            registry = DeviceRegistry()

            # Add a cluster node
            registry.update_device("AA:BB:CC:DD:EE:FF", {
                "ip": "192.0.2.143",
                "vendor": "Apple"
            })

            # Add a regular device
            registry.update_device("00:00:00:00:00:63", {
                "ip": "192.0.2.102",
                "vendor": "Samsung"
            })

            unknown = registry.get_unknown_macs()

            # Cluster node should not be in unknown list
            assert "AA:BB:CC:DD:EE:FF" not in unknown
            assert "00:00:00:00:00:63" in unknown

    def test_get_all_devices(self, registry_with_data):
        """Test getting all devices returns copy."""
        devices1 = registry_with_data.get_all_devices()
        devices2 = registry_with_data.get_all_devices()

        # Should be equal but different objects
        assert devices1 == devices2
        assert devices1 is not devices2

    def test_persistence_device_history(self, mock_data_dir, registry):
        """Test device history is persisted to disk."""
        device_data = {
            "ip": "192.0.2.102",
            "vendor": "Apple, Inc.",
        }

        registry.update_device("00:00:00:00:00:63", device_data)

        # Check file was written
        history_file = mock_data_dir / "device_history.json"
        assert history_file.exists()

        # Check content
        content = json.loads(history_file.read_text())
        assert "00:00:00:00:00:63" in content
        assert content["00:00:00:00:00:63"]["ip"] == "192.0.2.102"

    def test_persistence_known_devices(self, mock_data_dir, registry):
        """Test known devices are persisted to disk."""
        registry.update_device("00:00:00:00:00:63", {"ip": "192.0.2.102"})
        registry.mark_known("00:00:00:00:00:63", "My Device", "trusted")

        # Check file was written
        known_file = mock_data_dir / "known_devices.json"
        assert known_file.exists()

        # Check content
        content = json.loads(known_file.read_text())
        assert "00:00:00:00:00:63" in content
        assert content["00:00:00:00:00:63"]["label"] == "My Device"

    def test_mac_normalization(self, registry):
        """Test MAC addresses are normalized on update."""
        # Try different formats
        registry.update_device("aa:bb:cc:dd:ee:ff", {"ip": "192.0.2.1"})
        registry.update_device("AA-BB-CC-DD-EE-FF", {"ip": "192.0.2.2"})
        registry.update_device("aabbccddeeff", {"ip": "192.0.2.3"})

        # All should be stored as same normalized MAC
        all_devices = registry.get_all_devices()
        assert len(all_devices) == 1

        normalized = normalize_mac("aa:bb:cc:dd:ee:ff")
        assert normalized in all_devices
        assert all_devices[normalized]["ip"] == "192.0.2.3"  # Last update wins

    def test_thread_safety_concurrent_updates(self, registry):
        """Test thread-safe concurrent device updates."""
        import threading

        def update_device(n):
            for i in range(10):
                registry.update_device(
                    f"AA:BB:CC:DD:EE:{n:02X}",
                    {"ip": f"192.0.2.{i}"}
                )

        threads = [threading.Thread(target=update_device, args=(i,)) for i in range(5)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Should have 5 devices with consistent data
        all_devices = registry.get_all_devices()
        assert len(all_devices) == 5

        for device in all_devices.values():
            assert "seen_count" in device
            assert device["seen_count"] == 10

    def test_cluster_node_identification(self, mock_data_dir):
        """Test devices are marked as cluster nodes."""
        cluster_nodes = {
            "192.0.2.143": {
                "name": "orchestrator",
                "role": "orchestrator"
            }
        }

        with patch('network_scanner_mcp.server.CLUSTER_NODES', cluster_nodes):
            registry = DeviceRegistry()

            is_new, device = registry.update_device("AA:BB:CC:DD:EE:FF", {
                "ip": "192.0.2.143",
                "vendor": "Apple"
            })

            assert device["is_cluster_node"] is True

            is_new, device = registry.update_device("00:00:00:00:00:63", {
                "ip": "192.0.2.102",
                "vendor": "Samsung"
            })

            assert device["is_cluster_node"] is False
