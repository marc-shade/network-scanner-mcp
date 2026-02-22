"""Tests for utility functions in network_scanner_mcp.utils."""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from network_scanner_mcp.utils import (
    get_data_dir,
    get_config_value,
    load_cluster_nodes,
    get_cluster_node_display_name,
    detect_network_interface,
    detect_local_subnet,
    load_json_file,
    save_json_file,
    normalize_mac,
    get_timestamp,
    parse_timestamp,
    is_recent,
    setup_logging,
)


class TestConfigurationUtils:
    """Tests for configuration utilities."""

    def test_get_data_dir_from_env(self, tmp_path, monkeypatch):
        """Test data directory detection from environment variable."""
        test_dir = tmp_path / "custom-data"
        monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(test_dir))

        result = get_data_dir()

        assert result == test_dir
        assert result.exists()

    def test_get_data_dir_default(self, tmp_path, monkeypatch):
        """Test data directory detection with default path."""
        monkeypatch.delenv("NETWORK_SCANNER_DATA_DIR", raising=False)
        monkeypatch.setenv("AGENTIC_SYSTEM_PATH", str(tmp_path))

        result = get_data_dir()

        assert "network-scanner" in str(result)
        assert result.exists()

    def test_get_config_value_string(self, monkeypatch):
        """Test config value retrieval as string."""
        monkeypatch.setenv("TEST_KEY", "test_value")

        result = get_config_value("TEST_KEY", default="default")

        assert result == "test_value"

    def test_get_config_value_int(self, monkeypatch):
        """Test config value retrieval as integer."""
        monkeypatch.setenv("TEST_INT", "42")

        result = get_config_value("TEST_INT", default=0, cast_type=int)

        assert result == 42
        assert isinstance(result, int)

    def test_get_config_value_bool_true(self, monkeypatch):
        """Test config value retrieval as boolean (true)."""
        for value in ["true", "1", "yes", "on"]:
            monkeypatch.setenv("TEST_BOOL", value)
            result = get_config_value("TEST_BOOL", default=False, cast_type=bool)
            assert result is True

    def test_get_config_value_bool_false(self, monkeypatch):
        """Test config value retrieval as boolean (false)."""
        monkeypatch.setenv("TEST_BOOL", "false")

        result = get_config_value("TEST_BOOL", default=True, cast_type=bool)

        assert result is False

    def test_get_config_value_default(self):
        """Test config value returns default when not set."""
        result = get_config_value("NON_EXISTENT_KEY", default="default_value")

        assert result == "default_value"

    def test_get_config_value_invalid_cast(self, monkeypatch):
        """Test config value returns default on invalid cast."""
        monkeypatch.setenv("TEST_INVALID", "not_a_number")

        result = get_config_value("TEST_INVALID", default=100, cast_type=int)

        assert result == 100


class TestClusterNodeConfiguration:
    """Tests for cluster node configuration."""

    def test_load_cluster_nodes_from_file(self, tmp_path, monkeypatch):
        """Test loading cluster nodes from JSON file."""
        config_file = tmp_path / "cluster_nodes.json"
        config_data = {
            "192.0.2.143": {
                "name": "orchestrator",
                "role": "orchestrator",
                "type": "cluster_node"
            }
        }
        config_file.write_text(json.dumps(config_data))

        monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(tmp_path))

        result = load_cluster_nodes(config_file)

        assert "192.0.2.143" in result
        assert result["192.0.2.143"]["name"] == "orchestrator"
        assert result["192.0.2.143"]["role"] == "orchestrator"

    def test_load_cluster_nodes_from_env(self, monkeypatch):
        """Test loading cluster nodes from environment variable."""
        config_data = {
            "192.0.2.18": {
                "name": "builder",
                "role": "builder"
            }
        }
        monkeypatch.setenv("CLUSTER_NODES_JSON", json.dumps(config_data))

        result = load_cluster_nodes()

        assert "192.0.2.18" in result
        assert result["192.0.2.18"]["name"] == "builder"

    def test_load_cluster_nodes_simple_format(self, tmp_path, monkeypatch):
        """Test loading cluster nodes in simple name(role) format."""
        config_file = tmp_path / "cluster_nodes.json"
        config_data = {
            "192.0.2.143": "orchestrator (orchestrator)",
            "192.0.2.18": "builder (builder)"
        }
        config_file.write_text(json.dumps(config_data))

        monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(tmp_path))

        result = load_cluster_nodes(config_file)

        assert result["192.0.2.143"]["name"] == "orchestrator"
        assert result["192.0.2.143"]["role"] == "orchestrator"
        assert result["192.0.2.18"]["name"] == "builder"

    def test_load_cluster_nodes_empty(self, tmp_path, monkeypatch):
        """Test loading cluster nodes when no config exists."""
        monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("CLUSTER_NODES_JSON", raising=False)

        result = load_cluster_nodes()

        assert result == {}

    def test_get_cluster_node_display_name(self):
        """Test cluster node display name generation."""
        cluster_nodes = {
            "192.0.2.143": {
                "name": "orchestrator",
                "role": "orchestrator"
            }
        }

        result = get_cluster_node_display_name("192.0.2.143", cluster_nodes)

        assert result == "orchestrator (orchestrator)"

    def test_get_cluster_node_display_name_not_found(self):
        """Test display name for non-cluster IP."""
        cluster_nodes = {}

        result = get_cluster_node_display_name("192.0.2.200", cluster_nodes)

        assert result == "192.0.2.200"


class TestNetworkInterfaceDetection:
    """Tests for network interface detection."""

    def test_detect_network_interface_from_env(self, monkeypatch):
        """Test interface detection from environment variable."""
        monkeypatch.setenv("NETWORK_INTERFACE", "enp20s0")

        result = detect_network_interface()

        assert result == "enp20s0"

    def test_detect_network_interface_netifaces(self, monkeypatch):
        """Test interface detection using netifaces."""
        monkeypatch.delenv("NETWORK_INTERFACE", raising=False)

        mock_netifaces = MagicMock()
        mock_netifaces.AF_INET = 2
        mock_netifaces.gateways.return_value = {
            'default': {2: ['192.0.2.1', 'eth0']}
        }

        # Inject mock netifaces into sys.modules so `import netifaces` finds it
        monkeypatch.setitem(sys.modules, 'netifaces', mock_netifaces)

        result = detect_network_interface()

        assert result == "eth0"

    def test_detect_network_interface_fallback(self, monkeypatch):
        """Test interface detection fallback."""
        monkeypatch.delenv("NETWORK_INTERFACE", raising=False)

        # This will fall back to eth0 or detect from /sys/class/net
        result = detect_network_interface()

        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_local_subnet_from_env(self, monkeypatch):
        """Test subnet detection from environment."""
        monkeypatch.setenv("DEFAULT_SCAN_SUBNET", "10.0.0.0/24")

        result = detect_local_subnet()

        assert result == "10.0.0.0/24"

    @patch('socket.socket')
    def test_detect_local_subnet_from_socket(self, mock_socket, monkeypatch):
        """Test subnet detection from socket connection."""
        monkeypatch.delenv("DEFAULT_SCAN_SUBNET", raising=False)

        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 0)
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = detect_local_subnet()

        assert result == "192.168.1.0/24"


class TestJSONFileOperations:
    """Tests for JSON file operations."""

    def test_load_json_file_success(self, tmp_path):
        """Test loading valid JSON file."""
        test_file = tmp_path / "test.json"
        data = {"key": "value", "number": 42}
        test_file.write_text(json.dumps(data))

        result = load_json_file(test_file)

        assert result == data

    def test_load_json_file_not_exists(self, tmp_path):
        """Test loading non-existent file returns default."""
        test_file = tmp_path / "missing.json"

        result = load_json_file(test_file, default={"empty": True})

        assert result == {"empty": True}

    def test_load_json_file_empty(self, tmp_path):
        """Test loading empty file returns default."""
        test_file = tmp_path / "empty.json"
        test_file.write_text("")

        result = load_json_file(test_file)

        assert result == {}

    def test_load_json_file_invalid_json(self, tmp_path):
        """Test loading invalid JSON returns default."""
        test_file = tmp_path / "invalid.json"
        test_file.write_text("{invalid json")

        result = load_json_file(test_file, default={"error": True})

        assert result == {"error": True}

    def test_save_json_file_success(self, tmp_path):
        """Test saving JSON file."""
        test_file = tmp_path / "output.json"
        data = {"test": "data", "number": 123}

        result = save_json_file(test_file, data)

        assert result is True
        assert test_file.exists()

        loaded = json.loads(test_file.read_text())
        assert loaded == data

    def test_save_json_file_creates_directory(self, tmp_path):
        """Test saving JSON file creates parent directories."""
        test_file = tmp_path / "nested" / "dir" / "file.json"
        data = {"nested": True}

        result = save_json_file(test_file, data)

        assert result is True
        assert test_file.exists()


class TestMACAddressUtilities:
    """Tests for MAC address utilities."""

    def test_normalize_mac_colon_format(self):
        """Test MAC normalization from colon format."""
        result = normalize_mac("aa:bb:cc:dd:ee:ff")

        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_dash_format(self):
        """Test MAC normalization from dash format."""
        result = normalize_mac("aa-bb-cc-dd-ee-ff")

        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_no_separator(self):
        """Test MAC normalization from format without separators."""
        result = normalize_mac("aabbccddeeff")

        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_mixed_case(self):
        """Test MAC normalization preserves uppercase."""
        result = normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff")

        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_invalid_length(self):
        """Test MAC normalization with invalid length."""
        invalid_mac = "aa:bb:cc"

        result = normalize_mac(invalid_mac)

        # Should return uppercase version even if invalid
        assert result == "AA:BB:CC"


class TestTimestampUtilities:
    """Tests for timestamp utilities."""

    def test_get_timestamp_format(self):
        """Test timestamp generation returns ISO format."""
        result = get_timestamp()

        # Should be able to parse as ISO format
        parsed = datetime.fromisoformat(result)
        assert isinstance(parsed, datetime)

    def test_parse_timestamp_valid(self):
        """Test parsing valid ISO timestamp."""
        timestamp_str = "2024-01-15T12:30:45"

        result = parse_timestamp(timestamp_str)

        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 12
        assert result.minute == 30

    def test_parse_timestamp_invalid(self):
        """Test parsing invalid timestamp."""
        result = parse_timestamp("invalid-timestamp")

        assert result is None

    def test_is_recent_true(self):
        """Test is_recent returns True for recent timestamp."""
        recent_time = datetime.now() - timedelta(seconds=30)
        timestamp_str = recent_time.isoformat()

        result = is_recent(timestamp_str, max_age_seconds=60)

        assert result is True

    def test_is_recent_false(self):
        """Test is_recent returns False for old timestamp."""
        old_time = datetime.now() - timedelta(hours=1)
        timestamp_str = old_time.isoformat()

        result = is_recent(timestamp_str, max_age_seconds=60)

        assert result is False

    def test_is_recent_invalid_timestamp(self):
        """Test is_recent returns False for invalid timestamp."""
        result = is_recent("invalid", max_age_seconds=60)

        assert result is False


class TestLoggingSetup:
    """Tests for logging setup."""

    def test_setup_logging_default(self):
        """Test logging setup with default parameters."""
        logger = setup_logging()

        assert logger.name == "network-scanner"
        assert logger.level == 20  # INFO level

    def test_setup_logging_custom_level(self):
        """Test logging setup with custom level."""
        logger = setup_logging(level="DEBUG")

        assert logger.level == 10  # DEBUG level

    def test_setup_logging_with_file(self, tmp_path):
        """Test logging setup with file output."""
        log_file = tmp_path / "test.log"

        logger = setup_logging(log_file=log_file)

        assert len(logger.handlers) == 2  # Console + file
        assert log_file.exists()

    def test_setup_logging_from_env(self, monkeypatch):
        """Test logging setup respects environment variable."""
        monkeypatch.setenv("LOG_LEVEL", "WARNING")

        logger = setup_logging()

        assert logger.level == 30  # WARNING level
