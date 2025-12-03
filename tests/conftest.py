"""Pytest configuration and fixtures for network-scanner-mcp tests."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def temp_data_dir(tmp_path):
    """Create a temporary data directory for tests."""
    data_dir = tmp_path / "network-scanner"
    data_dir.mkdir(parents=True)
    return data_dir


@pytest.fixture
def mock_data_dir(temp_data_dir, monkeypatch):
    """Mock the data directory to use temp directory."""
    monkeypatch.setenv("NETWORK_SCANNER_DATA_DIR", str(temp_data_dir))
    return temp_data_dir


@pytest.fixture
def sample_device_history():
    """Sample device history data."""
    return {
        "00:00:00:00:00:63": {
            "mac": "00:00:00:00:00:63",
            "ip": "192.0.2.217",
            "vendor": "Test Vendor",
            "hostname": "test-host",
            "first_seen": "2024-01-01T12:00:00",
            "last_seen": "2024-01-15T12:00:00",
            "seen_count": 50,
            "is_known": False,
            "is_cluster_node": False,
            "ports": [],
            "services": [],
        },
        "00:00:00:00:00:1B": {
            "mac": "00:00:00:00:00:1B",
            "ip": "192.0.2.128",
            "vendor": "Another Vendor",
            "hostname": None,
            "first_seen": "2024-01-10T12:00:00",
            "last_seen": "2024-01-15T11:00:00",
            "seen_count": 10,
            "is_known": True,
            "is_cluster_node": False,
            "ports": [{"port": 22, "service": "ssh"}],
            "services": ["ssh"],
        }
    }


@pytest.fixture
def sample_known_devices():
    """Sample known devices data."""
    return {
        "00:00:00:00:00:1B": {
            "label": "My Laptop",
            "type": "trusted",
            "added": "2024-01-05T12:00:00"
        }
    }


@pytest.fixture
def sample_cluster_nodes():
    """Sample cluster nodes configuration."""
    return {
        "192.0.2.143": {
            "name": "orchestrator",
            "role": "orchestrator",
            "type": "cluster_node"
        },
        "192.0.2.18": {
            "name": "builder",
            "role": "builder",
            "type": "cluster_node"
        },
        "192.0.2.156": {
            "name": "researcher",
            "role": "researcher",
            "type": "cluster_node"
        }
    }


@pytest.fixture
def populated_data_dir(mock_data_dir, sample_device_history, sample_known_devices, sample_cluster_nodes):
    """Create a populated data directory with sample data."""
    # Write device history
    history_file = mock_data_dir / "device_history.json"
    history_file.write_text(json.dumps(sample_device_history, indent=2))

    # Write known devices
    known_file = mock_data_dir / "known_devices.json"
    known_file.write_text(json.dumps(sample_known_devices, indent=2))

    # Write cluster nodes
    cluster_file = mock_data_dir / "cluster_nodes.json"
    cluster_file.write_text(json.dumps(sample_cluster_nodes, indent=2))

    return mock_data_dir


@pytest.fixture
def mock_arp_scan_success():
    """Mock successful ARP scan results."""
    return [
        {"ip": "192.0.2.102", "mac": "00:00:00:00:00:63", "vendor": "Apple, Inc.", "scan_time": "2024-01-15T12:00:00", "hostname": None},
        {"ip": "192.0.2.138", "mac": "00:00:00:00:00:1B", "vendor": "Samsung", "scan_time": "2024-01-15T12:00:00", "hostname": None},
        {"ip": "192.0.2.143", "mac": "00:00:00:00:00:8D", "vendor": "Apple, Inc.", "scan_time": "2024-01-15T12:00:00", "hostname": None},
    ]


@pytest.fixture
def mock_network_interface():
    """Mock network interface detection to return a known value."""
    with patch('network_scanner_mcp.utils.detect_network_interface', return_value='eth0'):
        yield 'eth0'
