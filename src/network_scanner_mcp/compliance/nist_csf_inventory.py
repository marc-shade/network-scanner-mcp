"""
NIST Cybersecurity Framework (CSF) Asset Inventory Module.

Implements asset inventory capabilities aligned with the NIST CSF Identify
function, specifically:
    - ID.AM-1: Physical devices and systems inventoried
    - ID.AM-2: Software platforms and applications inventoried
    - ID.AM-3: Organizational data flows mapped
    - ID.AM-4: External information systems catalogued
    - ID.AM-5: Resources prioritized based on classification/criticality

Provides asset classification (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
aligned with CUI handling categories and risk scoring based on exposure,
criticality, vulnerability count, and patch status indicators.

References:
    - NIST Cybersecurity Framework v1.1 (and v2.0 GV/ID alignment)
    - NIST SP 800-171 Rev. 2 - CUI handling categories
    - CNSSI 1253 - Security categorization
    - FIPS 199 - Standards for Security Categorization
"""

import hashlib
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("network-scanner")


# ---------------------------------------------------------------------------
# Classification and Criticality Enums
# ---------------------------------------------------------------------------

class AssetClassification(str, Enum):
    """
    Asset security classification levels.

    Maps to CUI handling categories and FIPS 199 impact levels:
        PUBLIC     -> Low impact, no CUI
        INTERNAL   -> Low-Moderate impact, FCI (Federal Contract Information)
        CONFIDENTIAL -> Moderate impact, CUI Basic
        RESTRICTED -> High impact, CUI Specified
    """
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class AssetCriticality(str, Enum):
    """Asset criticality for mission impact assessment."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetType(str, Enum):
    """Asset type classification."""
    NETWORK_DEVICE = "network_device"
    SERVER = "server"
    WORKSTATION = "workstation"
    IOT_DEVICE = "iot_device"
    MOBILE_DEVICE = "mobile_device"
    PRINTER = "printer"
    STORAGE = "storage"
    SECURITY_APPLIANCE = "security_appliance"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


class DataFlowDirection(str, Enum):
    """Data flow directionality for ID.AM-3."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"
    INTERNAL = "internal"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class SoftwareInventoryItem:
    """Software platform or application identified on an asset (ID.AM-2)."""
    name: str
    version: str
    port: int
    protocol: str
    cpe_uri: Optional[str] = None
    category: str = "application"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "port": self.port,
            "protocol": self.protocol,
            "cpe_uri": self.cpe_uri,
            "category": self.category,
        }


@dataclass
class DataFlow:
    """Data flow record for ID.AM-3 mapping."""
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    service: str
    direction: DataFlowDirection
    encrypted: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "direction": self.direction.value,
            "encrypted": self.encrypted,
            "description": self.description,
        }


@dataclass
class RiskScore:
    """Multi-factor risk score for an asset."""
    overall: float  # 0.0 - 10.0
    exposure: float
    criticality: float
    vulnerability: float
    patch_status: float
    factors: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": round(self.overall, 2),
            "exposure": round(self.exposure, 2),
            "criticality": round(self.criticality, 2),
            "vulnerability": round(self.vulnerability, 2),
            "patch_status": round(self.patch_status, 2),
            "factors": self.factors,
        }


@dataclass
class AssetInventoryEntry:
    """Complete NIST CSF-aligned asset inventory entry."""
    asset_id: str
    ip: str
    mac: str
    hostname: Optional[str]
    vendor: str
    asset_type: AssetType
    classification: AssetClassification
    criticality: AssetCriticality
    risk_score: RiskScore
    software_inventory: list[SoftwareInventoryItem] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    is_external: bool = False
    is_cluster_node: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    nist_csf_functions: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "asset_type": self.asset_type.value,
            "classification": self.classification.value,
            "criticality": self.criticality.value,
            "risk_score": self.risk_score.to_dict(),
            "software_inventory": [s.to_dict() for s in self.software_inventory],
            "data_flows": [d.to_dict() for d in self.data_flows],
            "is_external": self.is_external,
            "is_cluster_node": self.is_cluster_node,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "nist_csf_functions": self.nist_csf_functions,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Vendor/Service Classification Mappings
# ---------------------------------------------------------------------------

_VENDOR_TYPE_MAP: dict[str, AssetType] = {
    "cisco": AssetType.NETWORK_DEVICE,
    "juniper": AssetType.NETWORK_DEVICE,
    "arista": AssetType.NETWORK_DEVICE,
    "fortinet": AssetType.SECURITY_APPLIANCE,
    "palo alto": AssetType.SECURITY_APPLIANCE,
    "paloalto": AssetType.SECURITY_APPLIANCE,
    "checkpoint": AssetType.SECURITY_APPLIANCE,
    "sonicwall": AssetType.SECURITY_APPLIANCE,
    "barracuda": AssetType.SECURITY_APPLIANCE,
    "apple": AssetType.WORKSTATION,
    "dell": AssetType.SERVER,
    "hewlett": AssetType.SERVER,
    "hp": AssetType.SERVER,
    "lenovo": AssetType.WORKSTATION,
    "samsung": AssetType.MOBILE_DEVICE,
    "google": AssetType.MOBILE_DEVICE,
    "huawei": AssetType.MOBILE_DEVICE,
    "synology": AssetType.STORAGE,
    "qnap": AssetType.STORAGE,
    "netgear": AssetType.NETWORK_DEVICE,
    "ubiquiti": AssetType.NETWORK_DEVICE,
    "tp-link": AssetType.NETWORK_DEVICE,
    "ring": AssetType.IOT_DEVICE,
    "nest": AssetType.IOT_DEVICE,
    "sonos": AssetType.IOT_DEVICE,
    "philips": AssetType.IOT_DEVICE,
    "epson": AssetType.PRINTER,
    "brother": AssetType.PRINTER,
    "canon": AssetType.PRINTER,
    "xerox": AssetType.PRINTER,
    "lexmark": AssetType.PRINTER,
    "vmware": AssetType.SERVER,
    "linux": AssetType.SERVER,
    "ubuntu": AssetType.SERVER,
    "debian": AssetType.SERVER,
    "redhat": AssetType.SERVER,
    "red hat": AssetType.SERVER,
}

# Services that indicate higher criticality
_CRITICAL_SERVICES = {
    "ssh", "rdp", "smb", "ldap", "ldaps", "dns", "dhcp",
    "mysql", "postgresql", "mssql", "oracle", "mongodb",
    "redis", "elasticsearch", "docker", "kubernetes",
}

# Services indicating infrastructure role
_INFRASTRUCTURE_SERVICES = {
    "dns", "dhcp", "ntp", "syslog", "snmp", "ldap", "ldaps",
}

# Encrypted service ports
_ENCRYPTED_PORTS = {443, 993, 995, 636, 465, 8443, 6514, 2376, 22}


# ---------------------------------------------------------------------------
# Asset Classification Logic
# ---------------------------------------------------------------------------

def classify_asset(device: dict[str, Any]) -> AssetClassification:
    """
    Assign a security classification to an asset based on its characteristics.

    Classification logic considers:
    - Service portfolio (databases, management interfaces)
    - Cluster membership
    - Device type (security appliances, infrastructure)
    - Vendor characteristics
    - Port exposure profile

    The classification maps to CUI handling levels:
        PUBLIC     -> No CUI, publicly accessible resources
        INTERNAL   -> FCI, general internal resources
        CONFIDENTIAL -> CUI Basic, sensitive operational data
        RESTRICTED -> CUI Specified, critical infrastructure

    Args:
        device: Device dictionary with vendor, services, ports, and
            cluster membership fields.

    Returns:
        AssetClassification enum value.
    """
    services: list[str] = [s.lower() for s in (device.get("services") or [])]
    ports_info: list[dict] = device.get("ports") or []
    open_ports = [p.get("port", 0) for p in ports_info if p.get("state") == "open"]
    vendor_lower = (device.get("vendor") or "").lower()
    is_cluster = device.get("is_cluster_node", False)

    # RESTRICTED: Critical infrastructure and security appliances
    if is_cluster:
        return AssetClassification.RESTRICTED

    security_vendor = any(
        kw in vendor_lower
        for kw in ["fortinet", "palo alto", "paloalto", "checkpoint", "sonicwall"]
    )
    if security_vendor:
        return AssetClassification.RESTRICTED

    # CONFIDENTIAL: Servers with databases or management services
    has_database = any(s in services for s in [
        "mysql", "postgresql", "mssql", "oracle", "mongodb",
        "redis", "elasticsearch",
    ])
    has_mgmt = any(s in services for s in ["ldap", "ldaps", "dns", "dhcp"])

    if has_database or has_mgmt:
        return AssetClassification.CONFIDENTIAL

    # INTERNAL: Servers, workstations, storage with services
    if len(services) >= 2:
        return AssetClassification.INTERNAL

    device_type = _infer_device_type(device)
    if device_type in (AssetType.SERVER, AssetType.STORAGE):
        return AssetClassification.INTERNAL

    # PUBLIC: IoT, printers, consumer devices with minimal services
    if device_type in (AssetType.IOT_DEVICE, AssetType.PRINTER, AssetType.MOBILE_DEVICE):
        return AssetClassification.PUBLIC

    # Default: INTERNAL for anything with open ports, PUBLIC otherwise
    if open_ports:
        return AssetClassification.INTERNAL

    return AssetClassification.PUBLIC


def _infer_device_type(device: dict[str, Any]) -> AssetType:
    """Infer asset type from vendor and services."""
    vendor_lower = (device.get("vendor") or "").lower()
    hostname_lower = (device.get("hostname") or "").lower()

    combined = vendor_lower + " " + hostname_lower

    for keyword, asset_type in _VENDOR_TYPE_MAP.items():
        if keyword in combined:
            return asset_type

    services = [s.lower() for s in (device.get("services") or [])]
    if any(s in _INFRASTRUCTURE_SERVICES for s in services):
        return AssetType.INFRASTRUCTURE

    if any(s in _CRITICAL_SERVICES for s in services):
        return AssetType.SERVER

    return AssetType.UNKNOWN


def _infer_criticality(
    device: dict[str, Any],
    classification: AssetClassification,
) -> AssetCriticality:
    """Determine asset criticality from classification and role."""
    if classification == AssetClassification.RESTRICTED:
        return AssetCriticality.CRITICAL

    services = [s.lower() for s in (device.get("services") or [])]

    if classification == AssetClassification.CONFIDENTIAL:
        if any(s in services for s in ["dns", "dhcp", "ldap"]):
            return AssetCriticality.CRITICAL
        return AssetCriticality.HIGH

    if classification == AssetClassification.INTERNAL:
        if len(services) >= 3:
            return AssetCriticality.MEDIUM
        return AssetCriticality.MEDIUM

    return AssetCriticality.LOW


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def calculate_risk_score(asset: dict[str, Any]) -> RiskScore:
    """
    Compute a multi-factor risk score for an asset.

    Scoring factors (each 0.0 - 10.0, weighted):
        - Exposure (30%): Number of open ports, insecure services, internet-facing
        - Criticality (25%): Asset classification, role in infrastructure
        - Vulnerability (25%): Known risky services, outdated versions
        - Patch status (20%): Service currency, version indicators

    The overall score is a weighted composite clamped to [0.0, 10.0].

    Args:
        asset: Device dictionary with ports, services, vendor, classification.

    Returns:
        RiskScore with component scores and contributing factors.
    """
    ports_info: list[dict] = asset.get("ports") or []
    services: list[str] = [s.lower() for s in (asset.get("services") or [])]
    open_ports = [p for p in ports_info if p.get("state") == "open"]
    classification = asset.get("classification", AssetClassification.INTERNAL)
    if isinstance(classification, str):
        try:
            classification = AssetClassification(classification)
        except ValueError:
            classification = AssetClassification.INTERNAL

    factors: dict[str, Any] = {}

    # --- Exposure Score ---
    exposure = 0.0
    num_open = len(open_ports)
    # Base exposure from port count (logarithmic scaling)
    if num_open > 0:
        exposure = min(2.0 + math.log2(num_open + 1) * 1.5, 7.0)

    # Insecure service penalty
    insecure_services = {"telnet", "ftp", "rsh", "rlogin", "tftp", "rexec"}
    insecure_found = [s for s in services if s in insecure_services]
    if insecure_found:
        exposure = min(exposure + len(insecure_found) * 1.5, 10.0)
        factors["insecure_services"] = insecure_found

    # Management interface exposure
    mgmt_ports = {22, 23, 3389, 5900, 8080, 8443}
    exposed_mgmt = [p for p in open_ports if p.get("port") in mgmt_ports]
    if len(exposed_mgmt) > 2:
        exposure = min(exposure + 1.0, 10.0)
        factors["exposed_management_ports"] = len(exposed_mgmt)

    factors["open_port_count"] = num_open

    # --- Criticality Score ---
    criticality_map = {
        AssetClassification.RESTRICTED: 9.0,
        AssetClassification.CONFIDENTIAL: 7.0,
        AssetClassification.INTERNAL: 4.0,
        AssetClassification.PUBLIC: 2.0,
    }
    criticality = criticality_map.get(classification, 4.0)

    # Boost for infrastructure services
    infra_count = sum(1 for s in services if s in _INFRASTRUCTURE_SERVICES)
    if infra_count > 0:
        criticality = min(criticality + infra_count * 0.5, 10.0)
        factors["infrastructure_services"] = infra_count

    is_cluster = asset.get("is_cluster_node", False)
    if is_cluster:
        criticality = min(criticality + 2.0, 10.0)
        factors["cluster_node"] = True

    # --- Vulnerability Score ---
    vulnerability = 0.0

    # High-risk service indicators
    risky_services = {"telnet", "ftp", "snmp", "rsh", "rlogin", "nfs"}
    risky_found = [s for s in services if s in risky_services]
    vulnerability += len(risky_found) * 1.5

    # Unencrypted services on non-encrypted ports
    unencrypted_count = sum(
        1 for p in open_ports
        if p.get("port") not in _ENCRYPTED_PORTS and p.get("service", "unknown") != "unknown"
    )
    if unencrypted_count > 0:
        vulnerability += min(unencrypted_count * 0.5, 3.0)
        factors["unencrypted_services"] = unencrypted_count

    # Database exposure
    db_services = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis"}
    exposed_dbs = [s for s in services if s in db_services]
    if exposed_dbs:
        vulnerability += len(exposed_dbs) * 2.0
        factors["exposed_databases"] = exposed_dbs

    vulnerability = min(vulnerability, 10.0)

    # --- Patch Status Score ---
    # Assessed via banner/version analysis
    patch_status = 3.0  # Default: moderate (unknown patch state)

    for port_entry in open_ports:
        banner = (port_entry.get("banner") or "").lower()
        if not banner:
            continue

        # Check for known outdated version patterns
        outdated_indicators = [
            ("openssh_4", 3.0), ("openssh_5", 2.5), ("openssh_6", 2.0),
            ("openssh_7", 1.0),
            ("apache/2.2", 2.5), ("apache/2.0", 3.0),
            ("nginx/0.", 3.0), ("nginx/1.0", 2.0),
            ("mysql 5.5", 2.5), ("mysql 5.0", 3.0),
            ("php/5.", 3.0), ("php/7.0", 2.0), ("php/7.1", 1.5),
        ]
        for pattern, penalty in outdated_indicators:
            if pattern in banner:
                patch_status = min(patch_status + penalty, 10.0)
                factors.setdefault("outdated_versions", []).append(
                    f"{pattern} on port {port_entry.get('port')}"
                )
                break

    # --- Composite Score ---
    weights = {
        "exposure": 0.30,
        "criticality": 0.25,
        "vulnerability": 0.25,
        "patch_status": 0.20,
    }

    overall = (
        exposure * weights["exposure"]
        + criticality * weights["criticality"]
        + vulnerability * weights["vulnerability"]
        + patch_status * weights["patch_status"]
    )
    overall = min(max(overall, 0.0), 10.0)

    return RiskScore(
        overall=overall,
        exposure=exposure,
        criticality=criticality,
        vulnerability=vulnerability,
        patch_status=patch_status,
        factors=factors,
    )


# ---------------------------------------------------------------------------
# Software Inventory (ID.AM-2)
# ---------------------------------------------------------------------------

def _build_software_inventory(device: dict[str, Any]) -> list[SoftwareInventoryItem]:
    """Build software inventory from port scan and service detection data."""
    inventory: list[SoftwareInventoryItem] = []
    ports_info: list[dict] = device.get("ports") or []

    for port_entry in ports_info:
        if port_entry.get("state") != "open":
            continue

        service_name = port_entry.get("service", "unknown")
        if service_name == "unknown":
            continue

        banner = port_entry.get("banner") or ""
        version = _extract_version(banner) if banner else "*"
        port_num = port_entry.get("port", 0)

        # Determine category
        category = "application"
        if service_name in _INFRASTRUCTURE_SERVICES:
            category = "infrastructure"
        elif service_name in ("http", "https", "nginx", "apache", "iis"):
            category = "web_server"
        elif service_name in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch"):
            category = "database"

        # Build CPE URI for the software
        cpe_uri = None
        from .scap_output import _SERVICE_CPE_MAP
        if service_name.lower() in _SERVICE_CPE_MAP:
            mapping = _SERVICE_CPE_MAP[service_name.lower()]
            cpe_uri = (
                f"cpe:2.3:a:{mapping['vendor']}:{mapping['product']}:"
                f"{version}:*:*:*:*:*:*:*"
            )

        protocol = "tcp"
        if port_num in (53, 67, 68, 69, 123, 161, 162, 514):
            protocol = "udp"

        inventory.append(SoftwareInventoryItem(
            name=service_name,
            version=version,
            port=port_num,
            protocol=protocol,
            cpe_uri=cpe_uri,
            category=category,
        ))

    return inventory


def _extract_version(banner: str) -> str:
    """Extract version from service banner."""
    import re
    patterns = [
        r"(\d+\.\d+\.\d+[a-z]?\d*)",
        r"(\d+\.\d+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return "*"


# ---------------------------------------------------------------------------
# Data Flow Mapping (ID.AM-3)
# ---------------------------------------------------------------------------

def _map_data_flows(device: dict[str, Any], all_devices: list[dict]) -> list[DataFlow]:
    """
    Infer data flows from service and port information.

    This maps observed services to likely data flow patterns based on
    service types and port characteristics.
    """
    flows: list[DataFlow] = []
    ip = device.get("ip", "unknown")
    ports_info: list[dict] = device.get("ports") or []

    for port_entry in ports_info:
        if port_entry.get("state") != "open":
            continue

        port_num = port_entry.get("port", 0)
        service_name = port_entry.get("service", "unknown")
        if service_name == "unknown":
            continue

        encrypted = port_num in _ENCRYPTED_PORTS

        # Determine flow direction based on service type
        if service_name in ("dns", "dhcp", "ntp", "ldap", "ldaps"):
            direction = DataFlowDirection.BIDIRECTIONAL
            description = f"{service_name.upper()} infrastructure service"
        elif service_name in ("syslog",):
            direction = DataFlowDirection.INBOUND
            description = "Log collection endpoint"
        elif service_name in ("http", "https", "nginx", "apache"):
            direction = DataFlowDirection.INBOUND
            description = "Web service accepting connections"
        elif service_name in ("mysql", "postgresql", "mongodb", "redis"):
            direction = DataFlowDirection.BIDIRECTIONAL
            description = f"Database service ({service_name})"
        elif service_name in ("ssh", "rdp", "vnc"):
            direction = DataFlowDirection.INBOUND
            description = f"Remote management ({service_name})"
        elif service_name in ("smtp", "smtps"):
            direction = DataFlowDirection.BIDIRECTIONAL
            description = "Email transport"
        else:
            direction = DataFlowDirection.BIDIRECTIONAL
            description = f"Service: {service_name}"

        protocol = "tcp"
        if port_num in (53, 67, 68, 69, 123, 161, 162, 514):
            protocol = "udp"

        flows.append(DataFlow(
            source_ip="*",
            destination_ip=ip,
            port=port_num,
            protocol=protocol,
            service=service_name,
            direction=direction,
            encrypted=encrypted,
            description=description,
        ))

    return flows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_asset_inventory(
    scan_results: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a NIST CSF-aligned asset inventory from network scan results.

    Processes all discovered devices and produces a comprehensive inventory
    covering NIST CSF Identify function subcategories:
        - ID.AM-1: Physical devices/systems inventory
        - ID.AM-2: Software/application inventory
        - ID.AM-3: Data flow mapping
        - ID.AM-4: External systems catalogue
        - ID.AM-5: Resource prioritization

    Args:
        scan_results: Dictionary from network scanning containing:
            - ``devices`` (list[dict]): Discovered devices with IP, MAC,
              vendor, hostname, services, ports, is_cluster_node fields.
            - ``cluster_nodes`` (dict, optional): Cluster node config.

    Returns:
        Dictionary with:
            - ``inventory``: List of AssetInventoryEntry dicts
            - ``summary``: Aggregate statistics
            - ``nist_csf_coverage``: Which ID.AM subcategories are addressed
            - ``classification_breakdown``: Count by classification level
            - ``risk_distribution``: Risk score distribution
            - ``data_flow_summary``: Aggregate data flow analysis
    """
    devices: list[dict] = scan_results.get("devices", [])
    cluster_nodes: dict = scan_results.get("cluster_nodes", {})

    inventory_entries: list[AssetInventoryEntry] = []
    all_data_flows: list[DataFlow] = []

    for device in devices:
        ip = device.get("ip", "unknown")
        mac = device.get("mac", "unknown")

        # Generate deterministic asset ID
        asset_id = hashlib.sha256(f"{mac}:{ip}".encode()).hexdigest()[:16]

        # Classify
        classification = classify_asset(device)
        device_type = _infer_device_type(device)
        criticality = _infer_criticality(device, classification)

        # Add classification to device for risk scoring
        device_enriched = {**device, "classification": classification}
        risk = calculate_risk_score(device_enriched)

        # Build sub-inventories
        software = _build_software_inventory(device)
        data_flows = _map_data_flows(device, devices)
        all_data_flows.extend(data_flows)

        # Determine if external
        is_external = _is_external_system(device, cluster_nodes)

        # NIST CSF function mapping
        csf_functions = {
            "ID.AM-1": f"Physical device: {device_type.value} at {ip}",
            "ID.AM-2": f"{len(software)} software items identified",
            "ID.AM-3": f"{len(data_flows)} data flows mapped",
            "ID.AM-4": "External" if is_external else "Internal",
            "ID.AM-5": f"Classification: {classification.value}, "
                       f"Criticality: {criticality.value}, "
                       f"Risk: {risk.overall:.1f}/10.0",
        }

        # Tags
        tags = [device_type.value, classification.value]
        if device.get("is_cluster_node"):
            tags.append("cluster_node")
        if is_external:
            tags.append("external")
        if risk.overall >= 7.0:
            tags.append("high_risk")

        entry = AssetInventoryEntry(
            asset_id=asset_id,
            ip=ip,
            mac=mac,
            hostname=device.get("hostname"),
            vendor=device.get("vendor", "Unknown"),
            asset_type=device_type,
            classification=classification,
            criticality=criticality,
            risk_score=risk,
            software_inventory=software,
            data_flows=data_flows,
            is_external=is_external,
            is_cluster_node=device.get("is_cluster_node", False),
            first_seen=device.get("first_seen"),
            last_seen=device.get("last_seen"),
            nist_csf_functions=csf_functions,
            tags=tags,
        )
        inventory_entries.append(entry)

    # Sort by risk score descending
    inventory_entries.sort(key=lambda e: e.risk_score.overall, reverse=True)

    # Build summary
    classification_breakdown = {}
    for cls in AssetClassification:
        classification_breakdown[cls.value] = sum(
            1 for e in inventory_entries if e.classification == cls
        )

    risk_distribution = {
        "critical_risk": sum(1 for e in inventory_entries if e.risk_score.overall >= 8.0),
        "high_risk": sum(1 for e in inventory_entries if 6.0 <= e.risk_score.overall < 8.0),
        "medium_risk": sum(1 for e in inventory_entries if 4.0 <= e.risk_score.overall < 6.0),
        "low_risk": sum(1 for e in inventory_entries if e.risk_score.overall < 4.0),
    }

    # Data flow summary
    encrypted_flows = sum(1 for f in all_data_flows if f.encrypted)
    total_flows = len(all_data_flows)

    result = {
        "inventory_time": datetime.now(timezone.utc).isoformat(),
        "total_assets": len(inventory_entries),
        "inventory": [e.to_dict() for e in inventory_entries],
        "summary": {
            "total_assets": len(inventory_entries),
            "by_type": _count_by_type(inventory_entries),
            "avg_risk_score": round(
                sum(e.risk_score.overall for e in inventory_entries) / max(len(inventory_entries), 1),
                2
            ),
            "highest_risk_asset": inventory_entries[0].to_dict() if inventory_entries else None,
        },
        "nist_csf_coverage": {
            "ID.AM-1": f"{len(inventory_entries)} physical devices inventoried",
            "ID.AM-2": f"{sum(len(e.software_inventory) for e in inventory_entries)} "
                       "software items catalogued",
            "ID.AM-3": f"{total_flows} data flows mapped "
                       f"({encrypted_flows} encrypted)",
            "ID.AM-4": f"{sum(1 for e in inventory_entries if e.is_external)} "
                       "external systems catalogued",
            "ID.AM-5": "All assets prioritized by classification and risk score",
        },
        "classification_breakdown": classification_breakdown,
        "risk_distribution": risk_distribution,
        "data_flow_summary": {
            "total_flows": total_flows,
            "encrypted_flows": encrypted_flows,
            "unencrypted_flows": total_flows - encrypted_flows,
            "encryption_percentage": round(
                (encrypted_flows / max(total_flows, 1)) * 100, 1
            ),
        },
    }

    logger.info(
        f"Asset inventory built: {len(inventory_entries)} assets, "
        f"avg risk {result['summary']['avg_risk_score']:.1f}"
    )

    return result


def _is_external_system(device: dict, cluster_nodes: dict) -> bool:
    """Determine if a device is an external system (ID.AM-4)."""
    ip = device.get("ip", "")

    # RFC 1918 private ranges are internal
    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.",
                      "172.24.", "172.25.", "172.26.", "172.27.",
                      "172.28.", "172.29.", "172.30.", "172.31.",
                      "192.168.")):
        return False

    # Cluster nodes are internal
    if ip in cluster_nodes:
        return False

    # Link-local is internal
    if ip.startswith("169.254."):
        return False

    return True


def _count_by_type(entries: list[AssetInventoryEntry]) -> dict[str, int]:
    """Count inventory entries by asset type."""
    counts: dict[str, int] = {}
    for entry in entries:
        key = entry.asset_type.value
        counts[key] = counts.get(key, 0) + 1
    return counts
