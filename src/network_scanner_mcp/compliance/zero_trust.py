"""
Zero Trust Architecture (ZTA) Assessment Module.

Assesses network posture against Zero Trust principles per:
    - NIST SP 800-207: Zero Trust Architecture
    - DISA Zero Trust Reference Architecture
    - CISA Zero Trust Maturity Model

Evaluates five pillars: Identity, Device, Network, Application, Data.
Each pillar is scored: TRADITIONAL, ADVANCED, or OPTIMAL.

References:
    - NIST SP 800-207 (August 2020)
    - DoD Zero Trust Reference Architecture v2.0
    - CISA Zero Trust Maturity Model v2.0 (April 2023)
    - OMB M-22-09 Federal Zero Trust Strategy
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("network-scanner")


# ---------------------------------------------------------------------------
# Maturity Levels
# ---------------------------------------------------------------------------

class ZTMaturityLevel(str, Enum):
    """
    Zero Trust maturity level per CISA ZT Maturity Model.

    TRADITIONAL: Perimeter-based, static policies, manual processes
    ADVANCED: Some automation, initial micro-segmentation, MFA started
    OPTIMAL: Fully automated, continuous verification, micro-segmented
    """
    TRADITIONAL = "TRADITIONAL"
    ADVANCED = "ADVANCED"
    OPTIMAL = "OPTIMAL"


class ZTPillar(str, Enum):
    """NIST 800-207 / CISA ZT pillars."""
    IDENTITY = "Identity"
    DEVICE = "Device"
    NETWORK = "Network"
    APPLICATION = "Application"
    DATA = "Data"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class PillarAssessment:
    """Assessment result for a single ZT pillar."""
    pillar: ZTPillar
    maturity: ZTMaturityLevel
    score: float  # 0.0 - 100.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    nist_800_207_sections: list[str] = field(default_factory=list)
    disa_zta_alignment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pillar": self.pillar.value,
            "maturity": self.maturity.value,
            "score": round(self.score, 1),
            "findings": self.findings,
            "recommendations": self.recommendations,
            "nist_800_207_sections": self.nist_800_207_sections,
            "disa_zta_alignment": self.disa_zta_alignment,
        }


@dataclass
class ZeroTrustAssessment:
    """Complete Zero Trust posture assessment."""
    assessment_time: str
    target_network: str
    overall_maturity: ZTMaturityLevel
    overall_score: float
    pillars: list[PillarAssessment] = field(default_factory=list)
    cross_pillar_findings: list[str] = field(default_factory=list)
    dod_zta_compliance: dict[str, Any] = field(default_factory=dict)
    omb_m2209_alignment: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_time": self.assessment_time,
            "target_network": self.target_network,
            "overall_maturity": self.overall_maturity.value,
            "overall_score": round(self.overall_score, 1),
            "pillars": [p.to_dict() for p in self.pillars],
            "cross_pillar_findings": self.cross_pillar_findings,
            "dod_zta_compliance": self.dod_zta_compliance,
            "omb_m2209_alignment": self.omb_m2209_alignment,
        }


# ---------------------------------------------------------------------------
# Pillar Assessment Functions
# ---------------------------------------------------------------------------

def _assess_identity_pillar(network_data: dict[str, Any]) -> PillarAssessment:
    """
    Pillar 1 - Identity: Authentication strength assessment.

    Evaluates:
    - Presence of centralized authentication services (LDAP/RADIUS/TACACS+)
    - Multi-factor authentication indicators
    - Certificate-based authentication (PKI services)
    - Password-based vs key-based SSH
    """
    devices = network_data.get("devices", [])
    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    score = 0.0

    # Check for centralized identity services
    has_ldap = False
    has_radius = False
    has_pki = False
    ssh_devices = 0
    telnet_devices = 0

    for device in devices:
        services = [s.lower() for s in (device.get("services") or [])]
        ports = device.get("ports") or []

        if "ldap" in services or "ldaps" in services:
            has_ldap = True
        # RADIUS uses UDP 1812/1813; port-based detection from TCP scan is
        # unreliable. A proper check would send a RADIUS Access-Request.
        # This is a heuristic based on open port observation.
        if any(p.get("port") in (1812, 1813) for p in ports if p.get("state") == "open"):
            has_radius = True
        # Port 8200 is commonly used by HashiCorp Vault, which may provide
        # PKI services. This is a heuristic -- the port could host other
        # applications. Not definitive proof of PKI infrastructure.
        if any(p.get("port") in (8200, 8201) for p in ports if p.get("state") == "open"):
            has_pki = True
        if "ssh" in services:
            ssh_devices += 1
            # Check for SSHv1 or password auth indicators in banner
            for p in ports:
                if p.get("port") == 22 and p.get("banner"):
                    banner = p["banner"].lower()
                    if "ssh-1." in banner and "ssh-1.99" not in banner:
                        findings.append({
                            "type": "weakness",
                            "detail": f"SSHv1 detected on {device.get('ip')} - no key exchange protection",
                            "severity": "high",
                        })
        if "telnet" in services:
            telnet_devices += 1

    # Scoring
    if has_ldap:
        score += 25.0
        findings.append({
            "type": "positive",
            "detail": "Centralized directory service (LDAP) detected",
        })
    else:
        recommendations.append(
            "Deploy centralized identity management (Active Directory, "
            "FreeIPA, or cloud IdP) for unified authentication."
        )

    if has_radius:
        score += 20.0
        findings.append({
            "type": "positive",
            "detail": "RADIUS/AAA service likely present (port 1812/1813 open; heuristic detection)",
        })
    else:
        recommendations.append(
            "Implement RADIUS or TACACS+ for network device authentication "
            "to centralize access control decisions."
        )

    if has_pki:
        score += 15.0
        findings.append({
            "type": "positive",
            "detail": "Possible PKI/certificate service detected (port 8200 open; may be HashiCorp Vault or other service)",
        })
    else:
        recommendations.append(
            "Deploy PKI for certificate-based authentication. "
            "Required for phishing-resistant MFA per OMB M-22-09."
        )

    if telnet_devices > 0:
        score -= 15.0
        findings.append({
            "type": "weakness",
            "detail": f"{telnet_devices} device(s) with telnet (cleartext authentication)",
            "severity": "critical",
        })
        recommendations.append(
            "Eliminate all telnet access. Replace with SSH key-based authentication."
        )
    else:
        score += 15.0

    if ssh_devices > 0:
        score += 10.0
        findings.append({
            "type": "positive",
            "detail": f"{ssh_devices} device(s) with SSH for encrypted authentication",
        })

    # MFA inference - if both LDAP and RADIUS present, likely MFA capable
    if has_ldap and has_radius:
        score += 15.0
        findings.append({
            "type": "positive",
            "detail": "MFA-capable infrastructure detected (LDAP + RADIUS)",
        })
    elif has_ldap or has_radius:
        recommendations.append(
            "Implement MFA for all user authentication. "
            "OMB M-22-09 requires phishing-resistant MFA (FIDO2/PIV)."
        )

    score = max(min(score, 100.0), 0.0)
    maturity = _score_to_maturity(score)

    return PillarAssessment(
        pillar=ZTPillar.IDENTITY,
        maturity=maturity,
        score=score,
        findings=findings,
        recommendations=recommendations,
        nist_800_207_sections=["3.1", "3.2.1", "7.1"],
        disa_zta_alignment=(
            "User Pillar - Identity, credential, and access management. "
            "DoD ZTA requires continuous identity verification and "
            "phishing-resistant MFA for all users."
        ),
    )


def _assess_device_pillar(network_data: dict[str, Any]) -> PillarAssessment:
    """
    Pillar 2 - Device: Device health and compliance status.

    Evaluates:
    - Device inventory completeness
    - Unknown/rogue device detection
    - Device health monitoring indicators
    - Endpoint management coverage
    """
    devices = network_data.get("devices", [])
    known_count = 0
    unknown_count = 0
    cluster_nodes = 0
    total_devices = len(devices)
    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    score = 0.0

    devices_with_services = 0
    devices_with_outdated = 0

    for device in devices:
        if device.get("is_known", False) or device.get("is_cluster_node", False):
            known_count += 1
        else:
            unknown_count += 1

        if device.get("is_cluster_node", False):
            cluster_nodes += 1

        services = device.get("services") or []
        if services:
            devices_with_services += 1

        # Check for outdated service indicators
        for p in (device.get("ports") or []):
            banner = (p.get("banner") or "").lower()
            if any(v in banner for v in ["openssh_4", "openssh_5", "openssh_6", "apache/2.0", "apache/2.2"]):
                devices_with_outdated += 1
                break

    # Scoring
    if total_devices > 0:
        known_ratio = known_count / total_devices
        # Inventory completeness
        if known_ratio >= 0.9:
            score += 30.0
            findings.append({
                "type": "positive",
                "detail": f"{known_ratio:.0%} of devices are inventoried/known",
            })
        elif known_ratio >= 0.7:
            score += 15.0
            findings.append({
                "type": "partial",
                "detail": f"{known_ratio:.0%} of devices inventoried. Target: 100%",
            })
        else:
            findings.append({
                "type": "weakness",
                "detail": f"Only {known_ratio:.0%} of devices inventoried",
                "severity": "high",
            })

        if unknown_count > 0:
            findings.append({
                "type": "weakness",
                "detail": f"{unknown_count} unknown/uninventoried device(s) detected",
                "severity": "medium",
            })
            recommendations.append(
                f"Investigate and catalogue {unknown_count} unknown devices. "
                "Zero Trust requires complete device inventory."
            )
    else:
        findings.append({
            "type": "weakness",
            "detail": "No devices detected - inventory cannot be assessed",
            "severity": "high",
        })

    # Device health monitoring
    if devices_with_services > 0:
        service_coverage = devices_with_services / max(total_devices, 1)
        if service_coverage >= 0.8:
            score += 20.0
            findings.append({
                "type": "positive",
                "detail": f"Service detection covers {service_coverage:.0%} of devices",
            })
        else:
            score += 10.0
            recommendations.append(
                "Extend service detection to all devices for comprehensive "
                "device health monitoring."
            )

    # Outdated software detection
    if devices_with_outdated > 0:
        findings.append({
            "type": "weakness",
            "detail": f"{devices_with_outdated} device(s) with outdated software",
            "severity": "medium",
        })
        recommendations.append(
            "Patch outdated services. Device compliance requires current "
            "software versions per DISA STIG requirements."
        )
    else:
        score += 15.0

    # Cluster node management
    if cluster_nodes > 0:
        score += 15.0
        findings.append({
            "type": "positive",
            "detail": f"{cluster_nodes} managed cluster node(s) detected",
        })

    # Device compliance enforcement indicator
    recommendations.append(
        "Implement endpoint detection and response (EDR) across all devices. "
        "ZTA requires continuous device posture assessment."
    )

    score = max(min(score, 100.0), 0.0)
    maturity = _score_to_maturity(score)

    return PillarAssessment(
        pillar=ZTPillar.DEVICE,
        maturity=maturity,
        score=score,
        findings=findings,
        recommendations=recommendations,
        nist_800_207_sections=["3.1", "3.2.2", "7.2"],
        disa_zta_alignment=(
            "Device Pillar - Device inventory, compliance, and health monitoring. "
            "DoD ZTA requires continuous device posture verification and "
            "automated compliance enforcement."
        ),
    )


def _assess_network_pillar(network_data: dict[str, Any]) -> PillarAssessment:
    """
    Pillar 3 - Network: Micro-segmentation verification.

    Evaluates:
    - Network segmentation evidence
    - Encrypted transport usage
    - Lateral movement potential
    - Network monitoring capabilities
    """
    devices = network_data.get("devices", [])
    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    score = 0.0

    # Analyze network topology
    subnets: set[str] = set()
    encrypted_services = 0
    unencrypted_services = 0
    total_open_ports = 0
    lateral_movement_risk = 0

    encrypted_ports = {443, 993, 995, 636, 465, 8443, 6514, 22, 2376}
    lateral_ports = {445, 135, 137, 138, 139, 3389, 5900, 22}

    for device in devices:
        ip = device.get("ip", "")
        parts = ip.split(".")
        if len(parts) == 4:
            subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

        for p in (device.get("ports") or []):
            if p.get("state") != "open":
                continue
            total_open_ports += 1
            port_num = p.get("port", 0)

            if port_num in encrypted_ports:
                encrypted_services += 1
            else:
                unencrypted_services += 1

            if port_num in lateral_ports:
                lateral_movement_risk += 1

    # Segmentation assessment
    if len(subnets) > 1:
        score += 20.0
        findings.append({
            "type": "positive",
            "detail": f"Multiple subnets detected ({len(subnets)}), indicating some segmentation",
        })
    elif len(subnets) == 1:
        findings.append({
            "type": "weakness",
            "detail": "All devices on single subnet - flat network topology",
            "severity": "high",
        })
        recommendations.append(
            "Implement network micro-segmentation. Separate management, "
            "data, and user traffic into distinct network segments. "
            "NIST 800-207 Section 3.2.3 requires granular access control."
        )
    else:
        findings.append({
            "type": "weakness",
            "detail": "Unable to determine network segmentation",
            "severity": "medium",
        })

    # Encryption assessment
    if total_open_ports > 0:
        enc_ratio = encrypted_services / total_open_ports
        if enc_ratio >= 0.8:
            score += 25.0
            findings.append({
                "type": "positive",
                "detail": f"{enc_ratio:.0%} of services use encrypted transport",
            })
        elif enc_ratio >= 0.5:
            score += 10.0
            findings.append({
                "type": "partial",
                "detail": f"{enc_ratio:.0%} of services use encrypted transport. Target: 100%",
            })
            recommendations.append(
                "Migrate remaining unencrypted services to encrypted alternatives. "
                "ZTA requires all traffic to be encrypted regardless of network location."
            )
        else:
            findings.append({
                "type": "weakness",
                "detail": f"Only {enc_ratio:.0%} of services use encrypted transport",
                "severity": "high",
            })
            recommendations.append(
                "Deploy TLS/mTLS across all services. Zero Trust assumes "
                "hostile network environment - encrypt everything."
            )

    # Lateral movement risk
    if lateral_movement_risk > 3:
        findings.append({
            "type": "weakness",
            "detail": f"{lateral_movement_risk} services enabling lateral movement (SMB, RDP, VNC)",
            "severity": "high",
        })
        recommendations.append(
            "Restrict lateral movement services (SMB, RDP, VNC) to "
            "authorized source-destination pairs. Implement host-based "
            "firewalls to enforce micro-segmentation at the host level."
        )
    elif lateral_movement_risk > 0:
        score += 10.0
        findings.append({
            "type": "partial",
            "detail": f"Limited lateral movement services ({lateral_movement_risk})",
        })
    else:
        score += 20.0
        findings.append({
            "type": "positive",
            "detail": "No common lateral movement services detected",
        })

    recommendations.append(
        "Deploy network traffic analysis (NTA/NDR) for continuous monitoring. "
        "Implement software-defined perimeter (SDP) for dynamic access control."
    )

    score = max(min(score, 100.0), 0.0)
    maturity = _score_to_maturity(score)

    return PillarAssessment(
        pillar=ZTPillar.NETWORK,
        maturity=maturity,
        score=score,
        findings=findings,
        recommendations=recommendations,
        nist_800_207_sections=["3.2.3", "4.1", "4.2", "7.3"],
        disa_zta_alignment=(
            "Network/Environment Pillar - Micro-segmentation, encrypted transport, "
            "and network access control. DoD ZTA mandates SDP, mTLS, and "
            "continuous network monitoring for all segments."
        ),
    )


def _assess_application_pillar(network_data: dict[str, Any]) -> PillarAssessment:
    """
    Pillar 4 - Application: Application access controls.

    Evaluates:
    - Application security posture (HTTPS vs HTTP)
    - API security indicators
    - Application authentication requirements
    - Secure development indicators
    """
    devices = network_data.get("devices", [])
    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    score = 0.0

    http_count = 0
    https_count = 0
    api_endpoints = 0
    web_apps = 0
    insecure_web = 0

    for device in devices:
        for p in (device.get("ports") or []):
            if p.get("state") != "open":
                continue
            port = p.get("port", 0)
            service = (p.get("service") or "").lower()
            banner = (p.get("banner") or "").lower()

            if port in (80, 8080) or service in ("http", "http-proxy"):
                http_count += 1
                if "api" in banner or "json" in banner or "rest" in banner:
                    api_endpoints += 1
                if any(kw in banner for kw in ["nginx", "apache", "iis", "express", "flask"]):
                    web_apps += 1
                    insecure_web += 1

            if port in (443, 8443) or service in ("https", "https-alt"):
                https_count += 1
                if "api" in banner or "json" in banner:
                    api_endpoints += 1
                if any(kw in banner for kw in ["nginx", "apache", "iis", "express", "flask"]):
                    web_apps += 1

    # Scoring
    total_web = http_count + https_count
    if total_web > 0:
        secure_ratio = https_count / total_web
        if secure_ratio >= 0.9:
            score += 30.0
            findings.append({
                "type": "positive",
                "detail": f"{secure_ratio:.0%} of web services use HTTPS",
            })
        elif secure_ratio >= 0.5:
            score += 15.0
            findings.append({
                "type": "partial",
                "detail": f"{secure_ratio:.0%} of web services use HTTPS",
            })
        else:
            findings.append({
                "type": "weakness",
                "detail": f"Only {secure_ratio:.0%} of web services use HTTPS",
                "severity": "high",
            })

        if insecure_web > 0:
            findings.append({
                "type": "weakness",
                "detail": f"{insecure_web} web application(s) accessible over HTTP",
                "severity": "medium",
            })
            recommendations.append(
                "Redirect all HTTP traffic to HTTPS. Implement HSTS headers. "
                "ZTA requires encrypted application access."
            )

    if api_endpoints > 0:
        score += 10.0
        findings.append({
            "type": "informational",
            "detail": f"{api_endpoints} API endpoint(s) detected",
        })
        recommendations.append(
            "Ensure all APIs use OAuth 2.0/OIDC with token validation. "
            "Implement API gateway for centralized access control."
        )

    # Default application security recommendations
    recommendations.extend([
        "Implement application-level authentication and authorization (ABAC/RBAC).",
        "Deploy Web Application Firewall (WAF) for public-facing applications.",
        "Implement runtime application self-protection (RASP) for critical apps.",
        "Enforce least-privilege access at the application layer.",
    ])

    score = max(min(score, 100.0), 0.0)
    maturity = _score_to_maturity(score)

    return PillarAssessment(
        pillar=ZTPillar.APPLICATION,
        maturity=maturity,
        score=score,
        findings=findings,
        recommendations=recommendations,
        nist_800_207_sections=["3.2.4", "4.3", "7.4"],
        disa_zta_alignment=(
            "Application & Workload Pillar - Secure access to applications, "
            "API security, and workload protection. DoD ZTA requires "
            "application-aware access policies and continuous workload monitoring."
        ),
    )


def _assess_data_pillar(network_data: dict[str, Any]) -> PillarAssessment:
    """
    Pillar 5 - Data: Data protection and classification.

    Evaluates:
    - Data-at-rest encryption indicators
    - Data-in-transit encryption
    - Database security posture
    - Data classification enforcement
    """
    devices = network_data.get("devices", [])
    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    score = 0.0

    exposed_databases = 0
    encrypted_db = 0
    unencrypted_db = 0
    storage_devices = 0

    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
                6379: "Redis", 9200: "Elasticsearch", 1433: "MSSQL",
                1521: "Oracle"}
    encrypted_db_ports = {3307, 5433, 27018}  # TLS variants

    for device in devices:
        vendor_lower = (device.get("vendor") or "").lower()
        if any(kw in vendor_lower for kw in ["synology", "qnap", "netgear"]):
            storage_devices += 1

        for p in (device.get("ports") or []):
            if p.get("state") != "open":
                continue
            port = p.get("port", 0)

            if port in db_ports:
                exposed_databases += 1
                unencrypted_db += 1
                findings.append({
                    "type": "weakness",
                    "detail": (
                        f"{db_ports[port]} database exposed on "
                        f"{device.get('ip')}:{port}"
                    ),
                    "severity": "high",
                })

            if port in encrypted_db_ports:
                encrypted_db += 1

    # Scoring
    if exposed_databases > 0:
        findings.append({
            "type": "weakness",
            "detail": f"{exposed_databases} database(s) accessible on the network",
            "severity": "high",
        })
        recommendations.append(
            "Restrict database access to application servers only. "
            "Databases should never be directly network-accessible. "
            "Use mTLS for all database connections."
        )
    else:
        score += 25.0
        findings.append({
            "type": "positive",
            "detail": "No exposed databases detected on standard ports",
        })

    # Data-in-transit assessment (from network pillar data)
    total_services = sum(
        1 for d in devices
        for p in (d.get("ports") or [])
        if p.get("state") == "open"
    )
    encrypted_services = sum(
        1 for d in devices
        for p in (d.get("ports") or [])
        if p.get("state") == "open" and p.get("port", 0) in {443, 993, 995, 636, 465, 8443, 6514, 22}
    )

    if total_services > 0:
        enc_ratio = encrypted_services / total_services
        if enc_ratio >= 0.7:
            score += 20.0
            findings.append({
                "type": "positive",
                "detail": f"Data-in-transit: {enc_ratio:.0%} of connections use encryption",
            })
        else:
            recommendations.append(
                "Implement encryption for all data in transit. "
                "ZTA requires TLS 1.2+ for all network communications."
            )

    # Data classification recommendations
    recommendations.extend([
        "Implement data classification tagging per NIST SP 800-171 CUI categories.",
        "Deploy Data Loss Prevention (DLP) to enforce classification policies.",
        "Encrypt all data at rest using FIPS 140-2/3 validated modules.",
        "Implement database activity monitoring (DAM) for all data stores.",
    ])

    if storage_devices > 0:
        findings.append({
            "type": "informational",
            "detail": f"{storage_devices} network storage device(s) detected",
        })
        recommendations.append(
            "Verify encryption at rest on all storage devices. "
            "Implement access logging and DLP policies."
        )

    score = max(min(score, 100.0), 0.0)
    maturity = _score_to_maturity(score)

    return PillarAssessment(
        pillar=ZTPillar.DATA,
        maturity=maturity,
        score=score,
        findings=findings,
        recommendations=recommendations,
        nist_800_207_sections=["3.2.5", "4.4", "7.5"],
        disa_zta_alignment=(
            "Data Pillar - Data classification, protection, and access control. "
            "DoD ZTA requires data-centric security with continuous monitoring, "
            "encryption, and DLP enforcement."
        ),
    )


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def _score_to_maturity(score: float) -> ZTMaturityLevel:
    """Convert numeric score to ZT maturity level."""
    if score >= 70.0:
        return ZTMaturityLevel.OPTIMAL
    elif score >= 40.0:
        return ZTMaturityLevel.ADVANCED
    return ZTMaturityLevel.TRADITIONAL


def _overall_maturity(pillar_scores: list[float]) -> ZTMaturityLevel:
    """Determine overall maturity from pillar scores."""
    if not pillar_scores:
        return ZTMaturityLevel.TRADITIONAL

    avg = sum(pillar_scores) / len(pillar_scores)
    min_score = min(pillar_scores)

    # Overall maturity is limited by the weakest pillar
    if min_score < 30.0:
        return ZTMaturityLevel.TRADITIONAL
    if avg >= 65.0 and min_score >= 40.0:
        return ZTMaturityLevel.OPTIMAL

    return ZTMaturityLevel.ADVANCED


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assess_zero_trust_posture(
    network_data: dict[str, Any],
) -> ZeroTrustAssessment:
    """
    Perform comprehensive Zero Trust Architecture assessment.

    Evaluates the network against all five ZT pillars per NIST SP 800-207
    and the CISA Zero Trust Maturity Model.

    Args:
        network_data: Dictionary containing:
            - ``devices`` (list[dict]): Discovered devices with full scan data
            - ``topology`` (dict, optional): Network topology information
            - ``cluster_nodes`` (dict, optional): Cluster configuration

    Returns:
        ZeroTrustAssessment with per-pillar and overall scores.
    """
    assessment_time = datetime.now(timezone.utc).isoformat()
    target_network = network_data.get("subnet", "unknown")

    logger.info("Starting Zero Trust posture assessment")

    # Assess each pillar
    identity = _assess_identity_pillar(network_data)
    device = _assess_device_pillar(network_data)
    network = _assess_network_pillar(network_data)
    application = _assess_application_pillar(network_data)
    data = _assess_data_pillar(network_data)

    pillars = [identity, device, network, application, data]
    pillar_scores = [p.score for p in pillars]

    # Overall assessment
    overall_score = sum(pillar_scores) / len(pillar_scores) if pillar_scores else 0.0
    overall_maturity = _overall_maturity(pillar_scores)

    # Cross-pillar findings
    cross_findings = _identify_cross_pillar_gaps(pillars)

    # DoD ZTA Reference Architecture alignment
    dod_compliance = _assess_dod_zta_compliance(pillars)

    # OMB M-22-09 alignment
    omb_alignment = {
        "identity": (
            "Agency staff use enterprise-managed identities" if identity.score >= 50
            else "DEFICIENCY: Centralized identity management not detected"
        ),
        "devices": (
            "Agency maintains comprehensive device inventory" if device.score >= 50
            else "DEFICIENCY: Incomplete device inventory"
        ),
        "networks": (
            "DNS traffic encrypted and network traffic monitored" if network.score >= 50
            else "DEFICIENCY: Network encryption and monitoring gaps"
        ),
        "applications": (
            "Applications tested and accessible over encrypted connections" if application.score >= 50
            else "DEFICIENCY: Application security gaps detected"
        ),
        "data": (
            "Data categorized and protected" if data.score >= 50
            else "DEFICIENCY: Data classification and protection gaps"
        ),
    }

    assessment = ZeroTrustAssessment(
        assessment_time=assessment_time,
        target_network=target_network,
        overall_maturity=overall_maturity,
        overall_score=overall_score,
        pillars=pillars,
        cross_pillar_findings=cross_findings,
        dod_zta_compliance=dod_compliance,
        omb_m2209_alignment=omb_alignment,
    )

    logger.info(
        f"ZTA assessment complete: {overall_maturity.value} "
        f"({overall_score:.1f}/100)"
    )

    return assessment


def _identify_cross_pillar_gaps(pillars: list[PillarAssessment]) -> list[str]:
    """Identify gaps that span multiple pillars."""
    gaps: list[str] = []
    pillar_map = {p.pillar: p for p in pillars}

    # Identity + Network gap: No MFA + flat network = high risk
    identity = pillar_map.get(ZTPillar.IDENTITY)
    network = pillar_map.get(ZTPillar.NETWORK)
    if identity and network:
        if identity.score < 40 and network.score < 40:
            gaps.append(
                "CRITICAL: Weak identity controls combined with flat network topology "
                "creates extreme lateral movement risk. Prioritize MFA deployment "
                "and network micro-segmentation simultaneously."
            )

    # Device + Data gap: Unknown devices + exposed databases
    device = pillar_map.get(ZTPillar.DEVICE)
    data = pillar_map.get(ZTPillar.DATA)
    if device and data:
        if device.score < 40 and data.score < 40:
            gaps.append(
                "HIGH RISK: Incomplete device inventory combined with data protection "
                "gaps. Unknown devices may have access to sensitive data stores."
            )

    # Application + Identity gap: Web apps without strong auth
    application = pillar_map.get(ZTPillar.APPLICATION)
    if application and identity:
        if application.score < 40 and identity.score < 50:
            gaps.append(
                "Applications lack strong authentication backing. Deploy SSO/OIDC "
                "integration for all web applications."
            )

    # Universal gap: All pillars below ADVANCED
    all_traditional = all(p.maturity == ZTMaturityLevel.TRADITIONAL for p in pillars)
    if all_traditional:
        gaps.append(
            "CRITICAL: All Zero Trust pillars at TRADITIONAL maturity level. "
            "Organization operates on legacy perimeter-based security model. "
            "Comprehensive ZTA transformation required per OMB M-22-09."
        )

    return gaps


def _assess_dod_zta_compliance(pillars: list[PillarAssessment]) -> dict[str, Any]:
    """Assess alignment with DoD Zero Trust Reference Architecture."""
    pillar_map = {p.pillar: p for p in pillars}

    return {
        "user_pillar": {
            "status": pillar_map[ZTPillar.IDENTITY].maturity.value
            if ZTPillar.IDENTITY in pillar_map else "NOT_ASSESSED",
            "target": "OPTIMAL",
            "gap": max(0, 70.0 - (pillar_map.get(ZTPillar.IDENTITY, PillarAssessment(
                pillar=ZTPillar.IDENTITY, maturity=ZTMaturityLevel.TRADITIONAL, score=0
            )).score)),
        },
        "device_pillar": {
            "status": pillar_map[ZTPillar.DEVICE].maturity.value
            if ZTPillar.DEVICE in pillar_map else "NOT_ASSESSED",
            "target": "OPTIMAL",
            "gap": max(0, 70.0 - (pillar_map.get(ZTPillar.DEVICE, PillarAssessment(
                pillar=ZTPillar.DEVICE, maturity=ZTMaturityLevel.TRADITIONAL, score=0
            )).score)),
        },
        "network_environment_pillar": {
            "status": pillar_map[ZTPillar.NETWORK].maturity.value
            if ZTPillar.NETWORK in pillar_map else "NOT_ASSESSED",
            "target": "OPTIMAL",
            "gap": max(0, 70.0 - (pillar_map.get(ZTPillar.NETWORK, PillarAssessment(
                pillar=ZTPillar.NETWORK, maturity=ZTMaturityLevel.TRADITIONAL, score=0
            )).score)),
        },
        "application_workload_pillar": {
            "status": pillar_map[ZTPillar.APPLICATION].maturity.value
            if ZTPillar.APPLICATION in pillar_map else "NOT_ASSESSED",
            "target": "OPTIMAL",
            "gap": max(0, 70.0 - (pillar_map.get(ZTPillar.APPLICATION, PillarAssessment(
                pillar=ZTPillar.APPLICATION, maturity=ZTMaturityLevel.TRADITIONAL, score=0
            )).score)),
        },
        "data_pillar": {
            "status": pillar_map[ZTPillar.DATA].maturity.value
            if ZTPillar.DATA in pillar_map else "NOT_ASSESSED",
            "target": "OPTIMAL",
            "gap": max(0, 70.0 - (pillar_map.get(ZTPillar.DATA, PillarAssessment(
                pillar=ZTPillar.DATA, maturity=ZTMaturityLevel.TRADITIONAL, score=0
            )).score)),
        },
        "overall_dod_readiness": (
            "READY" if all(p.maturity == ZTMaturityLevel.OPTIMAL for p in pillars)
            else "IN_PROGRESS" if any(p.maturity != ZTMaturityLevel.TRADITIONAL for p in pillars)
            else "NOT_STARTED"
        ),
    }


def generate_zt_roadmap(
    assessment: ZeroTrustAssessment,
) -> dict[str, Any]:
    """
    Generate a Zero Trust transformation roadmap from assessment results.

    Produces phased recommendations prioritized by risk and implementation
    complexity, aligned with OMB M-22-09 timelines.

    Args:
        assessment: ZeroTrustAssessment from assess_zero_trust_posture().

    Returns:
        Dictionary with phased roadmap, quick wins, and resource estimates.
    """
    # Collect all recommendations by priority
    all_recs: list[dict[str, Any]] = []
    for pillar in assessment.pillars:
        for rec in pillar.recommendations:
            all_recs.append({
                "pillar": pillar.pillar.value,
                "recommendation": rec,
                "pillar_score": pillar.score,
                "priority": "high" if pillar.score < 40 else "medium" if pillar.score < 70 else "low",
            })

    # Sort: lowest scoring pillars first
    all_recs.sort(key=lambda r: r["pillar_score"])

    # Phase categorization
    phase_1_quick_wins = [r for r in all_recs if r["priority"] == "high"][:5]
    phase_2_foundation = [r for r in all_recs if r["priority"] in ("high", "medium")][:8]
    phase_3_advanced = [r for r in all_recs if r["priority"] in ("medium", "low")]

    # Identify weakest pillar for immediate focus
    weakest = min(assessment.pillars, key=lambda p: p.score) if assessment.pillars else None

    roadmap = {
        "current_state": {
            "overall_maturity": assessment.overall_maturity.value,
            "overall_score": round(assessment.overall_score, 1),
            "weakest_pillar": weakest.pillar.value if weakest else "N/A",
            "weakest_score": round(weakest.score, 1) if weakest else 0,
        },
        "target_state": {
            "maturity": "OPTIMAL",
            "target_score": 70.0,
            "timeline": "18-24 months per OMB M-22-09",
        },
        "phase_1_quick_wins": {
            "timeline": "0-3 months",
            "focus": "Eliminate critical gaps and easy wins",
            "actions": phase_1_quick_wins,
        },
        "phase_2_foundation": {
            "timeline": "3-12 months",
            "focus": "Build core ZTA capabilities",
            "actions": phase_2_foundation,
        },
        "phase_3_advanced": {
            "timeline": "12-24 months",
            "focus": "Achieve OPTIMAL maturity across all pillars",
            "actions": phase_3_advanced,
        },
        "cross_pillar_priorities": assessment.cross_pillar_findings,
        "omb_m2209_gaps": [
            v for v in assessment.omb_m2209_alignment.values()
            if "DEFICIENCY" in v
        ],
    }

    return roadmap


def zt_maturity_score(assessment: ZeroTrustAssessment) -> dict[str, Any]:
    """
    Calculate numeric Zero Trust maturity score.

    Returns a composite score (0-100) with per-pillar breakdown suitable
    for tracking ZT transformation progress over time.

    Args:
        assessment: ZeroTrustAssessment from assess_zero_trust_posture().

    Returns:
        Dictionary with overall and per-pillar numeric scores.
    """
    pillar_scores = {
        p.pillar.value: round(p.score, 1)
        for p in assessment.pillars
    }

    return {
        "overall_score": round(assessment.overall_score, 1),
        "overall_maturity": assessment.overall_maturity.value,
        "pillar_scores": pillar_scores,
        "target_score": 70.0,
        "gap_to_target": round(max(0, 70.0 - assessment.overall_score), 1),
        "assessment_time": assessment.assessment_time,
        "maturity_distribution": {
            "TRADITIONAL": sum(
                1 for p in assessment.pillars
                if p.maturity == ZTMaturityLevel.TRADITIONAL
            ),
            "ADVANCED": sum(
                1 for p in assessment.pillars
                if p.maturity == ZTMaturityLevel.ADVANCED
            ),
            "OPTIMAL": sum(
                1 for p in assessment.pillars
                if p.maturity == ZTMaturityLevel.OPTIMAL
            ),
        },
    }
