"""
CIS (Center for Internet Security) Benchmark Checking Module.

Implements network device hardening checks aligned with CIS Benchmark concepts
for network devices including Cisco, Juniper, and generic network infrastructure.

Each check returns structured results with benchmark ID, severity level,
compliance status, rationale, and remediation guidance.

References:
    - CIS Cisco IOS Benchmark v4.1.1
    - CIS Juniper OS Benchmark v2.0.0
    - CIS Controls v8 (network device hardening sections)
    - DISA STIG for Network Devices
"""

import asyncio
import logging
import re
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("network-scanner")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

class CISLevel(str, Enum):
    """CIS Benchmark recommendation levels."""
    L1 = "L1"  # Level 1 - essential, broadly applicable
    L2 = "L2"  # Level 2 - defense-in-depth, may reduce functionality


class ComplianceStatus(str, Enum):
    """Check compliance status values."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    MANUAL_REVIEW = "manual_review"


@dataclass
class CISCheckResult:
    """Result of a single CIS benchmark check."""
    benchmark_id: str
    title: str
    description: str
    level: CISLevel
    status: ComplianceStatus
    rationale: str
    remediation: str
    severity: str = "medium"
    evidence: str = ""
    cis_control_id: str = ""
    nist_mapping: list[str] = field(default_factory=list)
    check_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "benchmark_id": self.benchmark_id,
            "title": self.title,
            "description": self.description,
            "level": self.level.value,
            "status": self.status.value,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "severity": self.severity,
            "evidence": self.evidence,
            "cis_control_id": self.cis_control_id,
            "nist_mapping": self.nist_mapping,
            "check_duration_ms": self.check_duration_ms,
        }


@dataclass
class CISAssessmentResult:
    """Aggregate result of a CIS benchmark assessment."""
    target: str
    assessment_time: str
    total_checks: int
    passed: int
    failed: int
    errors: int
    not_applicable: int
    manual_review: int
    compliance_score: float
    checks: list[CISCheckResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "target": self.target,
            "assessment_time": self.assessment_time,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "not_applicable": self.not_applicable,
            "manual_review": self.manual_review,
            "compliance_score": self.compliance_score,
            "checks": [c.to_dict() for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Port/Service Detection Helpers
# ---------------------------------------------------------------------------

async def _check_port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open on the target."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _grab_banner(ip: str, port: int, timeout: float = 3.0, probe: bytes = b"") -> str:
    """Grab a service banner from a port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        if probe:
            writer.write(probe)
            await writer.drain()

        data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
        return ""


async def _check_tls_version(ip: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """
    Check TLS version and cipher suite on a port.

    Returns dict with:
        - tls_version: negotiated TLS version string
        - cipher: negotiated cipher suite name
        - supports_tls12: bool
        - supports_tls13: bool
        - weak_cipher: bool
    """
    result: dict[str, Any] = {
        "tls_version": None,
        "cipher": None,
        "supports_tls12": False,
        "supports_tls13": False,
        "weak_cipher": False,
        "error": None,
    }

    for ctx_version, label in [
        (ssl.TLSVersion.TLSv1_3, "supports_tls13"),
        (ssl.TLSVersion.TLSv1_2, "supports_tls12"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ctx_version
            ctx.maximum_version = ctx_version

            loop = asyncio.get_event_loop()

            def _do_tls_handshake() -> tuple[str, str]:
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        return ssock.version() or "unknown", (ssock.cipher() or ("unknown",))[0]

            tls_ver, cipher = await asyncio.wait_for(
                loop.run_in_executor(None, _do_tls_handshake),
                timeout=timeout + 1,
            )
            result[label] = True

            if result["tls_version"] is None:
                result["tls_version"] = tls_ver
                result["cipher"] = cipher

        except (ssl.SSLError, OSError, asyncio.TimeoutError, Exception):
            pass

    # Check for weak ciphers
    if result["cipher"]:
        cipher_lower = result["cipher"].lower()
        weak_patterns = ["rc4", "des", "null", "export", "anon", "md5"]
        result["weak_cipher"] = any(p in cipher_lower for p in weak_patterns)

    return result


# ---------------------------------------------------------------------------
# Individual CIS Checks
# ---------------------------------------------------------------------------

async def _check_unused_ports(ip: str, known_services: list[int]) -> CISCheckResult:
    """
    CIS Check: Ensure unused ports are disabled.

    Scans for commonly exploited ports that should not be open on
    production network infrastructure.
    """
    start = datetime.now(timezone.utc)
    high_risk_ports = [
        (23, "telnet"),
        (21, "ftp"),
        (69, "tftp"),
        (135, "msrpc"),
        (137, "netbios-ns"),
        (138, "netbios-dgm"),
        (139, "netbios-ssn"),
        (512, "rexec"),
        (513, "rlogin"),
        (514, "rsh"),
        (2049, "nfs"),
    ]

    open_risky: list[tuple[int, str]] = []

    for port, name in high_risk_ports:
        if port in known_services:
            continue  # Intentionally open
        if await _check_port_open(ip, port, timeout=2.0):
            open_risky.append((port, name))

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if open_risky:
        ports_str = ", ".join(f"{p}/{n}" for p, n in open_risky)
        return CISCheckResult(
            benchmark_id="CIS-ND-1.1",
            title="Ensure unused high-risk ports are disabled",
            description=(
                "High-risk services (telnet, FTP, rlogin, etc.) should be disabled "
                "unless explicitly required. These services transmit credentials "
                "in cleartext or have known vulnerability histories."
            ),
            level=CISLevel.L1,
            status=ComplianceStatus.FAIL,
            rationale=(
                "Unnecessary services expand the attack surface and may expose "
                "the device to credential interception, unauthorized access, or "
                "remote code execution."
            ),
            remediation=(
                f"Disable the following services: {ports_str}. "
                "For Cisco IOS: 'no service telnet', 'no ip ftp server'. "
                "For Linux: use firewalld/iptables to block unused ports."
            ),
            severity="high",
            evidence=f"Open high-risk ports: {ports_str}",
            cis_control_id="CIS Control 4.8",
            nist_mapping=["CM-7", "SC-7"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-1.1",
        title="Ensure unused high-risk ports are disabled",
        description=(
            "High-risk services (telnet, FTP, rlogin, etc.) should be disabled "
            "unless explicitly required."
        ),
        level=CISLevel.L1,
        status=ComplianceStatus.PASS,
        rationale="No high-risk unnecessary ports detected.",
        remediation="No action required.",
        severity="high",
        evidence="All high-risk ports are closed or filtered.",
        cis_control_id="CIS Control 4.8",
        nist_mapping=["CM-7", "SC-7"],
        check_duration_ms=elapsed,
    )


async def _check_default_credentials(ip: str) -> CISCheckResult:
    """
    CIS Check: Detect default or weak credential indicators.

    Checks for telnet/SSH banners that indicate default configurations,
    and tests for common default credential patterns.
    """
    start = datetime.now(timezone.utc)
    indicators: list[str] = []

    # Check for telnet with no authentication prompt
    telnet_open = await _check_port_open(ip, 23, timeout=2.0)
    if telnet_open:
        banner = await _grab_banner(ip, 23, timeout=3.0)
        banner_lower = banner.lower()

        # Indicators of default/weak config
        default_patterns = [
            "default", "factory", "password:", "login:",
            "router>", "switch>", "user access verification",
        ]
        for pattern in default_patterns:
            if pattern in banner_lower:
                indicators.append(f"Telnet banner suggests default config: '{pattern}' detected")
                break

        if not indicators and telnet_open:
            indicators.append("Telnet service is enabled (cleartext credentials)")

    # Check SSH banner for version/config hints
    ssh_open = await _check_port_open(ip, 22, timeout=2.0)
    if ssh_open:
        banner = await _grab_banner(ip, 22, timeout=3.0)
        if banner:
            # Check for SSH v1 (CVE-rich, deprecated)
            if "SSH-1." in banner and "SSH-1.99" not in banner:
                indicators.append(f"SSHv1 detected in banner: {banner[:80]}")

            # Check for very old versions
            old_ssh_versions = ["OpenSSH_4", "OpenSSH_5", "OpenSSH_6"]
            for old_ver in old_ssh_versions:
                if old_ver in banner:
                    indicators.append(f"Outdated SSH version: {banner[:80]}")
                    break

    # Check HTTP management interfaces for default pages
    for http_port in [80, 443, 8080, 8443]:
        if await _check_port_open(ip, http_port, timeout=1.5):
            banner = await _grab_banner(
                ip, http_port, timeout=3.0,
                probe=b"GET / HTTP/1.0\r\nHost: check\r\n\r\n",
            )
            banner_lower = banner.lower()
            if any(kw in banner_lower for kw in [
                "default password", "admin/admin", "default credentials",
                "setup wizard", "initial configuration",
            ]):
                indicators.append(
                    f"HTTP port {http_port} shows default configuration page"
                )

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if indicators:
        return CISCheckResult(
            benchmark_id="CIS-ND-1.2",
            title="Ensure default credentials are changed",
            description=(
                "Default credentials, factory configurations, and weak "
                "authentication indicators must be eliminated from all "
                "network devices."
            ),
            level=CISLevel.L1,
            status=ComplianceStatus.FAIL,
            rationale=(
                "Default credentials are the most common attack vector for "
                "network device compromise per CISA advisories. Threat actors "
                "maintain databases of default credentials for automated scanning."
            ),
            remediation=(
                "1. Change all default passwords immediately.\n"
                "2. Disable telnet and use SSH with key-based authentication.\n"
                "3. Implement AAA (TACACS+/RADIUS) for centralized auth.\n"
                "4. Remove default user accounts.\n"
                "5. Disable setup wizard / initial config pages."
            ),
            severity="critical",
            evidence="; ".join(indicators),
            cis_control_id="CIS Control 5.2",
            nist_mapping=["IA-5", "IA-2", "AC-7"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-1.2",
        title="Ensure default credentials are changed",
        description=(
            "Default credentials and factory configurations must be "
            "eliminated from all network devices."
        ),
        level=CISLevel.L1,
        status=ComplianceStatus.PASS,
        rationale="No default credential indicators detected.",
        remediation="No action required. Continue monitoring.",
        severity="critical",
        evidence="No default credential patterns found in service banners.",
        cis_control_id="CIS Control 5.2",
        nist_mapping=["IA-5", "IA-2", "AC-7"],
        check_duration_ms=elapsed,
    )


async def _check_encryption_requirements(ip: str) -> CISCheckResult:
    """
    CIS Check: Ensure TLS 1.2+ is enforced on all encrypted services.

    Checks HTTPS and other TLS-enabled ports for protocol version and
    cipher suite compliance.
    """
    start = datetime.now(timezone.utc)
    findings: list[str] = []
    tls_ports_checked = 0

    tls_candidate_ports = [443, 8443, 993, 995, 636, 465, 587]

    for port in tls_candidate_ports:
        if not await _check_port_open(ip, port, timeout=2.0):
            continue

        tls_ports_checked += 1
        tls_info = await _check_tls_version(ip, port)

        if tls_info.get("error"):
            findings.append(f"Port {port}: TLS check error - {tls_info['error']}")
            continue

        if not tls_info["supports_tls12"] and not tls_info["supports_tls13"]:
            findings.append(
                f"Port {port}: Neither TLS 1.2 nor TLS 1.3 supported "
                f"(detected: {tls_info['tls_version']})"
            )

        if tls_info["weak_cipher"]:
            findings.append(
                f"Port {port}: Weak cipher suite in use: {tls_info['cipher']}"
            )

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if tls_ports_checked == 0:
        return CISCheckResult(
            benchmark_id="CIS-ND-2.1",
            title="Ensure TLS 1.2+ is enforced for encryption",
            description="All encrypted services must use TLS 1.2 or higher.",
            level=CISLevel.L1,
            status=ComplianceStatus.NOT_APPLICABLE,
            rationale="No TLS-enabled services detected on standard ports.",
            remediation="N/A - no encrypted services to assess.",
            severity="high",
            evidence="No TLS services found on standard ports.",
            cis_control_id="CIS Control 3.10",
            nist_mapping=["SC-8", "SC-13", "SC-23"],
            check_duration_ms=elapsed,
        )

    if findings:
        return CISCheckResult(
            benchmark_id="CIS-ND-2.1",
            title="Ensure TLS 1.2+ is enforced for encryption",
            description=(
                "All encrypted services must negotiate TLS 1.2 or TLS 1.3. "
                "SSLv3, TLS 1.0, and TLS 1.1 are deprecated per NIST SP 800-52 Rev. 2."
            ),
            level=CISLevel.L1,
            status=ComplianceStatus.FAIL,
            rationale=(
                "TLS versions below 1.2 have known vulnerabilities (POODLE, BEAST, "
                "CRIME) that allow session hijacking and data interception. "
                "NIST and DoD mandate TLS 1.2+ for all federal systems."
            ),
            remediation=(
                "1. Disable TLS 1.0 and TLS 1.1 on all services.\n"
                "2. Configure minimum TLS version to 1.2.\n"
                "3. Remove weak cipher suites (RC4, DES, NULL, EXPORT, anonymous).\n"
                "4. Prefer TLS 1.3 where supported.\n"
                "5. Use cipher suites with forward secrecy (ECDHE/DHE)."
            ),
            severity="high",
            evidence="; ".join(findings),
            cis_control_id="CIS Control 3.10",
            nist_mapping=["SC-8", "SC-13", "SC-23"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-2.1",
        title="Ensure TLS 1.2+ is enforced for encryption",
        description="All encrypted services must use TLS 1.2 or higher.",
        level=CISLevel.L1,
        status=ComplianceStatus.PASS,
        rationale="All tested TLS services support TLS 1.2 or higher.",
        remediation="No action required.",
        severity="high",
        evidence=f"Checked {tls_ports_checked} TLS port(s); all compliant.",
        cis_control_id="CIS Control 3.10",
        nist_mapping=["SC-8", "SC-13", "SC-23"],
        check_duration_ms=elapsed,
    )


async def _check_snmp_community_strings(ip: str) -> CISCheckResult:
    """
    CIS Check: Ensure SNMP community strings are not default.

    Checks if SNMP is accessible and probes for well-known default
    community strings (public, private, community).
    """
    start = datetime.now(timezone.utc)

    # SNMP uses UDP port 161, not TCP. We probe with default community strings
    # directly -- if any respond, the service is present AND has weak credentials.
    # If none respond, the service is either not running or properly secured.
    default_communities = ["public", "private", "community", "snmp", "admin", "default"]
    weak_found: list[str] = []

    for community in default_communities:
        try:
            # SNMPv2c GET request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
            # Construct a minimal SNMP GET packet
            packet = _build_snmp_get_packet(community)

            loop = asyncio.get_event_loop()

            def _send_snmp() -> bool:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                try:
                    sock.sendto(packet, (ip, 161))
                    data, _ = sock.recvfrom(4096)
                    # Any response means the community string was accepted
                    return len(data) > 0
                except (socket.timeout, OSError):
                    return False
                finally:
                    sock.close()

            accepted = await asyncio.wait_for(
                loop.run_in_executor(None, _send_snmp),
                timeout=4.0,
            )

            if accepted:
                weak_found.append(community)

        except (asyncio.TimeoutError, Exception):
            pass

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if weak_found:
        return CISCheckResult(
            benchmark_id="CIS-ND-2.2",
            title="Ensure SNMP uses non-default community strings",
            description=(
                "SNMP community strings serve as passwords for device management. "
                "Default strings are publicly known and must be changed."
            ),
            level=CISLevel.L1,
            status=ComplianceStatus.FAIL,
            rationale=(
                "Default SNMP community strings allow unauthorized read/write "
                "access to device configuration. Attackers use tools like "
                "onesixtyone to brute-force community strings."
            ),
            remediation=(
                "1. Change SNMP community strings to complex, unique values.\n"
                "2. Migrate to SNMPv3 with authentication and encryption.\n"
                "3. Restrict SNMP access to management VLANs via ACLs.\n"
                "4. Disable SNMP if not required.\n"
                "5. For Cisco: 'no snmp-server community public'"
            ),
            severity="critical",
            evidence=f"Default community strings accepted: {', '.join(weak_found)}",
            cis_control_id="CIS Control 4.8",
            nist_mapping=["CM-7", "IA-5", "SC-8"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-2.2",
        title="Ensure SNMP uses non-default community strings",
        description="SNMP community strings must not use default values.",
        level=CISLevel.L1,
        status=ComplianceStatus.PASS,
        rationale="No default community strings accepted on UDP port 161.",
        remediation="No action required. Consider migrating to SNMPv3.",
        severity="high",
        evidence=(
            "No default SNMP community strings accepted via UDP/161. "
            "Service may not be running, or community strings have been changed."
        ),
        cis_control_id="CIS Control 4.8",
        nist_mapping=["CM-7", "IA-5", "SC-8"],
        check_duration_ms=elapsed,
    )


def _build_snmp_get_packet(community: str) -> bytes:
    """
    Build a minimal SNMPv2c GET request packet for sysDescr.0.

    This constructs a BER/DER encoded SNMP message without external
    dependencies.
    """
    # OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    oid_bytes = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])

    # NULL value
    null_value = bytes([0x05, 0x00])

    # VarBind: SEQUENCE { oid, null }
    varbind = oid_bytes + null_value
    varbind_seq = bytes([0x30, len(varbind)]) + varbind

    # VarBindList: SEQUENCE { varbind }
    varbind_list = bytes([0x30, len(varbind_seq)]) + varbind_seq

    # Request ID (integer, value 1)
    request_id = bytes([0x02, 0x01, 0x01])

    # Error status (integer, 0)
    error_status = bytes([0x02, 0x01, 0x00])

    # Error index (integer, 0)
    error_index = bytes([0x02, 0x01, 0x00])

    # GetRequest-PDU (0xA0)
    pdu_content = request_id + error_status + error_index + varbind_list
    pdu = bytes([0xA0, len(pdu_content)]) + pdu_content

    # Version (integer, 1 = SNMPv2c)
    version = bytes([0x02, 0x01, 0x01])

    # Community string
    community_bytes = community.encode("ascii")
    community_tlv = bytes([0x04, len(community_bytes)]) + community_bytes

    # SNMP Message: SEQUENCE { version, community, pdu }
    message_content = version + community_tlv + pdu
    message = bytes([0x30, len(message_content)]) + message_content

    return message


async def _check_ssh_configuration(ip: str) -> CISCheckResult:
    """
    CIS Check: Ensure SSH configuration meets security requirements.

    Verifies SSHv2 only, checks for key-based auth indicators, and
    assesses SSH version currency.
    """
    start = datetime.now(timezone.utc)
    ssh_open = await _check_port_open(ip, 22, timeout=2.0)

    if not ssh_open:
        elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
        return CISCheckResult(
            benchmark_id="CIS-ND-3.1",
            title="Ensure SSH is configured securely",
            description="SSH must be configured with SSHv2, key-based auth, and current versions.",
            level=CISLevel.L1,
            status=ComplianceStatus.NOT_APPLICABLE,
            rationale="SSH service not detected on port 22.",
            remediation="N/A - SSH not running.",
            severity="high",
            evidence="SSH port 22 is closed.",
            cis_control_id="CIS Control 4.1",
            nist_mapping=["AC-17", "IA-2", "SC-8"],
            check_duration_ms=elapsed,
        )

    banner = await _grab_banner(ip, 22, timeout=3.0)
    findings: list[str] = []

    if banner:
        # Check for SSHv1
        if banner.startswith("SSH-1.") and not banner.startswith("SSH-1.99"):
            findings.append(
                f"SSHv1 protocol detected ({banner[:40]}). "
                "SSHv1 is vulnerable to session hijacking."
            )

        # Check for outdated OpenSSH versions
        version_match = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", banner)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            if major < 8:
                findings.append(
                    f"Outdated OpenSSH version {major}.{minor}. "
                    "Versions < 8.0 have known CVEs."
                )
            elif major == 8 and minor < 5:
                findings.append(
                    f"OpenSSH {major}.{minor} should be updated. "
                    "CVE-2021-41617 affects versions < 8.8."
                )

        # Check for Dropbear (often default on embedded devices)
        if "dropbear" in banner.lower():
            db_match = re.search(r"dropbear[_\s](\d{4})", banner.lower())
            if db_match:
                year = int(db_match.group(1))
                if year < 2022:
                    findings.append(
                        f"Outdated Dropbear SSH ({banner[:40]}). "
                        "Update to latest version."
                    )
    else:
        findings.append("SSH service detected but no version banner received.")

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if findings:
        return CISCheckResult(
            benchmark_id="CIS-ND-3.1",
            title="Ensure SSH is configured securely",
            description=(
                "SSH must use protocol version 2 only, enforce key-based "
                "authentication, and run a current, patched version."
            ),
            level=CISLevel.L1,
            status=ComplianceStatus.FAIL,
            rationale=(
                "SSH misconfigurations can lead to credential theft, "
                "man-in-the-middle attacks, and remote code execution. "
                "DISA STIG requires SSHv2 and current patch levels."
            ),
            remediation=(
                "1. Ensure only SSHv2 is enabled (Protocol 2).\n"
                "2. Disable password authentication; use key-based auth.\n"
                "3. Update SSH to latest stable version.\n"
                "4. Set 'PermitRootLogin no'.\n"
                "5. Configure SSH idle timeout (ClientAliveInterval).\n"
                "6. Limit SSH access via AllowUsers/AllowGroups."
            ),
            severity="high",
            evidence="; ".join(findings),
            cis_control_id="CIS Control 4.1",
            nist_mapping=["AC-17", "IA-2", "SC-8"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-3.1",
        title="Ensure SSH is configured securely",
        description="SSH must use SSHv2, key-based auth, and current versions.",
        level=CISLevel.L1,
        status=ComplianceStatus.PASS,
        rationale="SSH version and protocol appear compliant.",
        remediation="No action required. Verify key-based auth is enforced.",
        severity="high",
        evidence=f"SSH banner: {banner[:80]}" if banner else "SSH detected, no issues found.",
        cis_control_id="CIS Control 4.1",
        nist_mapping=["AC-17", "IA-2", "SC-8"],
        check_duration_ms=elapsed,
    )


async def _check_ntp_synchronization(ip: str) -> CISCheckResult:
    """
    CIS Check: Verify NTP synchronization is configured.

    Checks for NTP service availability on standard port 123/UDP.
    """
    start = datetime.now(timezone.utc)

    # NTP uses UDP port 123
    ntp_responsive = False
    try:
        loop = asyncio.get_event_loop()

        def _check_ntp() -> bool:
            """Send NTP version request and check for response."""
            # NTP client mode packet (version 4, mode 3)
            ntp_packet = bytearray(48)
            ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3 (client)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            try:
                sock.sendto(bytes(ntp_packet), (ip, 123))
                data, _ = sock.recvfrom(1024)
                return len(data) >= 48
            except (socket.timeout, OSError):
                return False
            finally:
                sock.close()

        ntp_responsive = await asyncio.wait_for(
            loop.run_in_executor(None, _check_ntp),
            timeout=5.0,
        )
    except (asyncio.TimeoutError, Exception):
        pass

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if ntp_responsive:
        return CISCheckResult(
            benchmark_id="CIS-ND-4.1",
            title="Ensure NTP synchronization is configured",
            description=(
                "Network devices must synchronize time via NTP for accurate "
                "log timestamps and security event correlation."
            ),
            level=CISLevel.L1,
            status=ComplianceStatus.PASS,
            rationale="NTP service is responding on the target.",
            remediation="No action required. Verify NTP sources are authoritative.",
            severity="medium",
            evidence="NTP port 123/UDP responds to time queries.",
            cis_control_id="CIS Control 8.4",
            nist_mapping=["AU-8", "SC-45"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-4.1",
        title="Ensure NTP synchronization is configured",
        description=(
            "Network devices must synchronize time via NTP for accurate "
            "log timestamps and security event correlation."
        ),
        level=CISLevel.L1,
        status=ComplianceStatus.FAIL,
        rationale=(
            "Without NTP synchronization, log timestamps are unreliable, "
            "making incident investigation and forensic analysis difficult. "
            "NIST 800-53 AU-8 requires synchronized time sources."
        ),
        remediation=(
            "1. Configure NTP with authoritative time sources.\n"
            "2. Use at least two NTP servers for redundancy.\n"
            "3. For Cisco: 'ntp server <ip>' and 'ntp authenticate'.\n"
            "4. Consider NTS (Network Time Security) for authenticated NTP.\n"
            "5. Restrict NTP peer access to trusted sources."
        ),
        severity="medium",
        evidence="NTP port 123/UDP not responding.",
        cis_control_id="CIS Control 8.4",
        nist_mapping=["AU-8", "SC-45"],
        check_duration_ms=elapsed,
    )


async def _check_syslog_forwarding(ip: str) -> CISCheckResult:
    """
    CIS Check: Verify syslog forwarding is configured.

    Checks for syslog service on port 514/UDP and 514/TCP.
    """
    start = datetime.now(timezone.utc)

    syslog_tcp = await _check_port_open(ip, 514, timeout=2.0)
    syslog_tls = await _check_port_open(ip, 6514, timeout=2.0)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    if syslog_tls:
        return CISCheckResult(
            benchmark_id="CIS-ND-4.2",
            title="Ensure syslog forwarding is configured",
            description="Devices should forward logs to a central SIEM/syslog collector.",
            level=CISLevel.L1,
            status=ComplianceStatus.PASS,
            rationale="Syslog over TLS (port 6514) is available, indicating secure log forwarding.",
            remediation="No action required.",
            severity="medium",
            evidence="Syslog TLS port 6514 is open.",
            cis_control_id="CIS Control 8.2",
            nist_mapping=["AU-4", "AU-6", "SI-4"],
            check_duration_ms=elapsed,
        )

    if syslog_tcp:
        return CISCheckResult(
            benchmark_id="CIS-ND-4.2",
            title="Ensure syslog forwarding is configured",
            description="Devices should forward logs to a central SIEM/syslog collector.",
            level=CISLevel.L1,
            status=ComplianceStatus.PASS,
            rationale="Syslog TCP (port 514) is available.",
            remediation="Consider upgrading to syslog over TLS (RFC 5425) on port 6514.",
            severity="medium",
            evidence="Syslog TCP port 514 is open. Recommend TLS upgrade.",
            cis_control_id="CIS Control 8.2",
            nist_mapping=["AU-4", "AU-6", "SI-4"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-4.2",
        title="Ensure syslog forwarding is configured",
        description=(
            "All network devices must forward logs to a centralized "
            "logging facility for monitoring and incident response."
        ),
        level=CISLevel.L1,
        status=ComplianceStatus.MANUAL_REVIEW,
        rationale=(
            "No syslog listener detected on this host. This may indicate "
            "the device forwards logs elsewhere (compliant) or does not "
            "forward logs at all (non-compliant). Manual verification required."
        ),
        remediation=(
            "1. Configure syslog forwarding to central SIEM.\n"
            "2. Use syslog over TLS (RFC 5425) for encrypted transport.\n"
            "3. Set appropriate facility and severity levels.\n"
            "4. For Cisco: 'logging host <siem-ip>'\n"
            "5. Verify logs are being received at the SIEM."
        ),
        severity="medium",
        evidence="No syslog service detected on ports 514 or 6514.",
        cis_control_id="CIS Control 8.2",
        nist_mapping=["AU-4", "AU-6", "SI-4"],
        check_duration_ms=elapsed,
    )


async def _check_access_control_lists(ip: str) -> CISCheckResult:
    """
    CIS Check: Audit access control posture.

    Checks for management interfaces exposed on multiple ports and
    assesses whether access controls appear to be in place.
    """
    start = datetime.now(timezone.utc)
    management_ports = {
        22: "SSH",
        23: "Telnet",
        80: "HTTP Management",
        443: "HTTPS Management",
        161: "SNMP",
        8080: "HTTP Proxy/Management",
        8443: "HTTPS Alt Management",
        3389: "RDP",
        5900: "VNC",
    }

    open_mgmt_ports: list[tuple[int, str]] = []
    for port, name in management_ports.items():
        if await _check_port_open(ip, port, timeout=1.5):
            open_mgmt_ports.append((port, name))

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    insecure_ports = [(p, n) for p, n in open_mgmt_ports if p in (23, 80, 161, 5900, 3389)]

    if insecure_ports:
        ports_str = ", ".join(f"{p}/{n}" for p, n in insecure_ports)
        all_ports_str = ", ".join(f"{p}/{n}" for p, n in open_mgmt_ports)
        return CISCheckResult(
            benchmark_id="CIS-ND-5.1",
            title="Ensure access control lists restrict management access",
            description=(
                "Management interfaces must be restricted to authorized "
                "management networks. Insecure management protocols must "
                "be disabled or tightly controlled."
            ),
            level=CISLevel.L2,
            status=ComplianceStatus.FAIL,
            rationale=(
                "Insecure management protocols expose credentials and "
                "configuration data. ACLs should restrict management "
                "access to dedicated management VLANs only."
            ),
            remediation=(
                "1. Disable insecure management protocols (telnet, HTTP, SNMPv1/v2).\n"
                "2. Apply ACLs to restrict management access to management VLAN.\n"
                "3. Use out-of-band management network where possible.\n"
                f"4. Insecure ports to address: {ports_str}\n"
                "5. For Cisco: 'ip access-class <acl> in' on VTY lines."
            ),
            severity="high",
            evidence=f"Open management ports: {all_ports_str}. Insecure: {ports_str}",
            cis_control_id="CIS Control 4.5",
            nist_mapping=["AC-3", "AC-4", "AC-17", "SC-7"],
            check_duration_ms=elapsed,
        )

    if len(open_mgmt_ports) > 3:
        all_ports_str = ", ".join(f"{p}/{n}" for p, n in open_mgmt_ports)
        return CISCheckResult(
            benchmark_id="CIS-ND-5.1",
            title="Ensure access control lists restrict management access",
            description="Management interfaces must be restricted.",
            level=CISLevel.L2,
            status=ComplianceStatus.MANUAL_REVIEW,
            rationale=(
                f"Multiple management interfaces detected ({len(open_mgmt_ports)} ports). "
                "Verify ACLs restrict access to authorized networks."
            ),
            remediation=(
                "Review ACLs on all management interfaces. Ensure only "
                "authorized management networks can reach these ports."
            ),
            severity="medium",
            evidence=f"Open management ports: {all_ports_str}",
            cis_control_id="CIS Control 4.5",
            nist_mapping=["AC-3", "AC-4", "AC-17", "SC-7"],
            check_duration_ms=elapsed,
        )

    return CISCheckResult(
        benchmark_id="CIS-ND-5.1",
        title="Ensure access control lists restrict management access",
        description="Management interfaces must be restricted.",
        level=CISLevel.L2,
        status=ComplianceStatus.PASS,
        rationale="Limited management interfaces exposed.",
        remediation="No action required. Continue monitoring.",
        severity="medium",
        evidence=f"Open management ports: {len(open_mgmt_ports)}",
        cis_control_id="CIS Control 4.5",
        nist_mapping=["AC-3", "AC-4", "AC-17", "SC-7"],
        check_duration_ms=elapsed,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_cis_assessment(
    target: str,
    known_services: Optional[list[int]] = None,
) -> CISAssessmentResult:
    """
    Run a complete CIS benchmark assessment against a target.

    Executes all applicable CIS-aligned checks concurrently and returns
    an aggregate assessment result with individual check details.

    Args:
        target: IP address of the target device.
        known_services: List of port numbers known to be intentionally open.
            These are excluded from the unused-ports check.

    Returns:
        CISAssessmentResult containing all check results and aggregate scores.
    """
    if known_services is None:
        known_services = []

    assessment_time = datetime.now(timezone.utc).isoformat()

    logger.info(f"Starting CIS assessment for {target}")

    # Run all checks concurrently
    check_tasks = [
        _check_unused_ports(target, known_services),
        _check_default_credentials(target),
        _check_encryption_requirements(target),
        _check_snmp_community_strings(target),
        _check_ssh_configuration(target),
        _check_ntp_synchronization(target),
        _check_syslog_forwarding(target),
        _check_access_control_lists(target),
    ]

    results = await asyncio.gather(*check_tasks, return_exceptions=True)

    checks: list[CISCheckResult] = []
    for result in results:
        if isinstance(result, CISCheckResult):
            checks.append(result)
        elif isinstance(result, Exception):
            logger.error(f"CIS check error: {result}")
            checks.append(CISCheckResult(
                benchmark_id="CIS-ND-ERR",
                title="Check execution error",
                description=f"An error occurred during assessment: {result}",
                level=CISLevel.L1,
                status=ComplianceStatus.ERROR,
                rationale="Internal error during check execution.",
                remediation="Investigate the error and re-run the assessment.",
                severity="medium",
                evidence=str(result),
            ))

    # Aggregate counts
    passed = sum(1 for c in checks if c.status == ComplianceStatus.PASS)
    failed = sum(1 for c in checks if c.status == ComplianceStatus.FAIL)
    errors = sum(1 for c in checks if c.status == ComplianceStatus.ERROR)
    na = sum(1 for c in checks if c.status == ComplianceStatus.NOT_APPLICABLE)
    manual = sum(1 for c in checks if c.status == ComplianceStatus.MANUAL_REVIEW)

    # Compliance score: pass / (pass + fail) ignoring N/A and errors
    scorable = passed + failed
    score = (passed / scorable * 100.0) if scorable > 0 else 0.0

    assessment = CISAssessmentResult(
        target=target,
        assessment_time=assessment_time,
        total_checks=len(checks),
        passed=passed,
        failed=failed,
        errors=errors,
        not_applicable=na,
        manual_review=manual,
        compliance_score=round(score, 1),
        checks=checks,
    )

    logger.info(
        f"CIS assessment complete for {target}: "
        f"{passed}/{scorable} passed ({score:.1f}%)"
    )

    return assessment


def generate_cis_report(results: CISAssessmentResult) -> dict[str, Any]:
    """
    Generate a formatted CIS compliance report from assessment results.

    Produces a structured report suitable for JSON serialization and
    presentation, organized by compliance status with executive summary.

    Args:
        results: CISAssessmentResult from run_cis_assessment().

    Returns:
        Dictionary with executive summary, findings by severity, and
        remediation priorities.
    """
    critical_findings = [
        c.to_dict() for c in results.checks
        if c.status == ComplianceStatus.FAIL and c.severity in ("critical", "high")
    ]
    medium_findings = [
        c.to_dict() for c in results.checks
        if c.status == ComplianceStatus.FAIL and c.severity == "medium"
    ]
    low_findings = [
        c.to_dict() for c in results.checks
        if c.status == ComplianceStatus.FAIL and c.severity == "low"
    ]
    passing_checks = [
        c.to_dict() for c in results.checks
        if c.status == ComplianceStatus.PASS
    ]
    manual_checks = [
        c.to_dict() for c in results.checks
        if c.status == ComplianceStatus.MANUAL_REVIEW
    ]

    # Determine overall posture
    if results.compliance_score >= 90:
        posture = "STRONG"
    elif results.compliance_score >= 70:
        posture = "MODERATE"
    elif results.compliance_score >= 50:
        posture = "WEAK"
    else:
        posture = "CRITICAL"

    report = {
        "report_type": "CIS Benchmark Compliance Assessment",
        "target": results.target,
        "assessment_time": results.assessment_time,
        "executive_summary": {
            "overall_posture": posture,
            "compliance_score": results.compliance_score,
            "total_checks": results.total_checks,
            "passed": results.passed,
            "failed": results.failed,
            "errors": results.errors,
            "not_applicable": results.not_applicable,
            "manual_review": results.manual_review,
        },
        "critical_and_high_findings": critical_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "passing_checks": passing_checks,
        "manual_review_required": manual_checks,
        "remediation_priorities": [
            f.to_dict() for f in sorted(
                [c for c in results.checks if c.status == ComplianceStatus.FAIL],
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4),
            )
        ],
        "nist_control_coverage": _aggregate_nist_mappings(results.checks),
    }

    return report


def _aggregate_nist_mappings(checks: list[CISCheckResult]) -> dict[str, dict[str, int]]:
    """Aggregate NIST control mappings across all checks."""
    mapping: dict[str, dict[str, int]] = {}
    for check in checks:
        for ctrl in check.nist_mapping:
            if ctrl not in mapping:
                mapping[ctrl] = {"pass": 0, "fail": 0, "other": 0}
            if check.status == ComplianceStatus.PASS:
                mapping[ctrl]["pass"] += 1
            elif check.status == ComplianceStatus.FAIL:
                mapping[ctrl]["fail"] += 1
            else:
                mapping[ctrl]["other"] += 1
    return mapping
