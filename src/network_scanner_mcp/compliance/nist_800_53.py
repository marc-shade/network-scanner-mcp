"""
NIST SP 800-53 Rev. 5 Control Mapping Module.

Maps network scanner findings to relevant NIST SP 800-53 security controls
and generates POA&M (Plan of Action & Milestones) documents for compliance
remediation tracking.

Covered control families:
    - AC (Access Control): AC-17 Remote Access
    - CA (Assessment, Authorization, Monitoring): CA-7 Continuous Monitoring
    - CM (Configuration Management): CM-8 System Component Inventory
    - PM (Program Management): PM-5 System Inventory
    - RA (Risk Assessment): RA-5 Vulnerability Monitoring and Scanning
    - SC (System and Communications Protection): SC-7 Boundary Protection
    - SI (System and Information Integrity): SI-4 System Monitoring

References:
    - NIST SP 800-53 Rev. 5 (September 2020)
    - NIST SP 800-53A Rev. 5 (Assessment Procedures)
    - NIST SP 800-37 Rev. 2 (Risk Management Framework)
    - OMB Circular A-130
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("network-scanner")


# ---------------------------------------------------------------------------
# Control Definitions (NIST 800-53 Rev. 5)
# ---------------------------------------------------------------------------

class ControlBaseline(str, Enum):
    """FIPS 199 / NIST 800-53 baselines."""
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class FindingSeverity(str, Enum):
    """POA&M finding severity levels per NIST 800-37."""
    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class NISTControl:
    """NIST 800-53 control definition."""
    control_id: str
    family: str
    title: str
    description: str
    baselines: list[ControlBaseline]
    assessment_objectives: list[str]
    related_controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "baselines": [b.value for b in self.baselines],
            "assessment_objectives": self.assessment_objectives,
            "related_controls": self.related_controls,
        }


# Complete control definitions for scanner-relevant controls
CONTROLS: dict[str, NISTControl] = {
    "AC-17": NISTControl(
        control_id="AC-17",
        family="Access Control",
        title="Remote Access",
        description=(
            "Establish and document usage restrictions, configuration/connection "
            "requirements, and implementation guidance for each type of remote "
            "access allowed. Authorize each type of remote access prior to "
            "allowing such connections."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "AC-17a: Usage restrictions for remote access are established",
            "AC-17b: Configuration requirements for remote access are documented",
            "AC-17c: Connection requirements for remote access are documented",
            "AC-17d: Each type of remote access is authorized",
        ],
        related_controls=["AC-2", "AC-3", "AC-4", "AC-18", "AC-19", "AC-20",
                          "IA-2", "IA-3", "IA-8", "SC-10", "SC-12", "SC-13"],
    ),
    "CA-7": NISTControl(
        control_id="CA-7",
        family="Assessment, Authorization, and Monitoring",
        title="Continuous Monitoring",
        description=(
            "Develop a system-level continuous monitoring strategy and implement "
            "continuous monitoring in accordance with the organization-level "
            "continuous monitoring strategy."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "CA-7a: System-level continuous monitoring strategy is developed",
            "CA-7b: Metrics for continuous monitoring are established",
            "CA-7c: Ongoing security assessments are conducted",
            "CA-7d: Ongoing monitoring of security controls is performed",
            "CA-7e: Status of security controls is reported",
            "CA-7f: Response actions are implemented based on monitoring results",
        ],
        related_controls=["AC-2", "AC-6", "AU-6", "CA-2", "CM-3", "CM-4",
                          "PE-6", "PM-6", "PM-31", "RA-5", "SC-7", "SI-4"],
    ),
    "CM-8": NISTControl(
        control_id="CM-8",
        family="Configuration Management",
        title="System Component Inventory",
        description=(
            "Develop and document an inventory of system components that "
            "accurately reflects the system, includes all components within "
            "the system boundary, is at the level of granularity deemed "
            "necessary for tracking and reporting, and includes information "
            "deemed necessary to achieve effective system component accountability."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "CM-8a: Component inventory is developed and documented",
            "CM-8b: Inventory accurately reflects the system",
            "CM-8c: Inventory includes all components within boundary",
            "CM-8d: Inventory is at appropriate level of granularity",
            "CM-8e: Inventory is reviewed and updated per policy",
        ],
        related_controls=["CM-2", "CM-7", "CM-9", "CM-10", "CM-11", "CM-13",
                          "CP-9", "MA-6", "PM-5", "SA-4", "SA-5", "SI-2"],
    ),
    "PM-5": NISTControl(
        control_id="PM-5",
        family="Program Management",
        title="System Inventory",
        description=(
            "Develop and maintain an inventory of organizational systems."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "PM-5a: Inventory of organizational systems is developed",
            "PM-5b: Inventory is maintained and updated",
        ],
        related_controls=["CM-8", "CM-13", "PL-9", "PM-10"],
    ),
    "RA-5": NISTControl(
        control_id="RA-5",
        family="Risk Assessment",
        title="Vulnerability Monitoring and Scanning",
        description=(
            "Monitor and scan for vulnerabilities in the system and hosted "
            "applications per organization-defined frequency and randomly in "
            "accordance with organization-defined process, and when new "
            "vulnerabilities potentially affecting the system are identified "
            "and reported."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "RA-5a: Vulnerability scans are conducted at defined frequency",
            "RA-5b: Vulnerability scanning tools and techniques are employed",
            "RA-5c: Scan results are analyzed",
            "RA-5d: Legitimate vulnerabilities are remediated within timeframes",
            "RA-5e: Vulnerability information is shared across the organization",
        ],
        related_controls=["CA-2", "CA-7", "CA-8", "CM-4", "CM-6", "CM-8",
                          "RA-2", "RA-3", "SA-11", "SA-15", "SC-38", "SI-2",
                          "SI-3", "SI-4", "SI-7"],
    ),
    "SC-7": NISTControl(
        control_id="SC-7",
        family="System and Communications Protection",
        title="Boundary Protection",
        description=(
            "Monitor and control communications at the external managed "
            "interfaces to the system and at key internal managed interfaces "
            "within the system. Implement subnetworks for publicly accessible "
            "system components that are physically or logically separated "
            "from internal organizational networks."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "SC-7a: Communications at external interfaces are monitored",
            "SC-7b: Communications at external interfaces are controlled",
            "SC-7c: Key internal interfaces are monitored and controlled",
            "SC-7d: Subnetworks for public components are implemented",
            "SC-7e: External connections are limited to managed interfaces",
        ],
        related_controls=["AC-4", "AC-17", "AC-25", "CA-3", "CM-2", "CM-7",
                          "IR-4", "PL-8", "SC-5", "SC-8", "SC-26", "SI-4"],
    ),
    "SI-4": NISTControl(
        control_id="SI-4",
        family="System and Information Integrity",
        title="System Monitoring",
        description=(
            "Monitor the system to detect attacks and indicators of potential "
            "attacks, unauthorized local, network, and remote connections, "
            "and to identify unauthorized use."
        ),
        baselines=[ControlBaseline.LOW, ControlBaseline.MODERATE, ControlBaseline.HIGH],
        assessment_objectives=[
            "SI-4a: System monitoring is performed to detect attacks",
            "SI-4b: Indicators of potential attacks are identified",
            "SI-4c: Unauthorized connections are detected",
            "SI-4d: Unauthorized system use is identified",
            "SI-4e: Monitoring information is protected from unauthorized access",
            "SI-4f: Monitoring activities are heightened when threat indicators exist",
        ],
        related_controls=["AC-2", "AC-3", "AC-4", "AU-6", "AU-12", "CA-7",
                          "CM-3", "IA-10", "IR-4", "SC-7", "SC-26", "SC-31",
                          "SI-3", "SI-7"],
    ),
}


# ---------------------------------------------------------------------------
# Control Mapping Logic
# ---------------------------------------------------------------------------

@dataclass
class ControlMapping:
    """Mapping of a finding to one or more NIST 800-53 controls."""
    finding_id: str
    finding_description: str
    finding_severity: FindingSeverity
    mapped_controls: list[str]
    control_status: str  # "satisfied", "partially_satisfied", "not_satisfied", "not_assessed"
    evidence: str
    gaps: list[str] = field(default_factory=list)
    assessment_date: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_description": self.finding_description,
            "finding_severity": self.finding_severity.value,
            "mapped_controls": self.mapped_controls,
            "control_status": self.control_status,
            "evidence": self.evidence,
            "gaps": self.gaps,
            "assessment_date": self.assessment_date,
        }


def map_findings_to_controls(
    scan_results: dict[str, Any],
) -> dict[str, Any]:
    """
    Map network scanner findings to NIST SP 800-53 Rev. 5 security controls.

    Evaluates scan data against each relevant control's assessment objectives
    and produces a compliance mapping showing satisfied, partially satisfied,
    and unsatisfied controls.

    Args:
        scan_results: Dictionary containing:
            - ``devices`` (list[dict]): Scanned devices
            - ``total_devices`` (int): Total device count
            - ``new_devices`` (list[dict], optional): Newly discovered devices
            - ``topology`` (dict, optional): Network topology data
            - ``cis_results`` (dict, optional): CIS benchmark results
            - ``zero_trust`` (dict, optional): ZTA assessment results

    Returns:
        Dictionary with:
            - ``mappings``: Per-finding control mappings
            - ``control_summary``: Per-control satisfaction status
            - ``compliance_score``: Overall compliance percentage
            - ``baseline_coverage``: Coverage by FIPS 199 baseline level
    """
    assessment_date = datetime.now(timezone.utc).isoformat()
    devices = scan_results.get("devices", [])
    total_devices = scan_results.get("total_devices", len(devices))
    new_devices = scan_results.get("new_devices", [])
    topology = scan_results.get("topology", {})
    cis_results = scan_results.get("cis_results", {})

    mappings: list[ControlMapping] = []

    # --- CA-7: Continuous Monitoring ---
    ca7_mapping = _assess_ca7(devices, total_devices)
    mappings.append(ca7_mapping)

    # --- CM-8: System Component Inventory ---
    cm8_mapping = _assess_cm8(devices, total_devices, new_devices)
    mappings.append(cm8_mapping)

    # --- RA-5: Vulnerability Monitoring and Scanning ---
    ra5_mapping = _assess_ra5(devices, cis_results)
    mappings.append(ra5_mapping)

    # --- SC-7: Boundary Protection ---
    sc7_mapping = _assess_sc7(devices, topology)
    mappings.append(sc7_mapping)

    # --- SI-4: System Monitoring ---
    si4_mapping = _assess_si4(devices, new_devices)
    mappings.append(si4_mapping)

    # --- PM-5: System Inventory ---
    pm5_mapping = _assess_pm5(devices, total_devices)
    mappings.append(pm5_mapping)

    # --- AC-17: Remote Access ---
    ac17_mapping = _assess_ac17(devices)
    mappings.append(ac17_mapping)

    # Set assessment date on all mappings
    for m in mappings:
        m.assessment_date = assessment_date

    # Build control summary
    control_summary = _build_control_summary(mappings)

    # Calculate compliance score
    satisfied = sum(
        1 for m in mappings if m.control_status == "satisfied"
    )
    partial = sum(
        1 for m in mappings if m.control_status == "partially_satisfied"
    )
    total_assessed = len(mappings)
    compliance_score = (
        ((satisfied + partial * 0.5) / total_assessed * 100.0)
        if total_assessed > 0 else 0.0
    )

    # Baseline coverage
    baseline_coverage = _assess_baseline_coverage(mappings)

    result = {
        "assessment_date": assessment_date,
        "total_controls_assessed": total_assessed,
        "satisfied": satisfied,
        "partially_satisfied": partial,
        "not_satisfied": total_assessed - satisfied - partial,
        "compliance_score": round(compliance_score, 1),
        "mappings": [m.to_dict() for m in mappings],
        "control_summary": control_summary,
        "baseline_coverage": baseline_coverage,
        "controls_reference": {
            ctrl_id: ctrl.to_dict()
            for ctrl_id, ctrl in CONTROLS.items()
        },
    }

    logger.info(
        f"NIST 800-53 mapping complete: {satisfied}/{total_assessed} controls satisfied "
        f"({compliance_score:.1f}%)"
    )

    return result


def _assess_ca7(devices: list[dict], total_devices: int) -> ControlMapping:
    """Assess CA-7: Continuous Monitoring."""
    # Network scanning contributes to continuous monitoring but does not
    # fully satisfy CA-7 on its own. CA-7 requires a comprehensive
    # continuous monitoring strategy including metrics, reporting, and
    # response actions across all system components -- not just network scanning.
    evidence_parts = [
        f"Network scanning capability operational covering {total_devices} devices",
        "ARP-based device discovery active",
        "Port scanning and service detection implemented",
    ]

    gaps = [
        "A single network scanner contributes to but does not fully satisfy CA-7. "
        "Full compliance requires: organization-defined monitoring metrics (CA-7a/b), "
        "ongoing security control assessments (CA-7c/d), status reporting to "
        "designated officials (CA-7e), and defined response actions (CA-7f).",
    ]

    if total_devices > 0:
        return ControlMapping(
            finding_id="CA-7-001",
            finding_description=(
                "Network scanning provides partial continuous monitoring coverage. "
                "Additional monitoring capabilities required for full CA-7 satisfaction."
            ),
            finding_severity=FindingSeverity.MODERATE,
            mapped_controls=["CA-7"],
            control_status="partially_satisfied",
            evidence="; ".join(evidence_parts),
            gaps=gaps,
        )

    return ControlMapping(
        finding_id="CA-7-001",
        finding_description="Continuous monitoring capability present but no devices scanned",
        finding_severity=FindingSeverity.HIGH,
        mapped_controls=["CA-7"],
        control_status="not_satisfied",
        evidence="Scanner operational but device discovery incomplete",
        gaps=gaps + ["Expand scan coverage to include all network segments"],
    )


def _assess_cm8(
    devices: list[dict],
    total_devices: int,
    new_devices: list[dict],
) -> ControlMapping:
    """Assess CM-8: System Component Inventory."""
    known_count = sum(1 for d in devices if d.get("is_known") or d.get("is_cluster_node"))
    unknown_count = total_devices - known_count

    evidence = (
        f"Inventory contains {total_devices} devices. "
        f"{known_count} known/classified, {unknown_count} unclassified."
    )

    if len(new_devices) > 0:
        evidence += f" {len(new_devices)} new device(s) detected since last scan."

    gaps: list[str] = []

    if unknown_count > 0:
        gaps.append(
            f"{unknown_count} device(s) not yet classified. "
            "CM-8 requires all components to be inventoried and classified."
        )

    # Determine satisfaction level
    if unknown_count == 0 and total_devices > 0:
        status = "satisfied"
        severity = FindingSeverity.LOW
    elif known_count / max(total_devices, 1) >= 0.7:
        status = "partially_satisfied"
        severity = FindingSeverity.MODERATE
    else:
        status = "not_satisfied"
        severity = FindingSeverity.HIGH
        gaps.append(
            "Majority of devices unclassified. Implement automated "
            "asset classification and tagging."
        )

    return ControlMapping(
        finding_id="CM-8-001",
        finding_description="System component inventory assessment",
        finding_severity=severity,
        mapped_controls=["CM-8"],
        control_status=status,
        evidence=evidence,
        gaps=gaps,
    )


def _assess_ra5(devices: list[dict], cis_results: dict) -> ControlMapping:
    """Assess RA-5: Vulnerability Monitoring and Scanning."""
    evidence_parts = [
        "Network port scanning capability operational",
        "Service detection and banner analysis implemented",
    ]

    gaps: list[str] = []

    # Check if CIS assessment was performed
    if cis_results:
        score = cis_results.get("compliance_score", 0)
        evidence_parts.append(
            f"CIS benchmark assessment completed (score: {score}%)"
        )
        if score < 70:
            gaps.append(
                f"CIS compliance score {score}% below acceptable threshold (70%). "
                "Address failing benchmarks per remediation guidance."
            )
    else:
        gaps.append(
            "CIS benchmark assessment not yet performed. "
            "RA-5 requires structured vulnerability assessment."
        )

    devices_with_ports = sum(
        1 for d in devices
        if d.get("ports") and any(p.get("state") == "open" for p in d["ports"])
    )

    evidence_parts.append(f"Port scan data available for {devices_with_ports} device(s)")

    if cis_results and cis_results.get("compliance_score", 0) >= 70:
        status = "satisfied"
        severity = FindingSeverity.LOW
    elif devices_with_ports > 0:
        status = "partially_satisfied"
        severity = FindingSeverity.MODERATE
    else:
        status = "not_satisfied"
        severity = FindingSeverity.HIGH
        gaps.append("No vulnerability scan data available")

    return ControlMapping(
        finding_id="RA-5-001",
        finding_description="Vulnerability monitoring and scanning assessment",
        finding_severity=severity,
        mapped_controls=["RA-5"],
        control_status=status,
        evidence="; ".join(evidence_parts),
        gaps=gaps,
    )


def _assess_sc7(devices: list[dict], topology: dict) -> ControlMapping:
    """Assess SC-7: Boundary Protection."""
    evidence_parts: list[str] = []
    gaps: list[str] = []

    # Analyze boundary indicators
    subnets: set[str] = set()
    insecure_services = 0
    mgmt_interfaces = 0

    insecure_ports = {23, 21, 69, 135, 139}
    mgmt_ports = {22, 23, 80, 443, 3389, 5900, 8080, 8443}

    for device in devices:
        ip = device.get("ip", "")
        parts = ip.split(".")
        if len(parts) == 4:
            subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

        for p in (device.get("ports") or []):
            if p.get("state") != "open":
                continue
            port = p.get("port", 0)
            if port in insecure_ports:
                insecure_services += 1
            if port in mgmt_ports:
                mgmt_interfaces += 1

    if len(subnets) > 1:
        evidence_parts.append(f"Network segmentation detected: {len(subnets)} subnets")
    elif len(subnets) == 1:
        gaps.append(
            "Flat network topology detected (single subnet). "
            "SC-7 requires subnetworks for publicly accessible components."
        )
        evidence_parts.append("Single subnet detected")

    if insecure_services > 0:
        gaps.append(
            f"{insecure_services} insecure service(s) detected "
            "(telnet, FTP, TFTP, NetBIOS). These weaken boundary protection."
        )

    evidence_parts.append(f"Management interfaces: {mgmt_interfaces}")
    evidence_parts.append(f"Network monitoring: active via this scanner")

    # Determine satisfaction
    if len(subnets) > 1 and insecure_services == 0:
        status = "satisfied"
        severity = FindingSeverity.LOW
    elif insecure_services == 0:
        status = "partially_satisfied"
        severity = FindingSeverity.MODERATE
    else:
        status = "not_satisfied"
        severity = FindingSeverity.HIGH

    return ControlMapping(
        finding_id="SC-7-001",
        finding_description="Boundary protection assessment",
        finding_severity=severity,
        mapped_controls=["SC-7"],
        control_status=status,
        evidence="; ".join(evidence_parts),
        gaps=gaps,
    )


def _assess_si4(devices: list[dict], new_devices: list[dict]) -> ControlMapping:
    """Assess SI-4: System Monitoring."""
    # Network scanning contributes to SI-4 but cannot fully satisfy it alone.
    # SI-4 requires attack detection, indicator identification, unauthorized
    # connection detection, monitoring data protection, and heightened
    # monitoring in response to threat indicators.
    evidence_parts = [
        "Network scanning provides partial system monitoring capability",
        "New device detection operational",
        "Service monitoring via port scanning",
    ]

    if new_devices:
        evidence_parts.append(
            f"New device detection triggered: {len(new_devices)} device(s) identified"
        )

    gaps = [
        "A network scanner alone does not fully satisfy SI-4. Full compliance "
        "requires: real-time attack detection (SI-4a), indicators of potential "
        "attacks identification (SI-4b), unauthorized connection detection "
        "(SI-4c), monitoring information protection (SI-4e), and heightened "
        "monitoring when threat indicators exist (SI-4f). Consider integrating "
        "IDS/IPS, SIEM, and EDR solutions.",
    ]

    return ControlMapping(
        finding_id="SI-4-001",
        finding_description=(
            "Network scanning contributes to system monitoring but does not "
            "fully satisfy SI-4 requirements on its own."
        ),
        finding_severity=FindingSeverity.MODERATE,
        mapped_controls=["SI-4"],
        control_status="partially_satisfied",
        evidence="; ".join(evidence_parts),
        gaps=gaps,
    )


def _assess_pm5(devices: list[dict], total_devices: int) -> ControlMapping:
    """Assess PM-5: System Inventory."""
    if total_devices > 0:
        return ControlMapping(
            finding_id="PM-5-001",
            finding_description="Organizational system inventory",
            finding_severity=FindingSeverity.LOW,
            mapped_controls=["PM-5"],
            control_status="satisfied",
            evidence=f"System inventory maintained with {total_devices} devices tracked",
        )

    return ControlMapping(
        finding_id="PM-5-001",
        finding_description="System inventory incomplete",
        finding_severity=FindingSeverity.HIGH,
        mapped_controls=["PM-5"],
        control_status="not_satisfied",
        evidence="No devices in system inventory",
        gaps=["Conduct initial network discovery scan to populate inventory"],
    )


def _assess_ac17(devices: list[dict]) -> ControlMapping:
    """Assess AC-17: Remote Access."""
    remote_access_services = 0
    insecure_remote = 0
    secure_remote = 0

    for device in devices:
        for p in (device.get("ports") or []):
            if p.get("state") != "open":
                continue
            port = p.get("port", 0)

            if port == 22:
                secure_remote += 1
                remote_access_services += 1
            elif port == 23:
                insecure_remote += 1
                remote_access_services += 1
            elif port == 3389:
                remote_access_services += 1
                # RDP can be either - count as partial
            elif port == 5900:
                insecure_remote += 1
                remote_access_services += 1

    evidence = (
        f"Remote access services: {remote_access_services} total, "
        f"{secure_remote} secure (SSH), {insecure_remote} insecure (telnet/VNC)"
    )

    gaps: list[str] = []
    if insecure_remote > 0:
        gaps.append(
            f"{insecure_remote} insecure remote access service(s) detected. "
            "AC-17 requires secure, authorized remote access methods only."
        )

    if insecure_remote == 0 and remote_access_services > 0:
        status = "satisfied"
        severity = FindingSeverity.LOW
    elif insecure_remote > 0:
        status = "not_satisfied"
        severity = FindingSeverity.HIGH
    else:
        status = "not_assessed"
        severity = FindingSeverity.LOW

    return ControlMapping(
        finding_id="AC-17-001",
        finding_description="Remote access security assessment",
        finding_severity=severity,
        mapped_controls=["AC-17"],
        control_status=status,
        evidence=evidence,
        gaps=gaps,
    )


def _build_control_summary(mappings: list[ControlMapping]) -> dict[str, dict[str, Any]]:
    """Build per-control status summary."""
    summary: dict[str, dict[str, Any]] = {}

    for mapping in mappings:
        for ctrl_id in mapping.mapped_controls:
            if ctrl_id in CONTROLS:
                summary[ctrl_id] = {
                    "control": CONTROLS[ctrl_id].to_dict(),
                    "status": mapping.control_status,
                    "severity": mapping.finding_severity.value,
                    "evidence": mapping.evidence,
                    "gaps": mapping.gaps,
                }

    return summary


def _assess_baseline_coverage(mappings: list[ControlMapping]) -> dict[str, dict[str, int]]:
    """Assess coverage by FIPS 199 baseline level."""
    coverage: dict[str, dict[str, int]] = {
        "LOW": {"total": 0, "satisfied": 0, "partial": 0, "not_satisfied": 0},
        "MODERATE": {"total": 0, "satisfied": 0, "partial": 0, "not_satisfied": 0},
        "HIGH": {"total": 0, "satisfied": 0, "partial": 0, "not_satisfied": 0},
    }

    for mapping in mappings:
        for ctrl_id in mapping.mapped_controls:
            if ctrl_id in CONTROLS:
                for baseline in CONTROLS[ctrl_id].baselines:
                    coverage[baseline.value]["total"] += 1
                    if mapping.control_status == "satisfied":
                        coverage[baseline.value]["satisfied"] += 1
                    elif mapping.control_status == "partially_satisfied":
                        coverage[baseline.value]["partial"] += 1
                    else:
                        coverage[baseline.value]["not_satisfied"] += 1

    return coverage


# ---------------------------------------------------------------------------
# POA&M Generation
# ---------------------------------------------------------------------------

@dataclass
class POAMEntry:
    """Plan of Action & Milestones entry per NIST 800-37."""
    poam_id: str
    weakness_description: str
    control_id: str
    severity: FindingSeverity
    responsible_entity: str
    resources_required: str
    scheduled_completion: str
    milestones: list[dict[str, str]]
    status: str  # "open", "in_progress", "completed", "delayed"
    source: str
    comments: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "poam_id": self.poam_id,
            "weakness_description": self.weakness_description,
            "control_id": self.control_id,
            "severity": self.severity.value,
            "responsible_entity": self.responsible_entity,
            "resources_required": self.resources_required,
            "scheduled_completion": self.scheduled_completion,
            "milestones": self.milestones,
            "status": self.status,
            "source": self.source,
            "comments": self.comments,
        }


def generate_poam(
    findings: dict[str, Any],
    responsible_entity: str = "Information System Security Officer (ISSO)",
) -> dict[str, Any]:
    """
    Generate a POA&M (Plan of Action & Milestones) document from findings.

    Produces POA&M entries per NIST SP 800-37 Rev. 2 for all findings that
    map to unsatisfied or partially satisfied NIST 800-53 controls.

    Each entry includes remediation milestones with completion dates
    calculated from severity-based SLAs:
        - VERY_HIGH / HIGH: 30 days
        - MODERATE: 90 days
        - LOW / VERY_LOW: 180 days

    Args:
        findings: Output from map_findings_to_controls().
        responsible_entity: Name/title of responsible party.

    Returns:
        Dictionary with POA&M entries, summary statistics, and metadata.
    """
    now = datetime.now(timezone.utc)
    mappings = findings.get("mappings", [])
    entries: list[POAMEntry] = []

    # SLA timelines by severity
    sla_days = {
        FindingSeverity.VERY_HIGH: 30,
        FindingSeverity.HIGH: 30,
        FindingSeverity.MODERATE: 90,
        FindingSeverity.LOW: 180,
        FindingSeverity.VERY_LOW: 180,
    }

    poam_counter = 0

    for mapping in mappings:
        status = mapping.get("control_status", "")
        if status == "satisfied":
            continue

        severity_str = mapping.get("finding_severity", "moderate")
        try:
            severity = FindingSeverity(severity_str)
        except ValueError:
            severity = FindingSeverity.MODERATE

        for gap in mapping.get("gaps", []):
            poam_counter += 1
            poam_id = f"POAM-{now.strftime('%Y%m%d')}-{poam_counter:04d}"

            completion_days = sla_days.get(severity, 90)
            completion_date = (now + timedelta(days=completion_days)).strftime("%Y-%m-%d")

            # Generate milestones
            milestones = _generate_milestones(gap, severity, now, completion_days)

            # Estimate resources
            resources = _estimate_resources(severity, gap)

            entry = POAMEntry(
                poam_id=poam_id,
                weakness_description=gap,
                control_id=", ".join(mapping.get("mapped_controls", [])),
                severity=severity,
                responsible_entity=responsible_entity,
                resources_required=resources,
                scheduled_completion=completion_date,
                milestones=milestones,
                status="open",
                source="Network Scanner MCP - Automated Assessment",
                comments=mapping.get("evidence", ""),
            )
            entries.append(entry)

    # If no gaps but some controls are not fully satisfied, create general POAMs
    if not entries:
        for mapping in mappings:
            if mapping.get("control_status") == "partially_satisfied":
                poam_counter += 1
                poam_id = f"POAM-{now.strftime('%Y%m%d')}-{poam_counter:04d}"
                ctrl_ids = ", ".join(mapping.get("mapped_controls", []))

                entry = POAMEntry(
                    poam_id=poam_id,
                    weakness_description=(
                        f"Control {ctrl_ids} partially satisfied. "
                        f"Finding: {mapping.get('finding_description', 'N/A')}"
                    ),
                    control_id=ctrl_ids,
                    severity=FindingSeverity.MODERATE,
                    responsible_entity=responsible_entity,
                    resources_required="Staff time for remediation assessment",
                    scheduled_completion=(now + timedelta(days=90)).strftime("%Y-%m-%d"),
                    milestones=[{
                        "milestone": "Assess current control implementation",
                        "target_date": (now + timedelta(days=30)).strftime("%Y-%m-%d"),
                    }, {
                        "milestone": "Implement remediation actions",
                        "target_date": (now + timedelta(days=60)).strftime("%Y-%m-%d"),
                    }, {
                        "milestone": "Verify control satisfaction",
                        "target_date": (now + timedelta(days=90)).strftime("%Y-%m-%d"),
                    }],
                    status="open",
                    source="Network Scanner MCP - Automated Assessment",
                    comments=mapping.get("evidence", ""),
                )
                entries.append(entry)

    # Sort by severity (highest first)
    severity_order = {
        FindingSeverity.VERY_HIGH: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MODERATE: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.VERY_LOW: 4,
    }
    entries.sort(key=lambda e: severity_order.get(e.severity, 5))

    # Summary
    summary = {
        "total_poam_entries": len(entries),
        "by_severity": {
            sev.value: sum(1 for e in entries if e.severity == sev)
            for sev in FindingSeverity
        },
        "earliest_due_date": min(
            (e.scheduled_completion for e in entries), default="N/A"
        ),
        "latest_due_date": max(
            (e.scheduled_completion for e in entries), default="N/A"
        ),
    }

    result = {
        "poam_document": {
            "title": "Plan of Action & Milestones (POA&M)",
            "system_name": "Network Infrastructure",
            "generated_date": now.isoformat(),
            "generated_by": "Network Scanner MCP - Defense Compliance Module",
            "responsible_entity": responsible_entity,
            "review_frequency": "Monthly",
        },
        "summary": summary,
        "entries": [e.to_dict() for e in entries],
        "compliance_reference": {
            "framework": "NIST SP 800-53 Rev. 5",
            "rmf_step": "Step 6 - Monitor (NIST SP 800-37 Rev. 2)",
            "guidance": "OMB Circular A-130, Appendix III",
        },
    }

    logger.info(f"POA&M generated: {len(entries)} entries")

    return result


def _generate_milestones(
    gap: str,
    severity: FindingSeverity,
    start: datetime,
    total_days: int,
) -> list[dict[str, str]]:
    """Generate remediation milestones for a POA&M entry."""
    milestones = []

    if severity in (FindingSeverity.VERY_HIGH, FindingSeverity.HIGH):
        milestones = [
            {
                "milestone": "Immediate risk mitigation / compensating controls",
                "target_date": (start + timedelta(days=7)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Remediation plan approved",
                "target_date": (start + timedelta(days=14)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Remediation implemented",
                "target_date": (start + timedelta(days=21)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Verification and closure",
                "target_date": (start + timedelta(days=total_days)).strftime("%Y-%m-%d"),
            },
        ]
    elif severity == FindingSeverity.MODERATE:
        milestones = [
            {
                "milestone": "Assessment and planning",
                "target_date": (start + timedelta(days=30)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Implementation",
                "target_date": (start + timedelta(days=60)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Verification and closure",
                "target_date": (start + timedelta(days=total_days)).strftime("%Y-%m-%d"),
            },
        ]
    else:
        milestones = [
            {
                "milestone": "Planning and scheduling",
                "target_date": (start + timedelta(days=60)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Implementation",
                "target_date": (start + timedelta(days=120)).strftime("%Y-%m-%d"),
            },
            {
                "milestone": "Verification and closure",
                "target_date": (start + timedelta(days=total_days)).strftime("%Y-%m-%d"),
            },
        ]

    return milestones


def _estimate_resources(severity: FindingSeverity, gap: str) -> str:
    """Estimate resources required for remediation."""
    gap_lower = gap.lower()

    if "network segment" in gap_lower or "micro-segment" in gap_lower:
        return "Network engineering team, firewall/switch configuration changes, testing window"
    if "encrypt" in gap_lower or "tls" in gap_lower:
        return "Security engineering, certificate management, service restart windows"
    if "credential" in gap_lower or "password" in gap_lower:
        return "Identity management team, credential rotation, user communication"
    if "inventory" in gap_lower or "classify" in gap_lower:
        return "Asset management team, CMDB updates, automated discovery tools"
    if "patch" in gap_lower or "update" in gap_lower:
        return "System administration, patch management tools, maintenance windows"
    if "scan" in gap_lower or "assessment" in gap_lower:
        return "Security assessment team, scanning tools, analysis time"

    if severity in (FindingSeverity.VERY_HIGH, FindingSeverity.HIGH):
        return "Dedicated security engineering resources, expedited change management"

    return "Staff time for assessment and remediation"
