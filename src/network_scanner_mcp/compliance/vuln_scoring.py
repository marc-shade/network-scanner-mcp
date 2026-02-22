"""
Multi-Framework Vulnerability Scoring Module.

Provides defense-grade vulnerability scoring beyond basic CVSS:
    - CVSS v3.1 base, temporal, and environmental score computation
    - SSVC (Stakeholder-Specific Vulnerability Categorization) per CISA
    - KEV (Known Exploited Vulnerabilities) cross-reference
    - Mission impact assessment for defense environments

References:
    - CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
    - CISA SSVC: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
    - CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    - NIST NVD: https://nvd.nist.gov/
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("network-scanner")


# ===========================================================================
# CVSS v3.1 Implementation
# ===========================================================================

class AttackVector(str, Enum):
    """CVSS v3.1 Attack Vector (AV)."""
    NETWORK = "NETWORK"         # AV:N = 0.85
    ADJACENT = "ADJACENT"       # AV:A = 0.62
    LOCAL = "LOCAL"             # AV:L = 0.55
    PHYSICAL = "PHYSICAL"       # AV:P = 0.20


class AttackComplexity(str, Enum):
    """CVSS v3.1 Attack Complexity (AC)."""
    LOW = "LOW"       # AC:L = 0.77
    HIGH = "HIGH"     # AC:H = 0.44


class PrivilegesRequired(str, Enum):
    """CVSS v3.1 Privileges Required (PR)."""
    NONE = "NONE"     # PR:N = 0.85 (scope unchanged) / 0.68 (scope changed)
    LOW = "LOW"       # PR:L = 0.62 (SU) / 0.68 (SC)
    HIGH = "HIGH"     # PR:H = 0.27 (SU) / 0.50 (SC)


class UserInteraction(str, Enum):
    """CVSS v3.1 User Interaction (UI)."""
    NONE = "NONE"         # UI:N = 0.85
    REQUIRED = "REQUIRED"  # UI:R = 0.62


class Scope(str, Enum):
    """CVSS v3.1 Scope (S)."""
    UNCHANGED = "UNCHANGED"  # S:U
    CHANGED = "CHANGED"      # S:C


class Impact(str, Enum):
    """CVSS v3.1 CIA Impact values."""
    NONE = "NONE"     # 0.00
    LOW = "LOW"       # 0.22
    HIGH = "HIGH"     # 0.56


class ExploitCodeMaturity(str, Enum):
    """CVSS v3.1 Temporal - Exploit Code Maturity (E)."""
    NOT_DEFINED = "NOT_DEFINED"   # X = 1.00
    UNPROVEN = "UNPROVEN"         # U = 0.91
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"  # P = 0.94
    FUNCTIONAL = "FUNCTIONAL"     # F = 0.97
    HIGH = "HIGH"                 # H = 1.00


class RemediationLevel(str, Enum):
    """CVSS v3.1 Temporal - Remediation Level (RL)."""
    NOT_DEFINED = "NOT_DEFINED"     # X = 1.00
    OFFICIAL_FIX = "OFFICIAL_FIX"   # O = 0.95
    TEMPORARY_FIX = "TEMPORARY_FIX"  # T = 0.96
    WORKAROUND = "WORKAROUND"       # W = 0.97
    UNAVAILABLE = "UNAVAILABLE"     # U = 1.00


class ReportConfidence(str, Enum):
    """CVSS v3.1 Temporal - Report Confidence (RC)."""
    NOT_DEFINED = "NOT_DEFINED"   # X = 1.00
    UNKNOWN = "UNKNOWN"           # U = 0.92
    REASONABLE = "REASONABLE"     # R = 0.96
    CONFIRMED = "CONFIRMED"       # C = 1.00


# CVSS v3.1 metric value mappings (per specification Table 15-19)
_AV_VALUES = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.20,
}

_AC_VALUES = {
    AttackComplexity.LOW: 0.77,
    AttackComplexity.HIGH: 0.44,
}

# PR values depend on Scope
_PR_VALUES_UNCHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}

_PR_VALUES_CHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.50,
}

_UI_VALUES = {
    UserInteraction.NONE: 0.85,
    UserInteraction.REQUIRED: 0.62,
}

_IMPACT_VALUES = {
    Impact.NONE: 0.00,
    Impact.LOW: 0.22,
    Impact.HIGH: 0.56,
}

_ECM_VALUES = {
    ExploitCodeMaturity.NOT_DEFINED: 1.00,
    ExploitCodeMaturity.UNPROVEN: 0.91,
    ExploitCodeMaturity.PROOF_OF_CONCEPT: 0.94,
    ExploitCodeMaturity.FUNCTIONAL: 0.97,
    ExploitCodeMaturity.HIGH: 1.00,
}

_RL_VALUES = {
    RemediationLevel.NOT_DEFINED: 1.00,
    RemediationLevel.OFFICIAL_FIX: 0.95,
    RemediationLevel.TEMPORARY_FIX: 0.96,
    RemediationLevel.WORKAROUND: 0.97,
    RemediationLevel.UNAVAILABLE: 1.00,
}

_RC_VALUES = {
    ReportConfidence.NOT_DEFINED: 1.00,
    ReportConfidence.UNKNOWN: 0.92,
    ReportConfidence.REASONABLE: 0.96,
    ReportConfidence.CONFIRMED: 1.00,
}


@dataclass
class CVSSv31Vector:
    """CVSS v3.1 vector components."""
    # Base metrics (required)
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    # Temporal metrics (optional)
    exploit_code_maturity: ExploitCodeMaturity = ExploitCodeMaturity.NOT_DEFINED
    remediation_level: RemediationLevel = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence = ReportConfidence.NOT_DEFINED

    # Environmental metrics (optional) - modify CIA impact requirements
    conf_requirement: Impact = Impact.HIGH  # Default HIGH for defense
    integ_requirement: Impact = Impact.HIGH
    avail_requirement: Impact = Impact.HIGH

    def to_vector_string(self) -> str:
        """Generate CVSS v3.1 vector string."""
        av_map = {
            AttackVector.NETWORK: "N", AttackVector.ADJACENT: "A",
            AttackVector.LOCAL: "L", AttackVector.PHYSICAL: "P",
        }
        ac_map = {AttackComplexity.LOW: "L", AttackComplexity.HIGH: "H"}
        pr_map = {
            PrivilegesRequired.NONE: "N", PrivilegesRequired.LOW: "L",
            PrivilegesRequired.HIGH: "H",
        }
        ui_map = {UserInteraction.NONE: "N", UserInteraction.REQUIRED: "R"}
        s_map = {Scope.UNCHANGED: "U", Scope.CHANGED: "C"}
        i_map = {Impact.NONE: "N", Impact.LOW: "L", Impact.HIGH: "H"}

        parts = [
            "CVSS:3.1",
            f"AV:{av_map[self.attack_vector]}",
            f"AC:{ac_map[self.attack_complexity]}",
            f"PR:{pr_map[self.privileges_required]}",
            f"UI:{ui_map[self.user_interaction]}",
            f"S:{s_map[self.scope]}",
            f"C:{i_map[self.confidentiality]}",
            f"I:{i_map[self.integrity]}",
            f"A:{i_map[self.availability]}",
        ]
        return "/".join(parts)


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup function: smallest number >= input with 1 decimal."""
    return math.ceil(value * 10) / 10


def compute_cvss_base_score(vector: CVSSv31Vector) -> float:
    """
    Compute CVSS v3.1 Base Score per specification Section 7.4.

    Formula follows FIRST CVSS v3.1 calculator equations exactly.
    """
    # Exploitability sub-score
    av = _AV_VALUES[vector.attack_vector]
    ac = _AC_VALUES[vector.attack_complexity]

    if vector.scope == Scope.CHANGED:
        pr = _PR_VALUES_CHANGED[vector.privileges_required]
    else:
        pr = _PR_VALUES_UNCHANGED[vector.privileges_required]

    ui = _UI_VALUES[vector.user_interaction]

    exploitability = 8.22 * av * ac * pr * ui

    # Impact sub-score
    isc_conf = 1 - _IMPACT_VALUES[vector.confidentiality]
    isc_integ = 1 - _IMPACT_VALUES[vector.integrity]
    isc_avail = 1 - _IMPACT_VALUES[vector.availability]

    isc_base = 1 - (isc_conf * isc_integ * isc_avail)

    if vector.scope == Scope.UNCHANGED:
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    # Base score
    if impact <= 0:
        return 0.0

    if vector.scope == Scope.UNCHANGED:
        base = _roundup(min(impact + exploitability, 10))
    else:
        base = _roundup(min(1.08 * (impact + exploitability), 10))

    return base


def compute_cvss_temporal_score(vector: CVSSv31Vector) -> float:
    """Compute CVSS v3.1 Temporal Score."""
    base = compute_cvss_base_score(vector)

    e = _ECM_VALUES[vector.exploit_code_maturity]
    rl = _RL_VALUES[vector.remediation_level]
    rc = _RC_VALUES[vector.report_confidence]

    return _roundup(base * e * rl * rc)


def compute_cvss_environmental_score(vector: CVSSv31Vector) -> float:
    """
    Compute CVSS v3.1 Environmental Score.

    Uses Modified Impact sub-score with CIA requirements weighting.
    For defense contexts, default requirements are HIGH across all three.
    """
    # Modified Impact
    cr = _IMPACT_VALUES.get(vector.conf_requirement, 0.56)
    ir = _IMPACT_VALUES.get(vector.integ_requirement, 0.56)
    ar = _IMPACT_VALUES.get(vector.avail_requirement, 0.56)

    # Normalize requirements (0.5 for LOW, 1.0 for MEDIUM, 1.5 for HIGH)
    req_map = {Impact.NONE: 0.5, Impact.LOW: 0.5, Impact.HIGH: 1.5}
    mcr = req_map.get(vector.conf_requirement, 1.0)
    mir = req_map.get(vector.integ_requirement, 1.0)
    mar = req_map.get(vector.avail_requirement, 1.0)

    isc_conf = 1 - _IMPACT_VALUES[vector.confidentiality]
    isc_integ = 1 - _IMPACT_VALUES[vector.integrity]
    isc_avail = 1 - _IMPACT_VALUES[vector.availability]

    # Modified ISC with requirements
    miss = min(
        1 - (1 - isc_conf * mcr) * (1 - isc_integ * mir) * (1 - isc_avail * mar),
        0.915
    )

    if vector.scope == Scope.UNCHANGED:
        modified_impact = 6.42 * miss
    else:
        modified_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13

    if modified_impact <= 0:
        return 0.0

    # Exploitability
    av = _AV_VALUES[vector.attack_vector]
    ac = _AC_VALUES[vector.attack_complexity]
    if vector.scope == Scope.CHANGED:
        pr_val = _PR_VALUES_CHANGED[vector.privileges_required]
    else:
        pr_val = _PR_VALUES_UNCHANGED[vector.privileges_required]
    ui_val = _UI_VALUES[vector.user_interaction]

    exploitability = 8.22 * av * ac * pr_val * ui_val

    if vector.scope == Scope.UNCHANGED:
        env_score = _roundup(
            _roundup(min(modified_impact + exploitability, 10))
            * _ECM_VALUES[vector.exploit_code_maturity]
            * _RL_VALUES[vector.remediation_level]
            * _RC_VALUES[vector.report_confidence]
        )
    else:
        env_score = _roundup(
            _roundup(min(1.08 * (modified_impact + exploitability), 10))
            * _ECM_VALUES[vector.exploit_code_maturity]
            * _RL_VALUES[vector.remediation_level]
            * _RC_VALUES[vector.report_confidence]
        )

    return min(env_score, 10.0)


def _cvss_severity_rating(score: float) -> str:
    """Map CVSS score to qualitative severity rating per v3.1 spec."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    return "Critical"


# ===========================================================================
# SSVC (Stakeholder-Specific Vulnerability Categorization)
# ===========================================================================

class SSVCExploitation(str, Enum):
    """SSVC Exploitation status per CISA methodology."""
    NONE = "none"
    POC = "poc"           # Proof of concept available
    ACTIVE = "active"     # Active exploitation observed


class SSVCAutomatability(str, Enum):
    """SSVC Automatability - can exploitation be automated?"""
    NO = "no"
    YES = "yes"


class SSVCTechnicalImpact(str, Enum):
    """SSVC Technical Impact."""
    PARTIAL = "partial"
    TOTAL = "total"


class SSVCMissionPrevalence(str, Enum):
    """SSVC Mission Prevalence - how common is affected tech in mission."""
    MINIMAL = "minimal"
    SUPPORT = "support"
    ESSENTIAL = "essential"


class SSVCPublicWellBeing(str, Enum):
    """SSVC Public Well-Being Impact (for government/defense)."""
    MINIMAL = "minimal"
    MATERIAL = "material"
    IRREVERSIBLE = "irreversible"


class SSVCDecision(str, Enum):
    """SSVC Decision outcome per CISA decision tree."""
    TRACK = "Track"              # Monitor, lowest urgency
    TRACK_STAR = "Track*"        # Monitor closely
    ATTEND = "Attend"            # Prioritize attention
    ACT = "Act"                  # Immediate action required


@dataclass
class SSVCAssessment:
    """SSVC assessment result."""
    exploitation: SSVCExploitation
    automatability: SSVCAutomatability
    technical_impact: SSVCTechnicalImpact
    mission_prevalence: SSVCMissionPrevalence
    public_wellbeing: SSVCPublicWellBeing
    decision: SSVCDecision

    def to_dict(self) -> dict[str, str]:
        return {
            "exploitation": self.exploitation.value,
            "automatability": self.automatability.value,
            "technical_impact": self.technical_impact.value,
            "mission_prevalence": self.mission_prevalence.value,
            "public_wellbeing": self.public_wellbeing.value,
            "decision": self.decision.value,
        }


def compute_ssvc_decision(
    exploitation: SSVCExploitation,
    automatability: SSVCAutomatability,
    technical_impact: SSVCTechnicalImpact,
    mission_prevalence: SSVCMissionPrevalence,
    public_wellbeing: SSVCPublicWellBeing = SSVCPublicWellBeing.MATERIAL,
) -> SSVCAssessment:
    """
    Compute SSVC decision using CISA's decision tree for government stakeholders.

    The decision tree follows CISA's published SSVC methodology which considers
    exploitation status, automatability, technical impact, mission prevalence,
    and public well-being impact.

    Args:
        exploitation: Current exploitation status
        automatability: Whether exploitation can be automated
        technical_impact: Technical impact level
        mission_prevalence: How critical the affected technology is to mission
        public_wellbeing: Impact on public safety/welfare

    Returns:
        SSVCAssessment with decision outcome.
    """
    # CISA SSVC Decision Tree for Government Stakeholders
    # Active exploitation -> almost always ACT
    if exploitation == SSVCExploitation.ACTIVE:
        if technical_impact == SSVCTechnicalImpact.TOTAL:
            decision = SSVCDecision.ACT
        elif mission_prevalence == SSVCMissionPrevalence.ESSENTIAL:
            decision = SSVCDecision.ACT
        elif public_wellbeing == SSVCPublicWellBeing.IRREVERSIBLE:
            decision = SSVCDecision.ACT
        else:
            decision = SSVCDecision.ATTEND

    # POC exploit available
    elif exploitation == SSVCExploitation.POC:
        if automatability == SSVCAutomatability.YES:
            if technical_impact == SSVCTechnicalImpact.TOTAL:
                if mission_prevalence == SSVCMissionPrevalence.ESSENTIAL:
                    decision = SSVCDecision.ACT
                else:
                    decision = SSVCDecision.ATTEND
            else:
                if mission_prevalence == SSVCMissionPrevalence.ESSENTIAL:
                    decision = SSVCDecision.ATTEND
                else:
                    decision = SSVCDecision.TRACK_STAR
        else:
            if technical_impact == SSVCTechnicalImpact.TOTAL:
                decision = SSVCDecision.ATTEND
            elif mission_prevalence == SSVCMissionPrevalence.ESSENTIAL:
                decision = SSVCDecision.ATTEND
            else:
                decision = SSVCDecision.TRACK_STAR

    # No known exploitation
    else:
        if automatability == SSVCAutomatability.YES:
            if technical_impact == SSVCTechnicalImpact.TOTAL:
                decision = SSVCDecision.ATTEND
            elif mission_prevalence == SSVCMissionPrevalence.ESSENTIAL:
                decision = SSVCDecision.TRACK_STAR
            else:
                decision = SSVCDecision.TRACK
        else:
            if technical_impact == SSVCTechnicalImpact.TOTAL:
                if mission_prevalence == SSVCMissionPrevalence.ESSENTIAL:
                    decision = SSVCDecision.TRACK_STAR
                else:
                    decision = SSVCDecision.TRACK
            else:
                decision = SSVCDecision.TRACK

    # Public well-being escalation
    if public_wellbeing == SSVCPublicWellBeing.IRREVERSIBLE and decision != SSVCDecision.ACT:
        # Escalate by one level
        escalation = {
            SSVCDecision.TRACK: SSVCDecision.TRACK_STAR,
            SSVCDecision.TRACK_STAR: SSVCDecision.ATTEND,
            SSVCDecision.ATTEND: SSVCDecision.ACT,
        }
        decision = escalation.get(decision, decision)

    return SSVCAssessment(
        exploitation=exploitation,
        automatability=automatability,
        technical_impact=technical_impact,
        mission_prevalence=mission_prevalence,
        public_wellbeing=public_wellbeing,
        decision=decision,
    )


# ===========================================================================
# KEV (Known Exploited Vulnerabilities) Cross-Reference
# ===========================================================================

# Static KEV entries for common network service vulnerabilities.
# In production, this would be populated from the CISA KEV catalog
# (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
# via periodic synchronization.

_KEV_DATABASE: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "name": "Apache Log4j Remote Code Execution",
        "vendor": "Apache",
        "product": "Log4j",
        "date_added": "2021-12-10",
        "due_date": "2021-12-24",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["http", "https", "elasticsearch"],
    },
    "CVE-2023-27997": {
        "name": "Fortinet FortiOS Heap-Based Buffer Overflow",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "date_added": "2023-06-13",
        "due_date": "2023-07-04",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["https"],
    },
    "CVE-2024-3400": {
        "name": "Palo Alto Networks PAN-OS Command Injection",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "date_added": "2024-04-12",
        "due_date": "2024-04-19",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": False,
        "services": ["https"],
    },
    "CVE-2021-26855": {
        "name": "Microsoft Exchange Server-Side Request Forgery (ProxyLogon)",
        "vendor": "Microsoft",
        "product": "Exchange",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["https", "smtp"],
    },
    "CVE-2020-1472": {
        "name": "Microsoft Netlogon Privilege Escalation (Zerologon)",
        "vendor": "Microsoft",
        "product": "Windows Server",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["ldap", "smb"],
    },
    "CVE-2023-22515": {
        "name": "Atlassian Confluence Broken Access Control",
        "vendor": "Atlassian",
        "product": "Confluence",
        "date_added": "2023-10-05",
        "due_date": "2023-10-26",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": False,
        "services": ["http", "https"],
    },
    "CVE-2023-46805": {
        "name": "Ivanti Connect Secure Authentication Bypass",
        "vendor": "Ivanti",
        "product": "Connect Secure",
        "date_added": "2024-01-10",
        "due_date": "2024-01-31",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": False,
        "services": ["https"],
    },
    "CVE-2021-22205": {
        "name": "GitLab Remote Code Execution",
        "vendor": "GitLab",
        "product": "GitLab CE/EE",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["http", "https"],
    },
    "CVE-2019-0708": {
        "name": "Microsoft Remote Desktop Services RCE (BlueKeep)",
        "vendor": "Microsoft",
        "product": "Windows",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["rdp"],
    },
    "CVE-2022-47966": {
        "name": "Zoho ManageEngine RCE",
        "vendor": "Zoho",
        "product": "ManageEngine",
        "date_added": "2023-01-23",
        "due_date": "2023-02-13",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware": True,
        "services": ["http", "https"],
    },
}


def check_kev_exposure(
    services: list[str],
    vendor: str = "",
    banners: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """
    Cross-reference detected services against CISA KEV catalog.

    Checks if any detected services or vendor products match entries
    in the Known Exploited Vulnerabilities catalog.

    Args:
        services: List of detected service names
        vendor: Device vendor string
        banners: Optional list of service banner strings

    Returns:
        List of matching KEV entries with relevance context.
    """
    matches: list[dict[str, Any]] = []
    services_lower = {s.lower() for s in services}
    vendor_lower = vendor.lower()
    banner_text = " ".join((banners or [])).lower()

    for cve_id, kev_entry in _KEV_DATABASE.items():
        kev_services = set(kev_entry.get("services", []))
        product_lower = kev_entry.get("product", "").lower()
        vendor_entry = kev_entry.get("vendor", "").lower()

        # Check service overlap
        service_match = bool(services_lower & kev_services)

        # Check vendor match
        vendor_match = (
            vendor_entry in vendor_lower or
            vendor_lower in vendor_entry
        ) if vendor_lower and vendor_entry else False

        # Check banner for product indicators
        banner_match = product_lower in banner_text if product_lower and banner_text else False

        if service_match or vendor_match or banner_match:
            match_reasons = []
            if service_match:
                match_reasons.append(
                    f"Service overlap: {services_lower & kev_services}"
                )
            if vendor_match:
                match_reasons.append(f"Vendor match: {vendor_entry}")
            if banner_match:
                match_reasons.append(f"Product detected in banner: {product_lower}")

            matches.append({
                "cve_id": cve_id,
                "name": kev_entry["name"],
                "vendor": kev_entry["vendor"],
                "product": kev_entry["product"],
                "date_added_to_kev": kev_entry["date_added"],
                "remediation_due_date": kev_entry["due_date"],
                "required_action": kev_entry["required_action"],
                "known_ransomware_use": kev_entry.get("known_ransomware", False),
                "match_reasons": match_reasons,
                "confidence": (
                    "high" if (vendor_match and service_match)
                    else "medium" if vendor_match or banner_match
                    else "low"
                ),
            })

    return matches


# ===========================================================================
# Mission Impact Assessment
# ===========================================================================

class MissionImpactLevel(str, Enum):
    """Mission impact levels for defense environments."""
    NEGLIGIBLE = "negligible"
    MINOR = "minor"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    CATASTROPHIC = "catastrophic"


def assess_mission_impact(
    services_affected: list[str],
    is_cluster_node: bool = False,
    is_infrastructure: bool = False,
    classification: str = "INTERNAL",
) -> dict[str, Any]:
    """
    Assess mission impact of a vulnerability affecting specific services.

    Considers the role of affected services in mission capability,
    asset classification, and infrastructure criticality.

    Args:
        services_affected: Services impacted by the vulnerability
        is_cluster_node: Whether the asset is a cluster node
        is_infrastructure: Whether the asset provides infrastructure services
        classification: Asset security classification

    Returns:
        Mission impact assessment with justification.
    """
    impact_level = MissionImpactLevel.MINOR
    factors: list[str] = []

    # Classification escalation
    class_impact = {
        "RESTRICTED": MissionImpactLevel.SIGNIFICANT,
        "CONFIDENTIAL": MissionImpactLevel.MODERATE,
        "INTERNAL": MissionImpactLevel.MINOR,
        "PUBLIC": MissionImpactLevel.NEGLIGIBLE,
    }
    base_level = class_impact.get(classification, MissionImpactLevel.MINOR)
    impact_level = base_level
    factors.append(f"Asset classification: {classification}")

    # Infrastructure services escalation
    infra_services = {"dns", "dhcp", "ldap", "ldaps", "ntp"}
    affected_infra = [s for s in services_affected if s.lower() in infra_services]
    if affected_infra:
        impact_level = MissionImpactLevel.SIGNIFICANT
        factors.append(f"Infrastructure services affected: {', '.join(affected_infra)}")

    # Cluster node escalation
    if is_cluster_node:
        if impact_level.value in ("negligible", "minor"):
            impact_level = MissionImpactLevel.MODERATE
        factors.append("Asset is a managed cluster node")

    # Database services escalation
    db_services = {"mysql", "postgresql", "mongodb", "redis", "elasticsearch", "mssql"}
    affected_db = [s for s in services_affected if s.lower() in db_services]
    if affected_db:
        if impact_level.value in ("negligible", "minor"):
            impact_level = MissionImpactLevel.MODERATE
        factors.append(f"Database services affected: {', '.join(affected_db)}")

    impact_map = {
        MissionImpactLevel.NEGLIGIBLE: 1,
        MissionImpactLevel.MINOR: 3,
        MissionImpactLevel.MODERATE: 5,
        MissionImpactLevel.SIGNIFICANT: 8,
        MissionImpactLevel.CATASTROPHIC: 10,
    }

    return {
        "impact_level": impact_level.value,
        "impact_score": impact_map.get(impact_level, 5),
        "factors": factors,
        "services_affected": services_affected,
        "requires_immediate_action": impact_level in (
            MissionImpactLevel.SIGNIFICANT,
            MissionImpactLevel.CATASTROPHIC,
        ),
        "notification_required": impact_level != MissionImpactLevel.NEGLIGIBLE,
    }


# ===========================================================================
# Public API
# ===========================================================================

@dataclass
class VulnerabilityScore:
    """Multi-framework vulnerability score."""
    cvss_base: float
    cvss_temporal: float
    cvss_environmental: float
    cvss_vector: str
    cvss_severity: str
    ssvc: dict[str, str]
    kev_matches: list[dict[str, Any]]
    mission_impact: dict[str, Any]
    composite_priority: str  # "critical", "high", "medium", "low"
    composite_score: float   # 0.0 - 10.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cvss": {
                "base_score": self.cvss_base,
                "temporal_score": self.cvss_temporal,
                "environmental_score": self.cvss_environmental,
                "vector_string": self.cvss_vector,
                "severity": self.cvss_severity,
            },
            "ssvc": self.ssvc,
            "kev_matches": self.kev_matches,
            "mission_impact": self.mission_impact,
            "composite_priority": self.composite_priority,
            "composite_score": self.composite_score,
        }


def score_vulnerability(
    vuln: dict[str, Any],
    context: dict[str, Any],
) -> VulnerabilityScore:
    """
    Perform multi-framework vulnerability scoring.

    Combines CVSS v3.1 (base, temporal, environmental), SSVC decision,
    KEV cross-reference, and mission impact assessment into a composite
    defense-grade vulnerability score.

    Args:
        vuln: Vulnerability descriptor with:
            - ``attack_vector`` (str): NETWORK/ADJACENT/LOCAL/PHYSICAL
            - ``attack_complexity`` (str): LOW/HIGH
            - ``privileges_required`` (str): NONE/LOW/HIGH
            - ``user_interaction`` (str): NONE/REQUIRED
            - ``scope`` (str): UNCHANGED/CHANGED
            - ``confidentiality`` (str): NONE/LOW/HIGH
            - ``integrity`` (str): NONE/LOW/HIGH
            - ``availability`` (str): NONE/LOW/HIGH
            - ``exploit_maturity`` (str, optional): UNPROVEN/POC/FUNCTIONAL/HIGH
            - ``remediation_level`` (str, optional): OFFICIAL_FIX/TEMPORARY_FIX/WORKAROUND/UNAVAILABLE
            - ``report_confidence`` (str, optional): UNKNOWN/REASONABLE/CONFIRMED
            - ``exploitation_status`` (str, optional): none/poc/active
            - ``cve_id`` (str, optional): CVE identifier

        context: Environment context with:
            - ``services`` (list[str]): Services on affected asset
            - ``vendor`` (str): Asset vendor
            - ``is_cluster_node`` (bool): Cluster membership
            - ``classification`` (str): Asset classification
            - ``mission_critical`` (bool, optional): Mission criticality flag

    Returns:
        VulnerabilityScore with all framework scores and composite priority.
    """
    # Build CVSS vector
    vector = CVSSv31Vector(
        attack_vector=_parse_enum(vuln.get("attack_vector", "NETWORK"), AttackVector, AttackVector.NETWORK),
        attack_complexity=_parse_enum(vuln.get("attack_complexity", "LOW"), AttackComplexity, AttackComplexity.LOW),
        privileges_required=_parse_enum(vuln.get("privileges_required", "NONE"), PrivilegesRequired, PrivilegesRequired.NONE),
        user_interaction=_parse_enum(vuln.get("user_interaction", "NONE"), UserInteraction, UserInteraction.NONE),
        scope=_parse_enum(vuln.get("scope", "UNCHANGED"), Scope, Scope.UNCHANGED),
        confidentiality=_parse_enum(vuln.get("confidentiality", "NONE"), Impact, Impact.NONE),
        integrity=_parse_enum(vuln.get("integrity", "NONE"), Impact, Impact.NONE),
        availability=_parse_enum(vuln.get("availability", "NONE"), Impact, Impact.NONE),
        exploit_code_maturity=_parse_enum(
            vuln.get("exploit_maturity", "NOT_DEFINED"),
            ExploitCodeMaturity, ExploitCodeMaturity.NOT_DEFINED
        ),
        remediation_level=_parse_enum(
            vuln.get("remediation_level", "NOT_DEFINED"),
            RemediationLevel, RemediationLevel.NOT_DEFINED
        ),
        report_confidence=_parse_enum(
            vuln.get("report_confidence", "NOT_DEFINED"),
            ReportConfidence, ReportConfidence.NOT_DEFINED
        ),
    )

    # CVSS scores
    base_score = compute_cvss_base_score(vector)
    temporal_score = compute_cvss_temporal_score(vector)
    environmental_score = compute_cvss_environmental_score(vector)
    severity_rating = _cvss_severity_rating(base_score)

    # SSVC assessment
    exploitation_status = _parse_enum(
        vuln.get("exploitation_status", "none"),
        SSVCExploitation, SSVCExploitation.NONE
    )

    is_mission_critical = context.get("mission_critical", False)
    mission_prevalence = (
        SSVCMissionPrevalence.ESSENTIAL if is_mission_critical
        else SSVCMissionPrevalence.SUPPORT if context.get("is_cluster_node")
        else SSVCMissionPrevalence.MINIMAL
    )

    ssvc = compute_ssvc_decision(
        exploitation=exploitation_status,
        automatability=(
            SSVCAutomatability.YES
            if vuln.get("attack_complexity", "LOW") == "LOW"
            and vuln.get("user_interaction", "NONE") == "NONE"
            else SSVCAutomatability.NO
        ),
        technical_impact=(
            SSVCTechnicalImpact.TOTAL
            if vuln.get("confidentiality") == "HIGH"
            and vuln.get("integrity") == "HIGH"
            else SSVCTechnicalImpact.PARTIAL
        ),
        mission_prevalence=mission_prevalence,
    )

    # KEV check
    services = context.get("services", [])
    vendor = context.get("vendor", "")
    kev_matches = check_kev_exposure(services, vendor)

    # Mission impact
    mission_impact = assess_mission_impact(
        services_affected=services,
        is_cluster_node=context.get("is_cluster_node", False),
        classification=context.get("classification", "INTERNAL"),
    )

    # Composite priority
    composite_score = _compute_composite_score(
        base_score, temporal_score, environmental_score,
        ssvc, kev_matches, mission_impact
    )

    if composite_score >= 9.0:
        priority = "critical"
    elif composite_score >= 7.0:
        priority = "high"
    elif composite_score >= 4.0:
        priority = "medium"
    else:
        priority = "low"

    return VulnerabilityScore(
        cvss_base=base_score,
        cvss_temporal=temporal_score,
        cvss_environmental=environmental_score,
        cvss_vector=vector.to_vector_string(),
        cvss_severity=severity_rating,
        ssvc=ssvc.to_dict(),
        kev_matches=kev_matches,
        mission_impact=mission_impact,
        composite_priority=priority,
        composite_score=round(composite_score, 1),
    )


def _compute_composite_score(
    base: float,
    temporal: float,
    environmental: float,
    ssvc: SSVCAssessment,
    kev_matches: list[dict],
    mission_impact: dict,
) -> float:
    """Compute weighted composite score across all frameworks."""
    # Start with environmental score (accounts for org context)
    score = environmental

    # SSVC escalation
    ssvc_boost = {
        SSVCDecision.ACT: 2.0,
        SSVCDecision.ATTEND: 1.0,
        SSVCDecision.TRACK_STAR: 0.5,
        SSVCDecision.TRACK: 0.0,
    }
    score += ssvc_boost.get(ssvc.decision, 0)

    # KEV presence is a strong signal
    if kev_matches:
        ransomware = any(m.get("known_ransomware_use") for m in kev_matches)
        if ransomware:
            score += 2.0
        else:
            score += 1.5

    # Mission impact contribution
    impact_score = mission_impact.get("impact_score", 5)
    score += impact_score * 0.1

    return min(max(score, 0.0), 10.0)


def _parse_enum(value: str, enum_class: type, default: Any) -> Any:
    """Parse string to enum with fallback."""
    if isinstance(value, enum_class):
        return value
    try:
        return enum_class(value.upper() if hasattr(value, 'upper') else value)
    except (ValueError, KeyError):
        try:
            return enum_class(value)
        except (ValueError, KeyError):
            return default


def prioritize_vulnerabilities(
    vulns: list[dict[str, Any]],
    mission_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Perform defense-grade vulnerability prioritization.

    Scores and ranks multiple vulnerabilities using all available frameworks
    (CVSS, SSVC, KEV, mission impact) and produces a prioritized remediation
    order.

    Args:
        vulns: List of vulnerability descriptors (see score_vulnerability).
        mission_context: Environment/mission context (see score_vulnerability).

    Returns:
        Dictionary with:
            - ``prioritized``: Sorted list of scored vulnerabilities
            - ``summary``: Priority distribution statistics
            - ``immediate_actions``: Vulnerabilities requiring immediate response
            - ``kev_alerts``: Any KEV catalog matches found
    """
    scored: list[dict[str, Any]] = []

    for vuln in vulns:
        result = score_vulnerability(vuln, mission_context)
        scored.append({
            "vulnerability": vuln,
            "scoring": result.to_dict(),
        })

    # Sort by composite score descending
    scored.sort(key=lambda s: s["scoring"]["composite_score"], reverse=True)

    # Summary
    priority_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in scored:
        priority = s["scoring"]["composite_priority"]
        priority_dist[priority] = priority_dist.get(priority, 0) + 1

    # Immediate actions
    immediate = [
        s for s in scored
        if s["scoring"]["composite_priority"] == "critical"
        or s["scoring"]["ssvc"]["decision"] == "Act"
    ]

    # KEV alerts
    all_kev: list[dict] = []
    for s in scored:
        all_kev.extend(s["scoring"]["kev_matches"])

    result = {
        "assessment_time": datetime.now(timezone.utc).isoformat(),
        "total_vulnerabilities": len(scored),
        "prioritized": scored,
        "summary": {
            "priority_distribution": priority_dist,
            "average_composite_score": round(
                sum(s["scoring"]["composite_score"] for s in scored) / max(len(scored), 1),
                1
            ),
        },
        "immediate_actions": immediate,
        "kev_alerts": all_kev,
        "kev_alert_count": len(all_kev),
    }

    logger.info(
        f"Vulnerability prioritization complete: {len(scored)} vulns, "
        f"{len(immediate)} requiring immediate action"
    )

    return result
