"""
Defense & Federal Compliance Module for Network Scanner MCP.

Provides compliance assessment capabilities aligned with federal standards:
- SCAP (Security Content Automation Protocol) compliant output
- CIS Benchmark checking for network devices
- NIST CSF asset inventory and risk scoring
- Zero Trust Architecture assessment (NIST SP 800-207 / DISA ZTA)
- NIST SP 800-53 control mapping with POA&M generation
- Multi-framework vulnerability scoring (CVSS v3.1, SSVC, KEV)
"""

from .scap_output import (
    generate_xccdf_results,
    generate_oval_definitions,
    identify_cpe,
)
from .cis_benchmarks import (
    run_cis_assessment,
    generate_cis_report,
)
from .nist_csf_inventory import (
    build_asset_inventory,
    classify_asset,
    calculate_risk_score,
)
from .zero_trust import (
    assess_zero_trust_posture,
    generate_zt_roadmap,
    zt_maturity_score,
)
from .nist_800_53 import (
    map_findings_to_controls,
    generate_poam,
)
from .vuln_scoring import (
    score_vulnerability,
    prioritize_vulnerabilities,
)

__all__ = [
    # SCAP Output
    "generate_xccdf_results",
    "generate_oval_definitions",
    "identify_cpe",
    # CIS Benchmarks
    "run_cis_assessment",
    "generate_cis_report",
    # NIST CSF Inventory
    "build_asset_inventory",
    "classify_asset",
    "calculate_risk_score",
    # Zero Trust
    "assess_zero_trust_posture",
    "generate_zt_roadmap",
    "zt_maturity_score",
    # NIST 800-53
    "map_findings_to_controls",
    "generate_poam",
    # Vulnerability Scoring
    "score_vulnerability",
    "prioritize_vulnerabilities",
]
