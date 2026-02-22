"""
SCAP (Security Content Automation Protocol) Compliant Output Generator.

Generates standards-compliant output following NIST SCAP specifications:
- XCCDF 1.2 (Extensible Configuration Checklist Description Format) results
- OVAL 5.11 (Open Vulnerability and Assessment Language) definitions
- CPE 2.3 (Common Platform Enumeration) for asset identification
- CCE (Common Configuration Enumeration) references

References:
    - NIST SP 800-126 Rev. 3: The Technical Specification for SCAP
    - XCCDF 1.2: https://csrc.nist.gov/projects/security-content-automation-protocol
    - OVAL 5.11.2: https://oval.mitre.org/language/version5.11.2/
    - CPE 2.3: https://cpe.mitre.org/specification/
"""

import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional
from xml.dom import minidom

logger = logging.getLogger("network-scanner")

# ---------------------------------------------------------------------------
# XML Namespace URIs (per NIST SCAP 1.3)
# ---------------------------------------------------------------------------

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_COMMON_NS = "http://oval.mitre.org/XMLSchema/oval-common-5"
OVAL_IND_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
OVAL_LINUX_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
OVAL_WINDOWS_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#windows"
CPE_NS = "http://cpe.mitre.org/dictionary/2.0"
CPE_LANG_NS = "http://cpe.mitre.org/language/2.0"
DC_NS = "http://purl.org/dc/elements/1.1/"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

# Register namespaces so ElementTree preserves prefixes
ET.register_namespace("xccdf", XCCDF_NS)
ET.register_namespace("oval", OVAL_NS)
ET.register_namespace("oval-com", OVAL_COMMON_NS)
ET.register_namespace("oval-def-ind", OVAL_IND_NS)
ET.register_namespace("cpe", CPE_NS)
ET.register_namespace("cpe-lang", CPE_LANG_NS)
ET.register_namespace("dc", DC_NS)
ET.register_namespace("xsi", XSI_NS)

# ---------------------------------------------------------------------------
# XCCDF result status mapping
# ---------------------------------------------------------------------------

XCCDF_RESULT_PASS = "pass"
XCCDF_RESULT_FAIL = "fail"
XCCDF_RESULT_ERROR = "error"
XCCDF_RESULT_UNKNOWN = "unknown"
XCCDF_RESULT_NOTAPPLICABLE = "notapplicable"
XCCDF_RESULT_NOTCHECKED = "notchecked"
XCCDF_RESULT_NOTSELECTED = "notselected"
XCCDF_RESULT_INFORMATIONAL = "informational"
XCCDF_RESULT_FIXED = "fixed"

# Map internal check statuses to XCCDF result values
_STATUS_MAP: dict[str, str] = {
    "pass": XCCDF_RESULT_PASS,
    "passed": XCCDF_RESULT_PASS,
    "compliant": XCCDF_RESULT_PASS,
    "fail": XCCDF_RESULT_FAIL,
    "failed": XCCDF_RESULT_FAIL,
    "non-compliant": XCCDF_RESULT_FAIL,
    "non_compliant": XCCDF_RESULT_FAIL,
    "error": XCCDF_RESULT_ERROR,
    "unknown": XCCDF_RESULT_UNKNOWN,
    "not_applicable": XCCDF_RESULT_NOTAPPLICABLE,
    "not_checked": XCCDF_RESULT_NOTCHECKED,
    "informational": XCCDF_RESULT_INFORMATIONAL,
    "fixed": XCCDF_RESULT_FIXED,
}

# ---------------------------------------------------------------------------
# Vendor-to-CPE mappings for common network device manufacturers
# ---------------------------------------------------------------------------

_VENDOR_CPE_MAP: dict[str, dict[str, str]] = {
    "cisco": {"vendor": "cisco", "product_prefix": "ios"},
    "juniper": {"vendor": "juniper", "product_prefix": "junos"},
    "arista": {"vendor": "arista", "product_prefix": "eos"},
    "palo alto": {"vendor": "paloaltonetworks", "product_prefix": "pan-os"},
    "paloalto": {"vendor": "paloaltonetworks", "product_prefix": "pan-os"},
    "fortinet": {"vendor": "fortinet", "product_prefix": "fortios"},
    "fortigate": {"vendor": "fortinet", "product_prefix": "fortios"},
    "apple": {"vendor": "apple", "product_prefix": "macos"},
    "microsoft": {"vendor": "microsoft", "product_prefix": "windows"},
    "linux": {"vendor": "linux", "product_prefix": "linux_kernel"},
    "ubuntu": {"vendor": "canonical", "product_prefix": "ubuntu_linux"},
    "debian": {"vendor": "debian", "product_prefix": "debian_linux"},
    "redhat": {"vendor": "redhat", "product_prefix": "enterprise_linux"},
    "red hat": {"vendor": "redhat", "product_prefix": "enterprise_linux"},
    "centos": {"vendor": "centos", "product_prefix": "centos"},
    "fedora": {"vendor": "fedoraproject", "product_prefix": "fedora"},
    "samsung": {"vendor": "samsung", "product_prefix": "android"},
    "synology": {"vendor": "synology", "product_prefix": "diskstation_manager"},
    "qnap": {"vendor": "qnap", "product_prefix": "qts"},
    "ubiquiti": {"vendor": "ui", "product_prefix": "unifi"},
    "netgear": {"vendor": "netgear", "product_prefix": "prosafe"},
    "tp-link": {"vendor": "tp-link", "product_prefix": "firmware"},
    "dell": {"vendor": "dell", "product_prefix": "idrac"},
    "hewlett": {"vendor": "hp", "product_prefix": "ilo"},
    "hp": {"vendor": "hp", "product_prefix": "ilo"},
    "vmware": {"vendor": "vmware", "product_prefix": "esxi"},
    "intel": {"vendor": "intel", "product_prefix": "nuc"},
}

# Service-to-CPE application mappings
_SERVICE_CPE_MAP: dict[str, dict[str, str]] = {
    "ssh": {"vendor": "openbsd", "product": "openssh"},
    "openssh": {"vendor": "openbsd", "product": "openssh"},
    "nginx": {"vendor": "f5", "product": "nginx"},
    "apache": {"vendor": "apache", "product": "http_server"},
    "iis": {"vendor": "microsoft", "product": "internet_information_services"},
    "mysql": {"vendor": "oracle", "product": "mysql"},
    "postgresql": {"vendor": "postgresql", "product": "postgresql"},
    "redis": {"vendor": "redis", "product": "redis"},
    "mongodb": {"vendor": "mongodb", "product": "mongodb"},
    "elasticsearch": {"vendor": "elastic", "product": "elasticsearch"},
    "docker": {"vendor": "docker", "product": "docker"},
    "kubernetes": {"vendor": "kubernetes", "product": "kubernetes"},
    "ollama": {"vendor": "ollama", "product": "ollama"},
    "smtp": {"vendor": "postfix", "product": "postfix"},
    "dns": {"vendor": "isc", "product": "bind"},
    "ftp": {"vendor": "pureftpd", "product": "pure-ftpd"},
    "rdp": {"vendor": "microsoft", "product": "remote_desktop_protocol"},
    "vnc": {"vendor": "realvnc", "product": "vnc"},
    "smb": {"vendor": "samba", "product": "samba"},
    "ldap": {"vendor": "openldap", "product": "openldap"},
    "ntp": {"vendor": "ntp", "product": "ntp"},
    "snmp": {"vendor": "net-snmp", "product": "net-snmp"},
    "syslog": {"vendor": "rsyslog", "product": "rsyslog"},
}


def _pretty_xml(element: ET.Element) -> str:
    """Produce indented XML string from an ElementTree element."""
    rough = ET.tostring(element, encoding="unicode", xml_declaration=False)
    parsed = minidom.parseString(rough)
    pretty = parsed.toprettyxml(indent="  ", encoding=None)
    # Remove the XML declaration that minidom adds (we add our own)
    lines = pretty.split("\n")
    if lines and lines[0].startswith("<?xml"):
        lines = lines[1:]
    return "\n".join(line for line in lines if line.strip())


def _normalize_status(status: str) -> str:
    """Normalize an internal status string to an XCCDF result value."""
    return _STATUS_MAP.get(status.lower().strip(), XCCDF_RESULT_UNKNOWN)


def _generate_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic ID from component parts."""
    raw = ":".join(str(p) for p in parts)
    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


# =========================================================================
# CPE Identification
# =========================================================================

def identify_cpe(device_info: dict[str, Any]) -> list[str]:
    """
    Generate CPE 2.3 URIs for a discovered network asset.

    Produces hardware (``cpe:2.3:h:...``), operating-system
    (``cpe:2.3:o:...``), and application (``cpe:2.3:a:...``) URIs based on
    vendor, hostname, service banners, and detected services.

    CPE 2.3 URI format::

        cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:
              <language>:<sw_edition>:<target_sw>:<target_hw>:<other>

    Args:
        device_info: Device dictionary containing at minimum ``vendor``; may
            also include ``hostname``, ``services``, ``ports``, ``os_guess``,
            and ``mac``.

    Returns:
        List of CPE 2.3 formatted URI strings. Empty list if no identification
        is possible.
    """
    cpes: list[str] = []
    vendor_raw = (device_info.get("vendor") or "").lower().strip()
    hostname_raw = (device_info.get("hostname") or "").lower().strip()
    os_guess = (device_info.get("os_guess") or "").lower().strip()
    services: list[str] = device_info.get("services") or []
    ports: list[dict] = device_info.get("ports") or []

    # --- Hardware CPE from vendor ---
    matched_vendor: Optional[dict[str, str]] = None
    for keyword, mapping in _VENDOR_CPE_MAP.items():
        if keyword in vendor_raw or keyword in hostname_raw:
            matched_vendor = mapping
            break

    if matched_vendor:
        hw_cpe = (
            f"cpe:2.3:h:{matched_vendor['vendor']}:"
            f"{matched_vendor['product_prefix']}:*:*:*:*:*:*:*:*"
        )
        cpes.append(hw_cpe)

        # OS CPE derived from vendor
        os_cpe = (
            f"cpe:2.3:o:{matched_vendor['vendor']}:"
            f"{matched_vendor['product_prefix']}:*:*:*:*:*:*:*:*"
        )
        cpes.append(os_cpe)

    # --- OS CPE from os_guess ---
    if os_guess:
        for keyword, mapping in _VENDOR_CPE_MAP.items():
            if keyword in os_guess:
                guess_cpe = (
                    f"cpe:2.3:o:{mapping['vendor']}:"
                    f"{mapping['product_prefix']}:*:*:*:*:*:*:*:*"
                )
                if guess_cpe not in cpes:
                    cpes.append(guess_cpe)
                break

    # --- Application CPEs from detected services ---
    seen_apps: set[str] = set()
    all_service_names = list(services)

    for port_info in ports:
        svc_name = (port_info.get("service") or "").lower()
        banner = (port_info.get("banner") or "").lower()

        if svc_name and svc_name != "unknown":
            all_service_names.append(svc_name)

        # Try to extract version from banner
        for svc_key, svc_mapping in _SERVICE_CPE_MAP.items():
            if svc_key in banner or svc_key in svc_name:
                app_key = f"{svc_mapping['vendor']}:{svc_mapping['product']}"
                if app_key not in seen_apps:
                    seen_apps.add(app_key)

                    # Attempt version extraction from banner
                    version = _extract_version(banner)

                    app_cpe = (
                        f"cpe:2.3:a:{svc_mapping['vendor']}:"
                        f"{svc_mapping['product']}:{version}:*:*:*:*:*:*:*"
                    )
                    cpes.append(app_cpe)

    # Service-level CPEs without banners
    for svc in all_service_names:
        svc_lower = svc.lower()
        if svc_lower in _SERVICE_CPE_MAP:
            mapping = _SERVICE_CPE_MAP[svc_lower]
            app_key = f"{mapping['vendor']}:{mapping['product']}"
            if app_key not in seen_apps:
                seen_apps.add(app_key)
                app_cpe = (
                    f"cpe:2.3:a:{mapping['vendor']}:"
                    f"{mapping['product']}:*:*:*:*:*:*:*:*"
                )
                cpes.append(app_cpe)

    # Fallback: generic CPE if nothing matched
    if not cpes and vendor_raw and vendor_raw != "unknown":
        sanitized = re.sub(r"[^a-z0-9_]", "_", vendor_raw)[:32]
        cpes.append(f"cpe:2.3:h:{sanitized}:*:*:*:*:*:*:*:*:*")

    return cpes


def _extract_version(banner: str) -> str:
    """Extract a version string from a service banner, or ``*`` if not found."""
    patterns = [
        r"(\d+\.\d+\.\d+[a-z]?\d*)",  # e.g. 8.0.28, 1.18.0p1
        r"(\d+\.\d+)",                  # e.g. 8.0
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return "*"


# =========================================================================
# XCCDF Results Generation
# =========================================================================

def generate_xccdf_results(
    scan_results: dict[str, Any],
    benchmark_id: str = "xccdf_network-scanner_benchmark_network-security",
    profile_id: str = "xccdf_network-scanner_profile_defense-compliance",
) -> str:
    """
    Generate XCCDF 1.2 compliant XML results document.

    Produces a ``<Benchmark>`` element with embedded ``<TestResult>`` that
    encapsulates all scan findings as XCCDF rule-results.

    The output conforms to NIST SP 800-126 Rev. 3 XCCDF 1.2 schema.

    Args:
        scan_results: Dictionary containing scan data. Expected keys:

            - ``target`` (str): IP or hostname of scanned target
            - ``scan_time`` (str, optional): ISO timestamp of scan
            - ``checks`` (list[dict]): List of check results, each with:
                - ``id`` (str): Check identifier
                - ``title`` (str): Human-readable title
                - ``description`` (str): Check description
                - ``status`` (str): Result status (pass/fail/error/etc.)
                - ``severity`` (str, optional): high/medium/low
                - ``evidence`` (str, optional): Supporting evidence
                - ``remediation`` (str, optional): Fix guidance
                - ``cce_id`` (str, optional): CCE identifier
                - ``nist_controls`` (list[str], optional): NIST 800-53 control IDs
            - ``device_info`` (dict, optional): Device metadata for CPE generation

        benchmark_id: XCCDF benchmark identifier.
        profile_id: XCCDF profile identifier.

    Returns:
        Pretty-printed XCCDF 1.2 XML string including XML declaration.
    """
    now = datetime.now(timezone.utc).isoformat()
    target = scan_results.get("target", "unknown-target")
    scan_time = scan_results.get("scan_time", now)
    checks: list[dict] = scan_results.get("checks", [])
    device_info: dict = scan_results.get("device_info", {})

    # Root <Benchmark>
    benchmark = ET.Element(f"{{{XCCDF_NS}}}Benchmark")
    benchmark.set("id", benchmark_id)
    benchmark.set("resolved", "1")
    benchmark.set("xml:lang", "en")
    benchmark.set(f"{{{XSI_NS}}}schemaLocation",
                  f"{XCCDF_NS} https://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd")

    # <status>
    status_elem = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}status")
    status_elem.set("date", now[:10])
    status_elem.text = "accepted"

    # <title>
    title_elem = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}title")
    title_elem.text = "Network Security Compliance Assessment"

    # <description>
    desc_elem = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}description")
    desc_elem.text = (
        "Automated network security compliance assessment generated by "
        "Network Scanner MCP. Covers CIS benchmarks, NIST controls, and "
        "defense-grade security requirements."
    )

    # <version>
    version_elem = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}version")
    version_elem.text = "1.0.0"
    version_elem.set("time", now)

    # <platform> elements via CPE
    cpes = identify_cpe(device_info) if device_info else []
    for cpe_uri in cpes:
        platform_elem = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}platform")
        platform_elem.set("idref", cpe_uri)

    # <Profile>
    profile = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}Profile")
    profile.set("id", profile_id)
    prof_title = ET.SubElement(profile, f"{{{XCCDF_NS}}}title")
    prof_title.text = "Defense Compliance Profile"
    prof_desc = ET.SubElement(profile, f"{{{XCCDF_NS}}}description")
    prof_desc.text = (
        "Profile for defense-grade network compliance assessment aligned "
        "with NIST SP 800-53, CIS Benchmarks, and DoD requirements."
    )

    # <Rule> elements
    for check in checks:
        rule_id = f"xccdf_network-scanner_rule_{check.get('id', 'unknown')}"
        rule = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}Rule")
        rule.set("id", rule_id)
        rule.set("selected", "true")
        rule.set("weight", _severity_weight(check.get("severity", "medium")))

        severity = check.get("severity", "medium").lower()
        if severity in ("high", "critical"):
            rule.set("severity", "high")
        elif severity == "medium":
            rule.set("severity", "medium")
        else:
            rule.set("severity", "low")

        r_title = ET.SubElement(rule, f"{{{XCCDF_NS}}}title")
        r_title.text = check.get("title", "Untitled Check")

        r_desc = ET.SubElement(rule, f"{{{XCCDF_NS}}}description")
        r_desc.text = check.get("description", "")

        # CCE reference
        cce_id = check.get("cce_id")
        if cce_id:
            ident = ET.SubElement(rule, f"{{{XCCDF_NS}}}ident")
            ident.set("system", "http://cce.mitre.org")
            ident.text = cce_id

        # NIST 800-53 control references
        nist_controls = check.get("nist_controls", [])
        for ctrl in nist_controls:
            ref = ET.SubElement(rule, f"{{{XCCDF_NS}}}reference")
            ref.set("href", "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final")
            ref.text = ctrl

        # Remediation fixtext
        remediation = check.get("remediation")
        if remediation:
            fixtext = ET.SubElement(rule, f"{{{XCCDF_NS}}}fixtext")
            fixtext.text = remediation

        # Select in profile
        sel = ET.SubElement(profile, f"{{{XCCDF_NS}}}select")
        sel.set("idref", rule_id)
        sel.set("selected", "true")

    # <TestResult>
    result_id = f"xccdf_network-scanner_testresult_{_generate_id('tr', target, scan_time)}"
    test_result = ET.SubElement(benchmark, f"{{{XCCDF_NS}}}TestResult")
    test_result.set("id", result_id)
    test_result.set("start-time", scan_time)
    test_result.set("end-time", now)
    test_result.set("version", "1.0.0")
    test_result.set("test-system", "network-scanner-mcp")

    # <benchmark> reference inside TestResult
    bench_ref = ET.SubElement(test_result, f"{{{XCCDF_NS}}}benchmark")
    bench_ref.set("id", benchmark_id)
    bench_ref.set("href", "")

    # <target>
    target_elem = ET.SubElement(test_result, f"{{{XCCDF_NS}}}target")
    target_elem.text = target

    # <target-address>
    target_addr = ET.SubElement(test_result, f"{{{XCCDF_NS}}}target-address")
    target_addr.text = target

    # <target-facts> with CPE
    if cpes:
        target_facts = ET.SubElement(test_result, f"{{{XCCDF_NS}}}target-facts")
        for cpe_uri in cpes:
            fact = ET.SubElement(target_facts, f"{{{XCCDF_NS}}}fact")
            fact.set("name", "urn:scap:fact:asset:identifier:cpe")
            fact.set("type", "string")
            fact.text = cpe_uri

    # <rule-result> entries
    pass_count = 0
    fail_count = 0
    error_count = 0
    other_count = 0

    for check in checks:
        rule_id = f"xccdf_network-scanner_rule_{check.get('id', 'unknown')}"
        rr = ET.SubElement(test_result, f"{{{XCCDF_NS}}}rule-result")
        rr.set("idref", rule_id)
        rr.set("time", scan_time)

        xccdf_status = _normalize_status(check.get("status", "unknown"))

        result_elem = ET.SubElement(rr, f"{{{XCCDF_NS}}}result")
        result_elem.text = xccdf_status

        if xccdf_status == XCCDF_RESULT_PASS:
            pass_count += 1
        elif xccdf_status == XCCDF_RESULT_FAIL:
            fail_count += 1
        elif xccdf_status == XCCDF_RESULT_ERROR:
            error_count += 1
        else:
            other_count += 1

        # Evidence as message
        evidence = check.get("evidence")
        if evidence:
            msg = ET.SubElement(rr, f"{{{XCCDF_NS}}}message")
            msg.set("severity", "info")
            msg.text = evidence

    # <score>
    total = pass_count + fail_count + error_count + other_count
    score_val = (pass_count / total * 100.0) if total > 0 else 0.0

    score_elem = ET.SubElement(test_result, f"{{{XCCDF_NS}}}score")
    score_elem.set("system", "urn:xccdf:scoring:default")
    score_elem.set("maximum", "100")
    score_elem.text = f"{score_val:.1f}"

    xml_decl = '<?xml version="1.0" encoding="UTF-8"?>\n'
    return xml_decl + _pretty_xml(benchmark)


def _severity_weight(severity: str) -> str:
    """Map severity to XCCDF numeric weight."""
    mapping = {
        "critical": "10.0",
        "high": "8.0",
        "medium": "5.0",
        "low": "2.0",
        "informational": "1.0",
    }
    return mapping.get(severity.lower(), "5.0")


# =========================================================================
# OVAL Definitions Generation
# =========================================================================

def generate_oval_definitions(
    checks: list[dict[str, Any]],
    schema_version: str = "5.11.2",
) -> str:
    """
    Generate OVAL 5.11 structural definitions document for documentation purposes.

    Produces OVAL XML that represents the compliance checks in OVAL schema format.
    The output is **structural/demonstrative** -- it captures check definitions,
    objects, and expected states in valid OVAL XML, but is not intended for direct
    execution by SCAP scanning tools (e.g., OpenSCAP, SCAP Workbench). The
    definitions use ``textfilecontent54`` objects that reference the scanner's own
    results data rather than live system files, so an external OVAL interpreter
    would not be able to evaluate them independently.

    Use this output for:
        - Compliance documentation and audit evidence
        - SCAP data-stream assembly where OVAL serves as a reference artifact
        - Mapping checks to OVAL-compatible structure for toolchain integration

    Args:
        checks: List of check dictionaries. Each must contain:

            - ``id`` (str): Unique check identifier
            - ``title`` (str): Human-readable title
            - ``description`` (str): Detailed description
            - ``status`` (str): Current assessment result
            - ``check_type`` (str, optional): One of ``port_check``,
              ``service_check``, ``config_check``, ``credential_check``.
              Defaults to ``config_check``.
            - ``target_ip`` (str, optional): Target IP address
            - ``port`` (int, optional): Port number (for port checks)
            - ``expected_value`` (str, optional): Expected configuration value
            - ``actual_value`` (str, optional): Observed value

        schema_version: OVAL schema version string.

    Returns:
        Pretty-printed OVAL 5.11 XML string with XML declaration.

    Note:
        These definitions are structural representations of network scanner
        checks, not executable OVAL content. They reference scan result data
        paths rather than live system paths.
    """
    now = datetime.now(timezone.utc).isoformat()

    root = ET.Element(f"{{{OVAL_NS}}}oval_definitions")
    root.set(f"{{{XSI_NS}}}schemaLocation",
             f"{OVAL_NS} https://oval.mitre.org/XMLSchema/oval-definitions-5")

    # <generator>
    generator = ET.SubElement(root, f"{{{OVAL_NS}}}generator")
    prod_name = ET.SubElement(generator, f"{{{OVAL_COMMON_NS}}}product_name")
    prod_name.text = "Network Scanner MCP - OVAL Generator"
    prod_version = ET.SubElement(generator, f"{{{OVAL_COMMON_NS}}}product_version")
    prod_version.text = "1.0.0"
    schema_ver = ET.SubElement(generator, f"{{{OVAL_COMMON_NS}}}schema_version")
    schema_ver.text = schema_version
    timestamp_elem = ET.SubElement(generator, f"{{{OVAL_COMMON_NS}}}timestamp")
    timestamp_elem.text = now

    # Containers
    definitions = ET.SubElement(root, f"{{{OVAL_NS}}}definitions")
    tests = ET.SubElement(root, f"{{{OVAL_NS}}}tests")
    objects = ET.SubElement(root, f"{{{OVAL_NS}}}objects")
    states = ET.SubElement(root, f"{{{OVAL_NS}}}states")

    for idx, check in enumerate(checks, start=1):
        check_id = check.get("id", f"check-{idx}")
        check_type = check.get("check_type", "config_check")

        def_id = f"oval:network-scanner:def:{idx}"
        tst_id = f"oval:network-scanner:tst:{idx}"
        obj_id = f"oval:network-scanner:obj:{idx}"
        ste_id = f"oval:network-scanner:ste:{idx}"

        # --- <definition> ---
        defn = ET.SubElement(definitions, f"{{{OVAL_NS}}}definition")
        defn.set("id", def_id)
        defn.set("version", "1")
        defn.set("class", "compliance")

        metadata = ET.SubElement(defn, f"{{{OVAL_NS}}}metadata")
        d_title = ET.SubElement(metadata, f"{{{OVAL_NS}}}title")
        d_title.text = check.get("title", check_id)

        affected = ET.SubElement(metadata, f"{{{OVAL_NS}}}affected")
        affected.set("family", _oval_family(check_type))
        platform_el = ET.SubElement(affected, f"{{{OVAL_NS}}}platform")
        platform_el.text = "Network Device"

        d_desc = ET.SubElement(metadata, f"{{{OVAL_NS}}}description")
        d_desc.text = check.get("description", "")

        criteria = ET.SubElement(defn, f"{{{OVAL_NS}}}criteria")
        criterion = ET.SubElement(criteria, f"{{{OVAL_NS}}}criterion")
        criterion.set("test_ref", tst_id)
        criterion.set("comment", check.get("title", check_id))

        # --- <test> ---
        # All checks use textfilecontent54 referencing scanner result files
        test_elem = ET.SubElement(tests, f"{{{OVAL_IND_NS}}}textfilecontent54_test")

        test_elem.set("id", tst_id)
        test_elem.set("version", "1")
        test_elem.set("check", "all")
        test_elem.set("comment", check.get("title", check_id))

        obj_ref = ET.SubElement(test_elem, f"{{{OVAL_IND_NS}}}object")
        obj_ref.set("object_ref", obj_id)
        ste_ref = ET.SubElement(test_elem, f"{{{OVAL_IND_NS}}}state")
        ste_ref.set("state_ref", ste_id)

        # --- <object> ---
        obj_elem = ET.SubElement(objects, f"{{{OVAL_IND_NS}}}textfilecontent54_object")

        obj_elem.set("id", obj_id)
        obj_elem.set("version", "1")
        obj_elem.set("comment", f"Object for {check_id}")

        # Object content varies by check type.
        # Note: These objects describe the scanner's own result data structure,
        # not live system files. They are structural OVAL representations.
        if check_type == "port_check":
            filepath_el = ET.SubElement(obj_elem, f"{{{OVAL_IND_NS}}}filepath")
            target_ip = check.get("target_ip", "unknown")
            port = check.get("port", 0)
            # Reference the scan results data for this check
            filepath_el.text = f"/var/lib/network-scanner/results/{target_ip}/port_scan.log"
            pattern_el = ET.SubElement(obj_elem, f"{{{OVAL_IND_NS}}}pattern")
            pattern_el.set("operation", "pattern match")
            pattern_el.text = f"^{port}/tcp\\s+open"
            instance_el = ET.SubElement(obj_elem, f"{{{OVAL_IND_NS}}}instance")
            instance_el.set("datatype", "int")
            instance_el.text = "1"
        else:
            # For config/service/credential checks, reference the check result file
            filepath_el = ET.SubElement(obj_elem, f"{{{OVAL_IND_NS}}}filepath")
            target_ip = check.get("target_ip", "unknown")
            filepath_el.text = f"/var/lib/network-scanner/results/{target_ip}/{check_id}.log"
            pattern_el = ET.SubElement(obj_elem, f"{{{OVAL_IND_NS}}}pattern")
            pattern_el.set("operation", "pattern match")
            actual = check.get("actual_value", ".*")
            pattern_el.text = actual
            instance_el = ET.SubElement(obj_elem, f"{{{OVAL_IND_NS}}}instance")
            instance_el.set("datatype", "int")
            instance_el.text = "1"

        # --- <state> ---
        state_elem = ET.SubElement(states, f"{{{OVAL_IND_NS}}}textfilecontent54_state")

        state_elem.set("id", ste_id)
        state_elem.set("version", "1")
        state_elem.set("comment", f"Expected state for {check_id}")

        expected = check.get("expected_value", "compliant")
        value_el = ET.SubElement(state_elem, f"{{{OVAL_IND_NS}}}value")
        value_el.set("datatype", "string")
        value_el.set("operation", "equals")
        value_el.text = expected

    xml_decl = '<?xml version="1.0" encoding="UTF-8"?>\n'
    return xml_decl + _pretty_xml(root)


def _oval_family(check_type: str) -> str:
    """Map check type to OVAL affected family."""
    mapping = {
        "port_check": "unix",
        "service_check": "unix",
        "config_check": "unix",
        "credential_check": "unix",
        "windows_check": "windows",
    }
    return mapping.get(check_type, "unix")
