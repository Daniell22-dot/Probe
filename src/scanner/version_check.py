import re

EXPOSED_SERVICE_RULES = [
    {
        "service": "microsoft-ds",
        "title": "SMB service exposed",
        "description": "File sharing service (SMB) is reachable on the network.",
        "kenyan_relevance": "Basic file-sharing exposure is repeatedly seen in Kenyan public-sector incidents.",
        "recommendation": "Confirm SMB is required, restrict it to trusted networks, and disable SMBv1.",
    },
    {
        "service": "ms-wbt-server",
        "title": "Remote Desktop exposed",
        "description": "Remote Desktop (RDP) is reachable on the network.",
        "kenyan_relevance": "Exposed RDP is one of the highest-value entry points in Kenyan threat reports.",
        "recommendation": "Limit RDP to trusted networks or VPN, enforce MFA, and remove it if unused.",
    },
    {
        "service": "vnc",
        "title": "VNC remote access exposed",
        "description": "VNC remote access service is reachable on the network.",
        "kenyan_relevance": "Remote access tools are commonly abused after weak credential management.",
        "recommendation": "Remove VNC or restrict it to trusted networks and require strong authentication.",
    },
]

KNOWN_CVES = {
    "CVE-2017-0199": {
        "name": "Microsoft Office/WordPad OLE remote code execution",
        "indicators": ("office", "wordpad", "winword", "ms-word"),
        "description": "A malicious OLE document can execute code when opened.",
        "kenyan_relevance": "Prioritised in Kenya-focused detection guidance on document-based attacks.",
        "recommendation": "Apply Office and Windows updates and block unsolicited Office documents.",
    },
}

OUTDATED_WINDOWS_PATTERN = re.compile(
    r"\bwindows\s+(?:xp|vista|7|8(?:\.1)?|server\s+(?:2003|2008(?:\s+r2)?|2012(?:\s+r2)?))\b",
    re.IGNORECASE,
)


def _finding(kind, title, service, port, info, description, recommendation, cve=None, kenyan_relevance=""):
    return {
        "kind": kind,
        "title": title,
        "cve": cve,
        "service": service,
        "port": port,
        "state": info.get("state", ""),
        "version": info.get("version", ""),
        "description": description,
        "kenyan_relevance": kenyan_relevance,
        "recommendation": recommendation,
    }


def check_versions(scan_result):
    """Check scan output for exposed services and known version issues.

    Args:
        scan_result: dict from port_scan.scan_ports() output

    Returns:
        List of finding dicts with a kind of exposure, cve, or version
    """
    findings = []

    for host_data in (scan_result or {}).values():
        for port, info in host_data.get("tcp", {}).items():
            if str(info.get("state", "")).lower() != "open":
                continue

            service = info.get("name", "")
            service_text = f"{service} {info.get('version', '')}".lower()

            for rule in EXPOSED_SERVICE_RULES:
                if rule["service"] in service_text:
                    findings.append(_finding(
                        "exposure",
                        rule["title"],
                        service,
                        port,
                        info,
                        rule["description"],
                        rule["recommendation"],
                        kenyan_relevance=rule["kenyan_relevance"],
                    ))
                    break

            for cve_id, rule in KNOWN_CVES.items():
                if any(indicator in service_text for indicator in rule["indicators"]):
                    findings.append(_finding(
                        "cve",
                        rule["name"],
                        service,
                        port,
                        info,
                        rule["description"],
                        rule["recommendation"],
                        cve=cve_id,
                        kenyan_relevance=rule["kenyan_relevance"],
                    ))

            if OUTDATED_WINDOWS_PATTERN.search(info.get("version", "")):
                findings.append(_finding(
                    "version",
                    "Outdated Windows version reported",
                    service,
                    port,
                    info,
                    "Nmap reports an unsupported or pre-2017 Windows version. Patch status was not confirmed.",
                    "Verify the patch level and upgrade or retire the system.",
                    kenyan_relevance="Outdated software is a leading exploitation vector in KE-CIRT/CC threat reports.",
                ))

    return findings
