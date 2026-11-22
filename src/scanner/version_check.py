KNOWN_CVES = {
    "CVE-2017-0199": {
        "name": "EternalBlue",
        "affected_service": "microsoft-ds",
        "description": "SMBv1 remote code execution vulnerability",
        "kenyan_relevance": "Documented exploitation in Kenya CVE patterns",
        "min_version": "Windows Vista/Server 2008 and earlier",
    },
}


def check_versions(scan_result):
    """Check detected service versions against known CVEs.

    Args:
        scan_result: dict from port_scan.scan_ports() output

    Returns:
        List of CVE findings matching detected services
    """
    findings = []

    host_key = list(scan_result.keys())[0] if scan_result else None
    if not host_key:
        return findings

    host_data = scan_result.get(host_key, {})

    for port, info in host_data.get("tcp", {}).items():
        service = info.get("name", "")
        version = info.get("version", "")

        for cve_id, cve_info in KNOWN_CVES.items():
            if cve_info["affected_service"] in service.lower():
                findings.append({
                    "cve": cve_id,
                    "service": service,
                    "port": port,
                    "version": version,
                    "description": cve_info["description"],
                    "kenyan_relevance": cve_info["kenyan_relevance"],
                })

    return findings