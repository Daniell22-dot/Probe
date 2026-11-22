import nmap


def scan_ports(host, ports, timeout=10, timing=4, arguments=None):
    """Scan specified ports on host using Nmap via nmap library.

    Args:
        host: Target IP or hostname
        ports: Comma-separated port string or list of ports
        timeout: Nmap process timeout in seconds
        timing: Nmap timing template (0=paranoid, 5=insane)
        arguments: Optional complete Nmap argument string

    Returns:
        dict with parsed scan results: {host: {tcp: {port: {name, version, state}}}}}
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not 0 <= timing <= 5:
        raise ValueError("timing must be between 0 and 5")

    scanner = nmap.PortScanner()
    port_str = ",".join(str(p) for p in ports) if isinstance(ports, list) else ports
    arguments = arguments or f"-T{timing} -sV"
    scanner.scan(host, port_str, arguments=arguments, timeout=timeout)
    return _parse_scan_output(scanner)


def _parse_scan_output(scanner):
    """Parse nmap PortScanner output into a structured dict.

    Args:
        scanner: nmap PortScanner object

    Returns:
        dict with host/port/tcp state info
    """
    result = {}
    hosts = scanner.all_hosts()
    if not hosts:
        return result

    host = hosts[0]
    host_data = {}
    tcp_data = scanner[host].get("tcp", {}) if scanner.has_host(host) else {}

    for port, info in tcp_data.items():
        host_data[port] = {
            "name": info.get("name", ""),
            "state": info.get("state", ""),
            "version": info.get("version", ""),
        }

    result[host] = {"tcp": host_data}
    return result


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
        scan_result: dict from scan_ports output

    Returns:
        List of CVE findings matching detected services
    """
    findings = []

    host_data = scan_result.get(list(scan_result.keys())[0], {}) if scan_result else {}

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