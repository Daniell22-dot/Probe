import nmap
from nmap.nmap import PortScannerTimeout


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
    try:
        scanner.scan(host, port_str, arguments=arguments, timeout=timeout)
    except PortScannerTimeout as exc:
        raise TimeoutError(f"Nmap timed out after {timeout} seconds") from exc
    return _parse_scan_output(scanner)


def _parse_scan_output(scanner):
    """Parse nmap PortScanner output into a structured dict.

    Args:
        scanner: nmap PortScanner object

    Returns:
        dict with host/port/tcp state info
    """
    result = {}

    for host in scanner.all_hosts():
        host_data = {}
        tcp_data = scanner[host].get("tcp", {}) if scanner.has_host(host) else {}

        for port, info in tcp_data.items():
            host_data[int(port)] = {
                "name": info.get("name", ""),
                "state": info.get("state", ""),
                "version": info.get("version", ""),
            }

        if host_data:
            result[host] = {"tcp": host_data}

    return result
