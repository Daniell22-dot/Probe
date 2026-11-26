import pytest
from nmap.nmap import PortScannerTimeout

from src.compliance.odpc_checklist import ODPCChecklist
from src.compliance.odpc_register import load_register, lookup_registration
from src.report.one_page_report import generate_report
from src.scanner import port_scan
from src.scanner.version_check import check_versions
from src import main


def _scan(tcp):
    return {"127.0.0.1": {"tcp": tcp}}


def _register_csv(tmp_path, row):
    path = tmp_path / "register.csv"
    path.write_text(
        "Data Handler Name,Data Handler Type,Registration Number,County,Country,Status\n"
        f"{row}\n",
        encoding="utf-8",
    )
    return path


def test_scan_ports_passes_timeout_and_parses_fake_nmap(monkeypatch):
    class FakeScanner:
        def __init__(self):
            self.call = None
            self.host = None

        def scan(self, hosts, ports, arguments, timeout):
            self.call = (hosts, ports, arguments, timeout)
            self.host = hosts

        def all_hosts(self):
            return [self.host] if self.host else []

        def has_host(self, host):
            return host == self.host

        def __getitem__(self, host):
            return {
                "tcp": {
                    445: {
                        "name": "microsoft-ds",
                        "state": "open",
                        "version": "",
                    }
                }
            }

    scanner = FakeScanner()
    monkeypatch.setattr(port_scan.nmap, "PortScanner", lambda: scanner)

    result = port_scan.scan_ports("127.0.0.1", [80, 445], timeout=7)

    assert scanner.call == ("127.0.0.1", "80,445", "-T4 -sV", 7)
    assert result["127.0.0.1"]["tcp"][445]["name"] == "microsoft-ds"
    assert result["127.0.0.1"]["tcp"][445]["state"] == "open"


def test_scan_ports_rejects_invalid_timing():
    with pytest.raises(ValueError, match="timing"):
        port_scan.scan_ports("127.0.0.1", [445], timing=9)


def test_scan_ports_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="timeout"):
        port_scan.scan_ports("127.0.0.1", [445], timeout=0)


def test_scan_ports_reports_timeout(monkeypatch):
    class TimeoutScanner:
        def scan(self, hosts, ports, arguments, timeout):
            raise PortScannerTimeout("slow")

    monkeypatch.setattr(port_scan.nmap, "PortScanner", TimeoutScanner)

    with pytest.raises(TimeoutError, match="timed out"):
        port_scan.scan_ports("127.0.0.1", [445], timeout=1)


def test_check_versions_flags_exposed_smb_without_cve_claim():
    findings = check_versions(_scan({
        445: {"name": "microsoft-ds", "state": "open", "version": ""},
    }))

    assert len(findings) == 1
    assert findings[0]["kind"] == "exposure"
    assert findings[0]["title"] == "SMB service exposed"
    assert findings[0]["cve"] is None


def test_check_versions_flags_rdp_and_vnc():
    findings = check_versions(_scan({
        3389: {"name": "ms-wbt-server", "state": "open", "version": ""},
        5900: {"name": "vnc", "state": "open", "version": ""},
    }))

    assert [finding["title"] for finding in findings] == [
        "Remote Desktop exposed",
        "VNC remote access exposed",
    ]


def test_check_versions_flags_outdated_windows_version():
    findings = check_versions(_scan({
        135: {"name": "msrpc", "state": "open", "version": "Windows Server 2008 R2 SP1"},
    }))

    assert len(findings) == 1
    assert findings[0]["kind"] == "version"
    assert findings[0]["title"] == "Outdated Windows version reported"
    assert findings[0]["cve"] is None


def test_check_versions_flags_cve_2017_0199_from_office_banner():
    findings = check_versions(_scan({
        80: {"name": "http", "state": "open", "version": "Microsoft WordPad 2010"},
    }))

    assert len(findings) == 1
    assert findings[0]["kind"] == "cve"
    assert findings[0]["cve"] == "CVE-2017-0199"


def test_check_versions_ignores_closed_ports():
    findings = check_versions(_scan({
        445: {"name": "microsoft-ds", "state": "closed", "version": ""},
    }))

    assert findings == []


def test_odpc_checklist_supports_not_applicable():
    checklist = ODPCChecklist(
        "127.0.0.1",
        statuses={
            "registration": "n/a",
            "dpo_designation": "n/a",
            "dpo_contact_published": "n/a",
        },
    )
    checklist.check_registration()
    checklist.check_dpo_designation()
    checklist.check_dpo_contact_published()

    assert checklist.overall_status() == "n/a"


def test_load_register_supports_html_table(tmp_path):
    path = tmp_path / "register.html"
    path.write_text(
        "<html><body><table>"
        "<tr><th>Data Handler Name</th><th>Data Handler Type</th>"
        "<th>Registration Number</th><th>Status</th></tr>"
        "<tr><td>Nairobi County Government</td><td>Data Controller</td>"
        "<td>INST-123</td><td>Active</td></tr>"
        "</table></body></html>",
        encoding="utf-8",
    )

    rows = load_register(path)

    assert rows[0]["registration_number"] == "INST-123"
    assert rows[0]["status"] == "Active"


def test_lookup_registration_exact_active_match(tmp_path):
    path = _register_csv(
        tmp_path,
        "Nairobi County Government,Data Controller,INST-123,NAIROBI,Kenya,Active",
    )
    rows = load_register(path)

    evidence = lookup_registration(
        "County Government of Nairobi", rows, checked_at="2026-11-26T00:00:00Z"
    )

    assert evidence["status"] == "green"
    assert evidence["confidence"] == "exact"
    assert evidence["registration_number"] == "INST-123"
    assert evidence["checked_at"] == "2026-11-26T00:00:00Z"


def test_lookup_registration_possible_match_is_amber(tmp_path):
    path = _register_csv(
        tmp_path,
        "Nairobi County Government,Data Controller,INST-123,NAIROBI,Kenya,Active",
    )
    rows = load_register(path)

    evidence = lookup_registration("Nairobi County", rows)

    assert evidence["status"] == "amber"
    assert evidence["confidence"] == "possible"


def test_lookup_registration_no_match_is_red(tmp_path):
    path = _register_csv(
        tmp_path,
        "Mombasa County Government,Data Controller,INST-456,MOMBASA,Kenya,Active",
    )
    rows = load_register(path)

    evidence = lookup_registration("Nairobi County Government", rows)

    assert evidence["status"] == "red"
    assert evidence["confidence"] == "none"


def test_lookup_registration_expired_match_is_red(tmp_path):
    path = _register_csv(
        tmp_path,
        "Nairobi County Government,Data Controller,INST-123,NAIROBI,Kenya,Expired",
    )
    rows = load_register(path)

    evidence = lookup_registration("Nairobi County Government", rows)

    assert evidence["status"] == "red"
    assert evidence["register_status"] == "Expired"


def test_generate_report_uses_target_metadata():
    checklist = ODPCChecklist("127.0.0.1")
    checklist.check_registration()
    checklist.check_dpo_designation()
    checklist.check_dpo_contact_published()
    findings = check_versions(_scan({
        445: {"name": "microsoft-ds", "state": "open", "version": ""},
    }))

    report = generate_report(
        findings,
        checklist,
        target={"name": "localhost", "host": "127.0.0.1"},
        generated_at="2026-11-22T00:00:00Z",
    )

    assert "localhost (127.0.0.1)" in report
    assert "2026-11-22T00:00:00Z" in report
    assert "SMB service exposed on port 445" in report
    assert "no login or exploitation was attempted" in report


def test_generate_report_shows_registration_evidence():
    evidence = {
        "registration": {
            "confidence": "exact",
            "registration_number": "INST-123",
            "handler_type": "Data Controller",
            "source": "output/odpc-register.csv",
            "note": "",
        }
    }
    checklist = ODPCChecklist("192.168.1.10", evidence=evidence)
    checklist.check_registration()
    checklist.check_dpo_designation()
    checklist.check_dpo_contact_published()

    report = generate_report([], checklist)

    assert "exact match from output/odpc-register.csv" in report
    assert "INST-123 (Data Controller)" in report


def test_main_writes_scan_and_report(tmp_path, monkeypatch):
    scan = _scan({
        445: {"name": "microsoft-ds", "state": "open", "version": ""},
    })
    monkeypatch.setattr(main, "scan_ports", lambda *args, **kwargs: scan)

    result = main.main(["--target", "localhost", "--output-dir", str(tmp_path)])

    assert result == 0
    scan_files = list((tmp_path / "scans").glob("*.json"))
    report_files = list((tmp_path / "reports").glob("*.md"))
    assert len(scan_files) == 1
    assert len(report_files) == 1
    assert "SMB service exposed on port 445" in report_files[0].read_text(encoding="utf-8")
    assert "CVE-2017-0199" not in report_files[0].read_text(encoding="utf-8")


def test_main_uses_register_file_for_registration(tmp_path, monkeypatch):
    scan = _scan({})
    monkeypatch.setattr(main, "scan_ports", lambda *args, **kwargs: scan)
    register = _register_csv(
        tmp_path,
        "Nairobi County Government,Data Controller,INST-123,NAIROBI,Kenya,Active",
    )

    result = main.main([
        "--target", "localhost",
        "--organization", "County Government of Nairobi",
        "--register-file", str(register),
        "--output-dir", str(tmp_path),
    ])

    assert result == 0
    report_text = list((tmp_path / "reports").glob("*.md"))[0].read_text(encoding="utf-8")
    assert "INST-123" in report_text
    assert "Registration: green" in report_text
    evidence_files = list((tmp_path / "scans").glob("*-compliance.json"))
    assert len(evidence_files) == 1
    assert "INST-123" in evidence_files[0].read_text(encoding="utf-8")


def test_manual_registration_status_overrides_register(tmp_path, monkeypatch):
    scan = _scan({})
    monkeypatch.setattr(main, "scan_ports", lambda *args, **kwargs: scan)
    register = _register_csv(
        tmp_path,
        "Nairobi County Government,Data Controller,INST-123,NAIROBI,Kenya,Active",
    )

    result = main.main([
        "--target", "localhost",
        "--organization", "County Government of Nairobi",
        "--register-file", str(register),
        "--compliance-status", "registration=red",
        "--output-dir", str(tmp_path),
    ])

    assert result == 0
    report_text = list((tmp_path / "reports").glob("*.md"))[0].read_text(encoding="utf-8")
    assert "Registration: red" in report_text
    assert "INST-123" not in report_text
    assert not list((tmp_path / "scans").glob("*-compliance.json"))


def test_main_refuses_unauthorized_target():
    with pytest.raises(SystemExit):
        main.main(["--target", "not-authorized"])
