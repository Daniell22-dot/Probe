import pytest

from src.compliance.odpc_checklist import ODPCChecklist
from src.report.one_page_report import generate_report
from src.scanner import port_scan
from src.scanner.version_check import check_versions
from src import main


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

    monkeypatch.setattr(port_scan.nmap, "PortScanner", FakeScanner)

    result = port_scan.scan_ports("127.0.0.1", [80, 445], timeout=7)

    assert result["127.0.0.1"]["tcp"][445]["name"] == "microsoft-ds"
    assert port_scan.nmap.PortScanner().call is None
    assert result["127.0.0.1"]["tcp"][445]["state"] == "open"


def test_scan_ports_rejects_invalid_timing():
    with pytest.raises(ValueError, match="timing"):
        port_scan.scan_ports("127.0.0.1", [445], timing=9)


def test_check_versions_matches_microsoft_ds():
    scan = {
        "127.0.0.1": {
            "tcp": {
                445: {
                    "name": "microsoft-ds",
                    "state": "open",
                    "version": "",
                }
            }
        }
    }

    findings = check_versions(scan)

    assert len(findings) == 1
    assert findings[0]["cve"] == "CVE-2017-0199"
    assert findings[0]["port"] == 445


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


def test_generate_report_uses_target_metadata():
    checklist = ODPCChecklist("127.0.0.1")
    checklist.check_registration()
    checklist.check_dpo_designation()
    checklist.check_dpo_contact_published()
    findings = [{"port": 445, "service": "microsoft-ds", "cve": "CVE-2017-0199"}]

    report = generate_report(
        findings,
        checklist,
        target={"name": "localhost", "host": "127.0.0.1"},
        generated_at="2026-11-22T00:00:00Z",
    )

    assert "localhost (127.0.0.1)" in report
    assert "2026-11-22T00:00:00Z" in report
    assert "CVE-2017-0199" in report


def test_main_writes_scan_and_report(tmp_path, monkeypatch):
    scan = {
        "127.0.0.1": {
            "tcp": {
                445: {
                    "name": "microsoft-ds",
                    "state": "open",
                    "version": "",
                }
            }
        }
    }
    monkeypatch.setattr(main, "scan_ports", lambda *args, **kwargs: scan)

    result = main.main(["--target", "localhost", "--output-dir", str(tmp_path)])

    assert result == 0
    scan_files = list((tmp_path / "scans").glob("*.json"))
    report_files = list((tmp_path / "reports").glob("*.md"))
    assert len(scan_files) == 1
    assert len(report_files) == 1
    assert "CVE-2017-0199" in report_files[0].read_text(encoding="utf-8")


def test_main_refuses_unauthorized_target():
    with pytest.raises(SystemExit):
        main.main(["--target", "not-authorized"])
