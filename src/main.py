import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml

from src.compliance.odpc_checklist import ODPCChecklist
from src.compliance.odpc_register import load_register, lookup_registration
from src.report.one_page_report import generate_report
from src.scanner.port_scan import scan_ports
from src.scanner.version_check import check_versions

DEFAULT_CONFIG = ROOT / "config" / "targets.yaml"
DEFAULT_OUTPUT = ROOT / "output"
DEFAULT_PORTS = "80,443,445,3389"
COMPLIANCE_KEYS = {
    "registration",
    "dpo_designation",
    "dpo_contact_published",
}


def load_targets(path=DEFAULT_CONFIG):
    config = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    targets = []
    for target in config.get("targets", []):
        if target.get("authorized") is True:
            targets.append({
                "name": str(target["name"]),
                "host": str(target["host"]),
                "notes": str(target.get("notes", "")),
            })
    return targets


def select_target(targets, name=None):
    if name is None:
        if len(targets) != 1:
            raise ValueError("Specify --target when multiple authorized targets are configured")
        return targets[0]
    for target in targets:
        if target["name"] == name:
            return target
    raise ValueError(f"Target {name!r} is not authorized in config/targets.yaml")


def parse_ports(value):
    ports = []
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
    return sorted(set(ports))


def parse_statuses(values):
    statuses = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"Expected KEY=VALUE, got {item!r}")
        name, status = item.split("=", 1)
        name = name.strip()
        if name not in COMPLIANCE_KEYS:
            raise ValueError(f"Unknown compliance check: {name}")
        statuses[name] = status.strip().lower()
    return statuses


def is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Scan an authorized target and produce a one-page exposure report."
    )
    parser.add_argument("--target", help="Name of an authorized target from config/targets.yaml")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to authorized targets YAML")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help="Comma-separated ports or ranges")
    parser.add_argument("--timeout", type=int, default=10, help="Nmap process timeout in seconds")
    parser.add_argument("--timing", type=int, default=4, help="Nmap timing template from 0 to 5")
    parser.add_argument(
        "--compliance-status",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Override a compliance status: registration, dpo_designation, dpo_contact_published",
    )
    parser.add_argument(
        "--register-file",
        help="CSV, JSON, or HTML snapshot of the ODPC public register of data handlers",
    )
    parser.add_argument(
        "--organization",
        help="Legal name to look up; defaults to the target name and requires --register-file",
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT), help="Directory for scan and report files")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.organization and not args.register_file:
        parser.error("--organization requires --register-file")

    try:
        targets = load_targets(args.config)
        target = select_target(targets, args.target)
        ports = parse_ports(args.ports)
        statuses = parse_statuses(args.compliance_status)
        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        evidence = {}

        if args.register_file and "registration" not in statuses:
            rows = load_register(args.register_file, timeout=args.timeout)
            organization = args.organization or target["name"]
            registration_evidence = lookup_registration(
                organization, rows, timeout=args.timeout, checked_at=generated_at
            )
            evidence["registration"] = registration_evidence
            statuses["registration"] = registration_evidence["status"]

        if is_loopback(target["host"]):
            default_statuses = {key: "n/a" for key in COMPLIANCE_KEYS}
            default_statuses.update(statuses)
            statuses = default_statuses

        scan = scan_ports(target["host"], ports, timeout=args.timeout, timing=args.timing)
        findings = check_versions(scan)

        checklist = ODPCChecklist(target["host"], statuses=statuses, evidence=evidence)
        checklist.check_registration()
        checklist.check_dpo_designation()
        checklist.check_dpo_contact_published()
        overall = checklist.overall_status()

        report = generate_report(findings, checklist, target=target, generated_at=generated_at)
        slug = re.sub(r"[^a-z0-9-]+", "-", target["name"].lower()).strip("-") or "target"
        stamp = generated_at.replace(":", "").replace("-", "")
        output_dir = Path(args.output_dir)
        scan_dir = output_dir / "scans"
        report_dir = output_dir / "reports"
        scan_dir.mkdir(parents=True, exist_ok=True)
        report_dir.mkdir(parents=True, exist_ok=True)

        scan_path = scan_dir / f"{slug}-{stamp}.json"
        report_path = report_dir / f"{slug}-{stamp}.md"
        scan_path.write_text(json.dumps(scan, indent=2) + "\n", encoding="utf-8")
        report_path.write_text(report + "\n", encoding="utf-8")
        evidence_path = None
        if evidence:
            evidence_path = scan_dir / f"{slug}-{stamp}-compliance.json"
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Scan complete for {target['name']} ({target['host']})")
    print(f"Findings: {len(findings)} | Compliance: {overall}")
    print(f"Scan data: {scan_path}")
    print(f"Report: {report_path}")
    if evidence_path:
        print(f"Compliance evidence: {evidence_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
