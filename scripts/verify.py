import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_REPORT_SECTIONS = (
    "# Basic Exposure & Compliance Risk Report",
    "**Target:**",
    "## Exposure Summary",
    "## Data Protection Act Compliance",
    "## Recommended Actions",
    "no login or exploitation was attempted",
)


def check_config():
    config = yaml.safe_load((ROOT / "config/targets.yaml").read_text(encoding="utf-8")) or {}
    targets = [target for target in config.get("targets", []) if target.get("authorized") is True]

    if not targets:
        raise ValueError("No authorized targets configured")

    if not any(target.get("name") == "localhost" for target in targets):
        raise ValueError("localhost must remain authorized for the build scan")

    for target in targets:
        host = str(target.get("host", ""))
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host.lower() == "localhost"
        if loopback:
            continue
        notes = str(target.get("notes", "")).lower()
        if "authorization" not in notes or "signatory" not in notes:
            raise ValueError(
                f"Non-loopback target {target.get('name')!r} needs authorization and signatory in notes"
            )

    print("Config check: OK", flush=True)


def check_report(path=None):
    reports_dir = ROOT / "output/reports"
    report_path = Path(path) if path else max(reports_dir.glob("*.md"), key=lambda item: item.stat().st_mtime, default=None)
    if report_path is None or not report_path.is_file():
        raise ValueError("No report Markdown found in output/reports")

    text = report_path.read_text(encoding="utf-8")
    for section in REQUIRED_REPORT_SECTIONS:
        if section not in text:
            raise ValueError(f"Report is missing: {section}")

    lines = len(text.splitlines())
    words = len(text.split())
    if lines > 60:
        raise ValueError(f"Report is too long: {lines} lines")
    if words > 500:
        raise ValueError(f"Report is too long: {words} words")

    print(f"Report check: OK ({lines} lines, {words} words)", flush=True)


def check_outputs():
    scans = sorted((ROOT / "output/scans").glob("*.json"))
    reports = sorted((ROOT / "output/reports").glob("*.md"))
    if not scans or not reports:
        raise ValueError("No scan JSON or report Markdown found in output/")

    latest_scan = max(scans, key=lambda item: item.stat().st_mtime)
    latest_report = max(reports, key=lambda item: item.stat().st_mtime)
    data = json.loads(latest_scan.read_text(encoding="utf-8"))
    if not any("tcp" in host_data for host_data in data.values() if isinstance(host_data, dict)):
        raise ValueError(f"Scan JSON has no TCP data: {latest_scan}")

    check_report(latest_report)
    print("Output check: OK", flush=True)
    print(f"Latest scan: {latest_scan.relative_to(ROOT).as_posix()}", flush=True)
    print(f"Latest report: {latest_report.relative_to(ROOT).as_posix()}", flush=True)


def run(command):
    subprocess.run(command, check=True, cwd=ROOT)


def full_verify():
    check_config()
    run([sys.executable, "-m", "compileall", "-q", "src"])
    run([sys.executable, "-m", "pytest", "-q", "test_probe.py"])
    run([sys.executable, "src/main.py", "--target", "localhost", "--timeout", "60"])
    check_outputs()
    print("Build check: OK", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify Probe without requiring Bash")
    parser.add_argument("--check-config", action="store_true", help="Validate targets.yaml only")
    parser.add_argument("--check-report", nargs="?", const="", help="Validate latest or given report")
    parser.add_argument("--check-outputs", action="store_true", help="Validate latest scan and report")
    args = parser.parse_args(argv)

    try:
        if args.check_config:
            check_config()
        elif args.check_report is not None:
            check_report(args.check_report or None)
        elif args.check_outputs:
            check_outputs()
        else:
            full_verify()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: command failed: {' '.join(exc.cmd)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
