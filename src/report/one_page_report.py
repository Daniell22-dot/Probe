def _finding_label(finding):
    label = f"{finding.get('title', finding.get('service', 'Finding'))} on port {finding.get('port', '?')}"
    cve = finding.get("cve")
    return f"{label} ({cve})" if cve else label


def generate_report(scan_findings, compliance_results, target=None, generated_at=None):
    """Generate a one-page risk report in non-technical language.

    Args:
        scan_findings: List of dicts from port_scan/version_check
        compliance_results: ODPCChecklist instance
        target: Optional authorized target dict with name and host
        generated_at: Optional timestamp string

    Returns:
        Markdown-formatted report string
    """
    if isinstance(target, dict):
        target_name = target.get("name") or target.get("host") or "Authorized target"
        target_host = target.get("host")
    else:
        target_name = target or "Authorized target"
        target_host = None

    target_label = f"{target_name} ({target_host})" if target_host else target_name
    generated = generated_at or "automated"

    lines = []
    lines.append("# Basic Exposure & Compliance Risk Report")
    lines.append("")
    lines.append(f"**Target:** {target_label} | **Generated:** {generated}")
    lines.append("")

    lines.append("## Exposure Summary")
    if scan_findings:
        lines.append(f"- **{len(scan_findings)} finding(s) detected**")
        for finding in scan_findings:
            lines.append(f"  - {_finding_label(finding)}")
        lines.append("- Checks used service banners only; no login or exploitation was attempted.")
    else:
        lines.append("- No exposed services or known version issues detected")
    lines.append("")

    lines.append("## Data Protection Act Compliance")
    overall = compliance_results.overall_status()
    lines.append(f"- **Overall status: {overall.upper()}**")
    lines.append(f"- Registration: {compliance_results.results.get('registration', 'N/A')}")
    lines.append(f"- DPO designated: {compliance_results.results.get('dpo_designation', 'N/A')}")
    lines.append(f"- DPO contact published: {compliance_results.results.get('dpo_contact_published', 'N/A')}")
    lines.append("")

    lines.append("## Recommended Actions")
    actions = []
    for finding in scan_findings:
        action = finding.get("recommendation")
        if action and action not in actions:
            actions.append(action)

    if overall == "red":
        actions.append("Register with the Office of the Data Protection Commissioner")
        actions.append("Designate a Data Protection Officer")
    elif overall == "amber":
        actions.append("Complete DPO designation and registration")
    elif overall == "n/a":
        actions.append("Compliance checks are not applicable to this validation target")
    else:
        actions.append("Continue monitoring basic compliance controls")

    for action in actions:
        lines.append(f"- {action}")

    lines.append("")
    lines.append("*This report is generated automatically for decision-makers. "
    "For detailed technical analysis, consult your IT security team.*")

    return "\n".join(lines)
