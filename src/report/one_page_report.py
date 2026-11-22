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

    # Exposure section
    lines.append("## Exposure Summary")
    if scan_findings:
        lines.append(f"- **{len(scan_findings)} exposed service(s) detected**")
        for finding in scan_findings:
            lines.append(f"  - Port {finding['port']}: {finding['service']} ({finding['cve']})")
    else:
        lines.append("- No exposed services detected")
    lines.append("")

    # Compliance section
    lines.append("## Data Protection Act Compliance")
    overall = compliance_results.overall_status()
    lines.append(f"- **Overall status: {overall.upper()}**")
    lines.append(f"- Registration: {compliance_results.results.get('registration', 'N/A')}")
    lines.append(f"- DPO designated: {compliance_results.results.get('dpo_designation', 'N/A')}")
    lines.append(f"- DPO contact published: {compliance_results.results.get('dpo_contact_published', 'N/A')}")
    lines.append("")

    # Action items
    lines.append("## Recommended Actions")
    if overall == "red":
        lines.append("- Immediate: Register with Office of the Data Protection Commissioner")
        lines.append("- Immediate: Designate a Data Protection Officer")
        if scan_findings:
            lines.append("- Review exposed services and apply relevant security patches")
    elif overall == "amber":
        lines.append("- Complete: DPO designation and registration pending")
        if scan_findings:
            lines.append("- Evaluate and patch exposed services")
    elif overall == "n/a":
        lines.append("- Compliance checks: not applicable to this validation target")
    else:
        lines.append("- Continue monitoring: All basic controls in place")

    lines.append("")
    lines.append("*This report is generated automatically for decision-makers. "
    "For detailed technical analysis, consult your IT security team.*")

    return "\n".join(lines)