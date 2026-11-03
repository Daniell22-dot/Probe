from src.scanner.port_scan import scan_ports
from src.scanner.version_check import check_versions
from src.compliance.odpc_checklist import ODPCChecklist
from src.report.one_page_report import generate_report

# Test port scan on localhost
scan = scan_ports('127.0.0.1', [80, 443, 445, 3389])
print('Port scan successful')

# Test version check
findings = check_versions(scan)
print(f'Version check findings: {findings}')

# Test compliance checklist
checklist = ODPCChecklist('127.0.0.1')
reg = checklist.check_registration()
dpo = checklist.check_dpo_designation()
contact = checklist.check_dpo_contact_published()
overall = checklist.overall_status()
print(f'Compliance - Reg: {reg}, DPO: {dpo}, Contact: {contact}, Overall: {overall}')

# Test report generation
report = generate_report(findings, checklist)
print('Report generated successfully')
print(report)