# Phase 0: Manual Assessment - Localhost Scan

**Target**: 127.0.0.1 (localhost)
**Date**: 2026-11-03
**Author**: Kilo

## Open Ports

| Port | State | Service | Notes |
|------|-------|---------|-------|
| 445/tcp | open | microsoft-ds (SMB) | SMB service detected |
| 80/tcp | closed | http | No web server listening |
| 443/tcp | closed | https | No TLS web server |
| 3389/tcp | closed | ms-wbt-server (RDP) | RDP not listening |

## Version Information

- SMB service on port 445: version not explicitly identified in basic scan
- No web services running on ports 80/443
- No RDP running on port 3389

## Compliance Checks

- ODPC registration: Not applicable for localhost
- DPO designation: Not applicable for localhost

## Observations

1. SMB (port 445) is the only open service - this is the primary exposure to flag
2. No web services (HTTP/HTTPS) running
3. RDP not exposed
4. All findings are consistent with a minimal Windows/local development setup

## Recommendations

- SMB on port 445 should be evaluated for necessity - SMBv1 should be disabled
- Ensure SMB version is patched against known CVEs
- Consider whether SMB exposure is expected for the target environment

## Phase 4: Validation (2026-11-25)

Command: `.\env\Scripts\python.exe src\main.py --target localhost --timeout 60`

| Port | State | Service | Scanner result |
|------|-------|---------|----------------|
| 445/tcp | open | microsoft-ds | SMB service exposed |
| 80/tcp | closed | http | Not reported |
| 443/tcp | closed | https | Not reported |
| 3389/tcp | closed | ms-wbt-server | Not reported |

- Findings: 1. No CVE was claimed because Nmap did not identify an SMB version.
- Compliance: N/A for localhost, as recorded in the manual assessment.
- False positives: none. Closed ports were not reported as exposure.
- Test suite: 13 passed.
- Scan data: `output/scans/` as JSON; report: `output/reports/` as Markdown. Both are ignored by git.
- Corrected interpretation: CVE-2017-0199 is an Office/WordPad OLE issue. Open SMB is reported as exposure only.

## Phase 5: ODPC Registration Lookup (2026-11-26)

Command: `.\env\Scripts\python.exe src\main.py --target localhost --organization "County Government of Nairobi" --register-file output\validation-odpc-register.csv --timeout 60`

- The register snapshot used for validation was synthetic and stored under `output/`, which is ignored by git.
- Exact active match returned GREEN and recorded the registration number in the report.
- Possible, missing, and expired cases are covered by tests.
- DPO status remains a manual input because ODPC does not publish a DPO register.
- Test suite: 21 passed.
