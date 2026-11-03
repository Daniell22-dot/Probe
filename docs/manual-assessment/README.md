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

- SMB on port 445 should be evaluated for necessity - CVE-2017-0199 affects SMBv1
- Ensure SMB version is patched against known CVEs
- Consider whether SMB exposure is expected for the target environment