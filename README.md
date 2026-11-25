# Basic Exposure Scanner

A lightweight tool for Kenyan SMEs and public sector units that:
1. Scans for basic exposed services (RDP, SMB, outdated Office/Windows)
2. Checks Data Protection Act registration/DPO compliance status
3. Produces a one-page risk report for non-technical decision-makers

## Status
Phase 0 manual assessment and Phase 4 localhost validation are complete. The scanner core is available for authorized targets only.

## Usage
From `D:\Probe`, using the local virtual environment:

```powershell
.\env\Scripts\python.exe src\main.py --target localhost
```

Only targets marked `authorized: true` in `config/targets.yaml` can be scanned. Results are written to
`output/scans/` and a plain-language report is written to `output/reports/`. Nmap must be installed on the machine.
If service detection takes longer than 10 seconds, add `--timeout 60` to the command.

Run the mock-based test suite with:

```powershell
.\env\Scripts\python.exe -m pytest
```

## Why this exists
Kenya's public sector has repeated breaches of basic controls:
presidency website defaced twice in 8 months, eCitizen lacked
backup site, Ministry of Energy used personal email for official
business. This tool makes that exposure visible before it becomes
a headline.

## Scope (deliberately narrow)
- NOT a penetration test
- NOT an AI threat detection system
- NOT Zero Trust or blockchain
- IS a checklist automated, with a report a Principal Secretary
  can read and act on