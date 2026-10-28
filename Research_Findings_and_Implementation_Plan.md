# Probe: Research Findings and Implementation Plan

**Project:** Probe (Basic Exposure Scanner and Compliance Snapshot Tool)
**Institution:** Dedan Kimathi University of Technology (DeKUT) — Centre for Data Research and Cyber Security (CeDReCS)
**Date:** 28 October 2026
**Current Phase:** Phase 0 (Manual Assessment Preparation)


## 1. Executive Summary

This report consolidates research findings on governance-level cybersecurity failures in Kenya's public sector and uses them to justify the design and boundaries of the Probe tool. The central conclusion is that repeated intrusions into high-value government systems are not the product of advanced persistent threats or AI-driven attacks, but of **long-standing failures in basic security hygiene and governance accountability**. The presidency website `president.go.ke` was defaced twice in eight months , the eCitizen platform was breached after an audit had already formally warned that it lacked a backup site and business continuity plan , and the State Department for Energy had officials using personal email for official business while failing to appoint a Data Protection Officer as required by law . These cases point to a single gap: **decision-makers cannot see their own basic exposure and compliance status before an incident becomes a headline**. Probe is designed to fill that gap, not to provide another advanced threat detection system.

The tool's scope is deliberately narrow: scan for basic exposed services, check Data Protection Act compliance status, and produce a one-page report readable by a Principal Secretary or County IT officer. The legal hook exists in Kenyan law, the threat evidence exists in national incident data, and the institutional home exists at DeKUT CeDReCS.


## 2. Research Findings: Evidence of Governance Failure in Kenya

### 2.1 Presidency Website: Two Defacements in Eight Months

**November 2025 incident.** A coordinated attack defaced multiple government websites, including `president.go.ke`, along with the ministries of Interior, Energy, Labour, Health, and Education, the DCI, and Immigration . Broadcasting and Telecommunications Principal Secretary Stephen Isaboke attributed the attack to a group known as PCP@Kenya and stated that websites were recovered within a couple of hours . Some defaced pages displayed neo-Nazi and white supremacist propaganda .

**July 2026 incident.** On Saturday 18 July 2026, `president.go.ke` was again defaced, this time with a ransom demand for **five Bitcoin** (approximately **KES 41.3 million**) and a threat to leak unspecified information . ICT Cabinet Secretary William Kabogo confirmed the attack and stated that the site was taken offline for containment and forensic analysis, claiming "no evidence" that sensitive data had been accessed . The defaced page read: "This message is the third time for you before we leak everything about you" .

**Key fact:** The interval between the two incidents was eight months. The first was a coordinated defacement; the second was a ransom defacement. This is a pattern, not bad luck.

### 2.2 eCitizen Platform: Audit Warning Preceded Breach

Auditor-General Nancy Gathungu's report for the financial year ended June 2023 recorded that eCitizen operated **without an approved ICT policy, without an ICT steering committee, without an approved business continuity plan, and without a secondary backup site** . The platform was breached days into the following financial year. The warning had been formally tabled in Parliament before the attack occurred . This is the clearest available evidence that the problem is not a lack of technical knowledge but a failure to act on known governance deficiencies.

### 2.3 State Department for Energy: Personal Email and Data Protection Non-Compliance

In July 2026, the National Assembly's Public Accounts Committee (PAC) grilled the State Department for Energy after an Auditor-General audit flagged gaps in compliance with the Data Protection Act, 2019 . The specific failures included:

- **Failure to appoint a Data Protection Officer** as required under Section 24 of the Act .
- **Failure to register** as required with the Office of the Data Protection Commissioner .
- **Officials using personal email accounts** (Yahoo, Gmail) to conduct official government business, contrary to a Head of the Public Service Circular issued on 14 June 2022 that bars public officers from using personal email for official communication .

Parliament ordered a systems audit of the department and directed the Principal Secretary to ensure full compliance and submit documentary evidence of corrective measures . The Committee's concern was explicit: the practice "weakens record keeping, reduces accountability and increases exposure to cyber security threats" .

### 2.4 National Threat Data: Basic Deficiencies Dominate

The National Kenya Computer Incident Response Team Coordination Centre (KE-CIRT/CC), domiciled at the Communications Authority of Kenya, reported **2.55 billion system attack events** in the July–September 2026 quarter alone . Key figures from that quarter:

- **Brute-force attacks rose 85.41%** to 44.95 million .
- **Web application attacks increased 57.62%** to 27.44 million .
- **Malware threats rose 20.01%** to 70.8 million .
- The regulator attributed threats to **weak credential management, particularly continued use of default passwords**, and identified **outdated software, weak access controls, and vulnerable databases** as the main exploitation vectors .

For the full financial year 2025/2026, Kenya recorded **11.12 billion cyber threat events**, a 29% increase from the previous year. System vulnerabilities accounted for the largest share at 10.64 billion events . The Communications Authority's Director-General, David Mugonyi, linked the threat landscape to "weak credential management" and "poor encryption practices" .

**This is directly relevant to Probe:** The attacks succeeding at scale in Kenya exploit the exact conditions that a basic exposure scanner can detect—exposed services, outdated software, weak authentication configurations. The tool does not need to detect novel threats; it needs to make visible the conditions that are already being exploited.

### 2.5 Legal and Regulatory Leverage

The Kenya Data Protection Act, 2019 provides the legal basis for Probe's compliance module. Section 24 defines the Data Protection Officer role . The Office of the Data Protection Commissioner has issued guidance on DPO designation, including the option for public bodies to share a DPO among several entities, taking into account size, complexity of processing, reporting lines, and operational independence .

However, the current framework has a documented weakness: designation is not mandatory in the way it is in Mauritius, there is no certification requirement, and there is no verification mechanism . This means the gap between legal requirement and actual compliance is exactly where a tool like Probe can intervene—by making non-compliance visible to the accounting officer and to Parliament.

The PAC's questioning of the Energy department demonstrates that Parliament is already using audit findings to enforce compliance . Probe's compliance snapshot would give accounting officers a way to see their status before the Auditor-General does.


## 3. Probe's Tool Definition and Design Boundaries

### 3.1 Core Functions (Three, Nothing More)

**Function 1: Basic exposure check.** Given an authorized target, scan for exposed RDP/VNC/SMB ports, outdated Windows/Office versions with known CVEs (specifically flagging CVE-2017-0199 given documented Kenyan exploitation patterns), publicly accessible cloud storage buckets, and missing MFA on administrative interfaces.

**Function 2: Data Protection Act compliance snapshot.** Check whether the organization has registered with the ODPC, designated a DPO, and published DPO contact details. Output a simple red/amber/green status on these legal requirements .

**Function 3: One-page risk report.** Generate a report readable by a Principal Secretary or County IT officer: what is exposed, what is missing, and what to fix first.

### 3.2 What Probe Is Not

- **Not a penetration test.** It does not attempt login, brute-force, or exploitation.
- **Not an AI threat detection system.** The documented threat data shows basic hygiene failures, not sophisticated novel attacks .
- **Not Zero Trust or blockchain.** Those frameworks address different problems and have no validated deployment path at DeKUT's scale.
- **Not a general-purpose global scanner.** It is built for Kenyan public sector and SME contexts, with detection priorities matched to documented local threats.

### 3.3 Authorized Targets Only

The tool must never scan an external IP or domain without written authorization recorded in `config/targets.yaml`. Scanning localhost and isolated test VMs is always permitted. This is a hard limit, not a guideline. The governance failure Probe addresses is the absence of accountability; replicating that failure by scanning unauthorized targets would be a direct contradiction.


## 4. Implementation Plan

### 4.1 Phase 0: Manual Assessment (Current Phase)

**Objective:** Manually assess one real target using existing open-source tools, document findings, and use that document as the requirements specification for the scanner.

**Steps:**
1. Identify one accessible target: a DeKUT department outside CeDReCS, a local SACCO, or a nearby county office. Obtain verbal or written permission.
2. Use Nmap from the command line to check for exposed ports. Use manual checks against the ODPC registration database for compliance status.
3. Document findings in `docs/manual-assessment/README.md`.
4. Do not write scanner automation until this document exists.

**Why this order:** The manual assessment defines what the scanner needs to catch. Writing code first produces a tool that detects what was easy to code, not what is actually exposed in Kenyan public sector environments.

### 4.2 Phase 1: Scanner Core

**Objective:** Automate the exposure check for authorized targets.

**Components:**
- `src/scanner/port_scan.py`: Wrap Nmap via `python-nmap`, with a mandatory `timeout` parameter (default 10 seconds).
- `src/scanner/version_check.py`: Compare detected service versions against a curated list of CVEs relevant to Kenya (starting with CVE-2017-0199).
- Output to `output/scans/` as XML or JSON.

### 4.3 Phase 2: Compliance Module

**Objective:** Check ODPC registration and DPO designation status.

**Components:**
- `src/compliance/odpc_checklist.py`: Manual or semi-automated lookup against the ODPC public register.
- Output: Red/amber/green status for each requirement.
- Reference: ODPC guidance on DPO designation and shared DPO arrangements for public bodies .

### 4.4 Phase 3: Report Generator

**Objective:** Produce a one-page report in plain language.

**Components:**
- `src/report/one_page_report.py`: Takes scan output and compliance status, produces a Markdown or plain-text report.
- Language: Non-technical. "You have 3 exposed services. You are missing 2 compliance items. Fix these first."

### 4.5 Phase 4: Validation

**Objective:** Test against the Phase 0 target and measure.

**Metrics:**
- Number of exposed services detected.
- Compliance gaps identified.
- Report readability (can a non-technical reader state the top three actions after reading?).
- False-positive rate (were any findings incorrect?).


## 5. Reference Links for Phase 0 Preparation

The following links should be visited during free time before starting Phase 0. They provide the primary evidence base for the project's justification.

### Government Website Incidents

1. **KBC, November 2025:** "State assessing damage extent of Monday's cyberattack" — https://www.kbc.co.ke/state-assessing-damage-extent-of-mondays-cyberattack/ 

2. **Anadolu Agency, July 2026:** "Hackers breach Kenyan president's official website, demand Bitcoin ransom" — https://www.anadoluagency.com/en/africa/hackers-breach-kenyan-presidents-official-website-demand-bitcoin-ransom/4002285 

3. **The Standard, July 2026:** "Kabogo: No sensitive data accessed after President's website hack" — https://www.standardmedia.co.ke/amp/national/article/2001553147/kabogo-no-sensitive-data-accessed-after-presidents-website-hack 

### eCitizen Audit and Breach

4. **Amnesty Kenya, August 2026:** "Kenya's Cybersecurity Gaps and Cost of Data Protection Failure" — https://www.amnestykenya.org/data-breaches-expose-more-than-systems-they-expose-accountability-failures/ 

### Energy Department Non-Compliance

5. **Radio Generation, July 2026:** "MPs question Energy State Department over failure to meet data protection rules" — https://radiogeneration.co.ke/mps-question-energy-state-department-over-failure-to-meet-data-protection-rules_43225 

6. **Daily Nation, July 2026:** "Revealed: Possible sensitive data breaches at Energy Ministry" — https://nation.africa/kenya/news/revealed-possible-sensitive-data-breaches-at-energy-ministry--5541252 

### National Threat Data

7. **The Kenyan Wallstreet, October 2026:** "Safaricom Faces 1.25bn Cyber Intrusion Attempts as Kenya Threats Rise" — https://kenyanwallstreet.com/safaricom-faces-1-25-billion-cyber-intrusion-attempts-as-kenya-threats-rise 

8. **Pulse Kenya, October 2026:** "Kenya records 11.12 billion cyber threats as mobile money and internet use surge" — https://www.pulse.co.ke/story/kenyas-cyber-threats-rise-29percent-as-mobile-money-grows-to-54-million-2026101211332948035 

### Legal and Regulatory Framework

9. **ODPC DPO Guidance Note (PDF):** https://www.odpc.go.ke/wp-content/uploads/2026/07/ODPC-%E2%80%93-Guidance-Note-for-Data-Protection-Officers-DPOs.pdf 

10. **Data Privacy Advocates, July 2026:** "Draft Guidelines on the Designation, Tasks, Position & Professional Development of Data Protection Officers" — https://dataprivacyadvocates.co.ke/resource-guidelines-dpo-framework 

11. **Data Privacy Advocates, July 2026:** "Kenya's DPO Framework Gap" — https://dataprivacyadvocates.co.ke/insight-kenya-dpo-framework-reform 


## 6. What to Do Immediately

Open `docs/manual-assessment/README.md` and begin the Phase 0 work. The folder structure is already in place. The reference links above provide the evidence for why this work matters. The next hour should be spent identifying one accessible target and documenting what you find manually—not writing Python.

The manual assessment is not a preliminary step to the "real" project. It is the requirements specification. The code will be better because it exists.


## 7. A Note on Scope Discipline

The research findings are stark, and the temptation to expand scope is real. The presidency website was defaced twice; the natural response is "we need better defenses everywhere." But Probe's value comes from its narrowness. It does one thing: it makes basic exposure and compliance gaps visible to the person who signs the report. If it also tried to be a threat detector, a SIEM, or a Zero Trust framework, it would become another unfinished prototype.

It is a failure of basic visibility and accountability. Probe addresses that failure, and nothing else.