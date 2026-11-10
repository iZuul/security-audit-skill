---
name: security-all
description: Run unified 360° security review combining DevSecOps baseline scanning (OSV.dev CVEs, leaked secrets, SAST) and Cloudflare 6-phase adversarial audit into a single consolidated master report (SECURITY-ALL-REPORT.md). Triggered via /security-all or when the user asks for a complete or all-in-one security audit.
---

# Unified Security Review (`security-all`)

Orchestrate both `security-remediation` (DevSecOps baseline + auto-fix) and `security-audit` (Cloudflare 6-phase adversarial hunting) to produce a single, comprehensive `SECURITY-ALL-REPORT.md`.

## Execution Workflow

### 1. Phase 1: Deterministic DevSecOps Baseline
Run the scanner to discover all locked package CVEs, git commit leaks, and SAST leads:
```bash
python3 <skill-dir>/../security-remediation/scan-project.py . --format markdown -o ./DEVSECOPS-BASELINE.md
```

### 2. Phase 2: Adversarial Verification & Hunting
Using the methodology from `../security-audit/HUNTING.md` and domain companions:
- Verify if any discovered CVEs or SAST findings violate real trust boundaries and are reachable by external actors.
- Run adversarial verifiers to challenge and disprove candidate findings.
- Check architecture, session handling, tenant isolation, and client-side boundaries.

### 3. Phase 3: Consolidated Master Report Generation
Generate `SECURITY-ALL-REPORT.md` at the project root with the following structure:
- **Executive Summary & Risk Matrix**: Counts of Critical, High, Medium, Low findings across supply chain and source code.
- **1. Supply Chain & Dependency CVEs**: Table with package, installed version, CVE/GHSA ID, severity, reachability assessment, and patched version.
- **2. Secret, Environment & Git History Hygiene**: Hardcoded keys, tracked `.env` files, and credentials found in commit history.
- **3. Verified Source Code & Architectural Vulnerabilities**: Confirmed IDOR, SQL injection, XSS, or logic bugs with exact source line citations and reproduction boundaries.
- **4. Triaged False Positives**: Documented non-exploitable patterns (test mocks, internal dictionaries, unreachable dead code).
- **5. Actionable Remediation Roadmap**: Safe `package.json` overrides and non-breaking surgical code patches following `AUTO-REMEDIATION.md`.
