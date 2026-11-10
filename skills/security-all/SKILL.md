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
Derive and write `SECURITY-ALL-REPORT.md` at the project root strictly adhering to [../../standards/REPORT-STANDARDIZATION.md](../../standards/REPORT-STANDARDIZATION.md):

- **Header**: Standard document metadata, technology stack, audit standard, audit date, execution scope, and overall posture (`ASSESSED (Action Required)` or `HARDENED & VERIFIED`).
- **Executive Summary & Risk Matrix**: Standard GFM pipe table (no ASCII-art boxes) with threat categories: Supply Chain, Broken Access Control / IDOR, Auth & Sessions, Network/SSRF, Injection, Secrets & Git, and Container/CI, including Remediated counts and Status.
- **Section 1: Supply Chain & Dependency CVEs**: Standard GFM table (`Severity | Package | Locked Version | Advisory / CVE ID | Reachability Assessment & Exploitability | Patched Version | Remediation Status`).
- **Section 2: Secret, Environment & Git History Hygiene**: Subsections A (Git history last 50 commits), B (Environment files & `.gitignore`), C (Container & runtime leaks).
- **Section 3: Verified Source Code & Architectural Vulnerabilities**: Standard finding cards using `[SEC-*]` rule IDs with File & Location links, Trust Boundary, Vulnerability snippet, Exploitation & Impact, Surgical Fix, Verification, and Remediation Status.
- **Section 4: Triaged False Positives**: Structured GFM table (`Rule ID | File & Location | Context / Triggered Pattern | Triage Verdict (Why It Is Safe)`).
- **Section 5: Actionable Remediation Roadmap**: Prioritized fixes (Priority 1: Dependencies, Priority 2: Source code, Priority 3: Infrastructure) with a verification & regression checklist.
