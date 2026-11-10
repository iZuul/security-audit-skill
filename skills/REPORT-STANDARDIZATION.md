# Security Report Standardization Specification

This document establishes the universal reporting standard for all security skills in this repository:
1. **`security-all`** $\rightarrow$ `SECURITY-ALL-REPORT.md` (Unified 360° Consolidated Audit & Remediation Master Report)
2. **`security-remediation`** $\rightarrow$ `SECURITY-REMEDIATION-REPORT.md` (DevSecOps Baseline, CVEs, Secrets, SAST & Auto-Fix)
3. **`security-audit`** $\rightarrow$ `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` (Cloudflare 6-Phase Adversarial Audit)

All agents executing these skills **must strictly follow these formatting, structural, and semantic standards** to guarantee consistency across repositories, tech stacks, and execution modes.

---

## 1. Core Formatting Rules

1. **GitHub Flavored Markdown (GFM) Strict Compatibility**:
   - **Never use ASCII-art box drawings** (e.g. `┌───┬───┐`, `│...│`). They break in GitHub, GitLab, IDE webviews, and mobile readers.
   - **Always use standard GFM pipe tables** (`| Column | Column |` with `:---` alignment).
2. **Dual-Posture Capability**:
   - Every report must support both **Audit/Assessment Mode** (findings are open with recommended fixes) and **Remediated/Hardened Mode** (findings have been patched and verified).
   - Use clear status badges: `ASSESSED (Action Required)` or `HARDENED & VERIFIED (All Remediated)`.
3. **Clickable Source Links**:
   - Every code citation, file reference, and test must use markdown links pointing to repository-relative files with line numbers: `[path/to/file.ts#L42](path/to/file.ts#L42)` or `[ClassName](file:///abs/path#L10)`.

---

## 2. Standard Header Block

Every report must begin with this standardized header:

```markdown
# <Report Title> (`<REPORT-FILENAME.md>`)

**Target Repository**: `<repo-name>` (`<path>`)  
**Technology Stack**: `<languages, frameworks, database, runtime, package managers>`  
**Audit Standard**: `<security-all | security-remediation | security-audit>`  
**Audit Date**: `<YYYY-MM-DD>`  
**Overall Posture**: `<ASSESSED (Action Required) | HARDENED & VERIFIED (0 Critical, 0 High Remaining)>`  
**Execution Scope**: `<apps, packages, libraries, containers, and pipelines inspected>`  

---
```

---

## 3. Standard Executive Summary & Risk Matrix

The Risk Matrix must categorize findings using standard threat categories and display remediation status:

```markdown
## Executive Summary & Risk Matrix

<Brief executive summary paragraph highlighting methodology and key outcomes.>

### Consolidated Findings Matrix

| Threat Category | Critical | High | Medium | Low / Info | Triaged FP | Remediated | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Supply Chain & Dependencies (CVE)** | 0 | 2 | 1 | 0 | 0 | 3 / 3 | COMPLETED |
| **Broken Access Control & IDOR** | 0 | 1 | 1 | 0 | 0 | 2 / 2 | COMPLETED |
| **Authentication & Session Lifecycle** | 0 | 1 | 0 | 0 | 0 | 1 / 1 | COMPLETED |
| **Network & SSRF Boundaries** | 0 | 1 | 0 | 0 | 0 | 1 / 1 | COMPLETED |
| **Injection & Memory Safety (SQL/DOM/RCE)** | 0 | 0 | 1 | 1 | 0 | 2 / 2 | COMPLETED |
| **Secrets, Environment & Git Hygiene** | 0 | 0 | 1 | 1 | 1 | 2 / 2 | COMPLETED |
| **Container & CI/CD Infrastructure** | 0 | 0 | 1 | 0 | 0 | 1 / 1 | COMPLETED |
| **TOTAL** | **0** | **5** | **5** | **2** | **1** | **12 / 12** | **HARDENED** |
```

> If in initial assessment mode (before fixes are applied), the `Remediated` column displays `0 / Total` and `Status` displays `OPEN`.

---

## 4. Standard Supply Chain & Dependency CVE Table

The dependency audit must use this exact column order and include reachability assessment:

```markdown
## 1. Supply Chain & Dependency CVEs

<Statement of total locked packages inspected and databases queried (OSV.dev, NVD, GHSA).>

| Severity | Package | Locked Version | Advisory / CVE ID | Reachability Assessment & Exploitability | Patched Version | Remediation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | `@sentry/nextjs` | `10.38.0` | [CVE-2026-114139](https://nvd.nist.gov/vuln/detail/CVE-2026-114139)<br>[GHSA-mchm-gjx6-7h55](https://github.com/advisories/GHSA-mchm-gjx6-7h55) | **Reachable**: Target activates `tunnelRoute: '/monitoring'` in `next.config.mjs`, causing Next.js middleware bypass. | `>=10.75.2`<br>`>=9.47.2` | **REMEDIATED** via package.json override |
| **HIGH** | `follow-redirects` | `1.16.0` | [CVE-2026-111755](https://nvd.nist.gov/vuln/detail/CVE-2026-111755) | **Reachable**: Used by HTTP client; cross-origin redirects leak Authorization headers. | `>=1.16.2` | **OPEN** |
```

---

## 5. Standard Secret, Environment & Git History Hygiene

Group findings into three standardized subsections:

```markdown
## 2. Secret, Environment & Git History Hygiene

### A. Git History Inspection (Last 50 Commits)
- **Methodology**: Inspected commit diffs via `scan-project.py --git-history` or `git log -p -n 50`.
- **Finding**: <No leaked secrets found OR details of credentials committed and deleted>.

### B. Environment & Configuration Files (`SEC-ENV-*`)
- **Inspection**: Inspected tracked `.env*` files via `git ls-files` and checked `.gitignore` rules.
- **Finding**: <Details of missing .gitignore rules or untracked .env files>.

### C. Container, Entrypoint & Runtime Secret Leaks (`SEC-CONFIG-*`)
- **Inspection**: Reviewed Dockerfiles, entrypoint scripts, and CI workflow secrets.
- **Finding**: <Details of environment echo logging, hardcoded fallback keys, or secrets printed to stdout>.
```

---

## 6. Standard Source Code & Architectural Vulnerabilities

Every code finding must follow this standardized card format with consistent Rule IDs (`SEC-*`):

```markdown
## 3. Verified Source Code & Architectural Vulnerabilities

### [SEC-IDOR-001] Broken Object Level Authorization on Broker Deletion (`HIGH`)
- **Remediation Status**: **REMEDIATED** (or **OPEN**)
- **File & Location**: [`lib/app_web/live/broker_live.ex:152`](lib/app_web/live/broker_live.ex#L152)
- **Trust Boundary**: Authenticated User Input -> Multi-tenant Database Mutation
- **Vulnerability**: Deletion handler retrieved broker by primary key ID without verifying ownership.
- **Exploitation & Impact**: Authenticated User A could supply User B's UUID to delete foreign resources.
- **Surgical Fix**:
  ```elixir
  # Safe, contract-preserving code snippet
  ```
- **Verification**: Verified by automated test in `test/app_web/broker_test.exs` and typechecker.
```

---

## 7. Standard Triaged False Positives Table

False positives must **always be presented in a clean GFM table** (never unstructured bullet paragraphs):

```markdown
## 4. Triaged False Positives

| Rule ID | File & Location | Context / Triggered Pattern | Triage Verdict (Why It Is Safe) |
| :--- | :--- | :--- | :--- |
| `SEC-SECRET-004` | [`packages/ui/__test__/mock.test.ts:42`](packages/ui/__test__/mock.test.ts#L42) | Mock bearer token string `accessToken: 'eyJ...'` | **False Positive**: Isolated test fixture for mock token parsing; never bundled into production runtime. |
| `SAST-XSS-001` | [`priv/static/assets/app.js:220`](priv/static/assets/app.js#L220) | Framework virtual DOM parser | **False Positive**: Compiled framework morphdom engine reflection; not an unvalidated user sink. |
| `SEC-CONFIG-001` | [`packages/ui/src/utils/idle.ts:22`](packages/ui/src/utils/idle.ts#L22) | Fallback value `'13'` in `process.env` | **False Positive**: 13-minute session idle timer default, not an API credential. |
```

---

## 8. Standard Actionable Remediation Roadmap

The roadmap must be prioritized logically:

```markdown
## 5. Actionable Remediation Roadmap

### Priority 1: Patch Vulnerable Transitive Dependencies
<Exact package.json overrides, pnpm.overrides, or mix.exs / requirements.txt snippet with safe floors>.

### Priority 2: Surgical Source Code Fixes
<Ordered implementation steps for Critical and High source vulnerabilities>.

### Priority 3: Configuration, Environment & Infrastructure Hardening
<Dockerignore, entrypoint log redaction, and gitignore hardening steps>.

### Verification & Regression Checklist
- [x] Dependency audit clean (`mix hex.audit` or `npm audit` or `scan-project.py`)
- [x] Static typecheck & compilation passes with zero warnings
- [x] Automated test suite executed and all passing
```

---

## 9. Skill-Specific Mapping

| Skill | Primary Output File | Sections Required | Special Requirements |
|---|---|---|---|
| **`security-all`** | `SECURITY-ALL-REPORT.md` | Full Sections 1 through 5 | Full 360° consolidated master report combining DevSecOps + Cloudflare adversarial audit. |
| **`security-remediation`** | `SECURITY-REMEDIATION-REPORT.md` | Sections 1, 2, 3, 5 | Focuses on DevSecOps baseline, CVE tables, high-signal SAST/IDOR, and non-breaking surgical patch execution. |
| **`security-audit`** | `REPORT.md` & `FINDINGS-DETAIL.md` | Executive Summary, Confirmed Findings, Needs Validation, Ledger | Cloudflare 6-phase formal audit; uses GFM tables for Confirmed and Needs Validation items. |
