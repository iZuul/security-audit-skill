# security-audit-skill

An enhanced security audit and DevSecOps skill suite for AI coding agents (Antigravity, Gemini CLI, Claude Code, Cursor, Codex, and compatible agent harnesses).

> **Note on Origin**: This repository is an extended fork of Cloudflare's [`security-audit-skill`](https://github.com/cloudflare/security-audit-skill) (seeded from Cloudflare's vulnerability discovery harness described in [*Build your own vulnerability harness*](https://blog.cloudflare.com/build-your-own-vulnerability-harness)). It retains the original 6-phase adversarial audit skill untouched while introducing **`security-remediation`**, a hybrid DevSecOps scanning and safe auto-remediation workflow.

---

## What's in this Repository

This repository packages two complementary skills:

```
security-audit-skill/
├── skills/
│   ├── security-remediation/ # Extended DevSecOps + CVE + SAST + Auto-Remediation
│   └── security-audit/       # Original Cloudflare 6-Phase Adversarial Audit (Untouched)
├── install.sh                # One-click installer for Antigravity & Gemini CLI
└── README.md
```

### Feature Comparison

| Capability | `skills/security-remediation` (Extended) | `skills/security-audit` (Cloudflare Upstream) |
|---|:---:|:---:|
| **Operating Modes** | DevSecOps & Auto-Fix (`/security-remediation`), Full Audit, Guidance | Full Audit (`/security-audit`), Guidance |
| **Live Dependency CVE Scan** | **Yes** (OSV.dev batch API via `scan-project.py`) | Manual agent exploration |
| **Offline CVE Fallback** | **Yes** (embedded offline CVE floor for air-gapped runs) | No |
| **Git & Secret Hygiene** | **Yes** (API keys, DB credentials, `--git-history`, `.env`) | Prompt-based checks |
| **High-Signal SAST & IDOR** | **Yes** (Server Action IDOR, raw SQL, XSS, RCE, insecure cookies) | Adversarial hunting prompts |
| **Auto-Remediation** | **Yes** (Surgical patches, non-breaking rules, `--fix-cve`) | Read-only reporting |
| **6-Phase Adversarial Hunt** | **Yes** (Integrates Cloudflare attack classes & validators) | **Yes** (Core 6-phase workflow) |
| **Findings & Ledger Validation** | Node.js validators + Python fallback validator | Node.js zero-dependency validators |
| **Slash Command Integration** | `/security-remediation`, `/security-all` | `/security-audit`, `/security-all` |

---

## 1. `security-remediation`: DevSecOps & Safe Auto-Remediation

The `security-remediation` skill combines deterministic baseline scanning with LLM-driven adversarial hunting and verified non-breaking remediation.

### Key Capabilities

1. **Deterministic Baseline Scanner (`scan-project.py`)**:
   - Zero-dependency Python 3 CLI tool.
   - **Live OSV.dev Batch CVE Lookup**: Queries `https://api.osv.dev/v1/querybatch` for `package-lock.json`, `package.json`, `requirements.txt`, `go.mod`, and `composer.json`.
   - **Offline CVE Floor**: Automatically falls back to an embedded CVE table in air-gapped sandboxes (`next`, `ws`, `undici`, `zod`, `jsonwebtoken`, `axios`, `lodash`, `cryptography`, `fastapi`, `django`, etc.).
   - **Secret & Git Hygiene**: Scans for leaked keys, tokens, hardcoded DB credentials, tracked `.env` files, and past commits (`--git-history`).
   - **Next.js & SAST Heuristics**: Detects broken access control / IDOR in `"use server"` actions (`SEC-IDOR-001`), unverified cookie slicing (`SEC-AUTH-001`), raw SQL interpolation (`SEC-SQL-001`), code execution (`SEC-RCE-001`), and Docker/CI misconfigurations.
2. **Safe Auto-Remediation (`AUTO-REMEDIATION.md`)**:
   - Explicit guardrails against breaking production: preserves UI/API contracts, return signatures, database schema, and dev ergonomics.
   - Automated dependency override updates via `--fix-cve`.
   - Post-fix verification requirement: re-runs linter, typechecker (`tsc --noEmit`), and scanner.
3. **Hybrid Workflow**:
   - Feeds deterministic findings directly into Cloudflare's Phase 2 (Hunting) and Phase 3 (Candidate Validation) for adversarial proof.

---

## 2. `security-audit`: Cloudflare 6-Phase Adversarial Audit

The pristine Cloudflare audit skill runs a rigorous, read-only adversarial audit across six structured phases:

1. **Reconnaissance**: Maps architecture, trust boundaries, and deterministic coverage in `architecture.md` and `coverage-ledger.json`.
2. **Coverage-led Hunting**: Assigns isolated hunter agents to ledger units with domain-specific attack classes.
3. **Candidate Validation**: Each candidate finding is assigned to a fresh verifier agent that attempts to disprove it.
4. **Structured Output**: Records `confirmed`, `needs_validation`, and `rejected` verdicts in `findings.json` validated against `report-schema.json`.
5. **Independent Record Verification**: Fresh agents verify final source citations.
6. **Target-Neutral Reporting**: Derives `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`.

---

## Installation

### Option A: One-Click Installer (Antigravity & Gemini CLI)

Run [`install.sh`](install.sh) from the repository root:

```bash
chmod +x install.sh
./install.sh
```

This script:
1. Installs `security-remediation` and `security-audit` into `~/.gemini/config/skills/` and `~/.agents/skills/`.
2. Registers `/security-all`, `/security-remediation`, and `/security-audit` slash commands for Antigravity, Gemini CLI, and Claude Extension / Code.

To also install both skills directly into a specific project workspace (`.agents/skills/`):

```bash
./install.sh /path/to/target-project
```

### Option B: Skills CLI (`npx skills`)

Install individual skills using the [Skills CLI](https://skills.sh):

```bash
# Install the extended DevSecOps + Auto-Fix skill
npx skills add https://github.com/iZuul/security-audit-skill \
  --skill security-remediation --global

# Install the upstream Cloudflare adversarial audit skill
npx skills add https://github.com/iZuul/security-audit-skill \
  --skill security-audit --global
```

---

## Usage

### In AI Coding Agents

#### 🌟 All-in-One Master Audit (`/security-all`)
Use `/security-all` to run both DevSecOps scanning and Cloudflare adversarial audit in one pass, generating a consolidated master report `SECURITY-ALL-REPORT.md`:

```text
/security-all
```

```text
run full security audit on this project and save consolidated report to SECURITY-ALL-REPORT.md
```

#### DevSecOps & Remediation (`/security-remediation`)
Use `/security-remediation` or natural language prompts:

```text
/security-remediation
```

```text
security-remediation: scan this repository for CVEs, secrets, and IDOR vulnerabilities, then suggest safe fixes
```

```text
run security-remediation baseline scan and fix package.json CVE overrides
```

#### Adversarial 6-Phase Audit (`/security-audit`)
Use `/security-audit` or standard audit triggers:

```text
/security-audit
```

```text
security audit this codebase, output to ~/audits/project-alpha
```

```text
pen-test the authentication flow in ./src/auth
```

---

### Standalone CLI: `scan-project.py`

You can also run the bundled Python scanner directly outside of an agent:

```bash
# Output readable Markdown report to stdout
python3 skills/security-remediation/scan-project.py . --format markdown

# Save Markdown report directly to a file
python3 skills/security-remediation/scan-project.py . --format markdown -o DEVSECOPS-SCAN.md

# Output JSON for CI/CD pipelines
python3 skills/security-remediation/scan-project.py . --format json

# Fast pre-commit scan on staged files (< 1s)
python3 skills/security-remediation/scan-project.py . --staged

# Scan the last 50 Git commits for leaked credentials or secrets
python3 skills/security-remediation/scan-project.py . --git-history

# Automatically add or update safe "overrides" in package.json from OSV.dev fixes
python3 skills/security-remediation/scan-project.py . --fix-cve

# Force offline mode (skip external OSV.dev network requests)
python3 skills/security-remediation/scan-project.py . --no-osv
```

---

## Repository Structure

```
.
├── install.sh                                # Automated setup script
├── LICENSE                                   # MIT License
├── README.md                                 # Documentation
└── skills/
    ├── security-remediation/                 # Extended DevSecOps & Auto-Fix Skill
    │   ├── SKILL.md                          # Skill definition & execution safety
    │   ├── DEVSECOPS-AND-CVE.md              # Scanner guide & rule catalog
    │   ├── AUTO-REMEDIATION.md               # Non-breaking fix rules & code patterns
    │   ├── scan-project.py                   # Multi-language zero-dependency scanner
    │   └── scan-project.test.cjs             # Unit tests for scanner
    │
    └── security-audit/                       # Original Cloudflare Audit Skill
        ├── SKILL.md                          # Core principles & 6-phase workflow
        ├── RECONNAISSANCE.md                 # Phase 1: Mapping & coverage ledger
        ├── HUNTING.md                        # Phase 2: Orchestration & hunter prompts
        ├── VALIDATION-AND-REPORTING.md       # Phases 3-6: Verification & reports
        ├── ATTACK-CLASSES.md                 # Universal & wildcard attack prompts
        ├── AI-AND-LLM.md                     # LLM / Prompt-injection attack classes
        ├── CLIENT-SIDE.md                    # DOM, XSS, prototype-pollution classes
        ├── CLOUD-AND-DEPLOYMENT.md           # IAM, containers, serverless, IaC
        ├── DATA-ISOLATION-AND-LIFECYCLE.md   # Multi-tenancy, caches, data lifecycle
        ├── DESKTOP-MOBILE-AND-LOCAL-IPC.md   # IPC, deep-links, native apps
        ├── MEMORY-SAFETY-AND-BINARY.md       # Native memory safety & kernel classes
        ├── PROTOCOLS-RPC-AND-MESSAGING.md    # RPC, serialization, webhooks, queues
        ├── RESOURCE-EXHAUSTION-AND-AVAILABILITY.md # Quotas, rate-limits, DoS classes
        ├── SUPPLY-CHAIN-AND-RELEASE.md       # CI/CD, signing, package dependencies
        ├── WEB-PROTOCOL-AND-AUTH.md          # HTTP framing, caching, auth protocols
        ├── report-schema.json                # JSON schema for findings.json
        ├── validate-findings.cjs             # Validator for findings.json
        ├── validate-findings.test.cjs        # Tests for findings validator
        ├── validate-coverage-ledger.cjs      # Validator for coverage-ledger.json
        └── validate-coverage-ledger.test.cjs # Tests for coverage ledger validator
```

---

## Requirements

- **Python 3.8+** (for `scan-project.py`, zero external pip dependencies).
- **Node.js 18+** (for zero-dependency findings and coverage ledger validation scripts).
- **Git** (for repository reconnaissance and secret history scans).
- An AI coding agent with support for tool execution, bash commands, and isolated sub-agents.

---

## Design Principles

- **Establish Real Boundary Failures**: Findings require a concrete affected principal, resource, and security impact. Defense-in-depth gaps are hardening notes, not vulnerabilities.
- **Adversarial Separation**: The verifier agent that evaluates a candidate finding is never the hunter that reported it.
- **Non-Breaking Remediation**: Security fixes must preserve existing public API signatures, UI component contracts, and database integrity.
- **Graceful Degradation**: If network access is restricted by sandbox policies, tools gracefully fall back to local offline heuristics and deterministic inspection.

---

## License & Attribution

- **License**: MIT License -- see [LICENSE](LICENSE).
- **Upstream Project**: Forked and extended from [Cloudflare `security-audit-skill`](https://github.com/cloudflare/security-audit-skill) (Copyright (c) 2025 Cloudflare, Inc.).
