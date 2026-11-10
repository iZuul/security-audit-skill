# DevSecOps, CVE, and Automated Baseline Scanning

Use this companion during **Phase 1 (Reconnaissance)** and **Phase 2 (Coverage-led hunting)** or in **DevSecOps & Auto-Fix mode (`/sec-audit`)** to run deterministic baseline checks for live CVEs, leaked secrets, infrastructure misconfigurations, and static source patterns before or alongside agent-led hunting.

## Overview

`scan-project.py` is a zero-dependency Python 3 scanner bundled in this skill directory. It provides five automated capabilities that complement LLM source hunting:

1. **Live OSV.dev Batch CVE Lookup + Offline Curated CVE Floor**:
   - Parses `package-lock.json` (v2/v3), `package.json`, `requirements.txt`, `go.mod`, and `composer.json`.
   - Queries `https://api.osv.dev/v1/querybatch` in a single batch HTTP POST and hydrates vulnerability details from `https://api.osv.dev/v1/vulns/<id>` (`GHSA-*`, `CVE-*`, severity, and patched version `Fix: >=...`).
   - Falls back automatically to an embedded offline CVE floor (`next`, `ws`, `undici`, `zod`, `brace-expansion`, `postcss`, `jsonwebtoken`, `axios`, `lodash`, `tar`, `semver`, `ip`, `cryptography`, `fastapi`, `django`, `flask`, `pillow`) when running in an offline sandbox.
2. **Secret, `.env`, & Git History Hygiene**:
   - Detects tracked `.env` files (via `git ls-files`), missing `.gitignore` entries, hardcoded private keys (`SEC-SECRET-001`), database URLs with literal credentials (`SEC-SECRET-002`), cloud/SaaS API tokens (`SEC-SECRET-003`), and hardcoded auth secrets (`SEC-SECRET-004`).
   - Supports `--git-history` to inspect recent commits (`git log -p -n 50`) for secrets that were committed and later deleted.
3. **High-Signal SAST & Next.js Server Action IDOR Heuristics**:
   - Flags unverified session cookie `.split(".")[0]` parsing (`SEC-AUTH-001`), leaked password reset URLs in API responses (`SEC-AUTH-002`), SQL identifier interpolation (`SEC-SQL-001`), raw DOM XSS sinks (`SEC-XSS-001`), code execution (`SEC-RCE-001`), disabled TLS verification (`SEC-TLS-001`), and `"use server"` actions that execute `.update()` / `.delete()` without workspace/tenant authorization (`SEC-IDOR-001`).
4. **Container, CI/CD, & Next.js Config Auditing**:
   - Inspects `Dockerfile` (`USER` directive, `ADD https://`), `.dockerignore` (`.env` / `.git` exclusions), GitHub Actions `.github/workflows/*.yml` (`${{ github.event.* }}` script injection in `run:` blocks), and `next.config.ts` (`ignoreBuildErrors: true`).
5. **Coverage Ledger & Findings Contract Helpers**:
   - `--emit-ledger <path>` generates an initial `coverage-ledger.json` skeleton from discovered API routes, Server Actions, auth modules, and database adapters.
   - `--validate-findings <path>` provides a Python fallback validator when Node.js is unavailable.

---

## CLI Usage

Run `scan-project.py` from the target repository root:

```bash
# Standard Markdown report (Live OSV.dev CVE + Secrets + SAST/IDOR + Infra)
python3 <skill-dir>/scan-project.py <target-dir> --format markdown

# Save Markdown report directly to a file
python3 <skill-dir>/scan-project.py <target-dir> --format markdown -o <output-dir>/DEVSECOPS-SCAN.md

# JSON output for programmatic consumption
python3 <skill-dir>/scan-project.py <target-dir> --format json
```

### Specialized Flags

| Flag | Purpose |
|------|---------|
| `--staged` | Scan only staged Git files (`git diff --cached`) in `< 1s` for pre-commit checks |
| `--git-history` | Scan the last 50 Git commits (`git log -p -n 50`) for leaked credentials/tokens |
| `--fix-cve` | Automatically add or update `"overrides"` in `package.json` with minimum patched versions (`>=...`) from OSV.dev |
| `--no-osv` | Skip live OSV.dev API calls and use only the offline CVE table (for strict air-gapped environments) |
| `--emit-ledger <file>` | Write an initial `coverage-ledger.json` inventory of entry points |
| `--validate-findings <file>` | Validate `findings.json` structure and required fields |
| `-o, --output <file>` | Write scanner output directly to a file |

---

## Mapping Scanner Output into the Audit Workflow

Scanner results are **leads and deterministic dependency facts**, not a substitute for source verification:

1. **Code & SAST Rules (`SEC-AUTH-*`, `SEC-IDOR-*`, `SEC-SQL-*`, `SEC-XSS-*`, `SEC-RCE-*`)**:
   - Feed every code match into **Phase 2 (Coverage-led hunting)** and **Phase 3 (Candidate validation)**.
   - Verify whether upstream middleware, framework defaults, or caller constraints neutralize the sink before promoting to `confirmed`.
   - For example, `SEC-IDOR-001` flags `"use server"` files containing `.update()` / `.delete()` without a workspace check in the same file; a hunter must inspect each exported function in that file to trace which specific actions lack tenant/workspace verification.
2. **Dependency CVEs (`CVE-*`, `GHSA-*`, `OSV-*`)**:
   - Check whether the vulnerable package is a production runtime dependency or a build/dev-only dependency, and whether the vulnerable API surface is reachable in the target.
   - Include the complete OSV.dev CVE table in the report's dependency appendix or remediation plan.
3. **Secret & Git Hygiene Findings (`SEC-SECRET-*`, `SEC-ENV-*`, `SEC-GIT-*`)**:
   - Verify whether matched strings are live/default credentials or benign test placeholders (`example`, `changeme`, `${VAR:-default}` variable expansions).
   - Never copy raw secret values into retained report artifacts; redact the middle characters when citing evidence.
