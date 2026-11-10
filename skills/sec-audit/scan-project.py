#!/usr/bin/env python3
"""
sec-audit: Zero-dependency project security scanner.
Detects tech stack, checks git/env hygiene, audits dependencies (local CLI / OSV API),
and scans source code for hardcoded secrets, config leaks, and SAST vulnerability patterns.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

IGNORE_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "out",
    ".turbo",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    ".agents",
    ".agent",
    ".gemini",
    ".claude",
}

CODE_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".go", ".php", ".rb", ".java", ".sql",
}

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
}

SECRET_RULES = [
    (
        "CRITICAL",
        "SEC-SECRET-001",
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "CRITICAL",
        "SEC-SECRET-002",
        "Hardcoded Database Connection URI with Password",
        re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://(?:\$\{[^}]+\}|[^/\s:@\"'`$])+:(?!\$\{[^}]+\}@)([^@\s\"'`]{3,})@[^/\s\"'`]+"),
    ),
    (
        "HIGH",
        "SEC-SECRET-003",
        "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "HIGH",
        "SEC-SECRET-004",
        "Generic Hardcoded Secret / Token Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|auth[_-]?secret|jwt[_-]?secret|private[_-]?key|access[_-]?token)\b"
            r"\s*[:=]\s*[\"']([A-Za-z0-9_\-+/=]{16,})[\"']"
        ),
    ),
    (
        "HIGH",
        "SEC-SECRET-005",
        "GitHub / GitLab / Slack / Stripe Live Token",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|glpat-[A-Za-z0-9\-_]{20}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk_live_[A-Za-z0-9]{20,})\b"),
    ),
    (
        "MEDIUM",
        "SEC-CONFIG-001",
        "Fallback Hardcoded Secret in Code",
        re.compile(r"process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z0-9_]*\s*(?:\|\||\?\?)\s*[\"'][^\"']+[\"']"),
    ),
    (
        "MEDIUM",
        "SEC-CONFIG-002",
        "Public Exposure of Sensitive Env Var (NEXT_PUBLIC_ / VITE_)",
        re.compile(r"\b(?:NEXT_PUBLIC_|VITE_)[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|DATABASE_URL)[A-Z0-9_]*\b"),
    ),
    (
        "MEDIUM",
        "SEC-CONFIG-003",
        "Wildcard CORS Origin",
        re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']"),
    ),
]

SAST_RULES = [
    (
        "CRITICAL",
        "SAST-SQLI-001",
        "Potential SQL Injection via Raw String Interpolation",
        re.compile(r"(?:sql\.raw|\.query|\.execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*`[^`]*\$\{"),
    ),
    (
        "HIGH",
        "SAST-SQLI-002",
        "Potential SQL Injection via String Concatenation",
        re.compile(r"(?i)(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[^;\"'\n]+[\"']\s*\+\s*[a-zA-Z0-9_.$]+"),
    ),
    (
        "CRITICAL",
        "SAST-CMDI-001",
        "Potential Command Injection (exec / execSync / child_process with interpolation)",
        re.compile(r"\b(?:exec|execSync|popen|system|passthru|shell_exec)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)"),
    ),
    (
        "HIGH",
        "SAST-XSS-001",
        "Potential XSS via dangerouslySetInnerHTML / innerHTML / v-html",
        re.compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|v-html\s*=)"),
    ),
    (
        "HIGH",
        "SAST-EVAL-001",
        "Dangerous Dynamic Code Execution (eval / new Function)",
        re.compile(r"\b(?:eval|new\s+Function)\s*\("),
    ),
    (
        "MEDIUM",
        "SAST-SSRF-001",
        "Potential SSRF (fetch/axios with direct request parameter)",
        re.compile(r"\b(?:fetch|axios\.(?:get|post|request))\s*\(\s*(?:req\.|request\.|params\.|searchParams\.)"),
    ),
    (
        "MEDIUM",
        "SAST-PATH-001",
        "Potential Path Traversal (fs operation with request input)",
        re.compile(r"\bfs\.(?:readFile|readFileSync|createReadStream|unlink|writeFile)\s*\([^)]*(?:req\.|params\.|searchParams)"),
    ),
    (
        "MEDIUM",
        "SAST-CRYPTO-001",
        "Weak Hash Algorithm (MD5 / SHA1) or Math.random() for Token/Secret",
        re.compile(r"(?:createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)|Math\.random\s*\(\s*\)[^;\n]*(?:token|secret|password|key|otp|id))", re.IGNORECASE),
    ),
]


def detect_stack(root: Path) -> Dict[str, Any]:
    stack = {
        "languages": [],
        "frameworks": [],
        "package_managers": [],
        "orm": [],
        "auth": [],
    }
    pkg_json = root / "package.json"
    if pkg_json.exists():
        stack["languages"].append("JavaScript/TypeScript")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "next" in deps:
                stack["frameworks"].append(f"Next.js ({deps['next']})")
            if "react" in deps:
                stack["frameworks"].append(f"React ({deps['react']})")
            if "express" in deps:
                stack["frameworks"].append("Express")
            if "drizzle-orm" in deps:
                stack["orm"].append(f"Drizzle ORM ({deps['drizzle-orm']})")
            if "prisma" in deps or "@prisma/client" in deps:
                stack["orm"].append("Prisma")
            if "pg" in deps:
                stack["orm"].append("node-postgres (pg)")
            if "better-auth" in deps:
                stack["auth"].append(f"Better Auth ({deps['better-auth']})")
            if "next-auth" in deps:
                stack["auth"].append("NextAuth.js")
        except Exception:
            pass

    if (root / "package-lock.json").exists():
        stack["package_managers"].append("npm")
    if (root / "pnpm-lock.yaml").exists():
        stack["package_managers"].append("pnpm")
    if (root / "yarn.lock").exists():
        stack["package_managers"].append("yarn")
    if (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        stack["languages"].append("Python")
    if (root / "go.mod").exists():
        stack["languages"].append("Go")
    if (root / "composer.json").exists():
        stack["languages"].append("PHP")

    return stack


def check_git_env_hygiene(root: Path) -> List[Dict[str, Any]]:
    findings = []
    # Check if git tracks any .env files
    if (root / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "ls-files"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                tracked = proc.stdout.splitlines()
                for f in tracked:
                    basename = os.path.basename(f)
                    if basename.startswith(".env") and not basename.endswith((".example", ".sample", ".template")):
                        findings.append({
                            "severity": "CRITICAL",
                            "rule_id": "SEC-GIT-001",
                            "title": "Environment file tracked in Git repository",
                            "file": f,
                            "line": 1,
                            "snippet": f"`{f}` is tracked by git and may leak secrets in commit history.",
                        })
        except Exception:
            pass

    # Check .gitignore for .env coverage
    gitignore = root / ".gitignore"
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8", errors="ignore")
        if ".env" not in content:
            findings.append({
                "severity": "HIGH",
                "rule_id": "SEC-GIT-002",
                "title": ".env* missing from .gitignore",
                "file": ".gitignore",
                "line": 1,
                "snippet": "Add `.env*` (and `!.env.example`) to `.gitignore`.",
            })
    return findings


# Offline database of high-impact CVEs for airgapped/sandbox environments:
# Format: (ecosystem, package_name, max_vulnerable_version_exclusive, cve_id, severity, summary)
OFFLINE_KNOWN_CVES: List[Tuple[str, str, Tuple[int, int, int], str, str, str]] = [
    ("npm", "next", (14, 2, 25), "CVE-2025-29927", "CRITICAL", "Next.js Middleware Authorization Bypass via x-middleware-subrequest header (<14.2.25 / <15.2.3)"),
    ("npm", "next", (14, 1, 1), "CVE-2024-34351", "HIGH", "Next.js Server-Side Request Forgery (SSRF) in Server Actions"),
    ("npm", "axios", (1, 7, 4), "CVE-2024-39338", "HIGH", "Axios Server-Side Request Forgery (SSRF) and credential leak"),
    ("npm", "jsonwebtoken", (9, 0, 0), "CVE-2022-23529", "CRITICAL", "jsonwebtoken unrestricted key retrieval / RCE in verify()"),
    ("npm", "ws", (8, 17, 1), "CVE-2024-37890", "HIGH", "ws DoS when handling request with many HTTP headers"),
    ("npm", "braces", (3, 0, 3), "CVE-2024-4068", "HIGH", "braces Regular Expression Denial of Service (ReDoS)"),
    ("npm", "micromatch", (4, 0, 8), "CVE-2024-4067", "MEDIUM", "micromatch Regular Expression Denial of Service (ReDoS)"),
    ("npm", "cross-spawn", (7, 0, 5), "CVE-2024-21538", "HIGH", "cross-spawn Regular Expression Denial of Service (ReDoS)"),
    ("npm", "path-to-regexp", (0, 1, 10), "CVE-2024-45296", "HIGH", "path-to-regexp backtracking ReDoS vulnerability"),
    ("npm", "cookie", (0, 7, 0), "CVE-2024-47764", "LOW", "cookie accepts out-of-bounds characters in name, path, and domain"),
    ("PyPI", "fastapi", (0, 109, 1), "CVE-2024-24762", "HIGH", "FastAPI / python-multipart ReDoS vulnerability"),
    ("PyPI", "django", (4, 2, 16), "CVE-2024-45230", "HIGH", "Django potential DoS in urlize() and AdminPasswordChangeForm"),
    ("PyPI", "requests", (2, 32, 0), "CVE-2024-35195", "MEDIUM", "Requests subsequent requests ignore verify=False session state"),
    ("PyPI", "cryptography", (42, 0, 4), "CVE-2024-26130", "HIGH", "NULL pointer dereference in PKCS12 parsing"),
]


def parse_semver(ver_str: str) -> Optional[Tuple[int, int, int]]:
    m = re.match(r"^[vV]?(\d+)\.(\d+)\.(\d+)", ver_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def extract_locked_dependencies(root: Path) -> List[Tuple[str, str, str]]:
    """
    Extract (ecosystem, package_name, version) tuples from project lockfiles/manifests.
    Supports: package-lock.json, pnpm-lock.yaml, yarn.lock, requirements.txt, go.mod, composer.lock.
    """
    deps: Dict[Tuple[str, str, str], bool] = {}

    # 1. npm: package-lock.json
    pkg_lock = root / "package-lock.json"
    if pkg_lock.exists():
        try:
            data = json.loads(pkg_lock.read_text(encoding="utf-8", errors="ignore"))
            for pkg_path, meta in data.get("packages", {}).items():
                if not pkg_path or not isinstance(meta, dict):
                    continue
                ver = meta.get("version", "")
                name = pkg_path.split("node_modules/")[-1]
                if name and ver:
                    deps[("npm", name, ver)] = True
        except Exception:
            pass

    # 2. pnpm: pnpm-lock.yaml
    pnpm_lock = root / "pnpm-lock.yaml"
    if pnpm_lock.exists():
        try:
            content = pnpm_lock.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(r"^\s*/?(@?[a-zA-Z0-9._\-/]+)@(\d+\.\d+\.\d+[^\s(:]*)", content, re.MULTILINE):
                deps[("npm", m.group(1), m.group(2))] = True
        except Exception:
            pass

    # 3. Python: requirements.txt
    req_txt = root / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([a-zA-Z0-9_.\-]+)\s*==\s*([0-9a-zA-Z_.\-]+)", line)
                if m:
                    deps[("PyPI", m.group(1).lower(), m.group(2))] = True
        except Exception:
            pass

    # 4. Go: go.mod
    go_mod = root / "go.mod"
    if go_mod.exists():
        try:
            for line in go_mod.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = re.match(r"^\s*([a-zA-Z0-9_.\-/]+)\s+(v\d+\.\d+\.\d+[^\s/]*)", line)
                if m:
                    deps[("Go", m.group(1), m.group(2).lstrip("v"))] = True
        except Exception:
            pass

    # 5. PHP: composer.lock
    comp_lock = root / "composer.lock"
    if comp_lock.exists():
        try:
            data = json.loads(comp_lock.read_text(encoding="utf-8", errors="ignore"))
            for pkg in data.get("packages", []) + data.get("packages-dev", []):
                name = pkg.get("name", "")
                ver = pkg.get("version", "").lstrip("v")
                if name and ver:
                    deps[("Packagist", name, ver)] = True
        except Exception:
            pass

    return list(deps.keys())


def query_osv_api(deps: List[Tuple[str, str, str]]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Query https://api.osv.dev/v1/querybatch in batches of 500 packages,
    then hydrate vulnerability details (CVE aliases, severity, summary).
    """
    if not deps:
        return [], None

    vulns_found: List[Dict[str, Any]] = []
    vuln_cache: Dict[str, Tuple[str, str, str, str]] = {}
    batch_size = 500

    for i in range(0, len(deps), batch_size):
        chunk = deps[i : i + batch_size]
        payload = {
            "queries": [
                {"package": {"ecosystem": eco, "name": name}, "version": ver}
                for eco, name, ver in chunk
            ]
        }
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "sec-audit-scanner/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return [], f"OSV.dev API unreachable ({e})"

        results = resp_data.get("results", [])
        for (_, pkg_name, pkg_ver), res_item in zip(chunk, results):
            if not res_item or "vulns" not in res_item:
                continue
            for v in res_item["vulns"]:
                vuln_id = v.get("id", "UNKNOWN")
                if not vuln_id.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-")):
                    continue

                if vuln_id in vuln_cache:
                    cve_id, sev, summary, fixed_ver = vuln_cache[vuln_id]
                else:
                    cve_id = vuln_id
                    summary = f"OSV Advisory {vuln_id}"
                    sev = "MEDIUM"
                    fixed_ver = ""

                    # Hydrate CVE alias, severity, summary, and fixed version from OSV vuln endpoint
                    try:
                        detail_req = urllib.request.Request(
                            f"https://api.osv.dev/v1/vulns/{vuln_id}",
                            headers={"User-Agent": "sec-audit-scanner/1.0"},
                        )
                        with urllib.request.urlopen(detail_req, timeout=5) as d_resp:
                            d_data = json.loads(d_resp.read().decode("utf-8"))
                            aliases = d_data.get("aliases", [])
                            cves = [a for a in aliases if a.startswith("CVE-")]
                            if cves:
                                cve_id = f"{cves[0]} ({vuln_id})" if vuln_id != cves[0] else cves[0]
                            summary = (d_data.get("summary") or d_data.get("details", "")[:120] or summary).strip()
                            db_sev = d_data.get("database_specific", {}).get("severity", "")
                            if db_sev:
                                sev = str(db_sev).upper()
                                if sev == "MODERATE":
                                    sev = "MEDIUM"
                            for aff in d_data.get("affected", []):
                                for rng in aff.get("ranges", []):
                                    for ev in rng.get("events", []):
                                        if "fixed" in ev and not fixed_ver:
                                            fixed_ver = ev["fixed"]
                    except Exception:
                        pass

                    vuln_cache[vuln_id] = (cve_id, sev, summary, fixed_ver)

                fix_note = f" (Fix: >={fixed_ver})" if fixed_ver else ""
                vulns_found.append({
                    "package": pkg_name,
                    "severity": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                    "range": pkg_ver,
                    "fixAvailable": bool(fixed_ver),
                    "fixedIn": fixed_ver,
                    "via": f"[{cve_id}] {summary}{fix_note}",
                })

    return vulns_found, None


def check_offline_cve_db(deps: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
    """Check locked dependencies against built-in offline CVE rules & pre-release checks."""
    findings: List[Dict[str, Any]] = []
    for eco, name, ver in deps:
        parsed = parse_semver(ver)
        if parsed:
            for rule_eco, rule_pkg, max_ver, cve_id, sev, desc in OFFLINE_KNOWN_CVES:
                if eco == rule_eco and name == rule_pkg:
                    # Special handling for Next.js 15.x CVE-2025-29927 (< 15.2.3)
                    if rule_pkg == "next" and cve_id == "CVE-2025-29927" and parsed[0] == 15:
                        if parsed < (15, 2, 3):
                            findings.append({
                                "package": name,
                                "severity": sev,
                                "range": ver,
                                "fixAvailable": True,
                                "via": f"[{cve_id}] {desc}",
                            })
                    elif parsed < max_ver:
                        findings.append({
                            "package": name,
                            "severity": sev,
                            "range": ver,
                            "fixAvailable": True,
                            "via": f"[{cve_id}] {desc}",
                        })

        if any(k in name for k in ("auth", "neon", "jwt", "crypto", "sql", "pg", "next")) and (
            "-beta" in ver or "-alpha" in ver or "-rc" in ver
        ):
            findings.append({
                "package": name,
                "severity": "LOW",
                "range": ver,
                "fixAvailable": True,
                "via": f"Pre-release version ({ver}) used in security-sensitive dependency",
            })

    return findings


def run_dependency_audit(root: Path, use_osv: bool = True) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "source": "none",
        "vulnerabilities": [],
        "notes": [],
    }
    sources_used: List[str] = []

    # 1. Try native CLI tools if available (npm / pnpm / pip-audit / govulncheck / composer)
    if (root / "package-lock.json").exists():
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=20,
            )
            if proc.stdout:
                data = json.loads(proc.stdout)
                if "vulnerabilities" in data and isinstance(data["vulnerabilities"], dict):
                    sources_used.append("npm audit")
                    for pkg_name, info in data["vulnerabilities"].items():
                        sev = str(info.get("severity", "info")).upper()
                        via = info.get("via", [])
                        via_titles = [
                            f"[{v.get('cve', v.get('source', 'ADVISORY'))}] {v.get('title', '')}".strip()
                            if isinstance(v, dict)
                            else str(v)
                            for v in via
                        ]
                        result["vulnerabilities"].append({
                            "package": pkg_name,
                            "severity": sev,
                            "range": info.get("range", ""),
                            "fixAvailable": bool(info.get("fixAvailable")),
                            "via": ", ".join(via_titles[:3]),
                        })
        except Exception as e:
            result["notes"].append(f"Native CLI `npm audit` unavailable in environment ({e}); using direct lockfile + OSV/CVE engine.")

    if (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        try:
            proc = subprocess.run(
                ["pip-audit", "--format", "json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=20,
            )
            if proc.returncode in (0, 1) and proc.stdout:
                data = json.loads(proc.stdout)
                sources_used.append("pip-audit")
                for dep in data.get("dependencies", []):
                    for v in dep.get("vulns", []):
                        aliases = v.get("aliases", [])
                        cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", "PYSEC"))
                        result["vulnerabilities"].append({
                            "package": dep.get("name", ""),
                            "severity": "HIGH",
                            "range": dep.get("version", ""),
                            "fixAvailable": bool(v.get("fix_versions")),
                            "via": f"[{cve}] {v.get('description', '')[:120]}",
                        })
        except Exception:
            pass

    if (root / "go.mod").exists():
        try:
            proc = subprocess.run(
                ["govulncheck", "-json", "./..."],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=25,
            )
            if proc.stdout and '"osv"' in proc.stdout:
                sources_used.append("govulncheck")
        except Exception:
            pass

    if (root / "composer.lock").exists():
        try:
            proc = subprocess.run(
                ["composer", "audit", "--format=json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=20,
            )
            if proc.stdout:
                data = json.loads(proc.stdout)
                advisories = data.get("advisories", {})
                if isinstance(advisories, dict):
                    sources_used.append("composer audit")
                    for pkg_name, adv_list in advisories.items():
                        for adv in adv_list:
                            result["vulnerabilities"].append({
                                "package": pkg_name,
                                "severity": str(adv.get("severity", "HIGH")).upper(),
                                "range": adv.get("affectedVersions", ""),
                                "fixAvailable": True,
                                "via": f"[{adv.get('cve', adv.get('advisoryId', 'CVE'))}] {adv.get('title', '')}",
                            })
        except Exception:
            pass

    # 2. Extract locked dependencies and query OSV.dev API + Offline Known CVE DB
    locked_deps = extract_locked_dependencies(root)
    if locked_deps:
        result["total_locked_packages"] = len(locked_deps)
        if use_osv:
            osv_vulns, osv_err = query_osv_api(locked_deps)
            if osv_err:
                result["notes"].append(f"OSV.dev live API fallback: {osv_err}; using built-in Offline CVE Database.")
            else:
                sources_used.append("OSV.dev CVE API")
                result["vulnerabilities"].extend(osv_vulns)

        offline_vulns = check_offline_cve_db(locked_deps)
        sources_used.append("Offline CVE & Lockfile DB")
        # Deduplicate by (package, via)
        existing_keys = {(v["package"], v["via"]) for v in result["vulnerabilities"]}
        for ov in offline_vulns:
            if (ov["package"], ov["via"]) not in existing_keys:
                result["vulnerabilities"].append(ov)

    result["source"] = " + ".join(sources_used) if sources_used else "none"
    return result


def scan_route_auth_and_idor(root: Path, rel_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
    """Heuristic analyzer for Next.js App Router API routes & Server Actions."""
    findings = []
    is_api_route = (
        ("app/api/" in rel_path or "pages/api/" in rel_path)
        and os.path.basename(rel_path).startswith(("route.", "index."))
    )
    is_auth_handler = "api/auth/" in rel_path

    if is_api_route and not is_auth_handler:
        delegates_to_actions = "src/actions/" in content or "@/actions/" in content
        has_auth_check = any(
            token in content
            for token in ("getSession", "getServerSession", "auth(", "currentUser", "verifyToken", "requireAuth", "session")
        )
        if not has_auth_check and not delegates_to_actions:
            findings.append({
                "severity": "HIGH",
                "rule_id": "SAST-AUTH-001",
                "title": "API Route appears to lack session/authentication check",
                "file": rel_path,
                "line": 1,
                "snippet": "No session verification (`getSession`, `auth`, etc.) detected in API route.",
            })

    # Check Server Actions ("use server") for functions mutating by ID without workspace/org ownership check
    is_server_action = '"use server"' in content[:200] or "'use server'" in content[:200]
    if is_server_action:
        func_pattern = re.compile(r"export\s+async\s+function\s+([a-zA-Z0-9_]+)\s*\(")
        func_starts = []
        for idx, line in enumerate(lines):
            m = func_pattern.search(line)
            if m:
                func_starts.append((idx, m.group(1)))
        for i, (start_idx, func_name) in enumerate(func_starts):
            end_idx = func_starts[i + 1][0] if i + 1 < len(func_starts) else len(lines)
            func_body = "\n".join(lines[start_idx:end_idx])
            has_mut_by_id = (
                (".update(" in func_body or ".delete(" in func_body)
                and '.eq("id",' in func_body
            )
            has_ownership_check = any(
                chk in func_body
                for chk in (
                    "requireWorkspaceMember",
                    "requireOrganizationAdmin",
                    "requireOrganizationMember",
                    "getWorkspaceUserRole",
                    "SYSTEM_SUPER_ADMIN",
                    "isSuperAdmin",
                    '.eq("user_id",',
                    '.eq("userId",',
                    "inv.email",
                )
            )
            if has_mut_by_id and not has_ownership_check:
                findings.append({
                    "severity": "HIGH",
                    "rule_id": "SAST-IDOR-002",
                    "title": f"Server Action `{func_name}()` mutates record by ID without ownership/membership verification",
                    "file": rel_path,
                    "line": start_idx + 1,
                    "snippet": lines[start_idx].strip()[:140],
                })

    # Check Drizzle ORM `.update(...)` or `.delete(...)` with `.where(eq(...id...))` that doesn't check `userId`
    for idx, line in enumerate(lines, start=1):
        if re.search(r"\.(?:update|delete)\s*\(", line):
            window = "\n".join(lines[max(0, idx - 1): min(len(lines), idx + 8)])
            if ".where(" in window and "and(" not in window and "userId" not in window and "user_id" not in window:
                if "scripts/" not in rel_path and "auth" not in window.lower():
                    findings.append({
                        "severity": "HIGH",
                        "rule_id": "SAST-IDOR-001",
                        "title": "Potential IDOR: Database update/delete without `userId` ownership filter",
                        "file": rel_path,
                        "line": idx,
                        "snippet": line.strip()[:140],
                    })

    return findings


def check_nextjs_security_config(root: Path) -> List[Dict[str, Any]]:
    findings = []
    for cfg_name in ("next.config.ts", "next.config.mjs", "next.config.js"):
        cfg = root / cfg_name
        if cfg.exists():
            content = cfg.read_text(encoding="utf-8", errors="ignore")
            if "headers(" not in content and "headers:" not in content:
                findings.append({
                    "severity": "LOW",
                    "rule_id": "SEC-HEADER-001",
                    "title": "Missing HTTP Security Headers in Next.js config",
                    "file": cfg_name,
                    "line": 1,
                    "snippet": f"`{cfg_name}` does not configure `headers()` (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).",
                })
            if "ignoreBuildErrors: true" in content:
                findings.append({
                    "severity": "LOW",
                    "rule_id": "SEC-CONFIG-004",
                    "title": "TypeScript build errors ignored in Next.js config",
                    "file": cfg_name,
                    "line": 1,
                    "snippet": "`ignoreBuildErrors: true` can mask type-safety bugs in production builds.",
                })
    return findings


def check_docker_and_ci(root: Path) -> List[Dict[str, Any]]:
    """Audit Dockerfile, .dockerignore, and GitHub Actions workflows."""
    findings = []
    dockerfile = root / "Dockerfile"
    dockerignore = root / ".dockerignore"

    if dockerfile.exists():
        df_content = dockerfile.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^\s*COPY\s+\.\s+", df_content, re.MULTILINE):
            if not dockerignore.exists():
                findings.append({
                    "severity": "HIGH",
                    "rule_id": "SEC-DOCKER-001",
                    "title": "Dockerfile copies context (`COPY . .`) without a `.dockerignore` file",
                    "file": "Dockerfile",
                    "line": 1,
                    "snippet": "Local `.env` or `.git` secrets may be baked into the container image.",
                })
            else:
                di_content = dockerignore.read_text(encoding="utf-8", errors="ignore")
                if ".env" not in di_content:
                    findings.append({
                        "severity": "HIGH",
                        "rule_id": "SEC-DOCKER-002",
                        "title": "`.dockerignore` does not exclude `.env*` files",
                        "file": ".dockerignore",
                        "line": 1,
                        "snippet": "Add `.env*` to `.dockerignore` to prevent leaking local secrets into Docker images.",
                    })

        if not re.search(r"^\s*USER\s+(?!root\b)[a-zA-Z0-9_\-]+", df_content, re.MULTILINE):
            findings.append({
                "severity": "LOW",
                "rule_id": "SEC-DOCKER-003",
                "title": "Dockerfile does not specify a non-root `USER`",
                "file": "Dockerfile",
                "line": 1,
                "snippet": "Container processes will run as `root` by default unless `USER` is set.",
            })

    workflows_dir = root / ".github" / "workflows"
    if workflows_dir.exists() and workflows_dir.is_dir():
        untrusted_gh_expr = re.compile(
            r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|comment\.body|commits\[[^\]]+\]\.message)"
        )
        for wf in workflows_dir.glob("*.y*ml"):
            rel_wf = str(wf.relative_to(root)).replace("\\", "/")
            for idx, line in enumerate(wf.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                if untrusted_gh_expr.search(line):
                    findings.append({
                        "severity": "HIGH",
                        "rule_id": "SEC-CI-001",
                        "title": "Potential GitHub Actions Script Injection via untrusted event context",
                        "file": rel_wf,
                        "line": idx,
                        "snippet": line.strip()[:140],
                    })

    return findings


def scan_git_history(root: Path, max_commits: int = 50) -> List[Dict[str, Any]]:
    """Scan recent git commit diffs for historically leaked secrets."""
    findings = []
    if not (root / ".git").exists():
        return findings
    try:
        proc = subprocess.run(
            ["git", "log", "-p", f"-n{max_commits}", "--no-color"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0 or not proc.stdout:
            return findings

        current_commit = "unknown"
        current_file = "unknown"
        for line in proc.stdout.splitlines():
            if line.startswith("commit "):
                current_commit = line.split()[1][:10]
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
            elif line.startswith("+") and not line.startswith("+++"):
                added = line[1:].strip()
                if current_file in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
                    continue
                for sev, rule_id, title, pattern in SECRET_RULES:
                    if sev in ("CRITICAL", "HIGH") and pattern.search(added):
                        findings.append({
                            "severity": sev,
                            "rule_id": f"{rule_id}-HIST",
                            "title": f"[Git History commit {current_commit}] {title}",
                            "file": current_file,
                            "line": 1,
                            "snippet": f"Found in commit {current_commit} history",
                        })
    except Exception:
        pass
    return findings


def get_staged_files(root: Path) -> Optional[List[str]]:
    if not (root / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            return [f.strip() for f in proc.stdout.splitlines() if f.strip()]
    except Exception:
        pass
    return None


def apply_cve_overrides(root: Path, dep_audit: Dict[str, Any]) -> List[str]:
    """Auto-populate `overrides` in package.json for OSV.dev CVEs that have a known fixed version."""
    pkg_json_path = root / "package.json"
    if not pkg_json_path.exists():
        return []
    try:
        pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    overrides = pkg_data.get("overrides", {})
    applied = []
    for v in dep_audit.get("vulnerabilities", []):
        pkg = v.get("package")
        fixed_in = v.get("fixedIn")
        if pkg and fixed_in and pkg not in pkg_data.get("dependencies", {}) and pkg not in pkg_data.get("devDependencies", {}):
            target_range = f"^{fixed_in}"
            if overrides.get(pkg) != target_range:
                overrides[pkg] = target_range
                applied.append(f"{pkg}: {target_range}")

    if applied:
        pkg_data["overrides"] = overrides
        pkg_json_path.write_text(json.dumps(pkg_data, indent=2) + "\n", encoding="utf-8")
    return applied


def emit_coverage_ledger(root: Path, ledger_path: Path) -> Dict[str, Any]:
    """
    Cloudflare-style Coverage Ledger generator:
    Inventories all security-relevant units (API Routes, Server Actions, Auth/Middleware, DB Adapters, Infra)
    so the agent or sub-agents can systematically audit 100% of the attack surface without skipping files.
    """
    units: List[Dict[str, Any]] = []
    func_export_re = re.compile(r"export\s+(?:async\s+)?function\s+([a-zA-Z0-9_]+)")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_path = str(fpath.relative_to(root)).replace("\\", "/")
            ext = fpath.suffix.lower()
            if ext not in CODE_EXTENSIONS and fname not in ("Dockerfile", "docker-compose.yml", "next.config.ts"):
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            category = None
            if ("app/api/" in rel_path or "pages/api/" in rel_path) and fname.startswith(("route.", "index.")):
                category = "API_ROUTE"
            elif '"use server"' in content[:200] or "'use server'" in content[:200]:
                category = "SERVER_ACTION"
            elif any(k in rel_path.lower() for k in ("auth", "middleware", "turnstile", "session")):
                category = "AUTH_BOUNDARY"
            elif any(k in rel_path.lower() for k in ("db", "schema", "adapter")):
                category = "DATA_LAYER"
            elif fname in ("Dockerfile", "docker-compose.yml", "next.config.ts"):
                category = "INFRA_CONFIG"

            if category:
                exported_funcs = func_export_re.findall(content)
                units.append({
                    "unit_id": f"{category}:{rel_path}",
                    "category": category,
                    "file": rel_path,
                    "lines": len(content.splitlines()),
                    "entrypoints": exported_funcs,
                    "coverage_status": "AUDITED_BY_SCANNER",
                })

    ledger = {
        "schema_version": "1.0-sec-audit-cf-hybrid",
        "project": str(root),
        "total_units": len(units),
        "units": units,
    }
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    return ledger


def validate_findings_file(findings_path: Path) -> Tuple[bool, List[str]]:
    """
    Cloudflare-style deterministic schema validator for `findings.json`.
    Ensures every reported vulnerability has complete trace & adversarial verification metadata.
    """
    errors: List[str] = []
    if not findings_path.exists():
        return False, [f"File not found: {findings_path}"]
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, [f"Invalid JSON: {e}"]

    items = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return False, ["Root or `findings` key must be a JSON array"]

    required_fields = {"id", "title", "severity", "status", "file", "source_trace", "adversarial_review"}
    valid_statuses = {"CONFIRMED", "NEEDS_VALIDATION", "REJECTED", "FIXED"}
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"Item #{idx} is not an object")
            continue
        missing = required_fields - set(item.keys())
        if missing:
            errors.append(f"Finding `{item.get('id', idx)}` missing required fields: {sorted(missing)}")
        if item.get("status") not in valid_statuses:
            errors.append(f"Finding `{item.get('id', idx)}` has invalid status `{item.get('status')}` (must be one of {sorted(valid_statuses)})")
        if item.get("severity") not in valid_severities:
            errors.append(f"Finding `{item.get('id', idx)}` has invalid severity `{item.get('severity')}`")

    return len(errors) == 0, errors


def scan_files(root: Path, only_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    only_set = set(only_files) if only_files is not None else None

    if only_set is None:
        findings.extend(check_git_env_hygiene(root))
        findings.extend(check_nextjs_security_config(root))
        findings.extend(check_docker_and_ci(root))

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_path = str(fpath.relative_to(root)).replace("\\", "/")
            if only_set is not None and rel_path not in only_set:
                continue

            # Skip lockfiles and generated files
            if fname in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock"):
                continue
            # Skip local .env files from secret regex dumping (checked by git hygiene instead)
            if fname.startswith(".env") and not fname.endswith((".example", ".sample", ".template")):
                continue

            ext = fpath.suffix.lower()
            if ext not in CODE_EXTENSIONS and ext not in CONFIG_EXTENSIONS:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                    continue

                # Check secret & config rules
                for sev, rule_id, title, pattern in SECRET_RULES:
                    match = pattern.search(line)
                    if match:
                        # Redact potential secret in snippet
                        snippet = stripped[:140]
                        if match.groups():
                            secret_val = match.group(1)
                            if len(secret_val) > 4:
                                redacted = secret_val[:2] + "***REDACTED***" + secret_val[-2:]
                                snippet = snippet.replace(secret_val, redacted)
                        findings.append({
                            "severity": sev,
                            "rule_id": rule_id,
                            "title": title,
                            "file": rel_path,
                            "line": idx,
                            "snippet": snippet,
                        })

                # Check SAST rules on code files
                if ext in CODE_EXTENSIONS:
                    for sev, rule_id, title, pattern in SAST_RULES:
                        if pattern.search(line):
                            findings.append({
                                "severity": sev,
                                "rule_id": rule_id,
                                "title": title,
                                "file": rel_path,
                                "line": idx,
                                "snippet": stripped[:140],
                            })

            if ext in {".ts", ".tsx", ".js", ".jsx"}:
                findings.extend(scan_route_auth_and_idor(root, rel_path, content, lines))

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["file"], x["line"]))
    return findings


def format_markdown(root: Path, stack: Dict[str, Any], dep_audit: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    out = []
    out.append(f"# Security Audit Report (`sec-audit`)")
    out.append(f"**Target Project**: `{root}`\n")

    out.append("## 1. Detected Tech Stack")
    out.append(f"- **Languages**: {', '.join(stack['languages']) or 'Unknown'}")
    out.append(f"- **Frameworks**: {', '.join(stack['frameworks']) or 'None detected'}")
    out.append(f"- **Database / ORM**: {', '.join(stack['orm']) or 'None detected'}")
    out.append(f"- **Auth**: {', '.join(stack['auth']) or 'None detected'}")
    out.append(f"- **Package Managers**: {', '.join(stack['package_managers']) or 'None detected'}\n")

    out.append("## 2. Dependency & CVE Audit")
    out.append(f"- **Audit Source**: `{dep_audit.get('source', 'none')}`")
    if "total_locked_packages" in dep_audit:
        out.append(f"- **Locked Packages Inspected**: {dep_audit['total_locked_packages']}")
    for note in dep_audit.get("notes", []):
        out.append(f"- **Note**: {note}")
    vulns = dep_audit.get("vulnerabilities", [])
    if not vulns:
        out.append("- **Findings**: No known dependency advisories flagged.\n")
    else:
        out.append("\n| Severity | Package | Version / Range | Details |")
        out.append("| :--- | :--- | :--- | :--- |")
        for v in vulns:
            out.append(f"| **{v['severity']}** | `{v['package']}` | `{v['range']}` | {v['via']} |")
        out.append("")

    out.append("## 3. Static Code & Configuration Findings (SAST & Secrets)")
    if not findings:
        out.append("No static vulnerabilities or hardcoded secrets detected.\n")
    else:
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        summary = ", ".join(f"**{k}**: {v}" for k, v in counts.items())
        out.append(f"Summary: {summary}\n")
        out.append("| Severity | Rule ID | File:Line | Issue & Snippet |")
        out.append("| :--- | :--- | :--- | :--- |")
        for f in findings:
            loc = f"`{f['file']}:{f['line']}`"
            snip = f["snippet"].replace("|", "\\|").replace("`", "'")
            out.append(f"| **{f['severity']}** | `{f['rule_id']}` | {loc} | **{f['title']}**<br>`{snip}` |")
        out.append("")

    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="sec-audit: Hybrid DevSecOps & Cloudflare-style Adversarial Security Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to project root")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    parser.add_argument("-o", "--output", metavar="FILE", help="Save report output directly to FILE (.md or .json)")
    parser.add_argument("--staged", action="store_true", help="Fast pre-commit mode: only scan git staged files")
    parser.add_argument("--git-history", action="store_true", help="Scan recent git commit history for leaked secrets")
    parser.add_argument("--fix-cve", action="store_true", help="Auto-populate package.json overrides for OSV.dev CVEs")
    parser.add_argument("--no-osv", action="store_true", help="Skip live OSV.dev API calls and use only offline CVE database")
    parser.add_argument("--emit-ledger", metavar="FILE", help="Write Cloudflare-style coverage-ledger.json to FILE")
    parser.add_argument("--validate-findings", metavar="FILE", help="Validate structured findings.json schema")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path {root} does not exist", file=sys.stderr)
        sys.exit(1)

    if args.validate_findings:
        ok, errs = validate_findings_file(Path(args.validate_findings))
        if ok:
            print(f"[sec-audit] findings schema valid: {args.validate_findings}")
            sys.exit(0)
        else:
            for e in errs:
                print(f"[sec-audit] schema error: {e}", file=sys.stderr)
            sys.exit(1)

    if args.emit_ledger:
        ledger = emit_coverage_ledger(root, Path(args.emit_ledger))
        print(f"[sec-audit] Emitted coverage ledger with {ledger['total_units']} security units to {args.emit_ledger}")
        if not args.staged and not args.git_history and not args.fix_cve:
            return

    stack = detect_stack(root)
    staged_files = get_staged_files(root) if args.staged else None

    if args.staged and staged_files is not None and "package-lock.json" not in staged_files:
        dep_audit = {"source": "skipped (--staged fast mode)", "vulnerabilities": [], "notes": []}
    else:
        dep_audit = run_dependency_audit(root, use_osv=not args.no_osv)

    if args.fix_cve:
        applied = apply_cve_overrides(root, dep_audit)
        if applied:
            dep_audit.setdefault("notes", []).append(f"Auto-applied package.json overrides: {', '.join(applied)}")

    findings = scan_files(root, only_files=staged_files)
    if args.git_history:
        findings.extend(scan_git_history(root))

    if args.format == "json":
        report_str = json.dumps({
            "project": str(root),
            "stack": stack,
            "dependency_audit": dep_audit,
            "findings": findings,
        }, indent=2)
    else:
        report_str = format_markdown(root, stack, dep_audit, findings)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report_str + "\n", encoding="utf-8")
        print(f"[sec-audit] Report saved to: {out_path}")
    else:
        print(report_str)


if __name__ == "__main__":
    main()
