#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CF_SKILL_SRC="${REPO_ROOT}/skills/security-audit"
SEC_REMEDIATION_SRC="${REPO_ROOT}/skills/security-remediation"

AGY_SKILLS_ROOT="${HOME}/.gemini/config/skills"
GEMINI_CMD_DIR="${HOME}/.gemini/commands"
CLAUDE_CMD_DIR="${HOME}/.claude/commands"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
AGENTS_SKILLS_ROOT="${HOME}/.agents/skills"

echo "[install] 1. Installing to Antigravity / Gemini (${AGY_SKILLS_ROOT}) and Universal Agents (${AGENTS_SKILLS_ROOT})..."
mkdir -p "${AGY_SKILLS_ROOT}/security-audit" "${AGY_SKILLS_ROOT}/security-remediation"
mkdir -p "${AGENTS_SKILLS_ROOT}/security-audit" "${AGENTS_SKILLS_ROOT}/security-remediation"

cp -r "${CF_SKILL_SRC}/"* "${AGY_SKILLS_ROOT}/security-audit/"
cp -r "${SEC_REMEDIATION_SRC}/"* "${AGY_SKILLS_ROOT}/security-remediation/"
chmod +x "${AGY_SKILLS_ROOT}/security-remediation/scan-project.py"

cp -r "${CF_SKILL_SRC}/"* "${AGENTS_SKILLS_ROOT}/security-audit/"
cp -r "${SEC_REMEDIATION_SRC}/"* "${AGENTS_SKILLS_ROOT}/security-remediation/"
chmod +x "${AGENTS_SKILLS_ROOT}/security-remediation/scan-project.py"

# Optional workspace install if a target workspace path is passed as $1
if [[ $# -ge 1 && -d "$1" ]]; then
  WS_SKILLS_ROOT="$1/.agents/skills"
  echo "[install] 1b. Also installing to workspace (${WS_SKILLS_ROOT})..."
  mkdir -p "${WS_SKILLS_ROOT}/security-audit" "${WS_SKILLS_ROOT}/security-remediation"
  cp -r "${CF_SKILL_SRC}/"* "${WS_SKILLS_ROOT}/security-audit/"
  cp -r "${SEC_REMEDIATION_SRC}/"* "${WS_SKILLS_ROOT}/security-remediation/"
  chmod +x "${WS_SKILLS_ROOT}/security-remediation/scan-project.py"
fi

echo "[install] 2. Registering slash commands for Antigravity & Gemini CLI (${GEMINI_CMD_DIR})..."
mkdir -p "${GEMINI_CMD_DIR}"

cat > "${GEMINI_CMD_DIR}/security-remediation.toml" << 'EOF'
description = "Run hybrid DevSecOps (CVE/OSV.dev, Secrets, SAST/IDOR, Auto-Fix) + Cloudflare 6-Phase Adversarial Security Hunting"
prompt = """
Activate and follow the security remediation workflow in ~/.gemini/config/skills/security-remediation/SKILL.md:
1. Run `python3 ~/.gemini/config/skills/security-remediation/scan-project.py . --format markdown` (see DEVSECOPS-AND-CVE.md).
2. Consult the relevant domain companions in `~/.gemini/config/skills/security-audit/` (e.g., WEB-PROTOCOL-AND-AUTH.md, DATA-ISOLATION-AND-LIFECYCLE.md, HUNTING.md) to perform coverage-led contextual hunting.
3. Present findings grouped by severity (CRITICAL, HIGH, MEDIUM, LOW) and, when requested, apply safe non-breaking auto-fixes following `~/.gemini/config/skills/security-remediation/AUTO-REMEDIATION.md`.
"""
EOF

cat > "${GEMINI_CMD_DIR}/security-audit.toml" << 'EOF'
description = "Run Cloudflare 6-Phase Adversarial Security Audit (read-only full audit or guidance mode)"
prompt = """
Activate and follow the security audit workflow in ~/.gemini/config/skills/security-audit/SKILL.md.
"""
EOF

echo "[install] 3. Registering slash commands & skills for Claude Code / Claude Extension (${CLAUDE_CMD_DIR})..."
mkdir -p "${CLAUDE_CMD_DIR}" "${CLAUDE_SKILLS_DIR}"

ln -sf "${AGENTS_SKILLS_ROOT}/security-audit" "${CLAUDE_SKILLS_DIR}/security-audit"
ln -sf "${AGENTS_SKILLS_ROOT}/security-remediation" "${CLAUDE_SKILLS_DIR}/security-remediation"

cat > "${CLAUDE_CMD_DIR}/security-remediation.md" << 'EOF'
---
description: Run hybrid DevSecOps (CVE/OSV.dev, Secrets, SAST/IDOR, Auto-Fix) + Cloudflare-style security audit
---

Follow the security remediation workflow in `~/.agents/skills/security-remediation/SKILL.md`:
1. Run the deterministic baseline scanner:
   `python3 ~/.agents/skills/security-remediation/scan-project.py . --format markdown`
2. Inspect the repository for vulnerabilities and high-signal patterns (leaked secrets, IDOR in Server Actions, SQL injection, insecure cookies).
3. Group findings by severity (CRITICAL, HIGH, MEDIUM, LOW) and, when requested, apply safe non-breaking auto-fixes following `~/.agents/skills/security-remediation/AUTO-REMEDIATION.md`.
EOF

cat > "${CLAUDE_CMD_DIR}/security-audit.md" << 'EOF'
---
description: Run Cloudflare 6-Phase Adversarial Security Audit (read-only full audit or guidance mode)
---

Follow the security audit workflow in `~/.agents/skills/security-audit/SKILL.md` to conduct a structured 6-phase adversarial security audit on this codebase.
EOF

echo "[install] Done! Commands '/security-remediation' and '/security-audit' are now available in Antigravity, Gemini CLI, and Claude Extension / Code."
