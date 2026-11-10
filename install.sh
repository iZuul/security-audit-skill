#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CF_SKILL_SRC="${REPO_ROOT}/skills/security-audit"
SEC_AUDIT_SRC="${REPO_ROOT}/skills/sec-audit"

AGY_SKILLS_ROOT="${HOME}/.gemini/config/skills"
GEMINI_CMD_DIR="${HOME}/.gemini/commands"

echo "[install] 1. Installing 'security-audit' (Cloudflare) and 'sec-audit' (DevSecOps + Auto-Fix) to ${AGY_SKILLS_ROOT}..."
mkdir -p "${AGY_SKILLS_ROOT}/security-audit" "${AGY_SKILLS_ROOT}/sec-audit"

cp -r "${CF_SKILL_SRC}/"* "${AGY_SKILLS_ROOT}/security-audit/"
cp -r "${SEC_AUDIT_SRC}/"* "${AGY_SKILLS_ROOT}/sec-audit/"
chmod +x "${AGY_SKILLS_ROOT}/sec-audit/scan-project.py"

# Optional workspace install if a target workspace path is passed as $1
if [[ $# -ge 1 && -d "$1" ]]; then
  WS_SKILLS_ROOT="$1/.agents/skills"
  echo "[install] 1b. Also installing 'security-audit' and 'sec-audit' to workspace (${WS_SKILLS_ROOT})..."
  mkdir -p "${WS_SKILLS_ROOT}/security-audit" "${WS_SKILLS_ROOT}/sec-audit"
  cp -r "${CF_SKILL_SRC}/"* "${WS_SKILLS_ROOT}/security-audit/"
  cp -r "${SEC_AUDIT_SRC}/"* "${WS_SKILLS_ROOT}/sec-audit/"
  chmod +x "${WS_SKILLS_ROOT}/sec-audit/scan-project.py"
fi

echo "[install] 2. Registering /sec-audit and /security-audit slash commands for Gemini CLI (${GEMINI_CMD_DIR})..."
mkdir -p "${GEMINI_CMD_DIR}"

cat > "${GEMINI_CMD_DIR}/sec-audit.toml" << 'EOF'
description = "Run hybrid DevSecOps (CVE/OSV.dev, Secrets, SAST/IDOR, Auto-Fix) + Cloudflare 6-Phase Adversarial Security Audit"
prompt = """
Activate and follow the security audit workflow in ~/.gemini/config/skills/sec-audit/SKILL.md:
1. Run `python3 ~/.gemini/config/skills/sec-audit/scan-project.py . --format markdown` (see DEVSECOPS-AND-CVE.md).
2. Consult the relevant domain companions in `~/.gemini/config/skills/security-audit/` (e.g., WEB-PROTOCOL-AND-AUTH.md, DATA-ISOLATION-AND-LIFECYCLE.md, HUNTING.md) to perform coverage-led contextual hunting.
3. Present findings grouped by severity (CRITICAL, HIGH, MEDIUM, LOW) and, when requested, apply safe non-breaking auto-fixes following `~/.gemini/config/skills/sec-audit/AUTO-REMEDIATION.md`.
"""
EOF

cat > "${GEMINI_CMD_DIR}/security-audit.toml" << 'EOF'
description = "Run Cloudflare 6-Phase Adversarial Security Audit (read-only full audit or guidance mode)"
prompt = """
Activate and follow the security audit workflow in ~/.gemini/config/skills/security-audit/SKILL.md.
"""
EOF

echo "[install] Done! Both '/sec-audit' and '/security-audit' are now available in Antigravity and Gemini CLI."
