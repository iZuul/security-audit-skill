"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const SCANNER_PATH = path.join(__dirname, "scan-project.py");

function makeTempFixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sec-audit-scan-test-"));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }
  return dir;
}

test("scan-project.py detects offline CVEs, IDOR in Server Actions, and SQL injection", () => {
  const dir = makeTempFixture({
    ".gitignore": ".env\nnode_modules\n",
    "package.json": JSON.stringify({
      name: "fixture-app",
      dependencies: {
        next: "14.2.0",
        ws: "8.17.0",
      },
    }),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      lockfileVersion: 3,
      packages: {
        "node_modules/next": { version: "14.2.0" },
        "node_modules/ws": { version: "8.17.0" },
      },
    }),
    "src/actions/items.ts": [
      '"use server";',
      'import { db } from "@/lib/db";',
      "export async function deleteItem(id: string) {",
      "  const user = await getCurrentUser();",
      "  await db.delete(items).where(eq(items.id, id));",
      "}",
    ].join("\n"),
    "src/lib/sql.ts": [
      "export function runRaw(db: any, table: string) {",
      "  return db.execute(`SELECT * FROM ${table}`);",
      "}",
    ].join("\n"),
  });

  try {
    const stdout = execFileSync(
      "python3",
      [SCANNER_PATH, dir, "--no-osv", "--format", "json"],
      { encoding: "utf8" }
    );
    const report = JSON.parse(stdout);
    const vulns = report.dependency_audit.vulnerabilities;
    assert.ok(vulns.some((v) => v.package === "next" && v.via.includes("CVE-2025-29927")), "Should detect Next.js CVE-2025-29927");
    assert.ok(vulns.some((v) => v.package === "ws" && v.via.includes("CVE-2024-37890")), "Should detect ws CVE-2024-37890");

    const ruleIds = new Set(report.findings.map((f) => f.rule_id));
    assert.ok(ruleIds.has("SAST-IDOR-001"), "Should detect Server Action IDOR candidate");
    assert.ok(ruleIds.has("SAST-SQLI-001"), "Should detect raw SQL interpolation");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("scan-project.py ignores Docker Compose ${VAR:-default} expansions while catching literal DB credentials", () => {
  const dir = makeTempFixture({
    ".gitignore": ".env\n",
    "docker-compose.yml": [
      "services:",
      "  app:",
      "    environment:",
      '      DATABASE_URL: "postgresql://${POSTGRES_USER:-user}:${POSTGRES_PASSWORD:-pass}@db:5432/app"',
    ].join("\n"),
    "src/config.ts": 'export const DB = "postgresql://admin:SuperSecretProd99@prod.db.internal:5432/main";\n',
  });

  try {
    const stdout = execFileSync(
      "python3",
      [SCANNER_PATH, dir, "--no-osv", "--format", "json"],
      { encoding: "utf8" }
    );
    const report = JSON.parse(stdout);
    const secretFindings = report.findings.filter((f) => f.rule_id === "SEC-SECRET-002");
    assert.equal(secretFindings.length, 1);
    assert.equal(secretFindings[0].file, "src/config.ts");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("scan-project.py --emit-ledger generates a coverage ledger of entry points", () => {
  const dir = makeTempFixture({
    ".gitignore": ".env\n",
    "src/actions/accounts.ts": '"use server";\nexport async function updateAccount() {}\n',
    "src/app/api/webhook/route.ts": "export async function POST() {}\n",
  });
  const ledgerPath = path.join(dir, "ledger.json");

  try {
    execFileSync(
      "python3",
      [SCANNER_PATH, dir, "--no-osv", "--emit-ledger", ledgerPath],
      { encoding: "utf8" }
    );
    const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
    assert.equal(ledger.schema_version, "1.0-sec-audit-cf-hybrid");
    assert.equal(ledger.units.length, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
