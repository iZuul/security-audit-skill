# Safe Auto-Remediation Guide

Use this companion when the user operates in **DevSecOps & Auto-Fix mode (`/sec-audit`)** or explicitly asks to **fix / remediate discovered vulnerabilities**.

> **Boundary rule**: In pure read-only **Full audit mode**, the skill only reports findings and describes minimal fixes without modifying target source (see [SKILL.md](SKILL.md)). Execute the source modifications in this guide **only** when the user asks to fix, patch, or auto-remediate vulnerabilities (or invokes `/sec-audit` with remediation intent).

---

## 1. Golden Rules of Non-Breaking Remediation

1. **Preserve API & UI Contracts**:
   - Never rename exported functions, Server Actions, API routes, or database columns.
   - Maintain identical return shapes (e.g., `{ success: boolean, error?: string, data?: T }`) so existing frontend components continue to work without modification.
2. **Preserve Database Data & Schema Compatibility**:
   - Do not drop columns, change column types destructively, or invalidate existing valid rows in the database.
3. **Preserve Local Development Ergonomics**:
   - When removing insecure development shortcuts (such as returning password reset links in JSON responses or using fallback dev secrets), gate them behind `process.env.NODE_ENV !== "production"` rather than breaking local developer workflows.
4. **Verify Compilation & Type Safety**:
   - After applying fixes, always run the project's typechecker (`tsc --noEmit`), linter, or test suite and re-run `scan-project.py` to confirm zero regressions.

---

## 2. Remediation Patterns by Vulnerability Class

### A. Broken Access Control & IDOR in Server Actions / API Routes (`SEC-IDOR-001`)

- **Vulnerability**: A mutating endpoint or `"use server"` action updates or deletes a record by its primary key (`eq(table.id, id)`) after checking only `getCurrentUser()`, allowing an authenticated user in Workspace A to modify or delete records belonging to Workspace B.
- **Safe Fix Pattern**:
  1. Fetch the target row's `workspaceId` / `organizationId` (or require `workspaceId` as an argument and constrain the query with `and(eq(table.id, id), eq(table.workspaceId, workspaceId))`).
  2. Call `await requireWorkspaceMember(user.id, record.workspaceId)` (or equivalent tenant guard) **before** executing `.update()` or `.delete()`.
  3. For organization-level mutations (`changeOrgMemberRole`, `removeOrgMember`, `sendInvitation`), verify `ADMIN` or `OWNER` role via `requireOrganizationAdmin(user.id, organizationId)`.

```ts
// BEFORE (Vulnerable to cross-workspace IDOR)
const user = await getCurrentUser();
if (!user) return { success: false, error: "Unauthorized" };
await db.delete(accounts).where(eq(accounts.id, id));

// AFTER (Safe, preserves exact return type and signature)
const user = await getCurrentUser();
if (!user) return { success: false, error: "Unauthorized" };
const existing = await db.query.accounts.findFirst({ where: eq(accounts.id, id) });
if (!existing) return { success: false, error: "Not found" };
if (existing.workspaceId) {
  await requireWorkspaceMember(user.id, existing.workspaceId);
}
await db.delete(accounts).where(eq(accounts.id, id));
```

---

### B. Unverified Session Token Fallback (`SEC-AUTH-001`)

- **Vulnerability**: Extracting the raw token from a signed session cookie via `cookieValue.split(".")[0]` and querying the session table without verifying the HMAC signature appended after the `.`.
- **Safe Fix Pattern**:
  - Verify the HMAC-SHA256 signature using `crypto.createHmac("sha256", secret).update(rawToken).digest("base64")` and compare using `crypto.timingSafeEqual` before accepting the fallback token.
  - Only allow unsigned tokens when ` !cookieValue.includes(".") && process.env.NODE_ENV !== "production"`.

```ts
const dotIndex = cookieValue.lastIndexOf(".");
if (dotIndex <= 0) return null;
const rawToken = cookieValue.slice(0, dotIndex);
const sig = cookieValue.slice(dotIndex + 1);
const expectedSig = crypto.createHmac("sha256", getAuthSecret()).update(rawToken).digest("base64");
const sigBuf = Buffer.from(sig);
const expBuf = Buffer.from(expectedSig);
if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
  return null;
}
```

---

### C. Password Reset Link Leaked in Production Response (`SEC-AUTH-002`)

- **Vulnerability**: Returning `devResetUrl` containing the live password reset token in the HTTP/action response when `RESEND_API_KEY` is unset, or returning `{ valid: true }` inside a `catch` block during token verification.
- **Safe Fix Pattern**:
  - Only return `devResetUrl` when `process.env.NODE_ENV !== "production"`. In production, return a generic error or success message without the URL.
  - In token verification `catch` blocks, always fail closed (`return { valid: false, error: "Verification error" }`).

---

### D. Hardcoded Production Fallback Secret (`SEC-SECRET-004`)

- **Vulnerability**: Using a static string literal fallback (`process.env.BETTER_AUTH_SECRET || "default-secret-..."`) in production.
- **Safe Fix Pattern**:
  - Keep the deterministic dev secret only when `process.env.NODE_ENV !== "production"`.
  - In production, if the environment variable is missing during build/startup, log a critical error and generate a per-process ephemeral secret (`crypto.randomBytes(32).toString("hex")`) so attackers cannot forge tokens using a known static string from source code.

---

### E. SQL Identifier Interpolation (`SEC-SQL-001`)

- **Vulnerability**: Wrapping identifiers in double quotes without escaping embedded double quotes (`return '"' + name + '"'`).
- **Safe Fix Pattern**:
  - Escape internal double quotes by doubling them (`name.replace(/"/g, '""')`) and reject null bytes (`\0`).

```ts
function quoteIdent(name: string): string {
  if (name.includes("\0")) throw new Error("Invalid identifier");
  return `"${name.replace(/"/g, '""')}"`;
}
```

---

### F. Transitive Dependency CVEs (`CVE-*` / `GHSA-*`)

- **Safe Fix Pattern**:
  - For direct dependencies with non-breaking minor/patch updates, bump the version range in `package.json`.
  - For transitive dependencies locked inside `package-lock.json`, run:
    ```bash
    python3 <skill-dir>/scan-project.py <target-dir> --fix-cve
    ```
    which safely populates `"overrides"` in `package.json` with the exact patched floor (`>=...`) reported by OSV.dev without breaking top-level major versions.
