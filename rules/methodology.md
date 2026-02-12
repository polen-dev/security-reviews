# Security Review Methodology

This document defines the structured approach for conducting security reviews. Follow these phases in order for every review.

---

## Phase 1 -- Repository Context Research

Before analyzing the diff, build an understanding of the project's security posture.

**Sub-tasks:**

1. **Identify existing security frameworks**: Search for authentication middleware, authorization checks, input validation libraries, and security headers already in use.
2. **Map established patterns**: Look for sanitization functions, parameterized query patterns, CSRF protections, and other defensive patterns the project already uses.
3. **Understand the security model**: Identify trust boundaries (e.g., authenticated vs. unauthenticated routes, admin vs. user permissions, internal vs. external APIs).
4. **Note the tech stack**: Framework-specific protections matter (e.g., React's JSX escaping, Next.js middleware, Prisma's parameterized queries).

**Why this matters:** A finding is only valid if it deviates from or is missed by the project's existing security model. Code that follows established patterns is not a vulnerability.

---

## Phase 2 -- Comparative Analysis

Compare the PR's changes against the patterns identified in Phase 1.

**Sub-tasks:**

1. **Pattern deviation detection**: Flag code that handles security differently from established patterns in the same codebase (e.g., a new endpoint that skips the auth middleware every other endpoint uses).
2. **Consistency check**: If the project uses parameterized queries everywhere but a new query uses string concatenation, that is a finding.
3. **New attack surface identification**: New endpoints, new user inputs, new file uploads, new external integrations, and new permission checks all expand the attack surface and deserve scrutiny.
4. **Removed protections**: If the diff removes security checks, validation, or sanitization, flag it with high confidence.

---

## Phase 3 -- Vulnerability Assessment

Examine each modified file for concrete vulnerabilities.

**Sub-tasks:**

1. **Trace data flow**: Follow user-controlled input from entry point (request parameter, form field, file upload, webhook payload) through to sensitive operations (database queries, shell commands, file system access, API calls).
2. **Identify privilege boundary crossings**: Look for places where data crosses trust boundaries without validation (e.g., user input reaching an admin-only operation, client data used in server-side rendering).
3. **Check injection points**: SQL injection, command injection, XSS, template injection, path traversal, SSRF -- but only where user-controlled input reaches these sinks without sanitization.
4. **Verify authentication and authorization**: New routes must enforce auth. Existing routes must not have auth weakened. Permission checks must not be bypassable.
5. **Examine secrets and credentials**: Look for hardcoded secrets, leaked tokens, or credentials committed to source control.

---

## Confidence Scoring

Every finding MUST include a confidence score. Only report findings at 0.7 or above.

| Score | Meaning | When to use |
|-------|---------|-------------|
| **0.9 -- 1.0** | Certain exploit path | You can describe the exact steps to exploit the vulnerability. The input is user-controlled, reaches a dangerous sink, and no sanitization exists in the path. |
| **0.8 -- 0.9** | Clear vulnerability pattern | A known vulnerability pattern is present with known exploitation methods, but exploitation may require specific conditions (e.g., a particular configuration or user role). |
| **0.7 -- 0.8** | Suspicious pattern | The pattern is concerning and requires specific conditions to exploit. You can describe what those conditions are. |
| **Below 0.7** | Do not report | Theoretical concerns, best-practice suggestions, or patterns that require too many assumptions to exploit. |

**How to assess confidence:**

- Can you describe a concrete attack scenario with specific steps? If yes, confidence >= 0.8.
- Can you identify the exact user-controlled input and the exact dangerous sink? If yes, confidence >= 0.8.
- Are you relying on assumptions about missing context (e.g., "if there's no auth middleware elsewhere...")? If yes, confidence < 0.7 -- do not report.
- Is the pattern only dangerous in theory but mitigated by the framework or runtime? If yes, confidence < 0.7 -- do not report.

---

## Severity Guidelines

Use these severity levels consistently:

### CRITICAL

Directly exploitable vulnerability that leads to:
- Remote code execution (RCE)
- Data breach (unauthorized access to sensitive data)
- Authentication bypass (accessing protected resources without credentials)
- Full privilege escalation (user to admin)

**Confidence requirement:** >= 0.9

### HIGH

Exploitable vulnerability under specific but realistic conditions, leading to:
- Significant data exposure
- Partial privilege escalation
- Stored XSS in sensitive contexts
- SQL injection with limited impact

**Confidence requirement:** >= 0.8

### MEDIUM

Only report if the vulnerability is obvious and concrete:
- Reflected XSS with a clear injection path
- Missing authorization on a non-critical endpoint
- Information disclosure of internal details

**Confidence requirement:** >= 0.8

### LOW / INFO

Use sparingly and only for advisory notes:
- Security improvements that would harden the code but are not exploitable
- Patterns that could become vulnerabilities if the code evolves

**Confidence requirement:** >= 0.7
