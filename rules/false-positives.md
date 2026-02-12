# False Positive Guidance

This document defines patterns that the security review should **skip** or **deprioritize**. Flagging these wastes reviewer time and creates noise that obscures real findings.

---

## 1. Test Files and Fixtures

**Skip**: Files matching these patterns are test code and are not deployed to production.

- `*.test.ts`, `*.test.tsx`, `*.test.js`, `*.test.jsx`
- `*.spec.ts`, `*.spec.tsx`, `*.spec.js`, `*.spec.jsx`
- `__tests__/` directories
- `__mocks__/` directories
- `__fixtures__/` directories
- `*.fixture.ts`, `*.fixture.js`
- `test/`, `tests/`, `e2e/`, `cypress/` directories
- `jest.config.*`, `vitest.config.*`, `playwright.config.*`

**Exception**: Flag test files that contain real credentials (not mock values). Look for patterns like `sk_live_`, `AKIA`, or actual URLs with embedded tokens.

---

## 2. Example Environment Files

**Skip**: `.env.example`, `.env.sample`, `.env.template` files contain placeholder values, not real secrets.

Common placeholders that are safe to ignore:
- `your-api-key-here`
- `changeme`
- `xxxxxxxxx`
- `<YOUR_TOKEN>`
- `TODO`
- `REPLACE_ME`
- Empty values (`KEY=`)

**Exception**: If a `.env.example` file contains a value that looks like a real key (high entropy, matches known key patterns like `sk_live_`, `AKIA`), flag it.

---

## 3. Type Definitions

**Skip**: TypeScript declaration files and interface-only files do not contain executable code.

- `*.d.ts` files
- Files that only export `interface` or `type` declarations
- Files in `@types/` directories

**Exception**: Type definitions that expose internal structure in a public-facing API package may warrant a review if they leak implementation details.

---

## 4. Comments, JSDoc, and Documentation Strings

**Skip**: Security-sensitive keywords in comments or documentation strings are not vulnerabilities.

Examples of false positives:
```typescript
// TODO: add rate limiting to this endpoint
/** @param password - the user's password (will be hashed) */
// Previously used MD5, migrated to bcrypt in PR #234
```

These are informational, not executable code.

---

## 5. Encrypted or Hashed Values

**Skip**: Values that are already encrypted or hashed are not plaintext secrets.

- bcrypt hashes: `$2b$12$...`, `$2a$10$...`
- SHA-256 hashes (64 hex chars used as checksums or integrity verification)
- JWT tokens in test fixtures (especially with `ey` prefix when used as test data)
- PGP-encrypted blocks
- Base64-encoded ciphertext from known encryption functions

**How to distinguish from real secrets**: Hashes/encrypted values are typically:
- Stored as the output of a hashing function, not used as input to auth
- In test fixtures or seed data
- Compared against (verified), not sent to external services

---

## 6. Public Client-Side API Keys

**Skip**: Some API keys are designed to be public and are safe to include in client-side code.

- **Google Maps**: Keys starting with `AIza` when used in frontend map components
- **Stripe publishable keys**: `pk_live_*`, `pk_test_*` (the publishable key is meant to be public)
- **Firebase config**: `apiKey` in Firebase client config (this is a project identifier, not a secret)
- **Sentry DSN**: The DSN is designed to be public
- **Analytics IDs**: Google Analytics (`G-`, `UA-`), Segment write keys

**Exception**: Flag if the same file also contains a corresponding secret key (e.g., `sk_live_` alongside `pk_live_`).

---

## 7. Environment Variable References

**Skip**: References to environment variables or secrets are not leaks -- they are the correct way to handle secrets.

- `process.env.SECRET_KEY` -- this reads a secret at runtime, it is not a hardcoded secret
- `${{ secrets.GITHUB_TOKEN }}` -- GitHub Actions secrets reference
- `os.environ['API_KEY']` -- Python env var access
- `${DATABASE_URL}` in config files -- variable substitution
- Docker `--env-file` or `environment:` in docker-compose referencing env vars

**Exception**: If an environment variable is set to a hardcoded value in the same file, that is a finding:
```yaml
# This IS a finding:
environment:
  API_KEY: sk_live_actual_key_here
```

---

## 8. Import Statements

**Skip**: Importing a module that has dangerous capabilities is not a vulnerability by itself. The vulnerability is in how it is used.

```typescript
// These imports are NOT findings:
import { execFile } from 'child_process';  // only dangerous if called with user input
import crypto from 'crypto';               // this is a security library
import { evaluate } from 'mathjs';         // only dangerous if called with unsanitized input
```

**Flag when**: The imported function is called with user-controlled input in the same file or module.

---

## 9. Generated and Vendored Files

**Skip**: Auto-generated and vendored files should not be reviewed for security issues as they are not authored by the team.

- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `dist/`, `build/`, `.next/`, `out/` directories
- `node_modules/` (should never be committed, but if present, skip)
- Generated GraphQL types, Prisma client output
- Compiled protobuf files
- Source maps (`*.map`)

**Exception**: `package.json` changes (new dependencies) SHOULD be reviewed -- see SEC-DEP-001 and SEC-DEP-002.

---

## 10. Documentation and Markdown Files

**Skip**: Markdown files, READMEs, and documentation do not contain executable code.

- `*.md` files
- `docs/` directories
- `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE`
- Wiki content

**Exception**: If a markdown file contains inline code blocks with hardcoded secrets (e.g., a README with a real API key in a curl example), flag it.

---

## 11. Database Migrations (Schema-Only)

**Skip**: Migration files that only perform DDL operations (create table, add column, add index, alter column type) do not introduce security vulnerabilities.

```sql
-- Safe to skip:
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
CREATE INDEX idx_users_email ON users(email);
```

**Flag when**: Migrations contain:
- DML operations (INSERT, UPDATE, DELETE) that handle sensitive data
- Raw SQL that constructs queries from variables
- Permission grants (GRANT, REVOKE) that change access control
- Operations that disable security features (disable RLS, drop constraints)

---

## 12. Denial of Service and Resource Exhaustion

**Skip**: DoS, rate limiting gaps, and resource exhaustion issues are out of scope for code-level security reviews.

- Missing rate limiting on endpoints
- Unbounded loops or large payload handling
- Memory or CPU exhaustion scenarios
- Regular expression denial of service (ReDoS) unless the regex is trivially exploitable

**Why**: DoS mitigation is an infrastructure concern (WAF, load balancer, API gateway) and not typically exploitable via a single PR change.

---

## 13. Lack of Hardening Measures

**Skip**: Missing best practices without a concrete, exploitable vulnerability are not findings.

- Missing security headers (CSP, HSTS, X-Frame-Options) unless their absence enables a specific exploit in the diff
- Missing input length limits without a concrete exploit path
- Not using the "most secure" option when the current option is still safe
- Suggestions to add logging, monitoring, or alerting

**Why**: Hardening suggestions are valuable but belong in architecture reviews, not PR-level security reviews.

---

## 14. Theoretical Race Conditions

**Skip**: Race conditions that are only theoretically exploitable without a concrete, practical attack path.

- Time-of-check to time-of-use (TOCTOU) in single-threaded contexts
- Race conditions that require implausible timing or access
- Concurrent access issues in code that runs in a single process

**Flag when**: The race condition has a concrete exploitation path -- e.g., a double-spend in a payment flow, or a privilege escalation via concurrent requests to a stateful endpoint.

---

## 15. SSRF (Path-Only)

**Skip**: Server-side request forgery findings where the attacker only controls the URL path, not the host or protocol.

```typescript
// NOT a finding -- attacker cannot change the host:
const response = await fetch(`https://api.internal.com/${userInput}`);
```

**Flag when**: The attacker controls the full URL, the host, or the protocol:
```typescript
// THIS is a finding -- attacker controls the full URL:
const response = await fetch(userProvidedUrl);
```

---

## 16. AI Prompt Content

**Skip**: User-controlled content being included in AI/LLM prompts is not a security vulnerability.

- User input passed to system prompts, chat completions, or embeddings
- Prompt injection concerns in AI-powered features

**Why**: Prompt injection is an AI safety concern, not a traditional security vulnerability. It does not lead to RCE, data breach, or privilege escalation in the application itself.

**Exception**: Flag if AI output is used in dangerous sinks without sanitization (e.g., AI-generated SQL executed directly, AI output rendered as raw HTML).

---

## 17. Client-Side Auth Checks

**Skip**: Client-side JavaScript code (React components, Vue components, etc.) that does not implement authentication or permission checks is not a vulnerability.

- Missing auth guards in frontend route definitions
- UI components that render without checking permissions
- Client-side form validation that does not verify auth state

**Why**: Authentication and authorization must be enforced server-side. Client-side checks are UX conveniences, not security controls. The server API is the trust boundary.

**Flag when**: The client-side code IS the only auth check (e.g., a serverless function or API route that relies on a client-sent "isAdmin" flag).

---

## Precedents

These precedents clarify recurring judgment calls. Apply them consistently across reviews.

1. **Logging URLs is safe; logging high-value secrets is a vulnerability.** URLs, request paths, and query parameters are safe to log. API keys, passwords, tokens, and PII in logs are findings.

2. **UUIDs are unguessable and do not need validation.** UUIDv4 values used as identifiers are cryptographically random. Do not flag "predictable ID" or "IDOR" for UUID-based lookups unless there is a concrete path to enumerate them.

3. **Environment variables and CLI flags are trusted values.** Values read from `process.env`, CLI arguments, or config files are not user-controlled input. Do not flag injection risks for these.

4. **React and Angular are generally secure against XSS.** These frameworks escape output by default. Only flag XSS when unsafe HTML injection methods are used with user input (e.g., innerHTML, bypassSecurityTrustHtml).

5. **GitHub Actions workflow vulnerabilities need a concrete attack path.** Flag only when untrusted input (e.g., PR title, branch name, issue body) flows into a dangerous context (run: step, actions/github-script) without sanitization.

6. **Notebook (.ipynb) vulnerabilities need a concrete attack path.** Notebooks are developer tools. Only flag if untrusted input enters a notebook's execution path in a production or CI context.

7. **Command injection in shell scripts needs a concrete untrusted input path.** Scripts that only process trusted inputs (hardcoded values, env vars, CI variables) are not vulnerable. Flag only when external, attacker-controlled input reaches a shell command.

8. **Logging non-PII data is not a vulnerability.** Logging request metadata, error codes, timestamps, feature flags, and internal identifiers is standard practice and not a finding.
