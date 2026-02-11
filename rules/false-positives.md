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
