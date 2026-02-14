# Code Quality Rules

These rules supplement security rules with code quality checks that affect maintainability and indirectly affect security posture. Long, complex, or poorly typed code is harder to audit and more likely to hide vulnerabilities.

**Severity guidance**: Code quality findings should use LOW or INFO severity. Do not inflate them to MEDIUM or higher unless they directly enable a security vulnerability.

---

## CQ-001: Excessive Function Length

**Severity:** LOW
**Confidence requirement:** N/A (heuristic)

Functions exceeding 50 lines of logic (excluding comments, blank lines, and type declarations) are harder to reason about and audit for security issues.

**Flag when:**
- A function in the diff exceeds 50 lines of logic
- The function handles security-sensitive operations (auth, input validation, data access)

**Do not flag:**
- Test functions (covered by false-positives.md)
- Configuration objects or static data declarations
- Generated code

**Recommendation:** Extract sub-functions with descriptive names. Each function should do one thing.

---

## CQ-002: Unnecessary TypeScript `any` Usage

**Severity:** LOW
**Confidence requirement:** N/A (heuristic)

The `any` type disables TypeScript's compile-time safety, which can mask type errors that lead to runtime vulnerabilities (e.g., passing unsanitized input where a validated type is expected).

**Patterns to flag:**
```typescript
// Problematic:
function processInput(data: any) { ... }
const result = response.data as any;
// @ts-ignore or @ts-expect-error hiding type issues
```

**Acceptable patterns:**
```typescript
// Safe: explicit unknown with narrowing
function processInput(data: unknown) {
  if (isValidInput(data)) { ... }
}

// Safe: third-party library types that genuinely require any
declare module 'legacy-lib' { ... }

// Safe: catch clause variable (TypeScript limitation)
catch (err: any) { ... }
```

**Do not flag:**
- `any` in `.d.ts` declaration files
- `any` in test files
- Catch clause parameters
- Explicit `// eslint-disable` with justification comment

**Recommendation:** Replace `any` with `unknown` and add type narrowing, or define a proper interface.

---

## CQ-003: Inadequate Error Handling

**Severity:** MEDIUM (when it masks security errors) / LOW (general)
**Confidence requirement:** >= 0.7 for MEDIUM

Empty catch blocks, swallowed errors, and overly broad error handling can hide security failures (e.g., silently failing authentication checks, swallowing authorization errors).

**Patterns to flag:**
```typescript
// Empty catch -- error is silently swallowed
try { await authenticate(user); } catch (e) {}

// Catch-all that continues execution as if nothing happened
try { validateInput(data); } catch { return defaultValue; }

// Logging error but not re-throwing in security-critical paths
try { verifyToken(token); } catch (e) { console.log(e); }
```

**Acceptable patterns:**
```typescript
// Intentional: fallback with comment explaining why
try { ... } catch {
  // Expected: external service may be unavailable, use cached value
  return cachedValue;
}

// Re-throwing or returning error
try { ... } catch (e) {
  logger.error('Auth failed', e);
  throw new UnauthorizedError();
}
```

**Cross-reference:** SEC-CONF-003 (Exposed Error Details) -- ensure error handling does not leak internal details while also not silently swallowing critical errors.

---

## CQ-004: Clean Architecture Violations

**Severity:** INFO
**Confidence requirement:** N/A (heuristic)

In projects following Clean Architecture, Use Cases should depend on abstractions (repository interfaces), not on infrastructure directly. Violations make the code harder to test and can bypass security layers implemented at the repository level.

**Patterns to flag:**
```typescript
// Use Case directly importing Prisma client
import { prisma } from '../../prisma/client';

// Use Case directly calling HTTP client
import axios from 'axios';
```

**Expected pattern:**
```typescript
// Use Case depends on injected repository
class CreateUserUseCase {
  constructor(private userRepository: IUserRepository) {}
  async execute(data: CreateUserDTO) {
    return this.userRepository.create(data);
  }
}
```

**Do not flag:**
- Infrastructure layer files (repositories, adapters, controllers)
- Utility imports (lodash, date-fns, etc.)
- Type-only imports from infrastructure

**Recommendation:** Inject dependencies through constructor parameters. Use Case should only import interfaces and domain types.

---

## CQ-005: Duplicated Security-Critical Logic

**Severity:** MEDIUM
**Confidence requirement:** >= 0.7

Duplicated validation, authorization, or sanitization logic diverges over time. One copy inevitably gets weakened or forgotten during updates, creating inconsistent security enforcement.

**Patterns to flag:**
- Same authorization check copy-pasted across multiple endpoints
- Input validation logic duplicated instead of extracted to a shared validator
- Same sanitization function reimplemented in multiple files within the diff

**Do not flag:**
- Similar but contextually different validation (e.g., different fields for different entities)
- Standard patterns that happen to look alike (e.g., `if (!user) throw new Error()`)
- Duplication across test files

**Recommendation:** Extract shared validation/authorization logic to a reusable function or middleware.

---

## CQ-006: Unclear Naming in Security-Sensitive Contexts

**Severity:** INFO
**Confidence requirement:** N/A (heuristic)

Variables and functions with vague names in security-sensitive code make it harder to verify correctness during reviews and audits.

**Patterns to flag:**
```typescript
// Vague names in auth/validation context
const data = await checkUser(x);     // what data? what is x?
const result = validate(input);       // what was validated? pass or fail?
const flag = check(token);            // what flag? boolean? what check?
```

**Better alternatives:**
```typescript
const authenticatedUser = await authenticateByToken(bearerToken);
const validationErrors = validateInvoiceInput(rawInput);
const isTokenValid = verifyJwtSignature(accessToken);
```

**Do not flag:**
- Loop variables (`i`, `j`, `k`)
- Callback parameters in standard patterns (`.map(x => ...)`)
- Variables with clear context from surrounding code
- Non-security code (UI rendering, formatting, etc.)

**Recommendation:** Use descriptive names that communicate intent, especially for variables holding sensitive data or security decisions.
