# Impact Analysis Rules

When reviewing a PR, assess the blast radius of changes beyond security vulnerabilities. High-impact changes deserve extra scrutiny because they affect multiple consumers and can introduce regressions across the system.

**Severity guidance**: Impact analysis findings should use INFO severity unless they directly relate to a security rule (cross-referenced below). The goal is awareness, not blocking.

---

## IA-001: Shared Utility and Service Changes

**Severity:** INFO

Changes to shared code affect every module that imports it. A subtle behavioral change in a utility function can cascade across the application.

**Flag when the diff modifies files in:**
- `src/shared/`, `src/common/`, `src/lib/`, `src/utils/`
- `src/services/` (shared service layer)
- `src/helpers/`, `src/core/`
- Any file imported by 3+ other modules

**Report should include:**
- Which shared file was modified
- Nature of the change (signature change, behavioral change, new export, removed export)
- Whether the change is additive (safe) or breaking (risky)

**Do not flag:**
- New files added to shared directories (additive, no existing consumers)
- Changes to internal implementation with no signature or behavior change
- Test file changes in shared directories

---

## IA-002: Interface and Type Contract Changes

**Severity:** INFO

Modifications to exported TypeScript interfaces, types, or enums can break consumers that depend on the contract. Removed or renamed fields are especially risky.

**Flag when:**
- An exported `interface`, `type`, or `enum` is modified (not just added)
- A field is removed or renamed in a shared type
- A type is changed from optional to required or vice versa
- An enum value is removed or renamed

**Acceptable patterns:**
- Adding new optional fields to an interface (non-breaking)
- Adding new enum values (non-breaking)
- Internal (non-exported) type changes

**Report should include:**
- The type/interface name and file
- What changed (field added, removed, renamed, type changed)
- Whether it is a breaking change

---

## IA-003: Database Migration and Schema Changes

**Severity:** MEDIUM
**Cross-reference:** POLEN-001 (Multi-Tenant Isolation), POLEN-002 (Financial Data Integrity)

Database schema changes have permanent, hard-to-reverse effects. They deserve careful review for data integrity, multi-tenant isolation, and performance impact.

**Flag when:**
- New migration files are added (Prisma, Knex, raw SQL)
- `schema.prisma` is modified
- DDL scripts (CREATE TABLE, ALTER TABLE, DROP) appear in the diff

**Check for:**
- New tables/columns: Do they include tenant isolation fields (companyId, partnerId)?
- Financial columns: Are they using `Decimal` type, not `Float`?
- Removed columns: Could this break existing queries or reports?
- Index changes: Could removal impact query performance on critical paths?
- Nullable changes: Could `NOT NULL` addition fail on existing data?

**Do not flag:**
- Schema-only migrations that only add columns or indexes (low risk)
- Comment-only changes to schema files

---

## IA-004: Route and Endpoint Modifications

**Severity:** INFO
**Cross-reference:** SEC-AC-001 (Missing Authentication)

New or modified endpoints change the application's attack surface. Every public endpoint must enforce authentication and authorization.

**Flag when:**
- New route definitions are added (Express, NestJS, GraphQL resolvers)
- Middleware chain is modified on existing routes
- Route parameters or query parameters change
- HTTP method changes (GET to POST, etc.)
- GraphQL schema adds new queries, mutations, or subscriptions

**Check for:**
- New endpoints: Is auth middleware present?
- Modified endpoints: Were security checks removed or weakened?
- Public endpoints: Is there a deliberate reason for no auth?

**Report should include:**
- Endpoint path and HTTP method (or GraphQL operation name)
- Whether auth middleware is present
- Whether this is a new or modified endpoint

---

## IA-005: Configuration and Infrastructure Changes

**Severity:** INFO
**Cross-reference:** SEC-DEP-001 (Known CVEs), POLEN-006 (Cloud Run Authentication)

Changes to configuration files affect the build, deployment, and runtime behavior of the application.

**Flag when the diff modifies:**
- `Dockerfile`, `docker-compose.yml`, `docker-compose.*.yml`
- `cloudbuild.yaml`, `app.yaml`, `dispatch.yaml`
- `.env.example` (new variables may indicate new secrets needed)
- `package.json` (new dependencies -- check SEC-DEP-001, SEC-DEP-002)
- GitHub Actions workflows (`.github/workflows/`)
- Terraform, Pulumi, or other IaC files
- `tsconfig.json` (compiler options affect type safety)

**Check for:**
- New dependencies: Are they well-known and maintained?
- Dockerfile changes: Are base images pinned? Is there a new EXPOSE?
- Cloud config: Are auth settings preserved? (POLEN-006)
- Environment variables: Are new secrets documented?

**Do not flag:**
- Version bumps in lock files (`yarn.lock`, `package-lock.json`)
- Dev-only dependency additions (`devDependencies`)
- Comment or formatting changes in config files
