# Polen-Specific Security Rules

These rules address security concerns specific to Polen's business domain, infrastructure, and regulatory environment. They supplement the general security rules in `security-rules.md`.

---

## POLEN-001: Multi-Tenant Data Isolation

**Severity**: CRITICAL

**Description**: Polen operates a multi-tenant platform where companies and partners share infrastructure. Every database query that touches company or partner data MUST filter by tenant ID (company ID, partner ID, or organization ID). Queries that select across tenants without explicit scoping create cross-tenant data leakage risks.

**What to flag**:
- Database queries on tenant-scoped tables that lack a `WHERE` clause filtering by tenant/company/partner ID
- ORM queries (Prisma, Sequelize, TypeORM) on tenant-scoped models without a tenant filter
- API endpoints that accept a tenant ID from the request without verifying it matches the authenticated user's tenant
- Bulk/list endpoints that return data across tenants
- Background jobs or cron tasks that iterate over tenant data without proper scoping

**Vulnerable code**:
```typescript
// No tenant filter -- returns ALL companies' transactions
const transactions = await prisma.transaction.findMany({
  where: { status: 'pending' },
});

// Tenant ID from URL param without ownership check
router.get('/api/companies/:companyId/reports', authenticate, async (req, res) => {
  const reports = await Report.findAll({
    where: { companyId: req.params.companyId },
  });
  res.json(reports);
});
```

**Fixed code**:
```typescript
// Tenant-scoped query
const transactions = await prisma.transaction.findMany({
  where: { status: 'pending', companyId: req.user.companyId },
});

// Verify tenant ownership
router.get('/api/companies/:companyId/reports', authenticate, async (req, res) => {
  if (req.params.companyId !== req.user.companyId) {
    return res.status(403).json({ error: 'Access denied' });
  }
  const reports = await Report.findAll({
    where: { companyId: req.user.companyId },
  });
  res.json(reports);
});
```

---

## POLEN-002: Financial Data Integrity (Decimal Handling)

**Severity**: HIGH

**Description**: Polen handles cashback calculations, financial transactions, and monetary values. Floating-point arithmetic introduces rounding errors that accumulate and cause financial discrepancies. All monetary calculations MUST use proper decimal handling.

**What to flag**:
- Arithmetic operations (`+`, `-`, `*`, `/`) on variables named `amount`, `value`, `price`, `cashback`, `balance`, `total`, `fee`, `commission`, or similar monetary terms using standard JavaScript numbers
- `parseFloat()` on monetary values
- Storing monetary values as `FLOAT` or `DOUBLE` in database schemas
- Rounding monetary values with `Math.round()` or `toFixed()` without using a decimal library

**Vulnerable code**:
```typescript
// Floating point arithmetic on money
const cashback = orderTotal * 0.05;
const newBalance = currentBalance + cashback;

// parseFloat loses precision
const amount = parseFloat(req.body.amount);

// toFixed returns a string and rounds incorrectly in edge cases
const display = (0.1 + 0.2).toFixed(2); // "0.30" but intermediate is 0.30000000000000004
```

**Fixed code**:
```typescript
import Decimal from 'decimal.js';

// Decimal arithmetic
const cashback = new Decimal(orderTotal).times('0.05');
const newBalance = new Decimal(currentBalance).plus(cashback);

// Or store amounts as integers (cents)
const cashbackCents = Math.round(orderTotalCents * 0.05);
const newBalanceCents = currentBalanceCents + cashbackCents;
```

**Database**: Use `DECIMAL(precision, scale)` or `NUMERIC` column types, never `FLOAT` or `DOUBLE`.

---

## POLEN-003: HubSpot Webhook Validation

**Severity**: HIGH

**Description**: Polen integrates with HubSpot via webhooks. Incoming webhook requests from HubSpot MUST validate the `X-HubSpot-Signature` (v1) or `X-HubSpot-Signature-v3` header to ensure they originate from HubSpot and have not been tampered with.

**What to flag**:
- Webhook endpoint handlers that process HubSpot data without verifying the signature header
- Routes matching patterns like `/webhook/hubspot`, `/api/hubspot/webhook`, `/hubspot/callback` that lack signature validation
- Middleware that skips validation based on environment (e.g., skipping in development but also accidentally in production)

**Vulnerable code**:
```typescript
// No signature validation -- anyone can send fake webhook events
router.post('/api/webhooks/hubspot', async (req, res) => {
  const events = req.body;
  for (const event of events) {
    await processHubSpotEvent(event);
  }
  res.status(200).send();
});
```

**Fixed code**:
```typescript
import crypto from 'crypto';

function validateHubSpotSignature(req: Request): boolean {
  const signature = req.headers['x-hubspot-signature-v3'] as string;
  const timestamp = req.headers['x-hubspot-request-timestamp'] as string;

  if (!signature || !timestamp) return false;

  // Reject if timestamp is older than 5 minutes (replay attack protection)
  const now = Date.now();
  if (now - parseInt(timestamp) > 5 * 60 * 1000) return false;

  const sourceString = `${req.method}${req.originalUrl}${JSON.stringify(req.body)}${timestamp}`;
  const hash = crypto
    .createHmac('sha256', process.env.HUBSPOT_CLIENT_SECRET!)
    .update(sourceString)
    .digest('base64');

  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(signature));
}

router.post('/api/webhooks/hubspot', async (req, res) => {
  if (!validateHubSpotSignature(req)) {
    return res.status(401).send('Invalid signature');
  }
  // Process events...
});
```

---

## POLEN-004: Omie Webhook Validation

**Severity**: HIGH

**Description**: Polen integrates with Omie ERP. Incoming Omie webhook requests MUST validate the authentication token/signature to confirm they originate from Omie.

**What to flag**:
- Webhook endpoints handling Omie data without verifying the `appKey` and `appSecret` or equivalent token
- Routes matching `/webhook/omie`, `/api/omie/webhook`, `/omie/callback` without authentication
- Endpoints that blindly trust the `appKey` in the request body without comparing against stored credentials

**Vulnerable code**:
```typescript
// No validation of Omie credentials
router.post('/api/webhooks/omie', async (req, res) => {
  const { evento, dados } = req.body;
  await processOmieEvent(evento, dados);
  res.status(200).send();
});
```

**Fixed code**:
```typescript
router.post('/api/webhooks/omie', async (req, res) => {
  const { appKey, appSecret } = req.body;

  if (appKey !== process.env.OMIE_APP_KEY || appSecret !== process.env.OMIE_APP_SECRET) {
    return res.status(401).send('Invalid credentials');
  }

  const { evento, dados } = req.body;
  await processOmieEvent(evento, dados);
  res.status(200).send();
});
```

---

## POLEN-005: BigQuery Access Scoping

**Severity**: HIGH

**Description**: BigQuery queries MUST be scoped to the `analytics-big-query-242119` project and the `dataform` dataset. Queries referencing other projects or using wildcard project references can access data outside Polen's intended scope.

**What to flag**:
- BigQuery queries referencing project IDs other than `analytics-big-query-242119`
- Wildcard table references (`project.*.*`)
- `INFORMATION_SCHEMA` queries across projects
- Dynamic project ID construction from user input
- Missing project qualification in table references (relying on default project configuration)

**Vulnerable code**:
```typescript
// Querying another project
const query = `SELECT * FROM \`other-project.dataset.table\``;

// Wildcard project reference
const query = `SELECT * FROM \`${projectId}.dataform.users\``;

// User-controlled project
const query = `SELECT * FROM \`${req.query.project}.dataform.table\``;
```

**Fixed code**:
```typescript
const BQ_PROJECT = 'analytics-big-query-242119';
const BQ_DATASET = 'dataform';

// Hardcoded project and dataset
const query = `SELECT * FROM \`${BQ_PROJECT}.${BQ_DATASET}.users\``;

// Validate table name but never allow project/dataset override
const ALLOWED_TABLES = new Set(['users', 'transactions', 'companies']);
if (!ALLOWED_TABLES.has(tableName)) {
  throw new Error('Invalid table name');
}
const query = `SELECT * FROM \`${BQ_PROJECT}.${BQ_DATASET}.${tableName}\``;
```

---

## POLEN-006: Cloud Run Authentication

**Severity**: CRITICAL

**Description**: Cloud Run services MUST require authentication. Services deployed with `--allow-unauthenticated` or IAM bindings granting `roles/run.invoker` to `allUsers` or `allAuthenticatedUsers` are publicly accessible without any access control.

**What to flag**:
- `gcloud run deploy` commands with `--allow-unauthenticated`
- Terraform/Pulumi/CDK resources setting `ingress` to `all` without IAM restrictions
- IAM policy bindings granting `roles/run.invoker` to `allUsers` or `allAuthenticatedUsers`
- Cloud Run service YAML with `run.googleapis.com/ingress: all` without corresponding IAM auth
- Missing `--no-allow-unauthenticated` in deployment scripts (the flag should be explicit)

**Vulnerable code**:
```yaml
# Terraform -- publicly accessible Cloud Run service
resource "google_cloud_run_service_iam_member" "public" {
  service  = google_cloud_run_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
```

```bash
# gcloud -- publicly accessible
gcloud run deploy my-service --allow-unauthenticated --image gcr.io/my-project/my-image
```

**Fixed code**:
```yaml
# Terraform -- only specific service account can invoke
resource "google_cloud_run_service_iam_member" "invoker" {
  service  = google_cloud_run_service.api.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:caller@my-project.iam.gserviceaccount.com"
}
```

```bash
# gcloud -- authenticated access required
gcloud run deploy my-service --no-allow-unauthenticated --image gcr.io/my-project/my-image
```

---

## POLEN-007: LGPD / Data Protection Compliance

**Severity**: HIGH

**Description**: Brazil's Lei Geral de Protecao de Dados (LGPD) applies to all Polen operations. Personal data (PII) must be handled with appropriate safeguards. Violations can result in fines up to 2% of revenue.

**What to flag**:

### Logging PII without masking
```typescript
// VIOLATION: logging CPF, email, phone in plaintext
logger.info(`User registered: ${user.cpf}, ${user.email}, ${user.phone}`);
```
```typescript
// COMPLIANT: mask PII in logs
logger.info(`User registered: CPF ***${user.cpf.slice(-4)}, email ${maskEmail(user.email)}`);
```

### Storing PII without encryption
```typescript
// VIOLATION: CPF stored as plaintext
await db.query('INSERT INTO users (cpf) VALUES ($1)', [cpf]);
```
```typescript
// COMPLIANT: encrypt PII at rest
const encryptedCpf = encrypt(cpf);
await db.query('INSERT INTO users (cpf_encrypted) VALUES ($1)', [encryptedCpf]);
```

### Exposing PII in API responses without explicit need
```typescript
// VIOLATION: returning full CPF in a list endpoint
router.get('/api/users', async (req, res) => {
  const users = await User.findAll();
  res.json(users); // includes cpf, phone, full address
});
```
```typescript
// COMPLIANT: return only necessary fields, mask sensitive ones
router.get('/api/users', async (req, res) => {
  const users = await User.findAll({
    attributes: ['id', 'name', 'email'],
  });
  res.json(users);
});
```

### Missing data retention policies
- Flag data models or tables that store PII without documented retention periods
- Flag missing data deletion endpoints (right to erasure / right to be forgotten)
- Flag PII stored in logs without log rotation/TTL configuration

**PII fields to watch for** (Brazilian context):
- CPF (Cadastro de Pessoas Fisicas) -- 11-digit tax ID
- RG (identity card number)
- Full name + address combination
- Phone numbers
- Email addresses
- Bank account details
- IP addresses (when linkable to individuals)
- Geolocation data

---

## POLEN-008: Service-to-Service Authentication

**Severity**: HIGH

**Description**: Internal service communication must use IAM-based authentication (GCP service accounts) or properly signed tokens (JWT with rotation). Shared, static API keys hardcoded across services are fragile, non-auditable, and difficult to rotate.

**What to flag**:
- Hardcoded API keys used for service-to-service authentication
- Shared secrets in environment variables that are the same across multiple services
- HTTP calls between internal services without any authentication headers
- Service-to-service communication using basic auth with static credentials
- API keys that never expire and have no rotation mechanism

**Vulnerable code**:
```typescript
// Hardcoded shared API key for internal service
const response = await fetch('https://internal-service.run.app/api/data', {
  headers: {
    'X-API-Key': 'shared-static-key-never-rotated',
  },
});

// Same key used by multiple services, stored as env var
const response = await fetch(INTERNAL_URL, {
  headers: { Authorization: `Bearer ${process.env.INTERNAL_API_KEY}` },
});
```

**Fixed code**:
```typescript
import { GoogleAuth } from 'google-auth-library';

// Use GCP IAM identity tokens for Cloud Run service-to-service
const auth = new GoogleAuth();
const client = await auth.getIdTokenClient(targetServiceUrl);
const response = await client.request({ url: `${targetServiceUrl}/api/data` });

// Or use a service account token
const authClient = await auth.getClient();
const { token } = await authClient.getAccessToken();
const response = await fetch(`${targetServiceUrl}/api/data`, {
  headers: { Authorization: `Bearer ${token}` },
});
```

**Infrastructure check**: Ensure Cloud Run services have the correct IAM bindings so that only authorized service accounts can invoke them (see POLEN-006).
