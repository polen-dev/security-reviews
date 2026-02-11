# Security Rules for Automated Code Review

This document defines the security rules applied during automated code reviews. Each rule has an ID, severity, description, and code examples.

Severity levels:
- **CRITICAL**: Exploitable vulnerability that can lead to data breach, RCE, or full system compromise. Must block merge.
- **HIGH**: Significant security risk that is likely exploitable. Should block merge.
- **MEDIUM**: Security weakness that increases attack surface or could be exploitable under certain conditions. Should be flagged for review.
- **LOW**: Minor security hygiene issue or defense-in-depth recommendation. Advisory only.

---

## 1. Injection

### SEC-INJ-001: SQL Injection

**Severity**: CRITICAL

**Description**: User input concatenated directly into SQL queries allows attackers to run arbitrary SQL, exfiltrate data, or modify/delete records.

**Vulnerable code**:
```typescript
// String concatenation in SQL
const query = `SELECT * FROM users WHERE email = '${req.body.email}'`;
await db.query(query);

// Template literal without parameterization
const result = await db.query(`DELETE FROM orders WHERE id = ${req.params.id}`);
```

**Fixed code**:
```typescript
// Parameterized query
const query = `SELECT * FROM users WHERE email = $1`;
await db.query(query, [req.body.email]);

// Using ORM with parameter binding
const result = await Order.findByPk(req.params.id);
```

---

### SEC-INJ-002: Command Injection

**Severity**: CRITICAL

**Description**: User input passed to shell command functions (child_process) can allow arbitrary command running on the server. Always use execFile (which does NOT invoke a shell) instead of shell-based alternatives, and pass arguments as an array.

**Vulnerable code**:
```typescript
import { execSync } from 'child_process';

// User input directly in shell command
app.post('/convert', (req, res) => {
  // DANGEROUS: shell invocation with user input
  const output = execSync(`convert ${req.body.filename} output.pdf`);
  res.send(output);
});
```

**Fixed code**:
```typescript
import { execFile } from 'child_process';

// execFile does NOT invoke a shell — arguments are passed as an array
app.post('/convert', (req, res) => {
  const filename = path.basename(req.body.filename); // sanitize path
  execFile('convert', [filename, 'output.pdf'], (err, stdout) => {
    res.send(stdout);
  });
});

// If shell is absolutely required, use allowlists
const ALLOWED_USERS = /^[a-zA-Z0-9._-]+$/;
if (!ALLOWED_USERS.test(username)) {
  throw new Error('Invalid username');
}
```

---

### SEC-INJ-003: Cross-Site Scripting (XSS)

**Severity**: HIGH

**Description**: Rendering unsanitized user input in HTML allows attackers to run scripts in other users' browsers, steal sessions, or perform actions on their behalf.

**Vulnerable code**:
```typescript
// React: dangerouslySetInnerHTML with user content
function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

// DOM manipulation with innerHTML
document.getElementById('output')!.innerHTML = userInput;

// Unsanitized template literal rendered as HTML
const html = `<p>Welcome, ${user.name}</p>`;
res.send(html);
```

**Fixed code**:
```typescript
// React: render as text (auto-escaped)
function Comment({ body }: { body: string }) {
  return <div>{body}</div>;
}

// DOM: use textContent instead of innerHTML
document.getElementById('output')!.textContent = userInput;

// Server-side: use a templating engine with auto-escaping, or sanitize
import DOMPurify from 'dompurify';
const html = `<p>Welcome, ${DOMPurify.sanitize(user.name)}</p>`;
res.send(html);
```

---

### SEC-INJ-004: Server-Side Request Forgery (SSRF)

**Severity**: HIGH

**Description**: When a server makes HTTP requests to URLs controlled by user input, attackers can reach internal services, cloud metadata endpoints, or other resources not meant to be publicly accessible.

**Vulnerable code**:
```typescript
// User-controlled URL in fetch
app.get('/proxy', async (req, res) => {
  const response = await fetch(req.query.url as string);
  const data = await response.text();
  res.send(data);
});

// URL built from user input without validation
const webhookUrl = `http://${req.body.host}/callback`;
await axios.post(webhookUrl, payload);
```

**Fixed code**:
```typescript
import { URL } from 'url';

// Validate against allowlist of domains
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

app.get('/proxy', async (req, res) => {
  const parsed = new URL(req.query.url as string);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    return res.status(403).send('Host not allowed');
  }
  // Also block private IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x)
  const response = await fetch(parsed.toString());
  const data = await response.text();
  res.send(data);
});
```

---

### SEC-INJ-005: Template Injection

**Severity**: HIGH

**Description**: Passing user input into server-side template engines (Handlebars, EJS, Pug, Nunjucks) without escaping can allow arbitrary code running.

**Vulnerable code**:
```typescript
// EJS: rendering user input as a template string
const template = req.body.template;
const html = ejs.render(template, data); // user controls the template itself

// Nunjucks: renderString with user input
const output = nunjucks.renderString(userInput, context);
```

**Fixed code**:
```typescript
// Use pre-defined templates, pass user input only as data
const html = ejs.render(PREDEFINED_TEMPLATE, { userName: req.body.name });

// Never let users control the template itself — only the data
const output = nunjucks.render('notification.html', { message: userInput });
```

---

### SEC-INJ-006: LDAP Injection

**Severity**: HIGH

**Description**: User input in LDAP queries without escaping can allow attackers to modify query logic, bypass authentication, or enumerate directory entries.

**Vulnerable code**:
```typescript
// Unescaped user input in LDAP filter
const filter = `(uid=${username})`;
const result = await ldapClient.search(baseDN, { filter });
```

**Fixed code**:
```typescript
import { escapeLDAPFilter } from './ldap-utils';

// Escape special characters: *, (, ), \, NUL, /
const filter = `(uid=${escapeLDAPFilter(username)})`;
const result = await ldapClient.search(baseDN, { filter });
```

---

## 2. Broken Access Control

### SEC-AC-001: Missing Authentication Check

**Severity**: CRITICAL

**Description**: API endpoints or routes that handle sensitive operations without verifying the caller's identity allow unauthenticated access.

**Vulnerable code**:
```typescript
// No auth middleware on sensitive endpoint
router.delete('/api/users/:id', async (req, res) => {
  await UserService.delete(req.params.id);
  res.status(204).send();
});
```

**Fixed code**:
```typescript
// Auth middleware applied
router.delete('/api/users/:id', authenticate, authorize('admin'), async (req, res) => {
  await UserService.delete(req.params.id);
  res.status(204).send();
});
```

---

### SEC-AC-002: Insecure Direct Object Reference (IDOR)

**Severity**: HIGH

**Description**: Using user-supplied IDs to access resources without verifying that the requesting user owns or is authorized to access that resource.

**Vulnerable code**:
```typescript
// No ownership check — any authenticated user can access any order
router.get('/api/orders/:orderId', authenticate, async (req, res) => {
  const order = await Order.findByPk(req.params.orderId);
  res.json(order);
});
```

**Fixed code**:
```typescript
// Ownership check ensures user can only access their own orders
router.get('/api/orders/:orderId', authenticate, async (req, res) => {
  const order = await Order.findOne({
    where: { id: req.params.orderId, userId: req.user.id },
  });
  if (!order) {
    return res.status(404).send('Order not found');
  }
  res.json(order);
});
```

---

### SEC-AC-003: Path Traversal

**Severity**: HIGH

**Description**: User input used in file system paths without sanitization allows reading or writing arbitrary files on the server.

**Vulnerable code**:
```typescript
// User controls the file path
app.get('/files', (req, res) => {
  const filePath = path.join('/uploads', req.query.name as string);
  res.sendFile(filePath);
});
// Attacker sends ?name=../../../../etc/passwd
```

**Fixed code**:
```typescript
app.get('/files', (req, res) => {
  const basePath = path.resolve('/uploads');
  const filePath = path.resolve(basePath, req.query.name as string);

  // Ensure resolved path is still within the base directory
  if (!filePath.startsWith(basePath + path.sep)) {
    return res.status(400).send('Invalid file path');
  }
  res.sendFile(filePath);
});
```

---

### SEC-AC-004: CORS Misconfiguration

**Severity**: MEDIUM

**Description**: Overly permissive CORS settings (especially `Access-Control-Allow-Origin: *` with credentials) allow malicious sites to make authenticated cross-origin requests.

**Vulnerable code**:
```typescript
// Wildcard origin with credentials — browsers block this, but reflects
// a misunderstanding of CORS that often leads to reflecting the Origin header
app.use(cors({
  origin: '*',
  credentials: true,
}));

// Reflecting any origin — effectively disables CORS protection
app.use(cors({
  origin: (origin, callback) => callback(null, true),
  credentials: true,
}));
```

**Fixed code**:
```typescript
const ALLOWED_ORIGINS = [
  'https://app.polen.com.br',
  'https://admin.polen.com.br',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));
```

---

### SEC-AC-005: Privilege Escalation

**Severity**: CRITICAL

**Description**: Allowing users to modify their own role, permissions, or access level through API inputs.

**Vulnerable code**:
```typescript
// User can set their own role via request body
router.put('/api/users/profile', authenticate, async (req, res) => {
  await User.update(req.body, { where: { id: req.user.id } });
  res.json({ success: true });
});
// Attacker sends { "role": "admin" }
```

**Fixed code**:
```typescript
// Allowlist of updatable fields
router.put('/api/users/profile', authenticate, async (req, res) => {
  const { name, email, phone } = req.body;
  await User.update({ name, email, phone }, { where: { id: req.user.id } });
  res.json({ success: true });
});
```

---

## 3. Cryptographic Failures

### SEC-CRYPTO-001: Hardcoded Secrets

**Severity**: CRITICAL

**Description**: API keys, passwords, tokens, or other secrets hardcoded in source code. These end up in version control and are trivially extractable.

**Vulnerable code**:
```typescript
// Hardcoded API key
const STRIPE_SECRET = 'sk_live_abc123xyz';

// Hardcoded database password
const dbConfig = {
  host: 'db.internal',
  password: 'supersecret123',
};

// Hardcoded JWT secret
const token = jwt.sign(payload, 'my-jwt-secret');
```

**Fixed code**:
```typescript
// Use environment variables
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;

const dbConfig = {
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD,
};

const token = jwt.sign(payload, process.env.JWT_SECRET!);
```

**Detection patterns**: Look for strings matching:
- `sk_live_`, `sk_test_`, `pk_live_`, `rk_live_` (Stripe)
- `AKIA` (AWS access key IDs)
- `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` (GitHub tokens)
- `xox[bpas]-` (Slack tokens)
- Strings assigned to variables named `secret`, `password`, `apiKey`, `api_key`, `token`, `credential`
- Base64-encoded strings longer than 40 characters assigned to auth-related variables

---

### SEC-CRYPTO-002: Weak Hashing Algorithms

**Severity**: HIGH

**Description**: Using MD5 or SHA1 for password hashing, token generation, or any security-sensitive purpose. These are fast and vulnerable to brute-force/collision attacks.

**Vulnerable code**:
```typescript
import crypto from 'crypto';

// MD5 for password hashing
const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

// SHA1 for token generation
const resetToken = crypto.createHash('sha1').update(email + Date.now()).digest('hex');
```

**Fixed code**:
```typescript
import bcrypt from 'bcrypt';
import crypto from 'crypto';

// bcrypt for password hashing
const hashedPassword = await bcrypt.hash(password, 12);

// Cryptographically secure random token
const resetToken = crypto.randomBytes(32).toString('hex');
```

---

### SEC-CRYPTO-003: Insecure Randomness

**Severity**: HIGH

**Description**: Using `Math.random()` for security-sensitive purposes (tokens, session IDs, OTPs). `Math.random()` is not cryptographically secure and its output is predictable.

**Vulnerable code**:
```typescript
// Math.random for token generation
const token = Math.random().toString(36).substring(2);

// Math.random for OTP
const otp = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
```

**Fixed code**:
```typescript
import crypto from 'crypto';

// Cryptographically secure token
const token = crypto.randomBytes(32).toString('hex');

// Cryptographically secure OTP
const otp = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
```

---

### SEC-CRYPTO-004: Plaintext Storage of Credentials

**Severity**: CRITICAL

**Description**: Storing passwords, tokens, or other credentials in plaintext in databases, files, or configuration.

**Vulnerable code**:
```typescript
// Storing password as plaintext
await db.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, password]);

// Storing API key in plaintext config file
fs.writeFileSync('config.json', JSON.stringify({ apiKey: key }));
```

**Fixed code**:
```typescript
// Hash password before storage
const hashed = await bcrypt.hash(password, 12);
await db.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hashed]);

// Use a secrets manager or environment variables — never store secrets in files
```

---

## 4. Security Misconfiguration

### SEC-CONF-001: Debug Mode in Production

**Severity**: HIGH

**Description**: Debug/development modes left enabled in production expose detailed error messages, stack traces, and internal state to attackers.

**Vulnerable code**:
```typescript
// Express error handler exposing stack traces
app.use((err, req, res, next) => {
  res.status(500).json({
    message: err.message,
    stack: err.stack,
    query: err.query,  // exposes SQL
  });
});

// Debug flag hardcoded to true
const config = { debug: true, verbose: true };
```

**Fixed code**:
```typescript
app.use((err, req, res, next) => {
  console.error(err); // log internally
  res.status(500).json({
    message: 'Internal server error',
    // No stack trace, no query details
  });
});
```

---

### SEC-CONF-002: Missing Security Headers

**Severity**: MEDIUM

**Description**: Missing HTTP security headers allows various client-side attacks (clickjacking, MIME sniffing, etc.).

**Vulnerable code**:
```typescript
// No security headers set
app.get('/', (req, res) => {
  res.send(html);
});
```

**Fixed code**:
```typescript
import helmet from 'helmet';

// helmet sets secure defaults for many headers
app.use(helmet());

// Or manually:
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-XSS-Protection', '0'); // modern browsers: CSP is preferred
  next();
});
```

---

### SEC-CONF-003: Exposed Error Details

**Severity**: MEDIUM

**Description**: Detailed error messages, database errors, or internal paths leaked to API consumers help attackers understand system internals.

**Vulnerable code**:
```typescript
try {
  await db.query(sql);
} catch (err) {
  // Leaks table names, column names, query structure
  res.status(500).json({ error: err.message, sql: err.query });
}
```

**Fixed code**:
```typescript
try {
  await db.query(sql);
} catch (err) {
  logger.error('Database query failed', { error: err, requestId: req.id });
  res.status(500).json({ error: 'An internal error occurred', requestId: req.id });
}
```

---

### SEC-CONF-004: Overly Permissive File Permissions

**Severity**: MEDIUM

**Description**: Creating files or directories with world-readable/writable permissions exposes sensitive data to other processes or users on the same system.

**Vulnerable code**:
```typescript
// World-readable credentials file
fs.writeFileSync('/tmp/credentials.json', JSON.stringify(creds), { mode: 0o777 });
```

**Fixed code**:
```typescript
// Owner-only read/write
fs.writeFileSync('/tmp/credentials.json', JSON.stringify(creds), { mode: 0o600 });
```

---

## 5. Vulnerable Dependencies

### SEC-DEP-001: Known CVEs in Dependencies

**Severity**: HIGH

**Description**: Using dependencies with known security vulnerabilities (CVEs) exposes the application to documented exploits.

**Detection**: Run `npm audit` or `yarn audit` and flag dependencies with HIGH or CRITICAL vulnerabilities that have available patches.

**Action**: Update to patched versions or find alternatives. If a vulnerability is in a transitive dependency, use `overrides` (npm) or `resolutions` (yarn) to force the patched version.

---

### SEC-DEP-002: Typosquatting Risk

**Severity**: MEDIUM

**Description**: Package names that are close misspellings of popular packages may be malicious typosquatting attempts.

**Detection patterns**: Flag new dependency additions that are close to popular package names:
- `lodahs` vs `lodash`
- `expresss` vs `express`
- `cross-env` vs `crossenv` (real historical attack)

**Action**: Verify package name, publisher, download count, and repository URL before adding new dependencies.

---

## 6. Authentication Failures

### SEC-AUTH-001: Missing Rate Limiting on Auth Endpoints

**Severity**: HIGH

**Description**: Authentication endpoints (login, password reset, OTP verification) without rate limiting allow brute-force attacks.

**Vulnerable code**:
```typescript
// No rate limiting on login
router.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  // ... validate password
});
```

**Fixed code**:
```typescript
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/api/auth/login', authLimiter, async (req, res) => {
  // ... login logic
});
```

---

### SEC-AUTH-002: JWT Without Expiry or Validation

**Severity**: HIGH

**Description**: JWTs issued without an expiration time remain valid indefinitely. JWTs verified without checking the algorithm allow algorithm-switching attacks.

**Vulnerable code**:
```typescript
// No expiry set
const token = jwt.sign({ userId: user.id }, secret);

// Decoding without verification
const payload = jwt.decode(token); // does NOT verify signature

// Allowing algorithm to be specified by the token itself
const payload = jwt.verify(token, secret); // may accept 'none' algorithm
```

**Fixed code**:
```typescript
// Set expiry
const token = jwt.sign({ userId: user.id }, secret, { expiresIn: '1h' });

// Verify with explicit algorithm
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

---

### SEC-AUTH-003: Session Fixation

**Severity**: HIGH

**Description**: Not regenerating the session ID after authentication allows attackers who set a known session ID before login to hijack the session afterward.

**Vulnerable code**:
```typescript
// Session not regenerated after login
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  req.session.userId = user.id; // same session ID as before login
  res.redirect('/dashboard');
});
```

**Fixed code**:
```typescript
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Session error');
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});
```

---

## 7. Data Integrity

### SEC-DATA-001: Missing Input Validation

**Severity**: MEDIUM

**Description**: Accepting and processing user input without validation can lead to unexpected behavior, data corruption, or downstream vulnerabilities.

**Vulnerable code**:
```typescript
// No validation on request body
router.post('/api/users', async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});
```

**Fixed code**:
```typescript
import { z } from 'zod';

const CreateUserSchema = z.object({
  name: z.string().min(1).max(255),
  email: z.string().email(),
  age: z.number().int().min(0).max(150).optional(),
});

router.post('/api/users', async (req, res) => {
  const parsed = CreateUserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ errors: parsed.error.issues });
  }
  const user = await User.create(parsed.data);
  res.json(user);
});
```

---

### SEC-DATA-002: Prototype Pollution

**Severity**: HIGH

**Description**: Merging or deep-cloning user-controlled objects without filtering `__proto__`, `constructor`, or `prototype` keys can modify the prototype chain of all objects, leading to denial of service or RCE.

**Vulnerable code**:
```typescript
// Naive deep merge with user input
function deepMerge(target: any, source: any) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker sends: { "__proto__": { "isAdmin": true } }
deepMerge(config, req.body);
```

**Fixed code**:
```typescript
const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeDeepMerge(target: any, source: any) {
  for (const key in source) {
    if (BLOCKED_KEYS.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = safeDeepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

---

### SEC-DATA-003: Mass Assignment

**Severity**: HIGH

**Description**: Passing entire request bodies to ORM create/update methods allows attackers to set fields they should not control (role, balance, permissions).

**Vulnerable code**:
```typescript
// Entire body passed to update — attacker can set any column
await User.update(req.body, { where: { id: req.user.id } });
```

**Fixed code**:
```typescript
// Explicit allowlist of updatable fields
const { name, email } = req.body;
await User.update({ name, email }, { where: { id: req.user.id } });
```

---

### SEC-DATA-004: Deserialization of Untrusted Data

**Severity**: HIGH

**Description**: Deserializing objects from untrusted sources (e.g., `node-serialize`, `js-yaml` with unsafe options) can lead to remote code running.

**Vulnerable code**:
```typescript
import { unserialize } from 'node-serialize';

// Deserializing user-controlled data
const obj = unserialize(req.body.data);

// js-yaml with unsafe schema
import yaml from 'js-yaml';
const config = yaml.load(userInput, { schema: yaml.DEFAULT_FULL_SCHEMA });
```

**Fixed code**:
```typescript
// Use JSON.parse for structured data (safe — no code running)
const obj = JSON.parse(req.body.data);

// js-yaml with safe schema (default in modern versions)
const config = yaml.load(userInput, { schema: yaml.DEFAULT_SCHEMA });
```

---

## 8. Logging Failures

### SEC-LOG-001: Logging Sensitive Data

**Severity**: HIGH

**Description**: Logging passwords, tokens, credit card numbers, CPFs, or other sensitive data creates a secondary exposure path through log aggregation systems.

**Vulnerable code**:
```typescript
// Logging the full request body (may contain passwords)
logger.info('Login attempt', { body: req.body });

// Logging tokens
logger.info(`User authenticated with token: ${token}`);

// Logging PII
logger.info(`Processing payment for CPF: ${user.cpf}`);
```

**Fixed code**:
```typescript
// Log only non-sensitive fields
logger.info('Login attempt', { email: req.body.email });

// Mask or omit sensitive values
logger.info('User authenticated', { userId: user.id });

// Mask PII
logger.info(`Processing payment for CPF: ***${user.cpf.slice(-4)}`);
```

---

### SEC-LOG-002: Missing Audit Logging

**Severity**: MEDIUM

**Description**: Security-relevant events (authentication, authorization decisions, data access, admin actions) without audit logging make incident investigation impossible.

**Action**: Ensure the following events are logged:
- Successful and failed login attempts
- Password changes and resets
- Permission/role changes
- Data exports or bulk reads
- Admin actions (user creation/deletion, config changes)

---

### SEC-LOG-003: Log Injection

**Severity**: MEDIUM

**Description**: User input written directly to logs without sanitization can inject fake log entries, corrupt log parsing, or exploit log viewers.

**Vulnerable code**:
```typescript
// Newlines in user input create fake log entries
logger.info(`User login: ${username}`);
// Attacker sends: "admin\n2024-01-01 INFO User login: admin [SUCCESS]"
```

**Fixed code**:
```typescript
// Strip or encode control characters
const safeUsername = username.replace(/[\n\r\t]/g, '_');
logger.info(`User login: ${safeUsername}`);

// Or use structured logging (JSON) which naturally escapes
logger.info({ event: 'login', username });
```

---

## 9. Node.js / TypeScript Specific

### SEC-NODE-001: eval / Function Constructor

**Severity**: CRITICAL

**Description**: `eval()`, `new Function()`, and `vm.runInNewContext()` with user-controlled input allow arbitrary code running.

**Vulnerable code**:
```typescript
// eval with user input
const result = eval(req.body.expression);

// Function constructor
const fn = new Function('x', req.body.code);
fn(data);
```

**Fixed code**:
```typescript
// Use a safe expression evaluator if math expressions are needed
import { evaluate } from 'mathjs';
const result = evaluate(req.body.expression); // only math, no code

// For templates, use a sandboxed template engine
// For dynamic logic, use a configuration-driven approach instead of arbitrary code
```

---

### SEC-NODE-002: Regular Expression Denial of Service (ReDoS)

**Severity**: MEDIUM

**Description**: Regular expressions with nested quantifiers or overlapping alternation can cause catastrophic backtracking on crafted input, hanging the event loop.

**Vulnerable code**:
```typescript
// Nested quantifiers — exponential backtracking
const emailRegex = /^([a-zA-Z0-9]+)*@example\.com$/;

// Overlapping alternation
const urlRegex = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=]*)*$/;

// User-controlled regex
const pattern = new RegExp(req.query.pattern as string);
```

**Fixed code**:
```typescript
// Use well-tested validation libraries
import { isEmail } from 'validator';
if (!isEmail(input)) { /* reject */ }

// Never let users supply raw regex patterns
// If pattern matching is needed, use a safe subset (glob patterns, exact match)

// For custom regex, use RE2 which guarantees linear-time matching
import { RE2 } from 're2';
const pattern = new RE2(safePattern);
```

---

### SEC-NODE-003: Unhandled Promise Rejections Leaking Info

**Severity**: MEDIUM

**Description**: Unhandled promise rejections in HTTP handlers can crash the process or leak error details to clients.

**Vulnerable code**:
```typescript
// Unhandled rejection — may leak stack trace or crash
router.get('/data', async (req, res) => {
  const data = await fetchExternalData(); // if this throws, no catch
  res.json(data);
});
```

**Fixed code**:
```typescript
// Use express-async-errors or wrap handlers
import 'express-async-errors';

// Or explicit error handling
router.get('/data', async (req, res, next) => {
  try {
    const data = await fetchExternalData();
    res.json(data);
  } catch (err) {
    next(err); // passed to error-handling middleware
  }
});
```

---

### SEC-NODE-004: Buffer() Without Encoding

**Severity**: LOW

**Description**: `Buffer(number)` (deprecated) allocates uninitialized memory that may contain sensitive data from previous allocations.

**Vulnerable code**:
```typescript
// Deprecated — may contain old memory contents
const buf = new Buffer(100);
```

**Fixed code**:
```typescript
// Zero-filled buffer
const buf = Buffer.alloc(100);

// From a string with explicit encoding
const buf = Buffer.from(input, 'utf-8');
```

---

### SEC-NODE-005: Unsafe JSON.parse on User Input

**Severity**: LOW

**Description**: `JSON.parse()` on user input without try-catch will throw on malformed JSON, potentially crashing the process or leaking error details.

**Vulnerable code**:
```typescript
// Crashes on invalid JSON
const data = JSON.parse(req.body.payload);
```

**Fixed code**:
```typescript
let data;
try {
  data = JSON.parse(req.body.payload);
} catch {
  return res.status(400).json({ error: 'Invalid JSON' });
}
```

---

## 10. GitHub Actions Specific

### SEC-GHA-001: Script Injection via Expressions

**Severity**: CRITICAL

**Description**: Using `${{ }}` expressions in `run:` steps with values from pull request titles, branch names, or issue bodies allows arbitrary code running in the CI environment.

**Vulnerable code**:
```yaml
# PR title injected directly into shell
- run: echo "PR title: ${{ github.event.pull_request.title }}"

# Issue body in a script
- run: |
    COMMENT="${{ github.event.comment.body }}"
    process_comment "$COMMENT"
```

**Fixed code**:
```yaml
# Use an environment variable — shell expansion, not template injection
- run: echo "PR title: $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}

# Same for issue body
- run: |
    process_comment "$COMMENT"
  env:
    COMMENT: ${{ github.event.comment.body }}
```

---

### SEC-GHA-002: Unsafe pull_request_target

**Severity**: CRITICAL

**Description**: `pull_request_target` runs in the context of the base branch with access to secrets but can check out code from the PR (fork). If combined with `actions/checkout@ref: PR-head`, it allows fork authors to steal secrets.

**Vulnerable code**:
```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Checking out PR code with base-branch secrets
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test  # runs attacker code with secrets
```

**Fixed code**:
```yaml
# Use pull_request (no secrets from base, safe for untrusted code)
on: pull_request

# If pull_request_target is truly needed, NEVER checkout and run PR code
# Only use it for labeling, commenting, or other metadata operations
on: pull_request_target

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5  # no checkout of PR code
```

---

### SEC-GHA-003: Secrets in Logs

**Severity**: HIGH

**Description**: Accidentally printing secrets to workflow logs exposes them in the Actions UI to anyone with repo read access.

**Vulnerable code**:
```yaml
- run: echo "Token is ${{ secrets.API_TOKEN }}"
- run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com
  # If the curl command fails, the error output may include the token
```

**Fixed code**:
```yaml
- run: |
    # Use ::add-mask:: to ensure value is redacted if printed
    echo "::add-mask::$API_TOKEN"
    curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
  env:
    API_TOKEN: ${{ secrets.API_TOKEN }}
```

---

### SEC-GHA-004: Mutable Action Versions

**Severity**: MEDIUM

**Description**: Referencing GitHub Actions by tag (`@v4`) or branch (`@main`) means the action's code can change without notice. A compromised or malicious update to the action affects all workflows using it.

**Vulnerable code**:
```yaml
- uses: actions/checkout@v4         # tag can be moved
- uses: some-org/action@main        # branch — always latest
```

**Fixed code**:
```yaml
# Pin to full commit SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
# Add a comment with the version for readability
```
