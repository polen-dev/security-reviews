# Security Reviews

Automated security review for pull requests, powered by Claude on Vertex AI. When a PR is opened or updated, Claude analyzes the diff against a curated set of security rules and posts findings as PR comments.

## How It Works

```
PR opened/updated
       |
       v
Caller workflow          (your repo - ~12 lines of YAML)
       |
       v
Reusable workflow        (this repo - polen-dev/security-reviews)
       |
       v
Checkout PR + rules
       |
       v
Conflict detection       (test merge against base branch)
       |
       v
Lint / Build / TypeCheck (optional - repo configures commands)
       |
       v
Authenticate via WIF     (Workload Identity Federation - no keys)
       |
       v
Claude on Vertex AI      (reviews diff against rules/)
       |
       +---> PR review (APPROVE / REQUEST_CHANGES / COMMENT)
       +---> Structured report with checklists
       +---> CI status: FAIL if CRITICAL findings exist
```

## Adding to Your Repo

### Quick setup (< 2 minutes)

**Step 1** — Copy the caller workflow into your repo:

```bash
# From the root of your repo
mkdir -p .github/workflows
curl -sL https://raw.githubusercontent.com/polen-dev/security-reviews/v1/caller-template.yml \
  > .github/workflows/security-review.yml
```

Or create `.github/workflows/security-review.yml` manually:

```yaml
name: Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-review:
    uses: polen-dev/security-reviews/.github/workflows/security-review.yml@v1
    secrets: inherit
```

**Step 2** — Commit and push to your default branch (`main`):

```bash
git add .github/workflows/security-review.yml
git commit -m "Add automated security review"
git push origin main
```

**Step 3** — Open a PR to verify it works. The "Security Review" check should appear within a few seconds and post findings as a PR comment when it finishes (~1-2 minutes).

That's it. The reusable workflow handles checkout, authentication, rules, and reporting.

### Prerequisites

The workflow uses two organization secrets that are already configured for all `polen-dev` repos:

| Secret | Purpose |
|--------|---------|
| `WIF_PROVIDER` | Workload Identity Federation provider for keyless GCP auth |
| `WIF_SERVICE_ACCOUNT` | Service account with Vertex AI access |

These are inherited via `secrets: inherit`. If your repo doesn't have access, ask in **#eng-infra**.

### Verifying it works

After pushing the workflow to `main`, open any PR and check:

1. The **Security Review** check appears under "Checks" on the PR
2. After 1-2 minutes, a comment appears with findings (or a clean report)
3. If CRITICALs are found, the check shows as failed

If the check doesn't appear, see [Troubleshooting](#troubleshooting) below.

## Configuration

Override defaults by passing inputs to the reusable workflow:

```yaml
jobs:
  security-review:
    uses: polen-dev/security-reviews/.github/workflows/security-review.yml@v1
    secrets: inherit
    with:
      model: claude-sonnet-4-5   # default; can use opus for critical repos
      max_turns: 10                        # max agent turns; increase for large PRs
      extra_instructions: |                # repo-specific rules appended to the prompt
        This repo handles payment processing.
        Flag any logging of credit card numbers or CVVs.
```

| Input                | Default                          | Description                                      |
|----------------------|----------------------------------|--------------------------------------------------|
| `model`              | `claude-sonnet-4-5`     | Claude model ID for the review                   |
| `max_turns`          | `10`                             | Maximum agent turns before timeout               |
| `extra_instructions` | `""`                             | Additional repo-specific security rules          |
| `run_lint`           | `""`                             | Lint command (e.g., `yarn lint`). Empty = skip    |
| `run_build`          | `""`                             | Build command (e.g., `yarn build`). Empty = skip  |
| `run_typecheck`      | `""`                             | Type-check command (e.g., `yarn tsc --noEmit`). Empty = skip |
| `node_version`       | `"20"`                           | Node.js version for lint/build/typecheck steps   |

## Branch Protection

To enforce security reviews before merging to `main`:

1. Go to **Settings > Branches > Branch protection rules** for `main`
2. Enable **Require status checks to pass before merging**
3. Search for and add **Security Review**
4. Save changes

PRs with CRITICAL findings will now be blocked from merging.

## Override / Escape Hatch

If a PR is blocked by a false positive or an accepted risk:

1. An **admin** adds the `security-override` label to the PR
2. The security review check is bypassed
3. The label serves as an audit trail for why the check was skipped

Only repository admins can apply this label. Use it sparingly and document the reason in the PR description.

## Automated Checks (Lint / Build / TypeCheck)

The workflow can optionally run lint, build, and type-check commands **before** the Claude review. Results are injected into the review report.

```yaml
jobs:
  security-review:
    uses: polen-dev/security-reviews/.github/workflows/security-review.yml@v1
    secrets: inherit
    with:
      run_lint: "yarn lint"
      run_build: "yarn build"
      run_typecheck: "yarn tsc --noEmit"
      node_version: "20"
```

These steps are **optional** — leave them empty (or omit them) to skip. When configured, results appear in the "Automated Checks" table of the report. Failed checks do not block the CI by themselves but are reported to the reviewer.

## Merge Conflict Detection

The workflow automatically checks if the PR branch has merge conflicts with the base branch. This runs on every PR without any configuration. Results appear in the "Automated Checks" table.

## Security Rules

Rules live in the `rules/` directory of this repo:

| File                    | Purpose                                                   |
|-------------------------|-----------------------------------------------------------|
| `security-rules.md`    | OWASP Top 10+ checklist with vulnerable/fixed code examples |
| `polen-specific.md`    | Business-context rules (multi-tenant isolation, LGPD, financial data) |
| `code-quality.md`      | Code quality checks (function length, types, error handling, architecture) |
| `impact-analysis.md`   | Blast radius assessment (shared files, types, migrations, endpoints) |
| `methodology.md`       | 3-phase review approach with confidence scoring           |
| `false-positives.md`   | What to skip (test files, env references, type definitions) |

To propose changes to rules, open a PR against this repo.

## Findings Schema

Review output follows a JSON schema at `schemas/findings.json`. Top-level fields:

- **has_critical**: Boolean used by CI to pass/fail the check
- **summary**: Human-readable overview
- **recommendation**: `APPROVE`, `APPROVE_WITH_CAVEATS`, or `REQUEST_CHANGES`
- **automated_checks**: Results of lint/build/typecheck/conflicts (if configured)
- **impact_areas**: List of impacted areas (shared-utils, database-schema, etc.)

Each finding includes:

- **severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **category**: Security or quality category
- **title**: Short description of the issue
- **file** and **line**: Location in the codebase
- **confidence**: Score (0.7-1.0) for security findings
- **recommendation**: Actionable fix
- **cwe**: CWE identifier when applicable

## Cost

Each review costs approximately **$0.35–0.55 USD** with the default Sonnet model. Cost scales with PR size since larger diffs require more tokens and the agent reads all rule files on each run. For most PRs (under 500 lines changed), expect costs under $0.55.

Using Opus increases cost roughly 5x but may catch more subtle issues. Consider it for repos that handle authentication, payments, or sensitive data.

Enabling lint/build/typecheck adds workflow execution time but does not increase Claude API costs.

## Troubleshooting

### WIF authentication failures

```
Error: google-github-actions/auth failed with: unable to generate credentials
```

- Verify your repo has access to the `WIF_PROVIDER` and `WIF_SERVICE_ACCOUNT` organization secrets
- Check that the Workload Identity Pool allows the repo's GitHub Actions identity
- Confirm the service account has `aiplatform.endpoints.predict` permission

### Timeout on large PRs

The workflow has a 15-minute timeout. For very large PRs (1000+ lines):

- Increase `max_turns` in the caller workflow
- Consider splitting the PR into smaller, reviewable chunks
- The review focuses on the diff only, so unchanged files do not count against the limit

### False positives

If Claude flags something that is not a real issue:

1. Check if `rules/false-positives.md` already covers the pattern
2. If not, open a PR to add the pattern to `false-positives.md`
3. For a one-off bypass, use the `security-override` label (admin-only)

### Review not triggering

- Confirm the workflow file is on the default branch (usually `main`)
- Check that the `on.pull_request` trigger includes the event type (`opened`, `synchronize`, `reopened`)
- Verify the workflow is not disabled under **Actions > Workflows** in your repo settings

### Claude posts no comments

- The PR diff may be empty or contain only non-code changes (docs, config)
- Check the workflow logs for the Claude Code action step output
- If the diff is clean, Claude reports zero findings and no comments are posted
