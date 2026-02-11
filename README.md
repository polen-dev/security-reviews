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
Authenticate via WIF     (Workload Identity Federation - no keys)
       |
       v
Claude on Vertex AI      (reviews diff against rules/)
       |
       +---> Inline comments on vulnerable lines
       +---> Summary comment grouped by severity
       +---> CI status: FAIL if CRITICAL findings exist
```

## Adding to Your Repo

1. Create `.github/workflows/security-review.yml` in your repo:

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

That's it. The reusable workflow handles checkout, authentication, rules, and reporting.

2. Make sure your repo has access to the required organization secrets:
   - `WIF_PROVIDER` - Workload Identity Federation provider resource name
   - `WIF_SERVICE_ACCOUNT` - Service account email for Vertex AI access

These should already be configured as organization-level secrets. If not, ask in #eng-infra.

## Configuration

Override defaults by passing inputs to the reusable workflow:

```yaml
jobs:
  security-review:
    uses: polen-dev/security-reviews/.github/workflows/security-review.yml@v1
    secrets: inherit
    with:
      model: claude-sonnet-4-5-20250929   # default; can use opus for critical repos
      max_turns: 10                        # max agent turns; increase for large PRs
      extra_instructions: |                # repo-specific rules appended to the prompt
        This repo handles payment processing.
        Flag any logging of credit card numbers or CVVs.
```

| Input                | Default                          | Description                                      |
|----------------------|----------------------------------|--------------------------------------------------|
| `model`              | `claude-sonnet-4-5-20250929`     | Claude model ID for the review                   |
| `max_turns`          | `10`                             | Maximum agent turns before timeout               |
| `extra_instructions` | `""`                             | Additional repo-specific security rules          |

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

## Security Rules

Rules live in the `rules/` directory of this repo:

| File                    | Purpose                                                   |
|-------------------------|-----------------------------------------------------------|
| `security-rules.md`    | OWASP Top 10+ checklist with vulnerable/fixed code examples |
| `false-positives.md`   | What to skip (test files, env references, type definitions) |
| `polen-specific.md`    | Business-context rules (multi-tenant isolation, LGPD, financial data) |

To propose changes to rules, open a PR against this repo.

## Findings Schema

Review output follows a JSON schema at `schemas/findings.json`. Each finding includes:

- **severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **category**: Security category (e.g., Injection, Broken Access Control)
- **title**: Short description of the issue
- **file** and **line**: Location in the codebase
- **recommendation**: Actionable fix
- **cwe**: CWE identifier when applicable

The `has_critical` boolean at the top level is what CI uses to pass/fail the check.

## Cost

Each review costs approximately **$0.05 USD** with the default Sonnet model. Cost scales with PR size since larger diffs require more tokens. For most PRs (under 500 lines changed), expect costs under $0.10.

Using Opus increases cost roughly 5x but may catch more subtle issues. Consider it for repos that handle authentication, payments, or sensitive data.

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
