# Plan: Multi-Model Security Review Action

## Context

The security-reviews project currently uses `anthropics/claude-code-action@v1`, which locks every review to Claude models. Switching to cheaper alternatives like Kimi K2.5 (~$0.05-0.10/review vs $0.30-0.50) or free Gemini requires a custom GitHub Action that calls any Vertex AI Model Garden model. The rules, methodology, and findings schema are already model-agnostic — only the runtime is coupled to Claude.

This is a **breaking v2 release**. Default model changes from Claude Sonnet 4.5 to Gemini 2.5 Pro.

## Approach: Single-Shot Custom Action

Replace the agentic multi-turn `claude-code-action` with a single-shot action that:
1. Gathers all context upfront (diff + rules + repo structure)
2. Makes one API call to any Vertex AI model via `generateContent`
3. Posts the review as a PR comment and fails CI on CRITICAL findings

This is simpler, faster, cheaper, and model-agnostic. The trade-off is losing the agentic loop's ability to explore the repo dynamically — but for security reviews, pre-gathering the diff + rules + file tree covers the vast majority of the value.

## File Structure

```
security-reviews/
  action/                          # NEW — custom GitHub Action
    action.yml                     # Action definition
    package.json                   # Dependencies
    tsconfig.json
    src/
      index.ts                     # Entry point — orchestrates the review
      vertex-client.ts             # Vertex AI generateContent API client
      context-builder.ts           # Gathers diff, rules, repo context into prompt
      output-parser.ts             # Extracts JSON findings from model response
      types.ts                     # Shared interfaces
    dist/
      index.js                     # Bundled output (ncc) — committed to repo
  .github/workflows/
    security-review.yml            # MODIFIED — use custom action instead of claude-code-action
  caller-template.yml              # MODIFIED — @v2, new model format
  rules/                           # UNCHANGED
  schemas/                         # UNCHANGED
  CLAUDE.md                        # UNCHANGED (renamed role: system prompt, not Claude-specific)
```

## Key Design Decisions

- **Model input format**: `publisher/model` (e.g., `google/gemini-2.5-pro`, `moonshotai/kimi-k2-thinking-maas`, `anthropic/claude-sonnet-4-5`). Maps directly to Vertex AI URL structure.
- **Default model**: `google/gemini-2.5-pro`
- **SDK**: Raw `fetch` + `google-auth-library` for token generation. No heavy SDK — we make one POST request.
- **Bundling**: `@vercel/ncc` produces `dist/index.js`. Standard pattern for JS GitHub Actions.
- **Diff truncation**: Configurable `max_context_chars` (default 400K chars ~100K tokens). Truncates tail with a warning message if exceeded.
- **Repo context**: Includes `git log --oneline -20` and a compact file tree in the prompt to partially compensate for losing the agentic exploration.
- **Comment posting + CI failure**: Handled inside the action itself (no separate `actions/github-script` step needed).

## Implementation Steps

### 1. Scaffold `action/` directory
- Create `package.json` with deps: `@actions/core`, `@actions/github`, `google-auth-library`
- Create `tsconfig.json` targeting Node 20
- Create `action.yml` with inputs: `model`, `project_id`, `location`, `rules_path`, `schema_path`, `system_prompt_path`, `extra_instructions`, `max_context_chars`, `temperature`, `github_token`

### 2. Implement `types.ts`
- `ActionInputs`, `ParsedModel`, `Finding`, `FindingsReport`, `VertexResponse` interfaces

### 3. Implement `vertex-client.ts`
- `parseModel(model: string)` — splits `publisher/model` format
- `callVertexAI(params)` — authenticates via `GoogleAuth`, POSTs to `generateContent` endpoint, extracts response text, logs token usage

### 4. Implement `context-builder.ts`
- `buildPrompt(inputs)` — reads rule files from disk, gets PR diff via `git diff`, gets repo context (log + file tree), assembles system instruction + user prompt
- Handles diff truncation with configurable char limit

### 5. Implement `output-parser.ts`
- `extractFindings(responseText)` — regex extracts last ` ```json ` block, parses and validates against schema
- `hasCriticalFindings(responseText, findings)` — checks parsed JSON first, falls back to string matching

### 6. Implement `index.ts`
- Reads action inputs, calls `buildPrompt`, calls `callVertexAI`, calls `extractFindings`, posts PR comment via Octokit, sets outputs, calls `core.setFailed` if critical

### 7. Bundle and commit
- `npm run build` (`ncc build src/index.ts -o dist --minify`)
- Commit `dist/index.js` to the repo

### 8. Update reusable workflow (`.github/workflows/security-review.yml`)
- Remove `claude-code-action` step and `actions/github-script` post-processing step
- Replace with single `uses: ./.security-config/action` step
- Remove `max_turns` input (no agentic loop)
- Change model default to `google/gemini-2.5-pro`
- Add `max_context_chars` input
- Remove `ANTHROPIC_VERTEX_PROJECT_ID` and `CLOUD_ML_REGION` env vars (now action inputs)
- Add `action/` to the sparse-checkout list

### 9. Update `caller-template.yml`
- Change ref from `@v1` to `@v2`
- Document new `publisher/model` format in comments

### 10. Test end-to-end
- Open a PR with known vulnerabilities in a test repo
- Verify: WIF auth works, model receives correct prompt, PR comment posts, CRITICAL findings fail CI, clean PRs pass
- Test with at least Gemini 2.5 Pro and one other model (Kimi or Claude)

### 11. Tag v2 release

## Critical Files

| File | Action |
|------|--------|
| `action/action.yml` | CREATE |
| `action/package.json` | CREATE |
| `action/tsconfig.json` | CREATE |
| `action/src/index.ts` | CREATE |
| `action/src/vertex-client.ts` | CREATE |
| `action/src/context-builder.ts` | CREATE |
| `action/src/output-parser.ts` | CREATE |
| `action/src/types.ts` | CREATE |
| `.github/workflows/security-review.yml` | MODIFY |
| `caller-template.yml` | MODIFY |

## Verification

1. **Unit tests**: `parseModel()`, `extractFindings()`, `hasCriticalFindings()`, prompt assembly
2. **Local test**: Run `context-builder.ts` against a real repo to verify diff + rules assembly
3. **Manual Vertex AI test**: Call `generateContent` with a sample diff to verify auth and response format
4. **E2E test**: Open PR in a test repo, confirm full workflow runs, comment posts, CI status correct
5. **Multi-model test**: Run the same PR through Gemini 2.5 Pro and at least one other model to verify model-agnostic behavior

## Risks

- **Model output quality variance**: Different models may follow JSON output instructions less reliably. Mitigated by fallback string matching in `hasCriticalFindings`.
- **Thinking models**: Kimi K2 Thinking may include reasoning tokens in response. Need to verify Vertex API response format and potentially filter thinking blocks.
- **Large diffs**: Truncation drops tail of diff. Future enhancement: prioritize truncating lock files / generated code first.
