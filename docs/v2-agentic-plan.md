# Plan: Multi-Model Agentic Security Review Action (v2)

## Context

The security-reviews project uses `anthropics/claude-code-action@v1`, locking every review to Claude. We want to support any Vertex AI Model Garden model (Gemini, Kimi K2.5, Claude, Mistral) without compromising on the agentic loop — the model must be able to explore the repo dynamically (read files, grep for patterns, check git history) just like `claude-code-action` does today.

The Claude Agent SDK was evaluated and rejected: it's architecturally locked to Claude's tool-use protocol with no model parameter or adapter layer for non-Claude models.

**This is a breaking v2 release.** Default model changes from Claude Sonnet 4.5 to Gemini 2.5 Pro.

## Approach: Custom Tool Loop Against Raw Vertex AI API

Build a lightweight agentic GitHub Action that:
1. Defines tools (read_file, list_files, search_files, git_diff, git_log, git_show)
2. Sends the prompt + tool definitions to any Vertex AI model via `generateContent` with the `tools` parameter
3. Runs a tool loop: model returns `functionCall` -> action executes tool -> sends `functionResponse` back -> repeat until model stops or hits max turns
4. For models without native function calling support, falls back to **prompt-based tool use** (tools described in system prompt, JSON tool calls parsed from text output)
5. Posts findings as PR comment and fails CI on CRITICAL findings

### Why not Vercel AI SDK?

It abstracts the tool loop beautifully but only has Vertex AI providers for Gemini (`@ai-sdk/google-vertex`) and Claude (`@ai-sdk/google-vertex/anthropic`). No generic Model Garden provider exists for Kimi, Mistral, etc.

### Why not Claude Agent SDK?

It's architecturally locked to Claude:
- Auth only routes to Claude endpoints (`CLAUDE_CODE_USE_VERTEX=1` = Claude-on-Vertex, not Model Garden)
- The agent loop speaks Claude's `tool_use`/`tool_result` protocol, not Vertex AI's `functionCall`/`functionResponse`
- Built-in tools (Read, Glob, Grep, etc.) are welded to the Claude-specific loop — can't reuse them
- No `model` parameter — model is determined entirely by which provider env var you set

### Why raw Vertex API + custom loop?

- **One code path** for all models — the `generateContent` endpoint with `tools` is the same for Gemini, Claude, DeepSeek, Llama, and Qwen on Vertex AI
- **~100 lines** for the core loop
- **Minimal dependencies**: just `google-auth-library` + `@actions/core` + `@actions/github`
- **Full control** over retry, timeout, fallback behavior

## File Structure

```
security-reviews/
  action/
    action.yml                     # GitHub Action definition
    package.json
    tsconfig.json
    src/
      index.ts                     # Entry point
      vertex-client.ts             # Vertex AI generateContent client + auth
      agent-loop.ts                # Core agentic loop (functionCall/functionResponse cycle)
      tools.ts                     # Tool definitions + executors (read, glob, grep, git)
      prompt-builder.ts            # Builds system instruction + initial user prompt
      output-parser.ts             # Extracts JSON findings from final model response
      fallback.ts                  # Prompt-based tool use for models without native function calling
      types.ts                     # Shared interfaces
    __tests__/
      agent-loop.test.ts
      tools.test.ts
      output-parser.test.ts
      fallback.test.ts
    dist/
      index.js                     # Bundled output (ncc) — committed to repo
  .github/workflows/
    security-review.yml            # MODIFIED — use custom action
  caller-template.yml              # MODIFIED — @v2, new model format
  rules/                           # UNCHANGED
  schemas/                         # UNCHANGED
  CLAUDE.md                        # UNCHANGED
```

## Key Design Decisions

### Model input format
`publisher/model` (e.g., `google/gemini-2.5-pro`, `moonshotai/kimi-k2-thinking-maas`, `anthropic/claude-sonnet-4-5`). Maps directly to Vertex AI URL: `publishers/{publisher}/models/{model}`.

### Tool definitions
Mirror the current claude-code-action's allowed tools, implemented as Vertex AI function declarations:

| Tool | Description | Parameters |
|------|-------------|------------|
| `read_file` | Read file contents | `path: string`, `offset?: number`, `limit?: number` |
| `list_files` | Glob for files by pattern | `pattern: string`, `path?: string` |
| `search_files` | Grep file contents | `pattern: string`, `path?: string`, `glob?: string` |
| `git_diff` | Get PR diff | `base?: string` |
| `git_log` | Recent commit history | `max_count?: number` |
| `git_show` | Show specific commit | `ref: string` |

All tools are **read-only**. All tools sanitize inputs (no path traversal outside repo, no command injection via `execFileSync` instead of `execSync`). All tools truncate output to 50K chars.

### Agent loop
```
1. Build initial messages: system instruction (rules + methodology) + user prompt (task + diff)
2. Send to generateContent with tool definitions
3. Check response:
   a. functionCall parts present -> execute each tool -> append functionResponse -> go to 2
   b. Only text parts -> extract findings -> done
   c. Max turns reached -> extract findings from last response -> done
4. Post PR comment + set CI status
```

### Diff always pre-loaded
The PR diff is included in the initial prompt even in agentic mode. The model doesn't need to discover it via a tool call — this saves 1-2 turns. The tools are for Phase 1 (repo context exploration): examining existing security patterns, checking auth middleware, looking at how other endpoints handle validation.

### Fallback strategy for models without native function calling
1. First call includes `tools` parameter
2. If API returns an error about unsupported tools, or model responds with text instead of `functionCall` on first turn -> switch to prompt-based mode
3. Prompt-based mode: describe tools in system prompt, instruct model to emit `<tool_call>{"name": "...", "args": {...}}</tool_call>` tags, parse from text, execute, inject results, continue
4. If prompt-based also fails -> fall back to single-shot (pre-gather all context, one call)

### Max turns
Default: 10. Configurable. Each turn = one API round-trip. A turn may include multiple parallel tool calls.

## Implementation Steps

### 1. Scaffold `action/` directory
- `package.json`: deps `google-auth-library`, `@actions/core`, `@actions/github`; devDeps `@vercel/ncc`, `typescript`, `vitest`, `@types/node`
- `tsconfig.json` targeting ES2022 + Node 20
- `action.yml` with inputs: `model`, `project_id`, `location`, `rules_path`, `schema_path`, `system_prompt_path`, `extra_instructions`, `max_context_chars`, `max_turns`, `temperature`, `github_token`

### 2. Implement `types.ts`
Interfaces: `ActionInputs`, `ParsedModel`, `VertexRequest`, `VertexResponse`, `FunctionCall`, `FunctionResponse`, `Finding`, `FindingsReport`, `ToolDefinition`, `ToolExecutor`, `Content`, `Part`

### 3. Implement `vertex-client.ts`
- `parseModel(model)` — splits `publisher/model`
- `generateContent(params)` — authenticates via `GoogleAuth`, POSTs to Vertex AI `generateContent` endpoint, returns parsed response
- Handles token refresh, error responses, safety filter blocks

### 4. Implement `tools.ts`
- `TOOL_DEFINITIONS`: Array of Vertex AI `FunctionDeclaration` objects
- `executeTool(name, args)`: Dispatch function for each tool
  - Uses `fs.readFileSync` for read_file
  - Uses `globSync` (from `glob` package or Node 22 fs.globSync) for list_files
  - Uses `execFileSync("grep", [...])` for search_files (safe, no shell injection)
  - Uses `execFileSync("git", ["diff", ...])` for git tools (safe, no shell injection)
- Input sanitization: resolve paths and reject anything outside the repo root
- Output truncation: 50K chars per tool result

### 5. Implement `agent-loop.ts`
Core loop (~100 lines):
- Maintains `messages: Content[]` conversation history
- On each turn: call `generateContent`, check for `functionCall` parts
- If function calls found: execute all in parallel via `Promise.all`, append `functionResponse` parts, continue
- If only text: return the text
- If max turns hit: return last text
- Logs turn count and token usage

### 6. Implement `fallback.ts`
For models without native function calling:
- `buildPromptBasedToolInstructions(tools)`: Text description of tools + `<tool_call>` format
- `parseToolCallsFromText(text)`: Regex for `<tool_call>...</tool_call>` JSON
- `runPromptBasedLoop(params)`: Same loop but tools in prompt, calls parsed from text

### 7. Implement `prompt-builder.ts`
- Read rule files, findings schema, system prompt from disk
- Get PR diff via `execFileSync("git", ["diff", ..."])` with truncation
- Assemble system instruction + initial user prompt

### 8. Implement `output-parser.ts`
- `extractFindings(text)`: Regex for last ```json block, parse, validate
- `hasCriticalFindings(text, findings)`: JSON check first, string fallback

### 9. Implement `index.ts`
1. Read inputs -> 2. Build prompt -> 3. Try agentic loop with native tools -> 4. On failure, try prompt-based fallback -> 5. Extract findings -> 6. Post PR comment -> 7. Set outputs + fail CI if critical

### 10. Write tests
- `agent-loop.test.ts`: Mock API, verify loop executes tools and terminates
- `tools.test.ts`: Real filesystem ops in temp directory
- `output-parser.test.ts`: Various response formats
- `fallback.test.ts`: `<tool_call>` parsing

### 11. Bundle + commit
`ncc build src/index.ts -o dist --minify` -> commit `dist/index.js`

### 12. Update reusable workflow
- Replace `claude-code-action` + `actions/github-script` with `uses: ./.security-config/action`
- Default model: `google/gemini-2.5-pro`
- Add `action/` to sparse-checkout

### 13. Update `caller-template.yml`
- Ref `@v2`, document `publisher/model` format

### 14. E2E test + tag v2

## Critical Files

| File | Action |
|------|--------|
| `action/action.yml` | CREATE |
| `action/package.json` | CREATE |
| `action/tsconfig.json` | CREATE |
| `action/src/index.ts` | CREATE |
| `action/src/vertex-client.ts` | CREATE |
| `action/src/agent-loop.ts` | CREATE |
| `action/src/tools.ts` | CREATE |
| `action/src/prompt-builder.ts` | CREATE |
| `action/src/output-parser.ts` | CREATE |
| `action/src/fallback.ts` | CREATE |
| `action/src/types.ts` | CREATE |
| `action/__tests__/*.test.ts` | CREATE (4 files) |
| `.github/workflows/security-review.yml` | MODIFY |
| `caller-template.yml` | MODIFY |

## Verification

1. **Unit tests**: Agent loop (mocked API), tool executors, output parser, fallback parser
2. **Integration test**: Agent loop against real Vertex AI with sample diff in temp repo
3. **E2E test**: Open PR in test repo -> full workflow: WIF auth, agentic exploration, PR comment, CI status
4. **Multi-model test**: Same PR through Gemini 2.5 Pro + at least one other model
5. **Fallback test**: Force prompt-based mode and verify it works

## Risks

| Risk | Mitigation |
|------|------------|
| Function calling quality varies by model | Prompt-based fallback + single-shot last resort |
| Thinking models include reasoning tokens | Filter `reasoning_content` from response parts |
| Token budget (10 turns with tool results) | Truncate tool outputs to 50K chars each |
| Cost with agentic loop | Default model (Gemini 2.5 Pro) is cheap; 10 turns < $0.50 |
| Command injection in tools | Use `execFileSync` (not `execSync`), validate paths against repo root |
