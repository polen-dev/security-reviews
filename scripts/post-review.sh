#!/usr/bin/env bash
set -euo pipefail

# Post Claude's security review as a PR comment and fail if CRITICAL findings exist.
# Expects env vars: GH_TOKEN, PR_NUMBER, REPO, RUNNER_TEMP

OUTPUT_FILE="${RUNNER_TEMP}/claude-execution-output.json"

if [ ! -f "$OUTPUT_FILE" ]; then
  echo "No execution output file found at $OUTPUT_FILE"
  echo "Listing RUNNER_TEMP contents:"
  ls -la "$RUNNER_TEMP"/ || true
  exit 0
fi

# Extract Claude's final result text
TMPFILE=$(mktemp)
jq -r '.result // empty' "$OUTPUT_FILE" > "$TMPFILE" 2>/dev/null

if [ ! -s "$TMPFILE" ]; then
  echo "No result in execution output."
  rm -f "$TMPFILE"
  exit 0
fi

# Build comment with header and footer
COMMENT_FILE=$(mktemp)
{
  echo "## Security Review"
  echo ""
  cat "$TMPFILE"
  echo ""
  echo "---"
  echo "*Automated security review by Claude on Vertex AI*"
} > "$COMMENT_FILE"

# Post as PR comment
gh pr comment "$PR_NUMBER" --repo "$REPO" --body-file "$COMMENT_FILE"
echo "Review comment posted."

# Check for CRITICAL findings
if grep -qi "CRITICAL" "$TMPFILE"; then
  echo "::error::Security review found CRITICAL findings. See PR comment for details."
  rm -f "$TMPFILE" "$COMMENT_FILE"
  exit 1
fi

rm -f "$TMPFILE" "$COMMENT_FILE"
echo "No CRITICAL findings detected."
