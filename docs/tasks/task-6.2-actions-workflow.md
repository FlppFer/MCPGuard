# Task 6.2: GitHub Actions Workflow for MCPGuard Analysis

| Field | Value |
|-------|-------|
| **ID** | task-6.2 |
| **Phase** | 6 — GitHub Actions PR Integration |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-6.1 (PR Comment Service) |

---

## Functional Specification

### Problem Statement

External repositories that want to use MCPGuard for PR security analysis have no reusable GitHub Actions workflow to integrate with. Each consumer would need to write their own integration logic.

### Expected Behavior

1. A reusable GitHub Actions workflow is available that:
   - Triggers MCPGuard analysis via the API.
   - Polls for completion.
   - Fetches results.
   - (Optionally) posts a PR comment with findings.
2. Consumer repos can reference the workflow or copy a helper script.

### Acceptance Criteria

- A working `.github/workflows/mcpguard-analysis.yaml` exists.
- The workflow can be triggered manually (`workflow_dispatch`) for testing.
- A helper script `scripts/mcpguard-analyze.sh` can be used standalone.

---

## Technical Specification

### Create `.github/workflows/mcpguard-analysis.yaml`

```yaml
name: MCPGuard Security Analysis

on:
  workflow_dispatch:
    inputs:
      repo_url:
        description: "Repository URL to analyze"
        required: true
      branch:
        description: "Branch to analyze"
        required: false
        default: "main"

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger MCPGuard Analysis
        id: trigger
        run: |
          RESPONSE=$(curl -s -X POST "${{ secrets.MCPGUARD_API_URL }}/v1/analysis" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: ${{ secrets.MCPGUARD_API_KEY }}" \
            -H "X-Client-ID: ${{ secrets.MCPGUARD_CLIENT_ID }}" \
            -d '{"repo_url": "${{ inputs.repo_url }}", "branch": "${{ inputs.branch }}"}')
          ANALYSIS_ID=$(echo "$RESPONSE" | jq -r '.analysis_id')
          echo "analysis_id=$ANALYSIS_ID" >> "$GITHUB_OUTPUT"
          echo "Triggered analysis: $ANALYSIS_ID"

      - name: Poll for Completion
        run: |
          ANALYSIS_ID="${{ steps.trigger.outputs.analysis_id }}"
          for i in $(seq 1 60); do
            STATUS=$(curl -s "${{ secrets.MCPGUARD_API_URL }}/v1/analysis/$ANALYSIS_ID/status" \
              -H "X-API-Key: ${{ secrets.MCPGUARD_API_KEY }}" \
              -H "X-Client-ID: ${{ secrets.MCPGUARD_CLIENT_ID }}" \
              | jq -r '.status')
            echo "Attempt $i: status=$STATUS"
            if [[ "$STATUS" == "static_analysis_done" || "$STATUS" == "completed" ]]; then
              echo "Analysis complete!"
              break
            fi
            if [[ "$STATUS" == "failed" ]]; then
              echo "Analysis failed!"
              exit 1
            fi
            sleep 10
          done

      - name: Fetch Results
        run: |
          ANALYSIS_ID="${{ steps.trigger.outputs.analysis_id }}"
          curl -s "${{ secrets.MCPGUARD_API_URL }}/v1/analysis/$ANALYSIS_ID/result" \
            -H "X-API-Key: ${{ secrets.MCPGUARD_API_KEY }}" \
            -H "X-Client-ID: ${{ secrets.MCPGUARD_CLIENT_ID }}" \
            | jq '.' > results.json
          echo "## Results"
          cat results.json
          FINDINGS=$(jq '.findings | length' results.json)
          echo "Total findings: $FINDINGS"
```

### Create `scripts/mcpguard-analyze.sh`

A standalone shell script that consumer repos can call:

```bash
#!/usr/bin/env bash
# Usage: ./mcpguard-analyze.sh <repo_url> [branch]
# Requires: MCPGUARD_API_URL, MCPGUARD_API_KEY, MCPGUARD_CLIENT_ID env vars

set -euo pipefail

REPO_URL="${1:?Usage: $0 <repo_url> [branch]}"
BRANCH="${2:-main}"
API_URL="${MCPGUARD_API_URL:?Set MCPGUARD_API_URL}"
API_KEY="${MCPGUARD_API_KEY:?Set MCPGUARD_API_KEY}"
CLIENT_ID="${MCPGUARD_CLIENT_ID:?Set MCPGUARD_CLIENT_ID}"

# Trigger
RESPONSE=$(curl -sf -X POST "$API_URL/v1/analysis" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Client-ID: $CLIENT_ID" \
  -d "{\"repo_url\": \"$REPO_URL\", \"branch\": \"$BRANCH\"}")

ANALYSIS_ID=$(echo "$RESPONSE" | jq -r '.analysis_id')
echo "Analysis started: $ANALYSIS_ID"

# Poll
for i in $(seq 1 60); do
  STATUS=$(curl -sf "$API_URL/v1/analysis/$ANALYSIS_ID/status" \
    -H "X-API-Key: $API_KEY" -H "X-Client-ID: $CLIENT_ID" | jq -r '.status')
  echo "[$i/60] Status: $STATUS"
  [[ "$STATUS" == "static_analysis_done" || "$STATUS" == "completed" ]] && break
  [[ "$STATUS" == "failed" ]] && { echo "FAILED"; exit 1; }
  sleep 10
done

# Fetch results
curl -sf "$API_URL/v1/analysis/$ANALYSIS_ID/result" \
  -H "X-API-Key: $API_KEY" -H "X-Client-ID: $CLIENT_ID" | jq '.'
```

### Required Repository Secrets (for consumer repos)

| Secret | Description |
|--------|-------------|
| `MCPGUARD_API_URL` | Base URL of the MCPGuard API (e.g., `https://mcpguard.example.com`) |
| `MCPGUARD_API_KEY` | API key for authentication |
| `MCPGUARD_CLIENT_ID` | Client ID for authentication |

### Files to Create

| File | Purpose |
|------|---------|
| `.github/workflows/mcpguard-analysis.yaml` | Reusable analysis workflow |
| `scripts/mcpguard-analyze.sh` | Standalone analysis script |

### Testing

- Run workflow manually via `workflow_dispatch` with a test repo URL.
- Run `scripts/mcpguard-analyze.sh` against a local MCPGuard instance.
