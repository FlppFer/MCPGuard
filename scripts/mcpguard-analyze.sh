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
