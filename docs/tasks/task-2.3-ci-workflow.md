# Task 2.3: GitHub Actions CI Workflow

| Field | Value |
|-------|-------|
| **ID** | task-2.3 |
| **Phase** | 2 — Docker & Deployment |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

No CI pipeline exists. Code changes are not automatically built, tested, or vetted. Regressions can be introduced without detection.

### Expected Behavior

1. On every push to `main`/`develop` and on every pull request, GitHub Actions:
   - Builds the project (`go build ./...`)
   - Runs all tests (`go test ./...`)
   - Runs the Go vet tool (`go vet ./...`)
2. Build failures block PR merges.
3. The workflow handles CGO (required for tree-sitter) by installing `gcc`.

### Acceptance Criteria

- Pushing to `main` triggers the CI workflow.
- Opening a PR triggers the CI workflow.
- Build, test, and vet steps all pass on the current codebase.
- Build failures are visible in the GitHub PR checks UI.

---

## Technical Specification

### .github/workflows/ci.yaml

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  build-and-test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.25"

      - name: Install C dependencies (for tree-sitter CGO)
        run: sudo apt-get update && sudo apt-get install -y gcc

      - name: Download Go modules
        run: go mod download

      - name: Build
        run: go build ./...

      - name: Vet
        run: go vet ./...

      - name: Test
        run: go test ./... -v -count=1
        env:
          CGO_ENABLED: "1"
```

### Files to Create

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yaml` | CI pipeline definition |

### Testing

- Push to a branch, verify the workflow runs in the GitHub Actions tab.
- Intentionally break a test, verify the workflow fails.
