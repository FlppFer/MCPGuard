# Task 2.1: Dockerfile (Multi-stage Build)

| Field | Value |
|-------|-------|
| **ID** | task-2.1 |
| **Phase** | 2 — Docker & Deployment |
| **Priority** | High |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-1.1 (Graceful Shutdown) |

---

## Functional Specification

### Problem Statement

MCPGuard has no containerization. The MCPGuard article specifies Docker for isolation (ensuring analyzed malicious code doesn't affect the host) and reproducibility. Currently, developers must manually install Go, gcc (for CGO/tree-sitter), and git to build and run.

### Expected Behavior

1. A single `docker build .` produces a minimal container image that runs the MCPGuard API.
2. The image includes all runtime dependencies: the compiled binary and `git` (for repository cloning).
3. The image uses a multi-stage build to keep the final image small (no Go toolchain in runtime).
4. The container exposes port 8080 and reads configuration from environment variables.

### Acceptance Criteria

- `docker build -t mcpguard .` succeeds.
- `docker run -p 8080:8080 -e GITHUB_WEBHOOK_SECRET=... -e MCPGUARD_API_KEYS=... mcpguard` starts the API.
- `GET http://localhost:8080/health` returns 200.
- Final image size is under 100MB.

---

## Technical Specification

### Key Constraint: CGO Required

tree-sitter is a C library accessed via CGO. The build stage **must** have `CGO_ENABLED=1` and a C compiler (`gcc`, `musl-dev` on Alpine).

### Dockerfile

Create `Dockerfile` at project root:

```dockerfile
# ============================================
# Stage 1: Build
# ============================================
FROM golang:1.25-alpine AS builder

# CGO is required for tree-sitter
RUN apk add --no-cache gcc musl-dev git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /app/mcpguard ./cmd/api

# ============================================
# Stage 2: Runtime
# ============================================
FROM alpine:3.19

# git is needed at runtime for repository cloning
RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY --from=builder /app/mcpguard .

EXPOSE 8080

# Default to local scope; override with -e SCOPE=prod
ENV SCOPE=local

ENTRYPOINT ["./mcpguard"]
```

### .dockerignore

Create `.dockerignore` at project root:

```
.git
.github
docs/
*.md
analysis_results/
mcpguard-local-storage/
resources/test/
```

### Files to Create

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build for MCPGuard API |
| `.dockerignore` | Exclude unnecessary files from build context |

### Testing

1. `docker build -t mcpguard .` — verify build succeeds.
2. `docker run --rm -e GITHUB_WEBHOOK_SECRET=test -e MCPGUARD_API_KEYS=client1:key1 -p 8080:8080 mcpguard` — verify server starts.
3. `curl http://localhost:8080/health` — verify 200 response.
4. `docker images mcpguard --format '{{.Size}}'` — verify image is small.
