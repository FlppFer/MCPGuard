# Task 2.2: Docker Compose (Local Development)

| Field | Value |
|-------|-------|
| **ID** | task-2.2 |
| **Phase** | 2 — Docker & Deployment |
| **Priority** | High |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-2.1 (Dockerfile) |

---

## Functional Specification

### Problem Statement

No local development environment definition exists. Developers must manually set environment variables, install dependencies, and run the binary. There's no standard way to spin up MCPGuard with its supporting services.

### Expected Behavior

1. `docker compose up` starts the MCPGuard API with all required environment variables.
2. A `.env.example` file documents every required/optional env var.
3. LocalStack is available for S3 integration testing (optional service).

### Acceptance Criteria

- `docker compose up mcpguard-api` starts the API on port 8080.
- `docker compose up localstack` starts LocalStack on port 4566 (for S3 testing).
- `.env.example` lists all required variables with descriptions.

---

## Technical Specification

### docker-compose.yaml

Create at project root:

```yaml
version: "3.9"

services:
  mcpguard-api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - SCOPE=local
      - GITHUB_WEBHOOK_SECRET=${GITHUB_WEBHOOK_SECRET:-default-webhook-secret}
      - MCPGUARD_API_KEYS=${MCPGUARD_API_KEYS:-dev-client:dev-key}
    volumes:
      - mcpguard-storage:/app/mcpguard-local-storage
    restart: unless-stopped

  localstack:
    image: localstack/localstack:latest
    ports:
      - "4566:4566"
    environment:
      - SERVICES=s3
      - DEFAULT_REGION=us-east-1
    volumes:
      - localstack-data:/var/lib/localstack
    profiles:
      - s3-testing

volumes:
  mcpguard-storage:
  localstack-data:
```

### .env.example

Create at project root:

```env
# MCPGuard Environment Variables
# Copy this file to .env and fill in the values.

# Config profile: "local" (mock DB/storage) or "prod" (SQLite file + S3)
SCOPE=local

# GitHub webhook HMAC-SHA256 secret (must match GitHub repository webhook config)
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here

# API key pairs for direct API access (format: client_id:api_key,client_id2:api_key2)
MCPGUARD_API_KEYS=client1:apikey1

# (Production only) AWS credentials for S3
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_REGION=us-east-1
```

### Files to Create

| File | Purpose |
|------|---------|
| `docker-compose.yaml` | Service definitions for local dev |
| `.env.example` | Documented environment variable template |

### Testing

1. `cp .env.example .env` → fill in values.
2. `docker compose up mcpguard-api` → verify API starts.
3. `docker compose --profile s3-testing up` → verify LocalStack also starts.
4. `curl http://localhost:8080/health` → verify 200.
