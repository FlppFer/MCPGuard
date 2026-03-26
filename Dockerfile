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
