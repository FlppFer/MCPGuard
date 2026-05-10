# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-release notice.** MCPGuard is still on the road to its first tagged
> release (`v1.0.0`). All entries below currently live under `[Unreleased]`
> and will be split into version sections once the API surface is frozen.

## [Unreleased]

### Added

#### Static analysis engine
- Tree-sitter–based static analyzer for **Python** with a rule registry and
  `init()`-driven rule registration.
- Vulnerable Python scripts under `static_analysis/test_data` for integration
  testing of the rule set.
- Static analysis foundation for **JavaScript / TypeScript** (Phase 7a),
  followed by 8 additional rules to bring JS rule coverage to parity with
  Python (Phase 7b).
- Secondary **agentic analysis** path that delegates deep semantic checks to
  the Python worker (`MCPGuard-Agentic`) over HTTP (Phase 3).

#### API & service layer
- HTTP server scaffold with controllers for analysis submission and result
  retrieval (`POST /analysis`, `GET /analysis/{id}`).
- Custom GitHub webhook handler with HMAC-SHA256 signature verification
  (`X-Hub-Signature-256`) and per-event routing.
- API-key authentication middleware (multi-tenant `client_id:api_key` pairs
  via the `MCPGUARD_API_KEYS` env var).
- Local-only troubleshooting endpoint guarded behind scope detection.
- Server hardening pass (Phase 1): structured logging, panic recovery,
  request ID propagation, graceful shutdown.

#### Infrastructure & deployment
- Docker / docker-compose stack (Phase 2) covering the API, worker,
  RabbitMQ, Postgres, LocalStack, and the full observability suite.
- **Postgres** as a first-class persistence backend alongside SQLite,
  selected via `data_base.provider` or the `DATABASE_URL` env var; the API
  and worker share the same DB, fixing the cross-process "record not found"
  loop that plagued the SQLite mock setup.
- **RabbitMQ** message queue (Phase 4) with durable queues and persistent
  messages; producer in the API, consumer in the worker.
- **LocalStack** S3 for local object storage, replacing the in-memory mock.
- Persistent named volumes for Postgres, RabbitMQ, and LocalStack so state
  survives container restarts.
- Runtime env-var overrides (`RABBITMQ_URL`, `DATABASE_URL`) in the config
  loader so infra endpoints can be re-pointed without rebuilding images.

#### Observability (Phase 5 / 6 / polish)
- Prometheus scraping for the API **and** the worker (`/metrics` exposed in
  worker mode on `:8080`).
- Custom application metrics: analysis stage transitions, queue
  publish/consume counters (with `success` / `failure` / `discarded`
  labels), HTTP latency histograms.
- Grafana dashboards: Logs stream (Loki + Promtail) and a complete service
  overview dashboard (provisioned automatically).
- cAdvisor and node-exporter for container and host metrics.
- Manual end-to-end test guide (`docs/MANUAL_TEST_GUIDE.md`).

#### GitHub PR integration (Phase 6)
- Worker posts PR comments with analysis results once a job finishes;
  `PRNumber` and `RepoFullName` are now propagated through the queue
  message so the worker has everything it needs.

#### Project / docs
- MIT license.
- Functional and technical specs under `docs/`.
- Architecture article in `docs/articles/`.
- Task tracker for pending implementations.
- README walkthrough for the docker-compose workflow and the new infra
  defaults.

### Changed

- Auth pipeline split into two distinct middlewares (webhook signature vs.
  API key) with shared error-response shape.
- Folder structure reorganised under `internal/` for clearer service
  boundaries (controllers, services, repositories, middleware, messaging,
  metrics, worker).
- DB client packages renamed for semantic clarity
  (`internal/repositories/db`).
- LocalStack integration moved from the embedded `go-localstack` library to
  a real external LocalStack container, matching the production AWS flow.
- Object storage layer trimmed: the local-filesystem implementation was
  removed in favour of the LocalStack-backed S3 client for both local and
  production scopes.
- Worker container now runs with `SCOPE=docker` so it shares the same
  config file as the API; default `RABBITMQ_URL` and `DATABASE_URL` are
  wired in `docker-compose.yaml`.
- Worker `/metrics` server runs on `:8080` and Prometheus has a dedicated
  `mcpguard-worker` scrape job.
- Logs dashboard defaults the **Service** dropdown to application services
  only (mcpguard-api, worker, python-worker, rabbitmq, postgres,
  localstack), keeping observability containers out of the default view.

### Fixed

- Local SQLite DB instantiation path resolved relative to the working
  directory.
- Authentication error messages and 401/403 routing.
- LocalStorage error propagation surfaced to the controller layer.
- `PRNumber` / `RepoFullName` no longer dropped between API publish and
  worker consume.
- RabbitMQ connect failure on API start no longer panics — the API falls
  back to a no-op publisher and continues to serve traffic.
- Worker no longer infinitely requeues messages whose analysis entity is
  missing from the DB; those are now nacked without requeue and counted
  with the `discarded` label.
- Grafana log noise: `authn.service` "user token not found" warnings from
  anonymous users are silenced via `GF_LOG_FILTERS`.

### Removed

- `.idea/` folder and other IDE artifacts from version control.
- In-memory / on-disk mock object storage (replaced by LocalStack).
- `data_base.mock` as the default for docker scope (still available for
  unit tests).

### Security

- Webhook signature verification is mandatory in all scopes; missing or
  malformed signatures are rejected with 401 before any payload parsing.
- API keys are never echoed in logs; the config loader masks the Postgres
  DSN suffix in startup logs.
