# ADR-0053: Public / internal boundary of the api

**Status:** Accepted (implemented in step 6.1; the Ingress is rendered with `kubectl kustomize` and tested, not applied to a cluster; verification record in [§13 of the step design](../../plan/steps/18-rest-api.md#13-verification-record)). Design: [step 6.1](../../plan/steps/18-rest-api.md) D13. Builds on [ADR-0015](0015-api-base-path.md); keeps the boundaries of [ADR-0031](0031-time-of-click-service.md) (click-service) and [ADR-0039](0039-sandbox-security-boundary-and-backends.md) (sandbox controller); supersedes nothing.

**Context.** The api port serves the business routes under `/api/v1`, the probes `/health/live` and `/health/ready`, the Prometheus scrape `/metrics` and, outside production, Swagger UI at `/docs` and `/docs-json`. Until 6.1 the only Kubernetes Ingress was the click-service's; nothing enforced which of the api's paths may be public, the two probes were listed in the public OpenAPI document, and a future route outside `/api/v1` would have been served silently.

**Decision.**

1. **Public:** only `/api/v1/*` of the api (and the click-service's `/c/…` and `/static/click.css`, ADR-0031). **Internal:** `/health/live`, `/health/ready`, `/metrics` on the api port; every worker's HTTP port (probes, metrics); `/docs`, `/docs-json` (never served in production: `setupOpenApiOutsideProduction` in `main.ts`); RabbitMQ management, MinIO, Redis, MySQL.
2. **The router serves nothing else:** the route inventory test fails a route that is neither under `/api/v1` nor one of the three internal endpoints; `/api/metrics`, `/api/health/*`, `/api/docs` and `/api/v1/metrics` are `404 route_not_found` (with `X-Request-Id`).
3. **The public OpenAPI document lists only `/api/v1/*`** (the probes were removed from it; they stay documented in contracts §9).
4. **Kubernetes:** the api `Ingress` (base `api.yaml`, class nginx, TLS host placeholder per environment) routes only `Prefix /api/v1/` to the api Service. `test/public-boundary.e2e.test.ts` parses every YAML document of `infrastructure/kubernetes/base` and fails when any Ingress routes another path, `/metrics`, `/health`, `/docs`, a worker Service or uses a default backend.
5. No worker exposes a business HTTP API; internal callbacks are RabbitMQ messages.
6. The v1 cursor HMAC key `API_CURSOR_KEY` is an api-only secret (its own Kubernetes Secret, mounted only in the api).

**Alternatives considered.** A separate internal port for probes and metrics on the api (as the click-service has): cleaner, but changes every probe, Compose health check and scrape target; the path allow-list plus the Ingress test gives the same exposure guarantee now. Keeping the probes in the public document: lists internal endpoints to every client. An Ingress with a catch-all `/` to the api relying on the app to 404: exposes `/metrics` and `/health`.

**Consequences.** Any new public surface (webhooks 6.2, archive 8.1, integrations 8.2) is a route under `/api/v1` and passes the inventory; a new Ingress path needs this ADR amended and the boundary test changed. Per-IP limiting is not done at the Ingress (API clients share NAT addresses); the api limits per principal and tenant (ADR-0052). A cluster apply and the ingress controller's behaviour are not verified locally.
