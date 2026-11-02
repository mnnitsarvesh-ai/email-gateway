# ADR-0015: Business API under `/api/v1`; probes stay unprefixed

**Status:** Accepted. Amends the route prefix in [ADR-0002](0002-modular-services-nestjs.md)

**Context.** ADR-0002 put business routes at `/v1/...` on the root of the `api` origin. The product brief for step 1.2 names the endpoints `/api/v1/organizations...`. In production the portal and the API are expected to sit behind one load balancer or ingress host, where a fixed `/api` prefix makes path-based routing to the `api` service trivial and keeps the portal's own routes (`/`, `/login`, `/api/health` of the Next.js app) separate by host or by rule. Health probes are consumed by Docker, Kubernetes and load balancers and must not move.

**Decision.**

- The `api` app sets the Nest global prefix `api` and keeps URI versioning (default version `1`). Business routes are `/api/v1/<resource>`.
- `GET /health/live` and `GET /health/ready` are excluded from the prefix and stay version-neutral. Compose health checks, Kubernetes probes and the portal's server-side readiness call do not change.
- OpenAPI (Swagger UI) stays at `/docs` (outside production), and documents the `/api/v1` paths.
- The prefix is applied in one exported function in `apps/api` (used by `main.ts` and by every in-process test), not in `packages/common`: the other services expose only health endpoints and keep the shared `configureHttpApp` unchanged.
- `API_INTERNAL_URL` remains the API **origin** (`http://api:3000`). Callers append `/health/ready` or `/api/v1/...`.

**Alternatives.** Keeping `/v1` and adding `/api` only at the ingress (path rewrite): hides a routing rule outside the code, makes local and production URLs differ, and contradicts the brief. Prefixing the health routes too: breaks every probe for no benefit.

**Consequences.** `/v1/meta` becomes `/api/v1/meta`; the old path returns 404. Tests, docs and the integration suite use the new paths. A breaking API change ships as `/api/v2` next to `/api/v1`.
