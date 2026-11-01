# API conventions

## Versioning

- Business routes are versioned in the URI: `/v1/...`. Breaking changes ship as `/v2` alongside `/v1` until clients migrate.
- Operational routes are unversioned: `GET /health/live`, `GET /health/ready`.
- In non-production environments, OpenAPI is served at `/docs`.

## Current endpoints

| Method | Path            | Description                                                  |
| ------ | --------------- | ------------------------------------------------------------ |
| GET    | `/health/live`  | Process liveness. No dependency checks                       |
| GET    | `/health/ready` | Dependency readiness. `200` when all are ok, `503` otherwise |
| GET    | `/v1/meta`      | API build/version information                                |

Every Node service exposes the same two health endpoints on its own port (see the root README).

### Readiness response

```json
{
  "service": "api",
  "status": "ok",
  "version": "0.1.0-local",
  "uptimeSeconds": 42,
  "checks": [
    { "name": "mysql", "status": "ok", "latencyMs": 2 },
    { "name": "redis", "status": "ok", "latencyMs": 1 },
    { "name": "s3", "status": "ok", "latencyMs": 6 }
  ]
}
```

## Errors

Every error uses one shape, produced by the global exception filter:

```json
{ "statusCode": 404, "error": "NOT_FOUND", "message": "Cannot GET /v1/x", "correlationId": "..." }
```

Unexpected errors return a generic `500` message. Details go to the logs only, and can be found there by `correlationId`.

## Correlation

Send `x-correlation-id` (8–128 chars of `[A-Za-z0-9._:-]`) to trace a request across services. If it is missing or invalid, a new id is generated. Either way, the id is returned in the response header.

## Tenancy and authorization (Identity phase)

Requests will be authenticated with OIDC (portal) or API keys (automation). The tenant is derived from the authenticated principal. A tenant guard sets it in the request context, and repositories filter by it. No endpoint accepts a tenant id from a header.
