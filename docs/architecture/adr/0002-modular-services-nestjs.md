# ADR-0002: NestJS modular services; 15 logical services on 8 deployables

**Status:** Accepted. Amended by [ADR-0015](0015-api-base-path.md): business routes are served under `/api/v1`; amended by [ADR-0023](0023-outbox-relay-and-reconciliation.md): a ninth deployable, `event-relay` (outbox relay and reconciliation)

**Context.** The requirements name 15 services. Running each as its own microservice from day one multiplies deployment, observability and on-call cost without a matching benefit at 1M messages/day. Some boundaries do need independent scaling, though. Scanning, for example, scales with mail volume, while tenant CRUD doesn't.

**Decision.**

- Use NestJS (Express adapter) with strict TypeScript for every backend workload. Shared cross-cutting setup lives in `packages/common`: health, correlation, exception filter, infra clients and bootstrap.
- Logical services are Nest modules. They are grouped into deployables by scaling profile: `api`, `smtp-adapter`, `email-worker`, `policy-engine`, `delivery-worker`, `notification-worker`, `archive-worker`, plus the Next.js `admin-portal`. The mapping is in `docs/architecture/overview.md`.
- Controllers only translate HTTP into service calls. Business logic lives in injectable services.
- REST with URI versioning (`/v1`). Health probes are version-neutral.

**Alternatives.** Fastify adapter: faster, but Express has wider middleware compatibility and HTTP throughput is not our bottleneck. We can switch per app later. One process per logical service: rejected for now (see Context).

**Consequences.** Fewer moving parts to operate. Splitting a module out later means moving it to a new `apps/*` entry; its contracts don't change.
