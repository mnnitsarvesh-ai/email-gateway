# ADR-0013: Vitest with SWC; unit, e2e and integration layers

**Status:** Accepted

**Decision.**

| Layer         | Where                   | Runs against                                  | Command                 |
| ------------- | ----------------------- | --------------------------------------------- | ----------------------- |
| Unit          | `**/src/**/*.test.ts`   | Nothing external                              | `pnpm test`             |
| E2E (per app) | `apps/*/test/*.test.ts` | The Nest app in-process, dependencies stubbed | `pnpm test:e2e`         |
| Integration   | `tests/integration`     | The running Docker Compose stack              | `pnpm test:integration` |

- Vitest everywhere. Nest packages use `unplugin-swc` so decorator metadata (needed by DI) is emitted.
- Integration tests assert real behaviour: SMTP replies, relay denial, fail-closed policy, EICAR detection (the test string is assembled at runtime and never committed), DB privilege separation, `processOnce` semantics, queue round-trips, auth enforcement on Redis, RabbitMQ and S3.
- CI runs all three layers. The `stack` job brings up the full Compose stack, including application images.

**Consequences.** Integration tests need the stack (`pnpm infra:up`). Application tests skip automatically when the `apps` profile isn't running.
