# ADR-0003: Prisma ORM and Prisma Migrate for MySQL

**Status:** Accepted

**Context.** The brief requires choosing either Prisma or TypeORM and using it consistently, with version-controlled MySQL migrations.

**Decision.** Use Prisma (6.x line) in `packages/database`.

- `prisma/schema.prisma` is the single schema definition. `prisma/migrations/*/migration.sql` is committed and reviewed like code.
- Production applies migrations with `prisma migrate deploy` from a dedicated job (`db-migrate` in Compose, a Kubernetes Job in clusters), using a **separate DDL-capable account** (`MIGRATION_DATABASE_URL`, mapped to Prisma's `directUrl`). Services connect with a DML-only account.
- CI applies every migration to a fresh MySQL 8.4 and fails if `schema.prisma` and the migrated database differ (`prisma migrate diff --exit-code`).
- Raw SQL is allowed inside migrations for things Prisma can't model, such as partitioning. Hand edits must keep the drift check green.

**Alternatives.** TypeORM: decorator entities fit Nest naturally, but its migrations generator and type safety are weaker, and its `synchronize` is a production foot-gun. Kysely/Drizzle: good, but the brief limits the choice to Prisma or TypeORM.

**Consequences.**

- Generated, fully typed client. Interactive transactions support the outbox and `processOnce` patterns.
- Prisma cannot express MySQL partitioning, so partitioned message tables will be created with hand-written SQL in their migrations, with Prisma models that use composite keys including the partition column. That is planned with ADR-0004.
- **Follow-up:** Prisma 7 is now the current major. It moves configuration into `prisma.config.ts` and requires driver adapters. We stay on 6.x for CommonJS/NestJS compatibility and will evaluate upgrading in a dedicated task. Deprecation warnings are expected until then.
