# Database

MySQL 8.4, managed with Prisma (ADR-0003, ADR-0004). The schema lives in `packages/database/prisma/schema.prisma`; migrations live in `packages/database/prisma/migrations/`.

## Accounts

| Account            | Privileges                                             | Used by                                   | Env var                  |
| ------------------ | ------------------------------------------------------ | ----------------------------------------- | ------------------------ |
| `gateway_app`      | `SELECT, INSERT, UPDATE, DELETE` on the gateway schema | Every service at runtime                  | `DATABASE_URL`           |
| `gateway_migrator` | DDL on the gateway schema (+ shadow DB locally)        | `prisma migrate` and the `db-migrate` job | `MIGRATION_DATABASE_URL` |

Locally, both accounts are created by `infrastructure/mysql/init/01-users.sh` on the first start of an empty volume.

## Conventions

- Tables and columns are `snake_case` (`@@map`/`@map`). Models are `PascalCase`.
- Every tenant-owned table has a non-null `tenant_id CHAR(36)`, and its indexes lead with it.
- Entity ids are UUIDv7 (`@default(uuid(7))`, `CHAR(36)`). Append-only logs use `BIGINT AUTO_INCREMENT`.
- Timestamps are `DATETIME(3)` in UTC (`created_at`, `updated_at`).
- Enums are MySQL `ENUM`s via Prisma enums. Add values at the end only.
- Every table has a primary key (`sql_require_primary_key=ON`).
- `audit_logs` is append-only. Services never update or delete it.

## Current tables

| Table              | Purpose                                                                     |
| ------------------ | --------------------------------------------------------------------------- |
| `tenants`          | Customer organisations (`slug` unique, `status`)                            |
| `tenant_domains`   | Domains per tenant with DNS verification state. `domain` is globally unique |
| `users`            | Portal users per tenant (`tenant_id, email` unique) with a role             |
| `audit_logs`       | Append-only trail of administrative actions with correlation id             |
| `outbox_events`    | Transactional outbox (ADR-0005)                                             |
| `processed_events` | Idempotency ledger, PK `(consumer, event_id)`                               |

## Workflows

```bash
pnpm db:migrate              # apply pending migrations (prisma migrate deploy)
pnpm db:status               # show migration status
pnpm db:migrate:dev          # local only: diff schema.prisma, create + apply a new migration
pnpm db:generate             # regenerate the Prisma client
```

Changing the schema:

1. Edit `schema.prisma`.
2. Run `pnpm db:migrate:dev --name <short_description>`. This creates `prisma/migrations/<timestamp>_<name>/migration.sql`.
3. Review the SQL, especially for locking on large tables. Prefer additive, backwards-compatible changes (expand → migrate → contract) so old and new pods can run side by side during a rollout.
4. Commit the schema and the migration together. CI fails if they don't match.

Never edit a migration that has been applied anywhere shared. Write a new one instead.
