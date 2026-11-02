# ADR-0004: MySQL 8.4 as the primary transactional store

**Status:** Superseded by [ADR-0014](0014-mysql-data-model-partitioning-read-write-split.md)

**Context.** Control-plane data and per-message pipeline state need ACID transactions, foreign keys where possible, and one atomic commit for "message + recipients + outbox". MySQL 8.4 LTS is mandated.

**Decision.**

- MySQL 8.4 with a single writer and read replicas (RDS or Aurora; the choice is open). The **data plane uses only the writer**. Replicas serve control-plane reads.
- Server settings: `utf8mb4`, UTC, `READ-COMMITTED`, `sql_require_primary_key=ON` (`infrastructure/mysql/conf.d`).
- Entity ids are UUIDv7 (`@default(uuid(7))`), which are time-ordered, so inserts mostly append to the InnoDB B-tree, and they are unique across SaaS and dedicated deployments. Control-plane tables store them as `CHAR(36)`. Append-only logs (`outbox_events`, `audit_logs`) use `BIGINT AUTO_INCREMENT` for strict ordering.
- Event history and analytics go to ClickHouse, not MySQL (ADR-0009).

**Planned (with the ingestion phase).** High-volume per-message tables are range-partitioned by month on `received_at`, so retention drops partitions instead of deleting rows. We will also evaluate `BINARY(16)` ids for those tables, because at ~2.5M rows/day `CHAR(36)` keys roughly double index size.

**Consequences.** Retention and partition maintenance become an operational job with alerting. Partitioned tables can't have foreign keys, so integrity across them relies on single-transaction writes and tests.
