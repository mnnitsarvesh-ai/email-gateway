-- Step 3.2: RabbitMQ event-driven processing, outbox relay and reconciliation
-- (docs/plan/steps/07-rabbitmq.md §4, Q11, Q12; ADR-0023, ADR-0024).
--
-- What changes:
--   * message_outbox (partitioned daily): two reconciliation columns, added in place
--     (ALGORITHM=INSTANT, metadata only, no table rebuild and no partition rewrite):
--       - redrive_count: how often the reconciler re-drove the row (published row whose
--         consumer left no message_idempotency row); bounded by RECONCILE_MAX_REDRIVES.
--       - last_redriven_at: set while a re-drive awaits its re-check; NULL once settled or
--         exhausted.
--   * Index (last_redriven_at) for the reconciler's re-check scan. Created separately: an
--     index cannot be added with ALGORITHM=INSTANT (InnoDB builds it online, in place).
--
-- The relay (apps/event-relay) writes published_at, attempts, available_at and last_error,
-- which already exist. Partitioning, the primary key (id, created_at), the index
-- (published_at, id) and every other table are unchanged (71 tables, 19 partitioned).
-- Permission platform:dead_letter_replay is catalog seed data (pnpm db:seed), not a migration.

ALTER TABLE `message_outbox`
  ADD COLUMN `redrive_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN `last_redriven_at` DATETIME(3) NULL,
  ALGORITHM=INSTANT;

CREATE INDEX `message_outbox_last_redriven_at_idx` ON `message_outbox` (`last_redriven_at`);
