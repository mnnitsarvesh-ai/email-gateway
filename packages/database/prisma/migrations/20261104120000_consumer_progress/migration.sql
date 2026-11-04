-- Step 3.2 review round 1 (docs/plan/steps/07-rabbitmq.md §14): consumer progress for the
-- reconciler, and the outbox index for the delivery planner's approval provenance check.
--
-- What changes:
--   * New table message_consumer_progress (not partitioned, no foreign keys; same key as the
--     message_idempotency ledger). The RabbitMQ QueueConsumer writes one row per (consumer,
--     event_id) it has not handled: state 'retrying' after each confirmed retry hop,
--     'dead_lettered' after the confirmed dead-letter copy. The outbox reconciler (event-relay)
--     reads it so it never re-drives an event that is still retrying or was dead-lettered on
--     purpose. Codes and counters only. Purged after 30 days with the ledger (db:partitions).
--   * Index (event_id) on message_outbox (partitioned daily; a local index per partition, built
--     online in place). The planner looks up the outbox row of an approval by event id, event
--     type and organization, pruned by created_at, before planning it.
--
-- Nothing else changes: 72 tables, 19 partitioned.

-- CreateTable
CREATE TABLE `message_consumer_progress` (
    `consumer` VARCHAR(100) NOT NULL,
    `event_id` CHAR(36) NOT NULL,
    `state` ENUM('retrying', 'dead_lettered') NOT NULL,
    `reason` VARCHAR(48) NULL,
    `attempt` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `transient_retries` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `message_consumer_progress_updated_at_idx`(`updated_at`),
    PRIMARY KEY (`consumer`, `event_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateIndex
CREATE INDEX `message_outbox_event_id_idx` ON `message_outbox`(`event_id`);
