-- Step 3.3: message lifecycle and state management (docs/plan/steps/08-message-lifecycle.md §3.1,
-- L2, L2.1, L5.3, L11; ADR-0025).
--
-- What changes:
--   * MessageStatus (email_messages.status, email_message_status_history.from_status/to_status)
--     is replaced by the fifteen lifecycle states, in this order: received, persisted, scanning,
--     scanned, scan_failed, policy_evaluated, approved, quarantined, held_for_review, rejected,
--     delivery_pending, delivery_retry, delivered, archived, expired (default 'received'). This is
--     the one-time exception to the append-only enum rule (ADR-0025 decision 2): widen (append the
--     nine new values), backfill/rename, narrow.
--   * email_messages: lifecycle_round (+1 on rescan/release) and status_reason (reason code of the
--     last applied transition).
--   * email_message_status_history: lifecycle_round, actor_role, actor_service, actor_type,
--     actor_id, correlation_id, transition_key (hex SHA-256 of the transition idempotency key),
--     state_event_id, occurred_at; unique key (message_id, transition_key, received_at). The
--     partitioned unique key ends with received_at (ADR-0014). Prisma's default name for it is
--     truncated to MySQL's 64-character identifier limit
--     (email_message_status_history_message_id_transition_key_recei_key).
--   * New table api_idempotency_keys (not partitioned, no foreign keys; the api's Idempotency-Key
--     store, L11). idempotency_key is case-sensitive (utf8mb4_bin).
--
-- Mapping of the old values (L2):
--   received            -> persisted        status_reason lifecycle_backfill, version + 1, history
--                                           rows NULL -> received (v0) and received -> persisted
--   delivery_queued     -> delivery_pending status_reason delivery_planned
--   delivered           -> delivered        status_reason delivery_complete
--   partially_delivered -> delivered        status_reason delivery_partial
--   failed              -> rejected         status_reason delivery_failed
--   discarded           -> rejected         status_reason discarded
--   scanning, scanned, policy_evaluated, quarantined keep their names.
-- History rows are renamed with the same mapping (from_status and to_status), keep their versions
-- and get actor_role/actor_service 'legacy' (column defaults). Every message without a version-0
-- history row gets a NULL -> received row (reason lifecycle_backfill, changed_at = received_at).
--
-- Locking (MySQL 8.4, algorithms verified on a throwaway schema and recorded in
-- docs/database/schema-reference.md):
--   1. widen: appending ENUM values that keep the 1-byte storage is INSTANT (stated explicitly, so
--      the statement fails instead of silently rebuilding);
--   2. new columns: INSTANT (appended, with constant defaults or nullable);
--   3. backfill: DML on every partition (no received_at bound; a one-time migration over the
--      local data, see risks in §8);
--   4. narrow + reorder: COPY (MySQL cannot remove or reorder ENUM members in place); this
--      rebuilds both partitioned tables partition by partition. Strict mode makes it fail if any
--      row still holds a retired value;
--   5. unique key: INPLACE, LOCK=NONE (online, a local index per partition);
--   6. new table: created empty.
-- The DDL statements auto-commit: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration; the backfill statements are written so
-- that re-running them matches no row once they have been applied.

-- 1. Widen (append the nine new values; in place).
ALTER TABLE `email_messages`
    MODIFY `status` ENUM('received', 'scanning', 'scanned', 'policy_evaluated', 'quarantined', 'delivery_queued', 'delivered', 'partially_delivered', 'discarded', 'failed', 'persisted', 'approved', 'rejected', 'delivery_pending', 'delivery_retry', 'archived', 'scan_failed', 'held_for_review', 'expired') NOT NULL DEFAULT 'received',
    ALGORITHM=INSTANT;

ALTER TABLE `email_message_status_history`
    MODIFY `from_status` ENUM('received', 'scanning', 'scanned', 'policy_evaluated', 'quarantined', 'delivery_queued', 'delivered', 'partially_delivered', 'discarded', 'failed', 'persisted', 'approved', 'rejected', 'delivery_pending', 'delivery_retry', 'archived', 'scan_failed', 'held_for_review', 'expired') NULL,
    MODIFY `to_status` ENUM('received', 'scanning', 'scanned', 'policy_evaluated', 'quarantined', 'delivery_queued', 'delivered', 'partially_delivered', 'discarded', 'failed', 'persisted', 'approved', 'rejected', 'delivery_pending', 'delivery_retry', 'archived', 'scan_failed', 'held_for_review', 'expired') NOT NULL,
    ALGORITHM=INSTANT;

-- 2. New columns (history first, so the backfill rows get the column defaults).
ALTER TABLE `email_message_status_history`
    ADD COLUMN `lifecycle_round` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `actor_role` VARCHAR(32) NOT NULL DEFAULT 'legacy',
    ADD COLUMN `actor_service` VARCHAR(64) NOT NULL DEFAULT 'legacy',
    ADD COLUMN `actor_type` ENUM('system', 'user', 'api_key') NOT NULL DEFAULT 'system',
    ADD COLUMN `actor_id` VARCHAR(64) NULL,
    ADD COLUMN `correlation_id` VARCHAR(128) NULL,
    ADD COLUMN `transition_key` CHAR(64) NULL,
    ADD COLUMN `state_event_id` CHAR(36) NULL,
    ADD COLUMN `occurred_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `email_messages`
    ADD COLUMN `lifecycle_round` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `status_reason` VARCHAR(64) NULL,
    ALGORITHM=INSTANT;

-- 3. Backfill (L2 mapping).
-- 3a. Every message starts its history with NULL -> received (version 0).
INSERT INTO `email_message_status_history`
    (`received_at`, `message_id`, `organization_id`, `version`, `from_status`, `to_status`, `reason_code`, `changed_at`, `created_at`)
SELECT m.`received_at`, m.`id`, m.`organization_id`, 0, NULL, 'received', 'lifecycle_backfill', m.`received_at`, CURRENT_TIMESTAMP(3)
FROM `email_messages` m
WHERE NOT EXISTS (
    SELECT 1 FROM `email_message_status_history` h
    WHERE h.`message_id` = m.`id` AND h.`received_at` = m.`received_at` AND h.`version` = 0
);

-- 3b. Messages still 'received' are committed, so they are 'persisted' (one transition).
INSERT INTO `email_message_status_history`
    (`received_at`, `message_id`, `organization_id`, `version`, `from_status`, `to_status`, `reason_code`, `changed_at`, `created_at`)
SELECT m.`received_at`, m.`id`, m.`organization_id`, m.`version` + 1, 'received', 'persisted', 'lifecycle_backfill', CURRENT_TIMESTAMP(3), CURRENT_TIMESTAMP(3)
FROM `email_messages` m
WHERE m.`status` = 'received';

UPDATE `email_messages`
SET `status` = 'persisted', `version` = `version` + 1, `status_reason` = 'lifecycle_backfill',
    `status_changed_at` = CURRENT_TIMESTAMP(3), `updated_at` = CURRENT_TIMESTAMP(3)
WHERE `status` = 'received';

-- 3c. In-place renames of the step 2.3 delivery aggregate (no version change).
UPDATE `email_messages`
SET `status` = 'delivery_pending', `status_reason` = 'delivery_planned', `updated_at` = CURRENT_TIMESTAMP(3)
WHERE `status` = 'delivery_queued';

UPDATE `email_messages`
SET `status_reason` = 'delivery_complete', `updated_at` = CURRENT_TIMESTAMP(3)
WHERE `status` = 'delivered' AND `status_reason` IS NULL;

UPDATE `email_messages`
SET `status` = 'delivered', `status_reason` = 'delivery_partial', `updated_at` = CURRENT_TIMESTAMP(3)
WHERE `status` = 'partially_delivered';

UPDATE `email_messages`
SET `status` = 'rejected', `status_reason` = 'delivery_failed', `updated_at` = CURRENT_TIMESTAMP(3)
WHERE `status` = 'failed';

UPDATE `email_messages`
SET `status` = 'rejected', `status_reason` = 'discarded', `updated_at` = CURRENT_TIMESTAMP(3)
WHERE `status` = 'discarded';

-- 3d. History renames (history rows with 'received' stay 'received': it is still a state).
UPDATE `email_message_status_history`
SET `from_status` = CASE `from_status`
        WHEN 'delivery_queued' THEN 'delivery_pending'
        WHEN 'partially_delivered' THEN 'delivered'
        ELSE 'rejected'
    END
WHERE `from_status` IN ('delivery_queued', 'partially_delivered', 'failed', 'discarded');

UPDATE `email_message_status_history`
SET `to_status` = CASE `to_status`
        WHEN 'delivery_queued' THEN 'delivery_pending'
        WHEN 'partially_delivered' THEN 'delivered'
        ELSE 'rejected'
    END
WHERE `to_status` IN ('delivery_queued', 'partially_delivered', 'failed', 'discarded');

-- 4. Narrow and reorder: exactly the fifteen states in L2 order (table copy).
ALTER TABLE `email_messages`
    MODIFY `status` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired') NOT NULL DEFAULT 'received',
    ALGORITHM=COPY;

ALTER TABLE `email_message_status_history`
    MODIFY `from_status` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired') NULL,
    MODIFY `to_status` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired') NOT NULL,
    ALGORITHM=COPY;

-- 5. Idempotency key of transitions (partitioned table: the unique key ends with received_at).
CREATE UNIQUE INDEX `email_message_status_history_message_id_transition_key_recei_key`
    ON `email_message_status_history`(`message_id`, `transition_key`, `received_at`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 6. API Idempotency-Key store (not partitioned, no foreign keys).
-- CreateTable
CREATE TABLE `api_idempotency_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `idempotency_key` VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `operation` VARCHAR(64) NOT NULL,
    `principal` VARCHAR(80) NOT NULL,
    `request_sha256` CHAR(64) NOT NULL,
    `resource_id` VARCHAR(64) NOT NULL,
    `status_code` SMALLINT UNSIGNED NOT NULL,
    `response` JSON NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `expires_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_idempotency_keys_organization_id_idempotency_key_key`(`organization_id`, `idempotency_key`),
    INDEX `api_idempotency_keys_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
