-- Step API-2: API-mode post-delivery remediation, restore and release
-- (docs/plan/steps/36-api-mode-remediation.md §3, R1–R5, R9, R10, R14; ADR-0101, ADR-0102).
--
-- What changes (two new tables, none partitioned: 191 tables, 42 partitioned):
--   * api_mailboxes: cached provider container ids `quarantine_container_id`,
--     `tag_container_id` (opaque Graph folder / Gmail label ids) and `containers_checked_at` (R3).
--   * api_message_copies (PARTITIONED): remediation state of the copy in its mailbox
--     (`remediation_state` NOT NULL DEFAULT 'none', `remediation_action`, `remediation_generation`
--     NOT NULL DEFAULT 0, `last_action_id`, `remediation_updated_at`) and the index
--     (organization_id, remediation_state, received_at) for the detections filter (R4, R5.5).
--   * api_mode_connections: the per-connection emergency stop `remediation_paused` NOT NULL
--     DEFAULT 0 and `remediation_paused_at` (R5.1, API2-16).
--   * api_mode_counters: ten hourly remediation counters, all NOT NULL DEFAULT 0 (R14).
--   * quarantine_messages: `location` ENUM('gateway','mailbox') NOT NULL DEFAULT 'gateway',
--     `mailbox_container`, the links `api_copy_id`, `api_copy_received_at`, `api_mailbox_id`,
--     `api_remediation_action_id` (no FKs) and two indexes; QuarantineOrigin + `api_remediation`
--     (R9, ADR-0102). For location = mailbox, `lifecycle_round` holds the copy's remediation
--     generation (R9.2; documented in schema.prisma, the column itself is unchanged).
--   * Appended enum values (append-only rule): QuarantineActionType (`quarantine_actions.action`,
--     the only column using it) + `mailbox_remediated`, `mailbox_restored`,
--     `mailbox_restore_failed`, `mailbox_deleted`; QuarantineReleaseStatus
--     (`quarantine_release_logs.status`, the only column using it) + `restored`, `restore_failed`;
--     QuarantineOrigin (`quarantine_messages.origin`, the only column using it) +
--     `api_remediation` (schema.prisma, checked on 2026-11-26).
--   * New tables: api_remediation_policies (one organization row and one row per overridden
--     domain; FK organizations RESTRICT, domains RESTRICT; STORED generated `scope_key`) and
--     api_remediation_actions (one row per mailbox action; FK api_mode_connections RESTRICT,
--     api_mailboxes RESTRICT; unique `action_key`). No other foreign key (§3.1): the copy is
--     partitioned, the quarantine and release links would form cycles, and the organization purge
--     deletes actions before mailboxes and connections and policies before domains (§3.4).
--
-- No backfill: every existing quarantine entry is `location = gateway`, every existing copy
-- `remediation_state = none`, every connection unpaused, every counter 0 (the defaults).
-- No RBAC or seed data (§3.3): remediation:read / remediation:write exist since API-1 and the
-- quarantine permissions apply unchanged to mailbox entries; `pnpm db:seed` stays a no-op.
--
-- No message content (R-I6): ids, enums, codes, counts, timings, opaque provider message ids and
-- the operator-typed reason only. Provider ids (`provider_refs`, container ids) are never returned
-- by the api.
--
-- scope_key is a MySQL generated column. Prisma has no syntax for generated columns, so
-- schema.prisma declares it as a plain nullable BIGINT UNSIGNED marked READ-ONLY (like
-- threat_indicators.org_scope and security_incidents.active_marker); the drift check compares type
-- and nullability only and stays clean. Application code never writes scope_key.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-5. ADD COLUMN (appended at the end, nullable or with a constant default) and the appended
--      ENUM values: ALGORITHM=INSTANT (metadata only; an ENUM with < 256 members keeps its
--      1-byte storage, so appending at the end needs no row change). This includes the
--      partitioned api_message_copies (INSTANT applies to every partition). MySQL refuses rather
--      than copies if INSTANT were impossible (for example after 64 row versions of a table; the
--      fallback then is ALGORITHM=INPLACE, LOCK=NONE, which rebuilds the table online).
--   6.-7. New tables created empty (the STORED generated column costs nothing on an empty table).
--   8. Secondary indexes on existing tables: ALGORITHM=INPLACE, LOCK=NONE (online index build;
--      reads and writes continue; on the partitioned api_message_copies the index is built per
--      partition). Each algorithm is stated explicitly, so an unexpected rebuild fails instead of
--      copying silently.
--   9. Foreign keys are added to the two empty new tables (the parent tables organizations,
--      domains, api_mode_connections and api_mailboxes only take a short metadata lock).
-- DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (never automatic; after rolling the api, mailbox-worker, policy-engine and the portal
-- back to API-1, and after deleting every quarantine entry with location = 'mailbox' and its
-- quarantine_actions / quarantine_release_logs / quarantine_approval_requests rows):
--   DROP TABLE api_remediation_actions, api_remediation_policies;
--   DROP INDEX quarantine_messages_api_copy_id_api_copy_received_at_idx ON quarantine_messages;
--   DROP INDEX quarantine_messages_organization_id_location_quarantined_at__idx ON quarantine_messages;
--   DROP INDEX api_message_copies_organization_id_remediation_state_receive_idx ON api_message_copies;
--   ALTER TABLE quarantine_messages DROP COLUMN location, DROP COLUMN mailbox_container,
--       DROP COLUMN api_copy_id, DROP COLUMN api_copy_received_at, DROP COLUMN api_mailbox_id,
--       DROP COLUMN api_remediation_action_id, ALGORITHM=INSTANT;
--   ALTER TABLE api_mode_counters DROP COLUMN remediation_succeeded, … (the ten counters), ALGORITHM=INSTANT;
--   ALTER TABLE api_mode_connections DROP COLUMN remediation_paused, DROP COLUMN remediation_paused_at, ALGORITHM=INSTANT;
--   ALTER TABLE api_message_copies DROP COLUMN remediation_state, DROP COLUMN remediation_action,
--       DROP COLUMN remediation_generation, DROP COLUMN last_action_id, DROP COLUMN remediation_updated_at, ALGORITHM=INSTANT;
--   ALTER TABLE api_mailboxes DROP COLUMN quarantine_container_id, DROP COLUMN tag_container_id,
--       DROP COLUMN containers_checked_at, ALGORITHM=INSTANT;
--   The appended enum values stay (append-only rule; an older release never writes them). To
--   remove them anyway, first delete or rewrite every row that uses them, then MODIFY the three
--   columns back to their API-1 value lists. Delete the migration's `_prisma_migrations` row.

-- 1. api_mailboxes: cached provider container ids (R3; opaque, never returned by the api).
ALTER TABLE `api_mailboxes` ADD COLUMN `containers_checked_at` DATETIME(3) NULL,
    ADD COLUMN `quarantine_container_id` VARCHAR(256) NULL,
    ADD COLUMN `tag_container_id` VARCHAR(256) NULL,
    ALGORITHM=INSTANT;

-- 2. api_message_copies (PARTITIONED): remediation state of the copy (R4, R5.2, R5.5, R10.3).
--    Every existing copy gets remediation_state = 'none' and generation 0 from the defaults.
ALTER TABLE `api_message_copies` ADD COLUMN `last_action_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `remediation_action` ENUM('move_quarantine', 'move_junk', 'tag', 'soft_delete', 'hard_delete') NULL,
    ADD COLUMN `remediation_generation` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_state` ENUM('none', 'pending', 'simulated', 'remediated', 'restored', 'failed', 'skipped') NOT NULL DEFAULT 'none',
    ADD COLUMN `remediation_updated_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

-- 3. api_mode_connections: per-connection emergency stop (R5.1, API2-16).
ALTER TABLE `api_mode_connections` ADD COLUMN `remediation_paused` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `remediation_paused_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

-- 4. api_mode_counters: hourly remediation counters (R14), added by the counter flush
--    (`INSERT … ON DUPLICATE KEY UPDATE x = x + VALUES(x)`); latency = completed_at − verdict_at
--    of policy-triggered actions, as count, sum and max in milliseconds (average = sum / count).
ALTER TABLE `api_mode_counters` ADD COLUMN `remediation_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_latency_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_latency_max_ms` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_latency_sum_ms` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_simulated` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_skipped` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_succeeded` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `remediation_throttled` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `restores_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `restores_succeeded` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ALGORITHM=INSTANT;

-- 5. Quarantine (ADR-0102). Appended enum values and the mailbox location of an entry.
-- 5a. QuarantineActionType + the four mailbox actions (R9.1, R10.3, R10.4).
ALTER TABLE `quarantine_actions` MODIFY `action` ENUM('release', 'delete', 'request_release', 'approve_release', 'deny_release', 'report_false_positive', 'expire', 'preview', 'view', 'download_grant', 'download', 'download_refused', 'reject', 'quarantine', 'release_queued', 'release_blocked', 'approval_cancelled', 'approval_expired', 'supersede', 'adopt', 'object_purged', 'object_retained', 'self_release', 'mailbox_remediated', 'mailbox_restored', 'mailbox_restore_failed', 'mailbox_deleted') NOT NULL,
    ALGORITHM=INSTANT;

-- 5b. quarantine_messages: location, container, links to the copy / mailbox / action (no FKs),
--     QuarantineOrigin + `api_remediation`. Existing entries become location = 'gateway' by default.
ALTER TABLE `quarantine_messages` ADD COLUMN `api_copy_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `api_copy_received_at` DATETIME(3) NULL,
    ADD COLUMN `api_mailbox_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `api_remediation_action_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `location` ENUM('gateway', 'mailbox') NOT NULL DEFAULT 'gateway',
    ADD COLUMN `mailbox_container` ENUM('quarantine_folder', 'junk', 'deleted_items') NULL,
    MODIFY `origin` ENUM('policy', 'manual', 'adopted', 'api_remediation') NOT NULL,
    ALGORITHM=INSTANT;

-- 5c. QuarantineReleaseStatus + `restored`, `restore_failed` (outcome of a mailbox restore, R10.3).
ALTER TABLE `quarantine_release_logs` MODIFY `status` ENUM('pending', 'delivered', 'failed', 'blocked_by_revalidation', 'dispatched', 'approval_required', 'rescan_required', 'refused', 'stale', 'message_busy', 'restored', 'restore_failed') NOT NULL DEFAULT 'pending',
    ALGORITHM=INSTANT;

-- 6. api_remediation_policies (§3.1, R2; not partitioned). One organization row (domain_id NULL)
--    and one row per overridden domain. No organization row = the platform default P1 policy.
--    `scope_key` = COALESCE(domain_id, 0) is a STORED generated column: MySQL treats NULLs as
--    distinct in a unique key, so UNIQUE (organization_id, domain_id) would allow several
--    organization rows; UNIQUE (organization_id, scope_key) allows exactly one per scope (domain
--    ids start at 1, so 0 never collides with a domain). CAS on row_version (api).
CREATE TABLE `api_remediation_policies` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NULL,
    `scope_key` BIGINT UNSIGNED
        GENERATED ALWAYS AS (COALESCE(`domain_id`, 0)) STORED NULL,
    `mode` ENUM('detect_only', 'enforce') NOT NULL,
    `document` JSON NOT NULL,
    `document_sha256` CHAR(64) NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_remediation_policies_public_id_key`(`public_id`),
    INDEX `api_remediation_policies_domain_id_idx`(`domain_id`),
    UNIQUE INDEX `api_remediation_policies_organization_id_scope_key_key`(`organization_id`, `scope_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. api_remediation_actions (§3.1, R1, R4, R5, R10, R12; not partitioned: actions exist only for
--    non-clean copies, they need FKs and a global unique key).
--    `action_key` = lower-case hex SHA-256 of
--    "api-remediation/1" NUL <copy public id> NUL <action> NUL <generation as decimal>,
--    computed by `remediationActionKey` of @email-gateway/mailbox-api. Every writer inserts with
--    INSERT IGNORE on it, so a redelivery, a crash replay or a repeated request within one
--    generation adds no second row (R-I4); a successful reversal increments the copy's generation,
--    so a later remediation of the same copy gets a fresh key (R5.5).
--    The claim loop of the mailbox-worker `remediate` role reads
--    `status = 'pending' AND next_attempt_at <= now AND (lease_until IS NULL OR lease_until < now)`
--    through (status, next_attempt_at) with FOR UPDATE SKIP LOCKED.
CREATE TABLE `api_remediation_actions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `api_connection_id` BIGINT UNSIGNED NOT NULL,
    `mailbox_id` BIGINT UNSIGNED NOT NULL,
    `copy_id` BIGINT UNSIGNED NOT NULL,
    `copy_received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `action` ENUM('move_quarantine', 'move_junk', 'tag', 'soft_delete', 'hard_delete', 'restore_inbox', 'remove_tag') NOT NULL,
    `generation` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `action_key` CHAR(64) NOT NULL,
    `trigger` ENUM('policy', 'admin', 'release', 'end_user', 'system') NOT NULL,
    `status` ENUM('pending', 'in_progress', 'succeeded', 'failed', 'skipped', 'simulated', 'cancelled') NOT NULL,
    `reason_code` VARCHAR(64) NULL,
    `decision` JSON NULL,
    `reverses_action_id` BIGINT UNSIGNED NULL,
    `reversed_by_action_id` BIGINT UNSIGNED NULL,
    `quarantine_entry_id` BIGINT UNSIGNED NULL,
    `release_log_id` BIGINT UNSIGNED NULL,
    `requested_by_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `request_reason` VARCHAR(512) NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `locate_attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `next_attempt_at` DATETIME(3) NULL,
    `lease_until` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `last_http_status` SMALLINT UNSIGNED NULL,
    `provider_refs` JSON NULL,
    `verdict_at` DATETIME(3) NULL,
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_remediation_actions_public_id_key`(`public_id`),
    UNIQUE INDEX `api_remediation_actions_action_key_key`(`action_key`),
    INDEX `api_remediation_actions_status_next_attempt_at_idx`(`status`, `next_attempt_at`),
    INDEX `api_remediation_actions_api_connection_id_status_idx`(`api_connection_id`, `status`),
    INDEX `api_remediation_actions_organization_id_created_at_id_idx`(`organization_id`, `created_at`, `id`),
    INDEX `api_remediation_actions_organization_id_copy_id_copy_receive_idx`(`organization_id`, `copy_id`, `copy_received_at`),
    INDEX `api_remediation_actions_organization_id_mailbox_id_created_a_idx`(`organization_id`, `mailbox_id`, `created_at`),
    INDEX `api_remediation_actions_organization_id_status_created_at_idx`(`organization_id`, `status`, `created_at`),
    INDEX `api_remediation_actions_quarantine_entry_id_idx`(`quarantine_entry_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. Secondary indexes on existing tables (online: INPLACE, LOCK=NONE).
-- 8a. api_message_copies (PARTITIONED; a local index on every partition): detections filter
--     `remediationState` (R13).
CREATE INDEX `api_message_copies_organization_id_remediation_state_receive_idx` ON `api_message_copies`(`organization_id`, `remediation_state`, `received_at`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 8b. quarantine_messages: the list's `location` filter (R10.5) and the entry of a copy (R12, R13).
CREATE INDEX `quarantine_messages_organization_id_location_quarantined_at__idx` ON `quarantine_messages`(`organization_id`, `location`, `quarantined_at`, `id`)
    ALGORITHM=INPLACE LOCK=NONE;

CREATE INDEX `quarantine_messages_api_copy_id_api_copy_received_at_idx` ON `quarantine_messages`(`api_copy_id`, `api_copy_received_at`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 9. Foreign keys (the two new tables only; §3.1). api_remediation_actions.mailbox_id has no index
--    leading with it, so MySQL creates the FK's own index `api_remediation_actions_mailbox_id_fkey`.
ALTER TABLE `api_remediation_policies` ADD CONSTRAINT `api_remediation_policies_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- domain_id is the base column of the STORED generated scope_key: MySQL refuses ON UPDATE CASCADE
-- (or SET NULL) there, so this key is ON UPDATE RESTRICT (domain ids never change).
ALTER TABLE `api_remediation_policies` ADD CONSTRAINT `api_remediation_policies_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE `api_remediation_actions` ADD CONSTRAINT `api_remediation_actions_api_connection_id_fkey` FOREIGN KEY (`api_connection_id`) REFERENCES `api_mode_connections`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_remediation_actions` ADD CONSTRAINT `api_remediation_actions_mailbox_id_fkey` FOREIGN KEY (`mailbox_id`) REFERENCES `api_mailboxes`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
