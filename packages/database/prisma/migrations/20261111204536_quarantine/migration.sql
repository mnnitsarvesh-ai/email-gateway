-- Step 5.3: Quarantine
-- (docs/plan/steps/17-quarantine.md §3, Q3-Q8, Q12-Q20, Q24, Q31; ADR-0046, ADR-0047, ADR-0048).
--
-- What changes:
--   * MessageAction (email_messages.final_action, email_recipients.final_action,
--     policy_execution_logs.action): `partial` APPENDED (Q5). Append-only.
--   * policy_execution_logs (PARTITIONED; altered, never re-created): `recipient_split`,
--     `recipient_decisions` (Q4 per-recipient evaluation).
--   * QuarantineStatus (quarantine_messages.status, the entry "state") is REBUILT by
--     widen / backfill / narrow (ADR-0046 decision 5; the second deliberate exception to the
--     append-only enum rule after MessageStatus in 3.3): MODIFY to old ∪ new values, UPDATE
--     `quarantined → held`, `release_requested → pending_approval` (`released`, `deleted`,
--     `expired` keep their value), MODIFY to the final eight values with DEFAULT 'held'.
--     The table never had a producer; the rebuild keeps every row (perf data, fixtures).
--   * QuarantineReason += `manual`; QuarantineActionType += `view` … `self_release`;
--     QuarantineReleaseStatus += `dispatched` … `message_busy` (all appended).
--   * quarantine_messages (altered): the entry columns of §3 item 1; unique key
--     (message_id, recipient_id) DROPPED and replaced by (message_id, lifecycle_round, rcpt_seq)
--     (one entry per message, lifecycle round and recipient); the search indexes of Q9.
--     `subject` is KEPT but retired: never written from 5.3 on (no message content in MySQL).
--     No index on (message_id, lifecycle_round): the new unique key's leftmost prefix serves it.
--   * quarantine_actions, quarantine_release_logs (altered): §3 items 2-3.
--   * New tables (not partitioned): quarantine_approval_requests, quarantine_download_grants,
--     quarantine_settings, quarantine_user_preferences, quarantine_object_purges,
--     quarantine_digest_runs, quarantine_digests (§3 items 4-9).
--
-- Backfill of existing rows (no data is dropped; the tables are empty in every environment
-- except perf data / fixtures): new NOT NULL columns whose value depends on the row are added
-- NULL, backfilled, then made NOT NULL:
--   quarantine_messages.direction        ← email_messages.direction (by message id + received_at;
--                                          'inbound' when the message row is gone)
--   quarantine_messages.rcpt_seq         ← email_recipients.rcpt_seq (by recipient id +
--                                          received_at); a row whose recipient is gone gets
--                                          65535 - n (n = its rank among such rows of the
--                                          message) so the new unique key cannot collide
--   quarantine_messages.kind / origin    ← 'quarantine' / 'adopted' (held before 5.3)
--   quarantine_messages.state_changed_at ← COALESCE(released_at, updated_at)
--   quarantine_release_logs.release_public_id ← UUID() per row (one release per legacy row)
--   quarantine_release_logs.mode         ← 'operator' (the 1.1 operator release)
--   quarantine_release_logs.requested_by_type ← quarantine_actions.actor_type of `action_id`
--
-- Foreign keys: the new tenant tables reference organizations ON DELETE RESTRICT (organization
-- purge removes them explicitly, api tenant-data, Q17); user actor columns ON DELETE SET NULL;
-- `quarantine_download_grants.user_id`, `quarantine_user_preferences.user_id` and
-- `quarantine_digests.user_id` ON DELETE CASCADE (a deleted user's grants, preferences and digest
-- rows go with it); rows of an entry (approval requests, grants) CASCADE with the entry.
-- No FK: quarantine_messages.approval_request_id (cycle), quarantine_actions.release_log_id /
-- approval_request_id, quarantine_release_logs.approval_request_id,
-- quarantine_approval_requests.requested_by_api_key_id (the trail survives the key),
-- quarantine_object_purges.message_id (partitioned target).
-- `object` (quarantine_download_grants) is not a reserved word in MySQL 8.4.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-2. MODIFY final_action (value appended): ALGORITHM=INSTANT on the partitioned
--         email_messages / email_recipients.
--   3.    policy_execution_logs ADD COLUMN x2 + MODIFY action (appended): ALGORITHM=INSTANT.
--   4.    quarantine_messages widen (values appended) + ADD COLUMN x33 (NULL or with constant
--         defaults): ALGORITHM=INSTANT.
--   6.    quarantine_messages narrow (values removed and reordered) + NULL → NOT NULL:
--         ALGORITHM=COPY (the only way MySQL removes enum values; the table is small).
--   7.    quarantine_messages indexes: ALGORITHM=INPLACE, LOCK=NONE.
--   8.    quarantine_messages ADD FOREIGN KEY decided_by_user_id: default (COPY, as in 4.2-5.2).
--   9.    quarantine_actions ADD COLUMN x5 + MODIFY action (appended): INSTANT; index INPLACE.
--   10.-12. quarantine_release_logs ADD COLUMN + MODIFY status (appended): INSTANT; NULL → NOT
--         NULL: INPLACE (rebuild), LOCK=NONE; indexes INPLACE, LOCK=NONE.
--   13.-19. new tables: created empty; their FKs added to empty tables.
-- Each algorithm is stated explicitly, so an unexpected rebuild fails instead of copying
-- silently. DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the api, policy-engine and notification-worker back): DROP the seven
-- new tables (grants, approval requests, digests, digest runs, purges, preferences, settings);
-- drop the added columns and indexes of quarantine_release_logs, quarantine_actions,
-- quarantine_messages and policy_execution_logs; restore the unique key (message_id,
-- recipient_id) only if no message has entries in several rounds; QuarantineStatus can be mapped
-- back (held → quarantined, pending_approval → release_requested) by the inverse widen /
-- backfill / narrow while no row uses a 5.3-only state. Appended enum values cannot be removed
-- while rows use them (append-only rule).

-- 1. MessageAction: append partial (Q5).
ALTER TABLE `email_messages` MODIFY `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval', 'partial') NULL,
    ALGORITHM=INSTANT;

-- 2.
ALTER TABLE `email_recipients` MODIFY `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval', 'partial') NULL,
    ALGORITHM=INSTANT;

-- 3. policy_execution_logs: per-recipient decisions (Q4).
ALTER TABLE `policy_execution_logs` ADD COLUMN `recipient_split` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `recipient_decisions` JSON NULL,
    MODIFY `action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval', 'partial') NOT NULL,
    ALGORITHM=INSTANT;

-- 4. quarantine_messages: WIDEN status (old ∪ new, appended), append reason `manual`, add the
-- entry columns (NULL where the value is backfilled below).
ALTER TABLE `quarantine_messages` MODIFY `status` ENUM('quarantined', 'release_requested', 'released', 'deleted', 'expired', 'held', 'pending_approval', 'releasing', 'rejected', 'superseded') NOT NULL DEFAULT 'quarantined',
    MODIFY `reason` ENUM('spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp', 'policy', 'suspicious', 'engine_unavailable', 'manual') NOT NULL,
    ADD COLUMN `lifecycle_round` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `scan_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `evaluation_seq` SMALLINT UNSIGNED NULL,
    ADD COLUMN `rcpt_seq` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `direction` ENUM('inbound', 'outbound', 'internal') NULL,
    ADD COLUMN `kind` ENUM('quarantine', 'review') NULL,
    ADD COLUMN `origin` ENUM('policy', 'manual', 'adopted') NULL,
    ADD COLUMN `header_from` VARCHAR(320) NULL,
    ADD COLUMN `has_attachments` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `attachment_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `size_bytes` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `risk_level` ENUM('none', 'low', 'medium', 'high', 'critical') NULL,
    ADD COLUMN `recommended_action` ENUM('deliver', 'tag', 'require_approval', 'quarantine', 'block') NULL,
    ADD COLUMN `risk_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    ADD COLUMN `has_hard_block` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `hard_blocks` JSON NULL,
    ADD COLUMN `reason_codes` JSON NULL,
    ADD COLUMN `floor_reasons` JSON NULL,
    ADD COLUMN `primary_engine` ENUM('rspamd', 'attachment', 'url', 'bec', 'dlp', 'sandbox', 'policy', 'none') NOT NULL DEFAULT 'none',
    ADD COLUMN `decision_source` ENUM('tenant_rule', 'platform_default', 'floor') NULL,
    ADD COLUMN `decisive_policy_public_id` CHAR(36) NULL,
    ADD COLUMN `decisive_policy_version_no` INTEGER UNSIGNED NULL,
    ADD COLUMN `decisive_rule_id` VARCHAR(48) NULL,
    ADD COLUMN `explanation` JSON NULL,
    ADD COLUMN `explanation_text` VARCHAR(2048) NULL,
    ADD COLUMN `state_changed_at` DATETIME(3) NULL,
    ADD COLUMN `decided_at` DATETIME(3) NULL,
    ADD COLUMN `decided_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `decided_by_type` ENUM('system', 'user', 'api_key') NULL,
    ADD COLUMN `terminal_reason` VARCHAR(64) NULL,
    ADD COLUMN `approval_request_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `object_purged_at` DATETIME(3) NULL,
    ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ALGORITHM=INSTANT;

-- 5. BACKFILL (idempotent; see the header).
UPDATE `quarantine_messages` SET `status` = 'held' WHERE `status` = 'quarantined';
UPDATE `quarantine_messages` SET `status` = 'pending_approval' WHERE `status` = 'release_requested';

UPDATE `quarantine_messages` q
  JOIN `email_messages` m ON m.`id` = q.`message_id` AND m.`received_at` = q.`message_received_at`
   SET q.`direction` = m.`direction`
 WHERE q.`direction` IS NULL;
UPDATE `quarantine_messages` SET `direction` = 'inbound' WHERE `direction` IS NULL;

UPDATE `quarantine_messages` q
  JOIN `email_recipients` r ON r.`id` = q.`recipient_id` AND r.`received_at` = q.`message_received_at`
   SET q.`rcpt_seq` = r.`rcpt_seq`;
UPDATE `quarantine_messages` q
  JOIN (
    SELECT q2.`id`, ROW_NUMBER() OVER (PARTITION BY q2.`message_id` ORDER BY q2.`recipient_id`) AS `n`
      FROM `quarantine_messages` q2
     WHERE NOT EXISTS (
       SELECT 1 FROM `email_recipients` r
        WHERE r.`id` = q2.`recipient_id` AND r.`received_at` = q2.`message_received_at`)
  ) orphan ON orphan.`id` = q.`id`
   SET q.`rcpt_seq` = 65535 - orphan.`n`;

UPDATE `quarantine_messages`
   SET `kind` = COALESCE(`kind`, 'quarantine'),
       `origin` = COALESCE(`origin`, 'adopted'),
       `state_changed_at` = COALESCE(`state_changed_at`, `released_at`, `updated_at`);

-- 6. NARROW status to the final eight values (DEFAULT 'held'); the backfilled columns NOT NULL.
ALTER TABLE `quarantine_messages` MODIFY `status` ENUM('held', 'pending_approval', 'releasing', 'released', 'rejected', 'deleted', 'expired', 'superseded') NOT NULL DEFAULT 'held',
    MODIFY `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    MODIFY `kind` ENUM('quarantine', 'review') NOT NULL,
    MODIFY `origin` ENUM('policy', 'manual', 'adopted') NOT NULL,
    MODIFY `state_changed_at` DATETIME(3) NOT NULL,
    ALGORITHM=COPY;

-- 7. quarantine_messages keys and search indexes (Q9). New indexes first, so the organization
-- foreign key always has an index; then the replaced ones are dropped.
ALTER TABLE `quarantine_messages`
    ADD UNIQUE INDEX `quarantine_messages_message_id_lifecycle_round_rcpt_seq_key`(`message_id`, `lifecycle_round`, `rcpt_seq`),
    ADD INDEX `quarantine_messages_organization_id_quarantined_at_id_idx`(`organization_id`, `quarantined_at`, `id`),
    ADD INDEX `quarantine_messages_organization_id_status_quarantined_at_id_idx`(`organization_id`, `status`, `quarantined_at`, `id`),
    ADD INDEX `quarantine_messages_organization_id_recipient_address_quaran_idx`(`organization_id`, `recipient_address`(100), `quarantined_at`, `id`),
    ADD INDEX `quarantine_messages_organization_id_envelope_from_quarantine_idx`(`organization_id`, `envelope_from`(100), `quarantined_at`),
    ADD INDEX `quarantine_messages_organization_id_reason_quarantined_at_idx`(`organization_id`, `reason`, `quarantined_at`),
    ADD INDEX `quarantine_messages_organization_id_decisive_policy_public_i_idx`(`organization_id`, `decisive_policy_public_id`, `quarantined_at`),
    ADD INDEX `quarantine_messages_organization_id_primary_engine_quarantin_idx`(`organization_id`, `primary_engine`, `quarantined_at`),
    ADD INDEX `quarantine_messages_status_state_changed_at_idx`(`status`, `state_changed_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `quarantine_messages`
    DROP INDEX `quarantine_messages_message_id_recipient_id_key`,
    DROP INDEX `quarantine_messages_organization_id_status_quarantined_at_idx`,
    DROP INDEX `quarantine_messages_organization_id_recipient_address_status_idx`,
    ALGORITHM=INPLACE, LOCK=NONE;

-- 8.
ALTER TABLE `quarantine_messages` ADD CONSTRAINT `quarantine_messages_decided_by_user_id_fkey` FOREIGN KEY (`decided_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- 9. quarantine_actions (§3 item 2).
ALTER TABLE `quarantine_actions` ADD COLUMN `actor_id` VARCHAR(64) NULL,
    ADD COLUMN `result` VARCHAR(64) NULL,
    ADD COLUMN `details` JSON NULL,
    ADD COLUMN `release_log_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `approval_request_id` BIGINT UNSIGNED NULL,
    MODIFY `action` ENUM('release', 'delete', 'request_release', 'approve_release', 'deny_release', 'report_false_positive', 'expire', 'preview', 'view', 'download_grant', 'download', 'download_refused', 'reject', 'quarantine', 'release_queued', 'release_blocked', 'approval_cancelled', 'approval_expired', 'supersede', 'adopt', 'object_purged', 'object_retained', 'self_release') NOT NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `quarantine_actions`
    ADD INDEX `quarantine_actions_organization_id_created_at_idx`(`organization_id`, `created_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 10. quarantine_release_logs (§3 item 3): columns (NULL where backfilled), statuses appended.
ALTER TABLE `quarantine_release_logs` ADD COLUMN `release_public_id` CHAR(36) NULL,
    ADD COLUMN `mode` ENUM('operator', 'self', 'approved') NULL,
    ADD COLUMN `approval_request_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `requested_by_type` ENUM('system', 'user', 'api_key') NULL,
    ADD COLUMN `requested_by_id` VARCHAR(64) NULL,
    ADD COLUMN `precheck` JSON NULL,
    ADD COLUMN `revalidation` JSON NULL,
    ADD COLUMN `delivered_object` ENUM('original', 'rewritten', 'policy_copy', 'none') NULL,
    ADD COLUMN `object_key` VARCHAR(512) NULL,
    ADD COLUMN `delivery_seq` INTEGER UNSIGNED NULL,
    ADD COLUMN `approval_event_ids` JSON NULL,
    ADD COLUMN `lifecycle_round_after` SMALLINT UNSIGNED NULL,
    ADD COLUMN `blocked_reason` VARCHAR(64) NULL,
    MODIFY `status` ENUM('pending', 'delivered', 'failed', 'blocked_by_revalidation', 'dispatched', 'approval_required', 'rescan_required', 'refused', 'stale', 'message_busy') NOT NULL DEFAULT 'pending',
    ALGORITHM=INSTANT;

-- 11. BACKFILL (idempotent).
UPDATE `quarantine_release_logs` l
  JOIN `quarantine_actions` a ON a.`id` = l.`action_id`
   SET l.`requested_by_type` = a.`actor_type`
 WHERE l.`requested_by_type` IS NULL;
UPDATE `quarantine_release_logs`
   SET `release_public_id` = COALESCE(`release_public_id`, UUID()),
       `mode` = COALESCE(`mode`, 'operator'),
       `requested_by_type` = COALESCE(`requested_by_type`, 'system');

-- 12.
ALTER TABLE `quarantine_release_logs` MODIFY `release_public_id` CHAR(36) NOT NULL,
    MODIFY `mode` ENUM('operator', 'self', 'approved') NOT NULL,
    MODIFY `requested_by_type` ENUM('system', 'user', 'api_key') NOT NULL,
    ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `quarantine_release_logs`
    ADD UNIQUE INDEX `quarantine_release_logs_quarantine_message_id_release_public_key`(`quarantine_message_id`, `release_public_id`),
    ADD INDEX `quarantine_release_logs_release_public_id_idx`(`release_public_id`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 13. quarantine_approval_requests (Q14).
CREATE TABLE `quarantine_approval_requests` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `quarantine_message_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('policy_review', 'release_approval', 'release_request') NOT NULL,
    `status` ENUM('pending', 'approved', 'denied', 'expired', 'cancelled') NOT NULL DEFAULT 'pending',
    `approval_reasons` JSON NOT NULL,
    `approved_reasons` JSON NULL,
    `requested_by_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `requested_by_api_key_id` BIGINT UNSIGNED NULL,
    `request_reason` VARCHAR(512) NULL,
    `decided_by_user_id` BIGINT UNSIGNED NULL,
    `decision_reason` VARCHAR(512) NULL,
    `decider_permissions_hash` CHAR(64) NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `decided_at` DATETIME(3) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `quarantine_approval_requests_public_id_key`(`public_id`),
    INDEX `quarantine_approval_requests_organization_id_status_created__idx`(`organization_id`, `status`, `created_at`),
    INDEX `quarantine_approval_requests_status_expires_at_idx`(`status`, `expires_at`),
    INDEX `quarantine_approval_requests_quarantine_message_id_created_a_idx`(`quarantine_message_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 14. quarantine_download_grants (Q12).
CREATE TABLE `quarantine_download_grants` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `jti` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `quarantine_message_id` BIGINT UNSIGNED NOT NULL,
    `object` ENUM('eml', 'attachment') NOT NULL,
    `part_index` SMALLINT UNSIGNED NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `consumed_at` DATETIME(3) NULL,
    `source_ip` VARCHAR(45) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `quarantine_download_grants_jti_key`(`jti`),
    INDEX `quarantine_download_grants_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 15. quarantine_settings (Q24).
CREATE TABLE `quarantine_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `settings` JSON NOT NULL,
    `settings_sha256` CHAR(64) NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `quarantine_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 16. quarantine_user_preferences (Q15, Q20).
CREATE TABLE `quarantine_user_preferences` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `digest_opt_out` BOOLEAN NOT NULL DEFAULT false,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `quarantine_user_preferences_user_id_key`(`user_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 17. quarantine_object_purges (Q17).
CREATE TABLE `quarantine_object_purges` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `status` ENUM('pending', 'purged', 'retained', 'failed') NOT NULL DEFAULT 'pending',
    `reason` VARCHAR(64) NULL,
    `purge_after` DATETIME(3) NOT NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `last_error_code` VARCHAR(64) NULL,
    `purged_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `quarantine_object_purges_status_purge_after_idx`(`status`, `purge_after`),
    UNIQUE INDEX `quarantine_object_purges_message_id_message_received_at_key`(`message_id`, `message_received_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 18. quarantine_digest_runs, quarantine_digests (Q20).
CREATE TABLE `quarantine_digest_runs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('user_digest', 'admin_alert') NOT NULL,
    `scheduled_for` DATETIME(3) NOT NULL,
    `window_from` DATETIME(3) NOT NULL,
    `users_total` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `users_done` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `quarantine_digest_runs_created_at_idx`(`created_at`),
    UNIQUE INDEX `quarantine_digest_runs_organization_id_kind_scheduled_for_key`(`organization_id`, `kind`, `scheduled_for`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `quarantine_digests` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `run_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `entry_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `event_id` CHAR(36) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `quarantine_digests_public_id_key`(`public_id`),
    UNIQUE INDEX `quarantine_digests_run_id_user_id_key`(`run_id`, `user_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 19. Foreign keys of the new tables (empty tables).
ALTER TABLE `quarantine_approval_requests` ADD CONSTRAINT `quarantine_approval_requests_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `quarantine_approval_requests` ADD CONSTRAINT `quarantine_approval_requests_quarantine_message_id_fkey` FOREIGN KEY (`quarantine_message_id`) REFERENCES `quarantine_messages`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `quarantine_approval_requests` ADD CONSTRAINT `quarantine_approval_requests_requested_by_user_id_fkey` FOREIGN KEY (`requested_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `quarantine_approval_requests` ADD CONSTRAINT `quarantine_approval_requests_decided_by_user_id_fkey` FOREIGN KEY (`decided_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `quarantine_download_grants` ADD CONSTRAINT `quarantine_download_grants_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `quarantine_download_grants` ADD CONSTRAINT `quarantine_download_grants_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `quarantine_download_grants` ADD CONSTRAINT `quarantine_download_grants_quarantine_message_id_fkey` FOREIGN KEY (`quarantine_message_id`) REFERENCES `quarantine_messages`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `quarantine_settings` ADD CONSTRAINT `quarantine_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `quarantine_settings` ADD CONSTRAINT `quarantine_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `quarantine_user_preferences` ADD CONSTRAINT `quarantine_user_preferences_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `quarantine_user_preferences` ADD CONSTRAINT `quarantine_user_preferences_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `quarantine_object_purges` ADD CONSTRAINT `quarantine_object_purges_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `quarantine_digest_runs` ADD CONSTRAINT `quarantine_digest_runs_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `quarantine_digests` ADD CONSTRAINT `quarantine_digests_run_id_fkey` FOREIGN KEY (`run_id`) REFERENCES `quarantine_digest_runs`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `quarantine_digests` ADD CONSTRAINT `quarantine_digests_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `quarantine_digests` ADD CONSTRAINT `quarantine_digests_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
