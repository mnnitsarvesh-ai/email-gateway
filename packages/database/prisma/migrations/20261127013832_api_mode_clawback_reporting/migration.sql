-- Step API-3: API-mode retroactive clawback, search and purge, internal mail and reported phishing
-- (docs/plan/steps/37-api-mode-clawback-reporting.md §3, C2–C12; ADR-0103, ADR-0104).
--
-- What changes (five new tables, none partitioned: 196 tables, 42 partitioned):
--   * api_mailboxes: the report-mailbox flag `report_mailbox` NOT NULL DEFAULT 0 and
--     `report_mailbox_at`, plus the index (organization_id, report_mailbox) (C9).
--   * api_message_copies (PARTITIONED): `verdict_revision` TINYINT UNSIGNED NOT NULL DEFAULT 0, the
--     number of late signals that raised the copy's stored verdict (C3.3).
--   * api_mode_counters: six hourly counters, all NOT NULL DEFAULT 0 (internal copies, clawback
--     targets queued / succeeded / failed, reports received / resolved; C8, C5.5, C9.2, C11.4).
--   * api_remediation_actions: ApiRemediationTrigger (`trigger`, the only column using it) +
--     `clawback`, `purge` (appended), the link `clawback_id` (no FK) and the index
--     (clawback_id, status) (C5.4–C5.7).
--   * threat_indicators, malware_signatures: index (created_at, id) for the keyset cursor of the
--     mailbox-worker threat-intelligence sweep (C2.2).
--   * New tables: api_clawbacks (FK organizations RESTRICT; UNIQUE (organization_id, signal_key)),
--     api_clawback_targets (FK api_clawbacks CASCADE; UNIQUE (clawback_id, copy_id,
--     copy_received_at)), api_user_reports (FK organizations, api_mode_connections, api_mailboxes
--     RESTRICT; UNIQUE (report_copy_id, report_copy_received_at)), api_mode_org_settings
--     (PK + FK organization_id RESTRICT) and the platform table api_mode_cursors (no FK). Every
--     other reference is a plain column (partitioned copies and messages, users whose trail
--     survives them, the purge order of §3.4).
--   * Data (§3.3): the idempotent, additive RBAC section 12 (remediation:purge and its grants).
--
-- api_clawback_targets.match_keys is a JSON array of key names instead of the SET of design §3.1:
-- Prisma has no SET type (an `Unsupported` field would be invisible to the Prisma client the api
-- and the mailbox-worker read targets with). Recorded in note 37 §15.1.
--
-- No backfill: every existing mailbox is not a report mailbox, every copy has verdict revision 0,
-- every action keeps its trigger and has no clawback, every counter is 0 (the defaults). No
-- organization gets an api_mode_org_settings row (absent = the defaults of
-- ORG_SETTINGS_DEFAULTS, equal to the column defaults).
--
-- No message content (C-I6): hashes, normalized keys (subject_key ≤ 128, Message-ID hashes),
-- sender / reporter addresses, windows, enums, codes, counts and timings; EML bytes stay in S3;
-- reasons and analyst notes are operator text marked untrusted.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-4. ADD COLUMN (appended at the end, nullable or with a constant default) and the appended
--      ENUM values: ALGORITHM=INSTANT (metadata only; an ENUM with < 256 members keeps its 1-byte
--      storage, so appending at the end needs no row change). This includes the partitioned
--      api_message_copies (INSTANT applies to every partition). MySQL refuses rather than copies
--      if INSTANT were impossible (for example after 64 row versions of a table; the fallback then
--      is ALGORITHM=INPLACE, LOCK=NONE, which rebuilds the table online).
--   5.-9. New tables created empty.
--   10. Secondary indexes on existing tables: ALGORITHM=INPLACE, LOCK=NONE (online index build;
--      reads and writes continue). Each algorithm is stated explicitly, so an unexpected rebuild
--      fails instead of copying silently.
--   11. Foreign keys are added to the empty new tables (the parent tables organizations,
--      api_mode_connections and api_mailboxes only take a short metadata lock).
--   12. RBAC data: two small idempotent statements on permissions / role_permissions.
-- DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration; the data section 12 is idempotent.
--
-- Rollback (never automatic; after rolling the api, mailbox-worker, email-worker,
-- notification-worker and the portal back to API-2, and after cancelling every pending action
-- with trigger 'clawback' / 'purge'):
--   DROP TABLE api_clawback_targets, api_clawbacks, api_user_reports, api_mode_org_settings,
--              api_mode_cursors;  -- children first
--   DROP INDEX threat_indicators_created_at_id_idx ON threat_indicators;
--   DROP INDEX malware_signatures_created_at_id_idx ON malware_signatures;
--   DROP INDEX api_remediation_actions_clawback_id_status_idx ON api_remediation_actions;
--   DROP INDEX api_mailboxes_organization_id_report_mailbox_idx ON api_mailboxes;
--   ALTER TABLE api_remediation_actions DROP COLUMN clawback_id, ALGORITHM=INSTANT;
--   ALTER TABLE api_mode_counters DROP COLUMN internal_copies, DROP COLUMN clawback_targets_queued,
--       DROP COLUMN clawback_targets_succeeded, DROP COLUMN clawback_targets_failed,
--       DROP COLUMN reports_received, DROP COLUMN reports_resolved, ALGORITHM=INSTANT;
--   ALTER TABLE api_message_copies DROP COLUMN verdict_revision, ALGORITHM=INSTANT;
--   ALTER TABLE api_mailboxes DROP COLUMN report_mailbox, DROP COLUMN report_mailbox_at,
--       ALGORITHM=INSTANT;
--   The appended trigger values stay (append-only rule; an older release never writes them). To
--   remove them anyway, first delete or rewrite every action row that uses them, then MODIFY
--   `trigger` back to its API-2 value list.
--   RBAC: DELETE the role_permissions rows of remediation:purge, then its permissions row (custom
--   roles lose it too); delete the migration's `_prisma_migrations` row.

-- 1. api_mailboxes: the report-mailbox flag (C9.1). Every existing mailbox is not a report mailbox.
ALTER TABLE `api_mailboxes` ADD COLUMN `report_mailbox` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `report_mailbox_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

-- 2. api_message_copies (PARTITIONED): late signals that raised the stored verdict (C3.3).
ALTER TABLE `api_message_copies` ADD COLUMN `verdict_revision` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    ALGORITHM=INSTANT;

-- 3. api_mode_counters: hourly internal-mail, clawback and report counters (C8, C5.5, C9.2,
--    C11.4), added by the counter flush (`INSERT … ON DUPLICATE KEY UPDATE x = x + VALUES(x)`).
ALTER TABLE `api_mode_counters` ADD COLUMN `clawback_targets_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `clawback_targets_queued` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `clawback_targets_succeeded` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `internal_copies` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `reports_received` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `reports_resolved` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ALGORITHM=INSTANT;

-- 4. api_remediation_actions: ApiRemediationTrigger + `clawback` (automatic clawback re-decided
--    through the policy; waits while the connection is paused) and `purge` (admin / report /
--    campaign clawback; runs like `admin`), appended; the clawback link (no FK) (C5.4, C5.7).
ALTER TABLE `api_remediation_actions` ADD COLUMN `clawback_id` BIGINT UNSIGNED NULL,
    MODIFY `trigger` ENUM('policy', 'admin', 'release', 'end_user', 'system', 'clawback', 'purge') NOT NULL,
    ALGORITHM=INSTANT;

-- 5. api_clawbacks (§3.1, C2–C7; not partitioned). One row per clawback. `signal_key` (C2.5) =
--    hex SHA-256 of the NUL-separated automatic signal tuple (version prefix
--    `api-clawback-signal/1`); NULL for admin / report / campaign clawbacks. With UNIQUE
--    (organization_id, signal_key) an automatic signal is written with INSERT IGNORE, so a
--    redelivery or a sweep replay creates no second clawback (MySQL treats NULLs as distinct, so
--    rows without a signal key never collide). The `clawback` role claims
--    `status IN (…) AND next_step_at <= now AND (lease_until IS NULL OR lease_until < now)`
--    through (status, next_step_at) with FOR UPDATE SKIP LOCKED; CAS on row_version. Approval
--    (C6) is stored on the row: (approval_status, approval_expires_at) serves the expiry sweep.
CREATE TABLE `api_clawbacks` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `trigger` ENUM('late_verdict', 'threat_intel', 'campaign', 'report', 'admin') NOT NULL,
    `signal_key` CHAR(64) NULL,
    `signal` JSON NOT NULL,
    `criteria` JSON NOT NULL,
    `criteria_sha256` CHAR(64) NOT NULL,
    `decision_mode` ENUM('policy', 'explicit') NULL,
    `action` ENUM('move_quarantine', 'move_junk', 'soft_delete', 'hard_delete') NULL,
    `signal_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    `signal_level` ENUM('low', 'medium', 'high', 'critical') NULL,
    `signal_hard_blocks` JSON NULL,
    `status` ENUM('searching', 'ready', 'review_required', 'pending_approval', 'queued', 'running', 'completed', 'completed_with_errors', 'no_match', 'too_broad', 'denied', 'expired', 'cancelled', 'failed') NOT NULL,
    `cancel_requested_at` DATETIME(3) NULL,
    `restore_status` ENUM('none', 'requested', 'running', 'completed', 'completed_with_errors') NOT NULL DEFAULT 'none',
    `targets_total` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `mailboxes_total` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_eligible` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `mailboxes_eligible` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_skipped` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_simulated` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_queued` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_succeeded` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `targets_cancelled` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `restores_queued` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `restores_succeeded` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `restores_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `restores_skipped` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `requires_approval` BOOLEAN NOT NULL DEFAULT false,
    `approval_reasons` JSON NULL,
    `approval_status` ENUM('pending', 'approved', 'denied', 'expired', 'cancelled') NULL,
    `approval_requested_at` DATETIME(3) NULL,
    `approval_expires_at` DATETIME(3) NULL,
    `approval_decided_at` DATETIME(3) NULL,
    `approved_by_user_id` BIGINT UNSIGNED NULL,
    `approval_decision_reason` VARCHAR(512) NULL,
    `approver_permissions_hash` CHAR(64) NULL,
    `requested_by_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `submitted_by_user_id` BIGINT UNSIGNED NULL,
    `request_reason` VARCHAR(512) NULL,
    `submitted_at` DATETIME(3) NULL,
    `report_id` BIGINT UNSIGNED NULL,
    `seed_copy_id` BIGINT UNSIGNED NULL,
    `seed_copy_received_at` DATETIME(3) NULL,
    `signal_at` DATETIME(3) NOT NULL,
    `lease_until` DATETIME(3) NULL,
    `next_step_at` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_clawbacks_public_id_key`(`public_id`),
    INDEX `api_clawbacks_organization_id_created_at_id_idx`(`organization_id`, `created_at`, `id`),
    INDEX `api_clawbacks_organization_id_status_created_at_idx`(`organization_id`, `status`, `created_at`),
    INDEX `api_clawbacks_status_next_step_at_idx`(`status`, `next_step_at`),
    INDEX `api_clawbacks_approval_status_approval_expires_at_idx`(`approval_status`, `approval_expires_at`),
    INDEX `api_clawbacks_restore_status_next_step_at_idx`(`restore_status`, `next_step_at`),
    INDEX `api_clawbacks_report_id_idx`(`report_id`),
    UNIQUE INDEX `api_clawbacks_organization_id_signal_key_key`(`organization_id`, `signal_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. api_clawback_targets (§3.1, C-I2, C4.3, C5; not partitioned). The frozen hit list: one row
--    per matched copy, materialized in pages of 1 000 with INSERT IGNORE on (clawback_id, copy_id,
--    copy_received_at), so a lease loss repeats nothing. `match_keys` = JSON array of the matched
--    key names (`message_id`, `attachment`, `url`, `url_domain`, `sender_subject`, `sender`,
--    `sender_domain`). Deleted with its clawback (FK CASCADE).
CREATE TABLE `api_clawback_targets` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `clawback_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `api_connection_id` BIGINT UNSIGNED NOT NULL,
    `mailbox_id` BIGINT UNSIGNED NOT NULL,
    `copy_id` BIGINT UNSIGNED NOT NULL,
    `copy_received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `match_keys` JSON NOT NULL,
    `status` ENUM('matched', 'skipped', 'simulated', 'queued', 'succeeded', 'failed', 'cancelled') NOT NULL,
    `reason_code` VARCHAR(64) NULL,
    `planned_action` ENUM('move_quarantine', 'move_junk', 'tag', 'soft_delete', 'hard_delete') NULL,
    `action_id` BIGINT UNSIGNED NULL,
    `restore_status` ENUM('none', 'queued', 'succeeded', 'failed', 'skipped') NOT NULL DEFAULT 'none',
    `restore_reason_code` VARCHAR(64) NULL,
    `restore_action_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `api_clawback_targets_clawback_id_status_id_idx`(`clawback_id`, `status`, `id`),
    INDEX `api_clawback_targets_clawback_id_mailbox_id_idx`(`clawback_id`, `mailbox_id`),
    INDEX `api_clawback_targets_clawback_id_restore_status_id_idx`(`clawback_id`, `restore_status`, `id`),
    INDEX `api_clawback_targets_organization_id_copy_id_copy_received_a_idx`(`organization_id`, `copy_id`, `copy_received_at`),
    INDEX `api_clawback_targets_action_id_idx`(`action_id`),
    UNIQUE INDEX `api_clawback_targets_clawback_id_copy_id_copy_received_at_key`(`clawback_id`, `copy_id`, `copy_received_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. api_user_reports (§3.1, C9–C12; not partitioned). One row per report e-mail in a report
--    mailbox, written by the copies handler with INSERT IGNORE on (report_copy_id,
--    report_copy_received_at) in the copy's ledger transaction (idempotent intake); claimed by the
--    `reports` role through (status, next_attempt_at); triaged by the api (CAS on row_version).
--    The reporter search uses a 100-character prefix of reporter_address.
CREATE TABLE `api_user_reports` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `api_connection_id` BIGINT UNSIGNED NOT NULL,
    `report_mailbox_id` BIGINT UNSIGNED NOT NULL,
    `report_copy_id` BIGINT UNSIGNED NOT NULL,
    `report_copy_received_at` DATETIME(3) NOT NULL,
    `report_message_id` BIGINT UNSIGNED NOT NULL,
    `reporter_address` VARCHAR(320) NOT NULL,
    `reporter_mailbox_id` BIGINT UNSIGNED NULL,
    `reporter_user_id` BIGINT UNSIGNED NULL,
    `status` ENUM('received', 'parsing', 'scanning', 'pending_triage', 'in_review', 'resolved', 'rejected') NOT NULL,
    `reject_reason` VARCHAR(64) NULL,
    `identification` ENUM('attachment', 'inline', 'none', 'unsupported') NULL,
    `original` JSON NULL,
    `original_message_id_hash` CHAR(64) NULL,
    `group_key` CHAR(64) NULL,
    `original_copy_id` BIGINT UNSIGNED NULL,
    `original_copy_received_at` DATETIME(3) NULL,
    `original_message_id` BIGINT UNSIGNED NULL,
    `original_received_at` DATETIME(3) NULL,
    `original_ingested` BOOLEAN NOT NULL DEFAULT false,
    `scan_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    `scan_risk_score` SMALLINT UNSIGNED NULL,
    `scan_level` ENUM('none', 'low', 'medium', 'high', 'critical') NULL,
    `assessment` ENUM('malicious', 'suspicious', 'clean', 'unknown') NULL,
    `analyst_verdict` ENUM('malicious', 'phishing_simulation', 'spam', 'clean', 'inconclusive') NULL,
    `analyst_note` VARCHAR(1000) NULL,
    `triaged_by_user_id` BIGINT UNSIGNED NULL,
    `triaged_at` DATETIME(3) NULL,
    `clawback_id` BIGINT UNSIGNED NULL,
    `ack_feedback` ENUM('none', 'queued', 'skipped') NOT NULL DEFAULT 'none',
    `result_feedback` ENUM('none', 'queued', 'skipped') NOT NULL DEFAULT 'none',
    `reported_at` DATETIME(3) NOT NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `lease_until` DATETIME(3) NULL,
    `next_attempt_at` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_user_reports_public_id_key`(`public_id`),
    INDEX `api_user_reports_organization_id_reported_at_id_idx`(`organization_id`, `reported_at`, `id`),
    INDEX `api_user_reports_organization_id_status_reported_at_id_idx`(`organization_id`, `status`, `reported_at`, `id`),
    INDEX `api_user_reports_organization_id_group_key_status_idx`(`organization_id`, `group_key`, `status`),
    INDEX `api_user_reports_status_next_attempt_at_idx`(`status`, `next_attempt_at`),
    INDEX `api_user_reports_original_message_id_original_received_at_idx`(`original_message_id`, `original_received_at`),
    INDEX `api_user_reports_organization_id_reporter_address_reported_a_idx`(`organization_id`, `reporter_address`(100), `reported_at`),
    UNIQUE INDEX `api_user_reports_report_copy_id_report_copy_received_at_key`(`report_copy_id`, `report_copy_received_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. api_mode_org_settings (§3.1). One row per organization; absent = the defaults (the column
--    defaults equal ORG_SETTINGS_DEFAULTS of @email-gateway/mailbox-api). Written by the api only
--    (CAS on row_version).
CREATE TABLE `api_mode_org_settings` (
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `internal_mail_enabled` BOOLEAN NOT NULL DEFAULT true,
    `auto_clawback` ENUM('enforce', 'review', 'off') NOT NULL DEFAULT 'enforce',
    `auto_max_mailboxes` INTEGER UNSIGNED NOT NULL DEFAULT 500,
    `purge_approval_mailboxes` INTEGER UNSIGNED NOT NULL DEFAULT 50,
    `clawback_lookback_days` SMALLINT UNSIGNED NOT NULL DEFAULT 14,
    `ti_min_confidence` TINYINT UNSIGNED NOT NULL DEFAULT 80,
    `report_ack_enabled` BOOLEAN NOT NULL DEFAULT true,
    `report_feedback_enabled` BOOLEAN NOT NULL DEFAULT true,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`organization_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. api_mode_cursors (§3.1, C2.2). Platform table: durable sweep cursors of the mailbox-worker
--    (`ti:threat_indicators`, `ti:malware_signatures`; position `{ createdAt, id }`).
CREATE TABLE `api_mode_cursors` (
    `name` VARCHAR(64) NOT NULL,
    `position` JSON NOT NULL,
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`name`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. Secondary indexes on existing tables (online: INPLACE, LOCK=NONE).
-- 10a. api_mailboxes: report mailboxes of an organization (C9.1 limit, intake lookups).
CREATE INDEX `api_mailboxes_organization_id_report_mailbox_idx` ON `api_mailboxes`(`organization_id`, `report_mailbox`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 10b. api_remediation_actions: the actions of a clawback (reconcile, cancel, C5.5, C5.6).
CREATE INDEX `api_remediation_actions_clawback_id_status_idx` ON `api_remediation_actions`(`clawback_id`, `status`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 10c. malware_signatures, threat_indicators: keyset cursor of the TI sweep (C2.2).
CREATE INDEX `malware_signatures_created_at_id_idx` ON `malware_signatures`(`created_at`, `id`)
    ALGORITHM=INPLACE LOCK=NONE;

CREATE INDEX `threat_indicators_created_at_id_idx` ON `threat_indicators`(`created_at`, `id`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 11. Foreign keys (the new tables only; §3.1). api_user_reports.api_connection_id and
--     report_mailbox_id have no index leading with them, so MySQL creates the FKs' own indexes
--     `api_user_reports_api_connection_id_fkey` and `api_user_reports_report_mailbox_id_fkey`.
ALTER TABLE `api_clawbacks` ADD CONSTRAINT `api_clawbacks_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_clawback_targets` ADD CONSTRAINT `api_clawback_targets_clawback_id_fkey` FOREIGN KEY (`clawback_id`) REFERENCES `api_clawbacks`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `api_user_reports` ADD CONSTRAINT `api_user_reports_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_user_reports` ADD CONSTRAINT `api_user_reports_api_connection_id_fkey` FOREIGN KEY (`api_connection_id`) REFERENCES `api_mode_connections`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_user_reports` ADD CONSTRAINT `api_user_reports_report_mailbox_id_fkey` FOREIGN KEY (`report_mailbox_id`) REFERENCES `api_mailboxes`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_mode_org_settings` ADD CONSTRAINT `api_mode_org_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- 12. RBAC data migration (§3.3). Idempotent and additive only (upsert, INSERT IGNORE); no
--     role_permissions or user_roles row is deleted or changed, so no user loses a permission.
--     The values equal the seed catalog (packages/database/src/seed/catalog.ts), so `pnpm db:seed`
--     afterwards is a no-op for these rows. On a fresh database (no system roles yet) the grant
--     touches no row and the seed grants it.
-- ---------------------------------------------------------------------------------------------

-- 12a. Permission (category `remediation`).
INSERT INTO `permissions` (`key`, `description`, `category`, `created_at`, `updated_at`) VALUES
    ('remediation:purge', 'Search API-mode mailbox copies and purge or claw back messages across mailboxes; approve another administrator''s purge', 'remediation', NOW(3), NOW(3))
AS new
ON DUPLICATE KEY UPDATE
    `description` = new.`description`,
    `category` = new.`category`,
    `updated_at` = IF(`permissions`.`description` <=> new.`description` AND `permissions`.`category` <=> new.`category`, `permissions`.`updated_at`, new.`updated_at`);

-- 12b. remediation:purge: the holders of remediation:write — organization_admin (every tenant
--      permission except the archive access set), security_analyst and super_admin (every
--      permission). Not in TENANT_READ_PERMISSIONS.
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` = 'remediation:purge'
WHERE r.`organization_id` IS NULL
  AND r.`key` IN ('super_admin', 'organization_admin', 'security_analyst');
