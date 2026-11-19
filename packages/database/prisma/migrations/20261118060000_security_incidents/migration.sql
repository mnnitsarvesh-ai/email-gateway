-- Step 8.4: Account takeover detection core, part 1 of 2: the security incident model shared by
-- account takeover (ATO) and advanced threat protection (ATP)
-- (docs/plan/steps/24-account-takeover-core.md D24, §3.1; ADR-0075).
--
-- What changes (three new tables, none partitioned: 135 tables, 35 partitioned):
--   * security_incidents: one incident of any category (8.4: `account_takeover`, subject an
--     `ato_accounts` row; ATP-4 appends categories, subject types, link types and origins:
--     every ENUM here is append-only). Six states; `active_marker` is a STORED generated column
--     (1 for open / investigating / confirmed / mitigated, NULL for false_positive / resolved),
--     so the unique key (organization_id, category, subject_type, subject_ref_id, active_marker)
--     allows one active incident per category and subject and any number of closed ones (MySQL
--     unique keys never collide on NULL). Prisma declares the column as a plain nullable
--     TINYINT marked READ-ONLY; application code never writes it.
--   * security_incident_events: the timeline and audit trail (generic and category-prefixed
--     event types, VARCHAR so categories add types without DDL).
--   * security_incident_links: typed evidence references (ref_id, ref_time) to partitioned rows
--     (messages, ATO signals, ATO authentication events); no FK to them.
-- No message content: ids, codes, counts and analyst notes only.
--
-- Foreign keys: security_incidents.organization_id → organizations RESTRICT (the organization
-- purge removes the rows explicitly); assigned_user_id → users SET NULL; events and links →
-- security_incidents CASCADE (deleted with the incident by the per-category retention purge).
-- No FK: resolved_by_user_id (the trail survives the user), subject_ref_id (category-dependent
-- target), events/links organization_id (always the incident's).
--
-- Locking: new, empty tables only; no existing table is touched.
--
-- Rollback (after rolling the api, ato-worker and policy-engine back, and only after the
-- `account_takeover` migration has been rolled back): DROP TABLE security_incident_links,
-- security_incident_events, security_incidents.

-- 1. security_incidents (D24).
CREATE TABLE `security_incidents` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `category` ENUM('account_takeover') NOT NULL,
    `subject_type` ENUM('ato_account') NOT NULL,
    `subject_ref_id` BIGINT UNSIGNED NOT NULL,
    `subject_ref_time` DATETIME(3) NULL,
    `subject_public_id` VARCHAR(64) NOT NULL,
    `origin` ENUM('detection', 'manual') NOT NULL,
    `status` ENUM('open', 'investigating', 'confirmed', 'false_positive', 'mitigated', 'resolved') NOT NULL DEFAULT 'open',
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `title_code` VARCHAR(64) NULL,
    `reason_codes` JSON NOT NULL,
    `detector_version` VARCHAR(32) NULL,
    `detected_at` DATETIME(3) NOT NULL,
    `first_evidence_at` DATETIME(3) NULL,
    `last_evidence_at` DATETIME(3) NULL,
    `evidence_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `assigned_user_id` BIGINT UNSIGNED NULL,
    `assigned_at` DATETIME(3) NULL,
    `escalated_at` DATETIME(3) NULL,
    `confirmed_at` DATETIME(3) NULL,
    `mitigated_at` DATETIME(3) NULL,
    `resolved_at` DATETIME(3) NULL,
    `resolved_by_user_id` BIGINT UNSIGNED NULL,
    `resolution_code` ENUM('remediated', 'false_positive', 'benign_activity', 'duplicate', 'other') NULL,
    `resolution_note` VARCHAR(4000) NULL,
    `last_update_event_at` DATETIME(3) NULL,
    `created_by_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `created_by_id` VARCHAR(64) NULL,
    `active_marker` TINYINT UNSIGNED
        GENERATED ALWAYS AS (IF(`status` IN ('open', 'investigating', 'confirmed', 'mitigated'), 1, NULL)) STORED NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `security_incidents_public_id_key`(`public_id`),
    INDEX `security_incidents_organization_id_detected_at_id_idx`(`organization_id`, `detected_at`, `id`),
    INDEX `security_incidents_organization_id_category_status_detected__idx`(`organization_id`, `category`, `status`, `detected_at`, `id`),
    INDEX `security_incidents_organization_id_category_severity_detecte_idx`(`organization_id`, `category`, `severity`, `detected_at`, `id`),
    INDEX `security_incidents_organization_id_assigned_user_id_status_idx`(`organization_id`, `assigned_user_id`, `status`),
    INDEX `security_incidents_organization_id_subject_type_subject_ref__idx`(`organization_id`, `subject_type`, `subject_ref_id`, `detected_at`),
    INDEX `security_incidents_category_status_resolved_at_idx`(`category`, `status`, `resolved_at`),
    UNIQUE INDEX `security_incidents_organization_id_category_subject_type_sub_key`(`organization_id`, `category`, `subject_type`, `subject_ref_id`, `active_marker`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 2. security_incident_events (timeline and audit trail).
CREATE TABLE `security_incident_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `incident_id` BIGINT UNSIGNED NOT NULL,
    `event_type` VARCHAR(48) NOT NULL,
    `actor_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `actor_id` VARCHAR(64) NULL,
    `from_status` ENUM('open', 'investigating', 'confirmed', 'false_positive', 'mitigated', 'resolved') NULL,
    `to_status` ENUM('open', 'investigating', 'confirmed', 'false_positive', 'mitigated', 'resolved') NULL,
    `from_severity` ENUM('low', 'medium', 'high', 'critical') NULL,
    `to_severity` ENUM('low', 'medium', 'high', 'critical') NULL,
    `note` TEXT NULL,
    `details` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `security_incident_events_incident_id_created_at_id_idx`(`incident_id`, `created_at`, `id`),
    INDEX `security_incident_events_organization_id_created_at_idx`(`organization_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. security_incident_links (typed evidence references; no FK to partitioned targets).
CREATE TABLE `security_incident_links` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `incident_id` BIGINT UNSIGNED NOT NULL,
    `link_type` ENUM('message', 'ato_signal', 'ato_auth_event') NOT NULL,
    `ref_id` BIGINT UNSIGNED NOT NULL,
    `ref_time` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `security_incident_links_organization_id_incident_id_link_typ_idx`(`organization_id`, `incident_id`, `link_type`, `ref_time`),
    UNIQUE INDEX `security_incident_links_incident_id_link_type_ref_id_ref_tim_key`(`incident_id`, `link_type`, `ref_id`, `ref_time`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. Foreign keys (added to the empty tables).
ALTER TABLE `security_incidents` ADD CONSTRAINT `security_incidents_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `security_incidents` ADD CONSTRAINT `security_incidents_assigned_user_id_fkey` FOREIGN KEY (`assigned_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `security_incident_events` ADD CONSTRAINT `security_incident_events_incident_id_fkey` FOREIGN KEY (`incident_id`) REFERENCES `security_incidents`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `security_incident_links` ADD CONSTRAINT `security_incident_links_incident_id_fkey` FOREIGN KEY (`incident_id`) REFERENCES `security_incidents`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
