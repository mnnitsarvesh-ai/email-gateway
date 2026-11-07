-- Step 4.4: Phishing and BEC detection engine
-- (docs/plan/steps/12-phishing-bec.md §3, B7, B11, B12, B14, B18; ADR-0033, ADR-0034, ADR-0035).
--
-- What changes (seven new tables, nothing altered):
--   * bec_scan_results (PARTITIONED monthly by RANGE COLUMNS(received_at), retention 6 months,
--     core): one row per scan round with a definite final result of the `bec` engine (B14),
--     unique per scan; codes, weights, scores, versions, input states, span offsets and the parsed
--     sender identity only.
--   * bec_executive_profiles, bec_vendor_profiles (B5, B18): tenant profiles for impersonation
--     detection, unique per tenant on the normalized name.
--   * bec_trusted_senders (B7): tenant trusted addresses / registrable domains, optional expiry.
--   * bec_feedback (B11): analyst false-positive / false-negative feedback per (scan, user, kind);
--     retention 24 months (docs/database/retention.md).
--   * bec_suppression_rules (B11): bounded, expiring (≤ 90 days) suppressions of suppressible
--     reason codes per sender, created from a false-positive feedback.
--   * bec_contact_history (B12, ADR-0035): opt-in aggregate communication context per keyed
--     hash (HMAC-SHA256, organization-scoped); no plaintext address, domain, IP or name.
--
-- No message content: never body text, span text, excerpts or LLM output text (§2.0 invariant 4).
--
-- The partitioned table follows ADR-0014: composite primary key (id, received_at), no foreign
-- keys in either direction, every unique key ends with received_at; created with the single
-- catch-all partition pmax (`pnpm db:partitions apply` splits it; registry:
-- packages/database/src/partitioning/registry.ts). `bec_feedback.message_id` / `scan_id` /
-- `bec_result_id` reference partitioned tables and therefore carry no foreign key either.
--
-- The six non-partitioned tenant tables follow scan_engine_settings (step 4.1): foreign key to
-- organizations ON DELETE RESTRICT (no cascade: organization deletion removes their rows
-- explicitly in the api's tenant-data module) and to users ON DELETE SET NULL (the user columns
-- are nullable). `bec_suppression_rules.feedback_id` has no foreign key (feedback is retained
-- 24 months, suppressions expire within 90 days; the id is a reference for the audit trail).
--
-- Locking: new tables only, created empty; no existing table is touched.

-- 1. bec_scan_results (B14).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `bec_scan_results` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `lifecycle_round` SMALLINT UNSIGNED NOT NULL,
    `engine_version` VARCHAR(64) NOT NULL,
    `rules_version` VARCHAR(16) NOT NULL,
    `settings_version` VARCHAR(96) NOT NULL,
    `lexicon_version` VARCHAR(16) NOT NULL,
    `text_version` VARCHAR(16) NOT NULL,
    `deterministic_score` TINYINT UNSIGNED NOT NULL,
    `score` TINYINT UNSIGNED NOT NULL,
    `deterministic_verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown', 'skipped') NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown', 'skipped') NOT NULL,
    `inputs` JSON NOT NULL,
    `rules` JSON NOT NULL,
    `features` JSON NULL,
    `identity` JSON NULL,
    `ai` JSON NULL,
    `ai_shadow` JSON NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `bec_scan_results_message_id_received_at_idx`(`message_id`, `received_at`),
    INDEX `bec_scan_results_organization_id_received_at_idx`(`organization_id`, `received_at`),
    UNIQUE INDEX `bec_scan_results_scan_id_received_at_key`(`scan_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 2. bec_executive_profiles (B5, B18; not partitioned).
-- CreateTable
CREATE TABLE `bec_executive_profiles` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `display_name` VARCHAR(128) NOT NULL,
    `normalized_name` VARCHAR(160) NOT NULL,
    `aliases` JSON NOT NULL,
    `known_addresses` JSON NOT NULL,
    `title` VARCHAR(128) NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `bec_executive_profiles_public_id_key`(`public_id`),
    INDEX `bec_executive_profiles_organization_id_enabled_idx`(`organization_id`, `enabled`),
    UNIQUE INDEX `bec_executive_profiles_organization_id_normalized_name_key`(`organization_id`, `normalized_name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. bec_vendor_profiles (B5, B18; not partitioned).
-- CreateTable
CREATE TABLE `bec_vendor_profiles` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `normalized_name` VARCHAR(160) NOT NULL,
    `aliases` JSON NOT NULL,
    `domains` JSON NOT NULL,
    `known_senders` JSON NOT NULL,
    `payment_change_sensitive` BOOLEAN NOT NULL DEFAULT true,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `bec_vendor_profiles_public_id_key`(`public_id`),
    UNIQUE INDEX `bec_vendor_profiles_organization_id_normalized_name_key`(`organization_id`, `normalized_name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. bec_trusted_senders (B7; not partitioned).
-- CreateTable
CREATE TABLE `bec_trusted_senders` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('address', 'domain') NOT NULL,
    `value` VARCHAR(320) NOT NULL,
    `reason` VARCHAR(512) NOT NULL,
    `expires_at` DATETIME(3) NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `bec_trusted_senders_public_id_key`(`public_id`),
    INDEX `bec_trusted_senders_organization_id_expires_at_idx`(`organization_id`, `expires_at`),
    UNIQUE INDEX `bec_trusted_senders_organization_id_kind_value_key`(`organization_id`, `kind`, `value`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. bec_feedback (B11; not partitioned).
-- CreateTable
CREATE TABLE `bec_feedback` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `bec_result_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('false_positive', 'false_negative') NOT NULL,
    `reason_codes` JSON NULL,
    `note` VARCHAR(500) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `bec_feedback_public_id_key`(`public_id`),
    INDEX `bec_feedback_organization_id_created_at_idx`(`organization_id`, `created_at`),
    UNIQUE INDEX `bec_feedback_scan_id_created_by_user_id_kind_key`(`scan_id`, `created_by_user_id`, `kind`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. bec_suppression_rules (B11; not partitioned).
-- CreateTable
CREATE TABLE `bec_suppression_rules` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `reason_code` VARCHAR(64) NOT NULL,
    `sender_scope` ENUM('address', 'domain') NOT NULL,
    `sender_value` VARCHAR(320) NOT NULL,
    `feedback_id` BIGINT UNSIGNED NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `bec_suppression_rules_public_id_key`(`public_id`),
    INDEX `bec_suppression_rules_organization_id_expires_at_idx`(`organization_id`, `expires_at`),
    UNIQUE INDEX `bec_suppression_rules_organization_id_reason_code_sender_sco_key`(`organization_id`, `reason_code`, `sender_scope`, `sender_value`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. bec_contact_history (B12, ADR-0035; not partitioned).
-- CreateTable
CREATE TABLE `bec_contact_history` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scope` ENUM('sender', 'pair') NOT NULL,
    `key_hash` CHAR(64) NOT NULL,
    `message_count` INTEGER UNSIGNED NOT NULL,
    `inbound_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `outbound_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `infra` JSON NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `bec_contact_history_organization_id_last_seen_at_idx`(`organization_id`, `last_seen_at`),
    UNIQUE INDEX `bec_contact_history_organization_id_scope_key_hash_key`(`organization_id`, `scope`, `key_hash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. Foreign keys of the non-partitioned tenant tables (organizations RESTRICT, users SET NULL).
-- AddForeignKey
ALTER TABLE `bec_executive_profiles` ADD CONSTRAINT `bec_executive_profiles_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_executive_profiles` ADD CONSTRAINT `bec_executive_profiles_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_executive_profiles` ADD CONSTRAINT `bec_executive_profiles_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_vendor_profiles` ADD CONSTRAINT `bec_vendor_profiles_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_vendor_profiles` ADD CONSTRAINT `bec_vendor_profiles_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_vendor_profiles` ADD CONSTRAINT `bec_vendor_profiles_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_trusted_senders` ADD CONSTRAINT `bec_trusted_senders_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_trusted_senders` ADD CONSTRAINT `bec_trusted_senders_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_feedback` ADD CONSTRAINT `bec_feedback_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_feedback` ADD CONSTRAINT `bec_feedback_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_suppression_rules` ADD CONSTRAINT `bec_suppression_rules_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_suppression_rules` ADD CONSTRAINT `bec_suppression_rules_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bec_contact_history` ADD CONSTRAINT `bec_contact_history_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
