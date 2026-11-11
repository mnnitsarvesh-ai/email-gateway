-- Step 5.2: Policy engine
-- (docs/plan/steps/16-policy-engine.md §3, P5, P10-P12, P16-P18; ADR-0043, ADR-0044, ADR-0045).
--
-- What changes:
--   * MessageAction (email_messages.final_action, email_recipients.final_action,
--     policy_execution_logs.action): `reject`, `require_approval` APPENDED (P18). Append-only.
--   * email_policies (existing): `row_version` (CAS of metadata and pointer), `updated_by_user_id`
--     (FK users SET NULL).
--   * policy_versions (existing): `row_version`, `dsl_version` (NULL = legacy format),
--     `references` (directory ids the definition names), `has_override_rules`, `rule_count`,
--     `created_by_user_id`, `updated_by_user_id` (FK users SET NULL).
--   * Legacy retirement (data, step 7 below): every policy version without `dsl_version` (the
--     step 1.1 relational format) becomes `superseded`, and every policy whose active version is
--     such a row is deactivated (`active_version_id` NULL, `status` `disabled`). NOTHING IS
--     DELETED: policy_conditions, policy_actions and policy_exceptions keep their rows and are
--     retired (no reader or writer from 5.2 on; removed only by organization purge).
--   * policy_settings (new, not partitioned): one row per organization; `generation` is the
--     per-organization snapshot generation every effective api change increments (P12).
--   * tenant_departments, tenant_department_members (new, not partitioned): the tenant directory
--     of P5. "Exactly one of address / user_id" is enforced by the api only: MySQL refuses a CHECK
--     on `user_id`, which carries the ON DELETE CASCADE referential action (ER 3823).
--   * policy_execution_logs (existing, PARTITIONED monthly, never written outside perf data):
--     ALTERED, not re-created: the P10 evaluation columns and three tenant-scoped indexes; the
--     unique key (message_id, evaluation_seq, received_at) is kept (evaluation_seq = the
--     lifecycle round). Retention changes to 6 months, core (partition registry).
--
-- The tenant tables follow the risk/dlp tables: FK to organizations ON DELETE RESTRICT (no
-- cascade: organization deletion removes their rows explicitly in the api's tenant-data module),
-- FK to users ON DELETE SET NULL for the actor columns; tenant_department_members.user_id is
-- ON DELETE CASCADE (deleting a user removes its memberships), department_id RESTRICT.
-- Reserved words: `trigger` (policy_execution_logs) and `references` (policy_versions) are
-- reserved in MySQL 8.4; Prisma quotes every identifier, hand-written SQL must quote them too.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-2. MODIFY final_action (values appended, same 1-byte storage): ALGORITHM=INSTANT on the
--         partitioned email_messages / email_recipients (metadata only).
--   3.,5. ADD COLUMN on email_policies / policy_versions: ALGORITHM=INSTANT.
--   4.,6. ADD FOREIGN KEY on email_policies / policy_versions: default algorithm (COPY: MySQL adds
--         a foreign key with foreign_key_checks = 1 only by copying); both tables are tiny
--         (tenant configuration rows).
--   8.-10. new tables: created empty.
--   11. policy_execution_logs ADD COLUMN x31 + MODIFY action (appended values): ALGORITHM=INSTANT.
--   12. three indexes on policy_execution_logs: ALGORITHM=INPLACE, LOCK=NONE (local per partition).
-- Each algorithm is stated explicitly where MySQL supports it, so a rebuild fails instead of
-- copying silently. The DDL statements auto-commit: if the migration fails part-way, inspect,
-- fix and resolve it (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the policy-engine, api, notification-worker and delivery-worker back):
-- drop the three indexes and the added columns of policy_execution_logs (ALGORITHM=INSTANT),
-- DROP TABLE tenant_department_members, tenant_departments, policy_settings; drop the FKs and
-- added columns of policy_versions and email_policies. The legacy retirement is not reverted
-- automatically (the old rows are intact: restore `status`/`active_version_id` by hand if the
-- legacy evaluator were ever needed; none exists). The appended MessageAction values cannot be
-- removed while rows use them (append-only rule).

-- 1. MessageAction: append reject, require_approval (P18).
-- AlterTable
ALTER TABLE `email_messages` MODIFY `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval') NULL,
    ALGORITHM=INSTANT;

-- 2.
-- AlterTable
ALTER TABLE `email_recipients` MODIFY `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval') NULL,
    ALGORITHM=INSTANT;

-- 3. email_policies: CAS counter and last editor (P17).
-- AlterTable
ALTER TABLE `email_policies` ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN `updated_by_user_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 4.
-- AddForeignKey
ALTER TABLE `email_policies` ADD CONSTRAINT `email_policies_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- 5. policy_versions: DSL version, directory references, publish facts, CAS, actors (P17).
-- AlterTable
ALTER TABLE `policy_versions` ADD COLUMN `created_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `dsl_version` VARCHAR(32) NULL,
    ADD COLUMN `has_override_rules` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `references` JSON NULL,
    ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN `rule_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `updated_by_user_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 6.
-- AddForeignKey
ALTER TABLE `policy_versions` ADD CONSTRAINT `policy_versions_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_versions` ADD CONSTRAINT `policy_versions_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- 7. Legacy retirement (§3 item 3). Every existing version predates `dsl_version` and is in the
-- step 1.1 relational format, which no evaluator reads. Policies first (they are found through
-- their active version), then the versions. Idempotent; nothing is deleted.
UPDATE `email_policies`
   SET `active_version_id` = NULL,
       `status` = 'disabled',
       `updated_at` = CURRENT_TIMESTAMP(3)
 WHERE `active_version_id` IN (SELECT `id` FROM `policy_versions` WHERE `dsl_version` IS NULL);

UPDATE `policy_versions`
   SET `status` = 'superseded',
       `updated_at` = CURRENT_TIMESTAMP(3)
 WHERE `dsl_version` IS NULL
   AND `status` <> 'superseded';

-- 8. policy_settings (P11, P12; not partitioned).
-- CreateTable
CREATE TABLE `policy_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `generation` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `settings` JSON NOT NULL,
    `settings_sha256` CHAR(64) NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `policy_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. tenant_departments (P5; not partitioned).
-- CreateTable
CREATE TABLE `tenant_departments` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `description` VARCHAR(512) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `tenant_departments_public_id_key`(`public_id`),
    UNIQUE INDEX `tenant_departments_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. tenant_department_members (P5; not partitioned). No CHECK (see the header).
-- CreateTable
CREATE TABLE `tenant_department_members` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `department_id` BIGINT UNSIGNED NOT NULL,
    `address` VARCHAR(320) NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `tenant_department_members_public_id_key`(`public_id`),
    INDEX `tenant_department_members_organization_id_address_idx`(`organization_id`, `address`(100)),
    UNIQUE INDEX `tenant_department_members_department_id_address_key`(`department_id`, `address`),
    UNIQUE INDEX `tenant_department_members_department_id_user_id_key`(`department_id`, `user_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `policy_settings` ADD CONSTRAINT `policy_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_settings` ADD CONSTRAINT `policy_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_departments` ADD CONSTRAINT `tenant_departments_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_departments` ADD CONSTRAINT `tenant_departments_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_departments` ADD CONSTRAINT `tenant_departments_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_department_members` ADD CONSTRAINT `tenant_department_members_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_department_members` ADD CONSTRAINT `tenant_department_members_department_id_fkey` FOREIGN KEY (`department_id`) REFERENCES `tenant_departments`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_department_members` ADD CONSTRAINT `tenant_department_members_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tenant_department_members` ADD CONSTRAINT `tenant_department_members_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- 11. policy_execution_logs (P10, P16): the evaluation record. Partitioned (ADR-0014): no foreign
-- keys; the partitioning clause and the composite primary key are untouched by ALTER TABLE.
-- The table is empty outside perf data; the NOT NULL columns without a default are filled by the
-- policy-engine for every row.
-- AlterTable
ALTER TABLE `policy_execution_logs` ADD COLUMN `actions` JSON NOT NULL,
    ADD COLUMN `clamps` JSON NOT NULL,
    ADD COLUMN `decision_source` ENUM('tenant_rule', 'platform_default', 'floor') NOT NULL,
    ADD COLUMN `decisive_policy_public_id` CHAR(36) NULL,
    ADD COLUMN `decisive_rule_id` VARCHAR(48) NULL,
    ADD COLUMN `delivered_object` ENUM('original', 'rewritten', 'policy_copy', 'none') NOT NULL,
    ADD COLUMN `delivery` JSON NULL,
    ADD COLUMN `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    ADD COLUMN `disposition` ENUM('allow', 'require_approval', 'quarantine', 'reject') NOT NULL,
    ADD COLUMN `dsl_version` VARCHAR(32) NOT NULL,
    ADD COLUMN `evaluator_version` VARCHAR(32) NOT NULL,
    ADD COLUMN `explanation` JSON NOT NULL,
    ADD COLUMN `explanation_text` VARCHAR(2048) NOT NULL,
    ADD COLUMN `final_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NOT NULL,
    ADD COLUMN `floor` JSON NOT NULL,
    ADD COLUMN `input_sha256` CHAR(64) NOT NULL,
    ADD COLUMN `input_version` VARCHAR(32) NOT NULL,
    ADD COLUMN `matched_rules` JSON NOT NULL,
    ADD COLUMN `object_key` VARCHAR(512) NULL,
    ADD COLUMN `override_applied` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `override_detail` JSON NULL,
    ADD COLUMN `platform_default_id` VARCHAR(32) NOT NULL,
    ADD COLUMN `policy_generation` BIGINT UNSIGNED NOT NULL,
    ADD COLUMN `policy_versions` JSON NOT NULL,
    ADD COLUMN `reason_codes` JSON NOT NULL,
    ADD COLUMN `recommendation` JSON NOT NULL,
    ADD COLUMN `risk_score` SMALLINT UNSIGNED NULL,
    ADD COLUMN `scan_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `snapshot_sha256` CHAR(64) NOT NULL,
    ADD COLUMN `trigger` ENUM('scanned', 'scan_failed', 'parse_failed') NOT NULL,
    ADD COLUMN `tzdata_version` VARCHAR(16) NOT NULL,
    MODIFY `action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval') NOT NULL,
    ALGORITHM=INSTANT;

-- 12.
-- CreateIndex
CREATE INDEX `policy_execution_logs_organization_id_received_at_idx` ON `policy_execution_logs`(`organization_id`, `received_at`) ALGORITHM=INPLACE LOCK=NONE;

-- CreateIndex
CREATE INDEX `policy_execution_logs_organization_id_disposition_received_a_idx` ON `policy_execution_logs`(`organization_id`, `disposition`, `received_at`) ALGORITHM=INPLACE LOCK=NONE;

-- CreateIndex
CREATE INDEX `policy_execution_logs_organization_id_decisive_policy_public_idx` ON `policy_execution_logs`(`organization_id`, `decisive_policy_public_id`, `received_at`) ALGORITHM=INPLACE LOCK=NONE;
