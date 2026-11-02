-- Steps 1.2 + 1.3: identity and tenancy (docs/plan/steps/02-tenants-auth-rbac.md, D10).
--
-- users: email verification, TOTP replay protection, status reason. user_sessions: session
-- age and second-factor state (D5). New user_tokens (single-use tokens) and
-- user_mfa_recovery_codes (D4). organizations: status reason and the deletion workflow (D12).
-- organization_settings.mfa_required (D7). LoginOutcome gains rate_limited (appended).
--
-- No partitioned table is touched. Every change is additive; the only rewrite is the
-- user_sessions backfill below (a small table: expired rows are purged hourly).
-- AlterTable
ALTER TABLE `login_audit_logs` MODIFY `outcome` ENUM('success', 'failure', 'locked', 'mfa_required', 'mfa_failure', 'rate_limited') NOT NULL;

-- AlterTable
ALTER TABLE `organization_settings` ADD COLUMN `mfa_required` BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE `organizations` ADD COLUMN `deletion_confirmed_at` DATETIME(3) NULL,
    ADD COLUMN `deletion_confirmed_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `deletion_reason` VARCHAR(512) NULL,
    ADD COLUMN `deletion_requested_at` DATETIME(3) NULL,
    ADD COLUMN `deletion_requested_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `purge_after` DATETIME(3) NULL,
    ADD COLUMN `status_before_deletion` ENUM('active', 'suspended', 'deleted', 'pending_deletion') NULL,
    ADD COLUMN `status_changed_at` DATETIME(3) NULL,
    ADD COLUMN `status_reason` VARCHAR(512) NULL;

-- AlterTable: the two NOT NULL datetimes are added as NULL, backfilled from the existing
-- columns (authenticated_at = created_at, absolute_expires_at = expires_at), then made NOT NULL.
ALTER TABLE `user_sessions` ADD COLUMN `absolute_expires_at` DATETIME(3) NULL,
    ADD COLUMN `authenticated_at` DATETIME(3) NULL,
    ADD COLUMN `mfa_authenticated` BOOLEAN NOT NULL DEFAULT false;

UPDATE `user_sessions`
SET `authenticated_at` = `created_at`, `absolute_expires_at` = `expires_at`
WHERE `authenticated_at` IS NULL OR `absolute_expires_at` IS NULL;

ALTER TABLE `user_sessions` MODIFY `absolute_expires_at` DATETIME(3) NOT NULL,
    MODIFY `authenticated_at` DATETIME(3) NOT NULL;

-- AlterTable
ALTER TABLE `users` ADD COLUMN `email_verified_at` DATETIME(3) NULL,
    ADD COLUMN `mfa_last_used_step` BIGINT UNSIGNED NULL,
    ADD COLUMN `status_changed_at` DATETIME(3) NULL,
    ADD COLUMN `status_reason` VARCHAR(512) NULL;

-- CreateTable
CREATE TABLE `user_tokens` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `purpose` ENUM('invitation', 'password_reset', 'email_verification') NOT NULL,
    `token_hash` CHAR(64) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `consumed_at` DATETIME(3) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_ip` VARCHAR(45) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `user_tokens_token_hash_key`(`token_hash`),
    INDEX `user_tokens_user_id_purpose_consumed_at_idx`(`user_id`, `purpose`, `consumed_at`),
    INDEX `user_tokens_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `user_mfa_recovery_codes` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `code_hash` CHAR(64) NOT NULL,
    `used_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `user_mfa_recovery_codes_user_id_code_hash_key`(`user_id`, `code_hash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateIndex
CREATE INDEX `organizations_status_purge_after_idx` ON `organizations`(`status`, `purge_after`);

-- CreateIndex: (family_id, revoked_at) replaces (family_id); created first so family lookups
-- are never without an index.
CREATE INDEX `user_sessions_family_id_revoked_at_idx` ON `user_sessions`(`family_id`, `revoked_at`);

-- DropIndex
DROP INDEX `user_sessions_family_id_idx` ON `user_sessions`;

-- AddForeignKey
ALTER TABLE `user_tokens` ADD CONSTRAINT `user_tokens_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_tokens` ADD CONSTRAINT `user_tokens_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_tokens` ADD CONSTRAINT `user_tokens_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_mfa_recovery_codes` ADD CONSTRAINT `user_mfa_recovery_codes_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_mfa_recovery_codes` ADD CONSTRAINT `user_mfa_recovery_codes_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
