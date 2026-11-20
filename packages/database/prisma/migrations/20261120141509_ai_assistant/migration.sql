-- Step AI-1: AI assistant, chat-based management (phase 1)
-- (docs/plan/steps/28-ai-chat-management.md §3, D7, D11-D13; ADR-0091 .. ADR-0094).
--
-- What changes (six new tables, none partitioned: 175 tables, 41 partitioned):
--   * ai_chat_settings: one row per organization (`assistant-settings/1`, CAS on row_version).
--   * ai_chat_conversations, ai_chat_turns, ai_chat_messages, ai_chat_tool_executions: a user's
--     private conversations, their turns (metrics, provider-native transcript), messages and
--     every tool execution (allowed or denied). Content columns (title, content,
--     provider_transcript, result_card, result_refs, next_cursor) are purged at `purge_after`
--     and on conversation delete; no email body or attachment is ever stored (I5).
--   * ai_chat_usage_daily: tokens and advisory cost per organization, UTC day, provider, model.
--   * Foreign keys: organizations RESTRICT on all six (the organization purge deletes them first,
--     AssistantTenantDataRepository); ai_chat_conversations.user_id → users CASCADE (private data
--     of the user, as saved_views); turns, messages and executions → their conversation CASCADE,
--     messages and executions → their turn CASCADE. No FK on the denormalized `user_id` of turns
--     and executions, on `parent_execution_id`, or on the settings' acknowledging / updating user
--     (the trail survives the user).
--   * Indexes: organization_id first in every tenant index; the conversation list index
--     (organization_id, user_id, status, last_turn_at, id) and the purge index (purge_after) of
--     design §3; (organization_id, created_at) on ai_chat_messages and the (turn_id) /
--     (user_id) indexes back the foreign keys and the organization purge.
--   * Data (D13, PO Q3): the idempotent, grant-preserving RBAC section 3 below.
--
-- Locking: every table is created empty; the foreign keys are added to empty tables (the parent
-- tables organizations and users only take a short metadata lock). No existing table is altered.
--
-- Rollback (never automatic; after rolling the api and the portal back, AI-1 being the only
-- reader and writer of these tables):
--   DROP TABLE ai_chat_tool_executions, ai_chat_messages, ai_chat_turns, ai_chat_usage_daily,
--              ai_chat_settings, ai_chat_conversations;   -- children before conversations
--   DELETE rp FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
--     WHERE p.`key` IN ('assistant:use', 'assistant:configure');
--   DELETE FROM permissions WHERE `key` IN ('assistant:use', 'assistant:configure');
--   (custom roles that were given the permissions lose them with the second statement; the
--   feature key `ai_assistant` rows in organization_features are harmless and may stay).
--   Then delete the migration's `_prisma_migrations` row. See docs/database/README.md.

-- 1a. ai_chat_settings (D13).
CREATE TABLE `ai_chat_settings` (
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `external_processing_ack_at` DATETIME(3) NULL,
    `external_processing_ack_by_user_id` BIGINT UNSIGNED NULL,
    `daily_token_budget` INTEGER UNSIGNED NULL,
    `retention_days` SMALLINT UNSIGNED NOT NULL DEFAULT 30,
    `data_sharing` ENUM('metadata') NOT NULL DEFAULT 'metadata',
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`organization_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 1b. ai_chat_conversations (D7, D12).
CREATE TABLE `ai_chat_conversations` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `platform_override_id` CHAR(36) NULL,
    `title` VARCHAR(200) NULL,
    `status` ENUM('active', 'archived', 'deleted') NOT NULL DEFAULT 'active',
    `turn_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `segment` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    `last_turn_at` DATETIME(3) NULL,
    `purge_after` DATETIME(3) NULL,
    `content_purged_at` DATETIME(3) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ai_chat_conversations_public_id_key`(`public_id`),
    INDEX `ai_chat_conversations_organization_id_user_id_status_last_tu_idx`(`organization_id`, `user_id`, `status`, `last_turn_at`, `id`),
    INDEX `ai_chat_conversations_purge_after_idx`(`purge_after`),
    INDEX `ai_chat_conversations_user_id_idx`(`user_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 1c. ai_chat_turns (D7).
CREATE TABLE `ai_chat_turns` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `seq` INTEGER UNSIGNED NOT NULL,
    `segment` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    `client_turn_id` CHAR(36) NOT NULL,
    `status` ENUM('running', 'completed', 'failed', 'cancelled') NOT NULL DEFAULT 'running',
    `provider` VARCHAR(32) NOT NULL,
    `model` VARCHAR(64) NOT NULL,
    `response_model` VARCHAR(128) NULL,
    `prompt_version` VARCHAR(32) NOT NULL,
    `registry_version` VARCHAR(32) NOT NULL,
    `rounds` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `tool_calls` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `input_tokens` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `output_tokens` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `cache_read_tokens` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `cache_write_tokens` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `cost_micros` BIGINT UNSIGNED NULL,
    `latency_ms` INTEGER UNSIGNED NULL,
    `error_code` VARCHAR(64) NULL,
    `correlation_id` VARCHAR(128) NOT NULL,
    `provider_transcript` MEDIUMTEXT NULL,
    `started_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `finished_at` DATETIME(3) NULL,

    UNIQUE INDEX `ai_chat_turns_public_id_key`(`public_id`),
    INDEX `ai_chat_turns_organization_id_started_at_idx`(`organization_id`, `started_at`),
    INDEX `ai_chat_turns_status_started_at_idx`(`status`, `started_at`),
    UNIQUE INDEX `ai_chat_turns_conversation_id_seq_key`(`conversation_id`, `seq`),
    UNIQUE INDEX `ai_chat_turns_conversation_id_client_turn_id_key`(`conversation_id`, `client_turn_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 1d. ai_chat_messages (D12).
CREATE TABLE `ai_chat_messages` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `turn_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `seq` INTEGER UNSIGNED NOT NULL,
    `role` ENUM('user', 'assistant') NOT NULL,
    `content` TEXT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ai_chat_messages_public_id_key`(`public_id`),
    INDEX `ai_chat_messages_organization_id_created_at_idx`(`organization_id`, `created_at`),
    INDEX `ai_chat_messages_turn_id_idx`(`turn_id`),
    UNIQUE INDEX `ai_chat_messages_conversation_id_seq_key`(`conversation_id`, `seq`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 1e. ai_chat_tool_executions (D5, D8, D12).
CREATE TABLE `ai_chat_tool_executions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `turn_id` BIGINT UNSIGNED NULL,
    `parent_execution_id` BIGINT UNSIGNED NULL,
    `seq` INTEGER UNSIGNED NOT NULL,
    `tool_name` VARCHAR(96) NOT NULL,
    `operation_id` VARCHAR(128) NOT NULL,
    `http_method` ENUM('GET', 'POST', 'PUT', 'PATCH', 'DELETE') NOT NULL,
    `access` ENUM('read', 'write') NOT NULL,
    `risk` ENUM('read', 'read_audited', 'low', 'medium', 'high', 'critical') NOT NULL,
    `decision` ENUM('allowed', 'denied_permission', 'denied_unknown_tool', 'denied_disabled', 'denied_not_applicable', 'denied_schema', 'denied_ref', 'denied_budget') NOT NULL,
    `status` ENUM('succeeded', 'failed', 'refused', 'timeout') NOT NULL,
    `http_status` SMALLINT UNSIGNED NULL,
    `error_code` VARCHAR(64) NULL,
    `correlation_id` VARCHAR(128) NOT NULL,
    `params_redacted` JSON NULL,
    `resource_ref` VARCHAR(64) NULL,
    `result_card` JSON NULL,
    `result_refs` JSON NULL,
    `next_cursor` VARCHAR(2048) NULL,
    `latency_ms` INTEGER UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ai_chat_tool_executions_public_id_key`(`public_id`),
    INDEX `ai_chat_tool_executions_organization_id_created_at_idx`(`organization_id`, `created_at`),
    INDEX `ai_chat_tool_executions_correlation_id_idx`(`correlation_id`),
    INDEX `ai_chat_tool_executions_turn_id_idx`(`turn_id`),
    UNIQUE INDEX `ai_chat_tool_executions_conversation_id_seq_key`(`conversation_id`, `seq`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 1f. ai_chat_usage_daily (D11).
CREATE TABLE `ai_chat_usage_daily` (
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `day` DATE NOT NULL,
    `provider` VARCHAR(32) NOT NULL,
    `model` VARCHAR(64) NOT NULL,
    `turns` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `input_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `output_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `cache_read_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `cache_write_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `cost_micros` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`organization_id`, `day`, `provider`, `model`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 2. Foreign keys (empty tables).
ALTER TABLE `ai_chat_settings` ADD CONSTRAINT `ai_chat_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_conversations` ADD CONSTRAINT `ai_chat_conversations_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_conversations` ADD CONSTRAINT `ai_chat_conversations_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_turns` ADD CONSTRAINT `ai_chat_turns_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_turns` ADD CONSTRAINT `ai_chat_turns_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_messages` ADD CONSTRAINT `ai_chat_messages_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_messages` ADD CONSTRAINT `ai_chat_messages_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_messages` ADD CONSTRAINT `ai_chat_messages_turn_id_fkey` FOREIGN KEY (`turn_id`) REFERENCES `ai_chat_turns`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_tool_executions` ADD CONSTRAINT `ai_chat_tool_executions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_tool_executions` ADD CONSTRAINT `ai_chat_tool_executions_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_tool_executions` ADD CONSTRAINT `ai_chat_tool_executions_turn_id_fkey` FOREIGN KEY (`turn_id`) REFERENCES `ai_chat_turns`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_usage_daily` ADD CONSTRAINT `ai_chat_usage_daily_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------------------------
-- 3. Grant-preserving RBAC data (D13, PO Q3; the pattern of 20261120053633_journal_intake).
--    Idempotent (upsert, INSERT IGNORE); no existing grant, role or user_roles row is deleted or
--    changed. The values equal the seed catalog (packages/database/src/seed/catalog.ts), so
--    `pnpm db:seed` afterwards is a no-op for these rows. On a fresh database (no catalog yet)
--    the grants below touch no row (no system role exists); the seed then grants them exactly.
--    Custom roles get the permissions only when an administrator adds them.
-- ---------------------------------------------------------------------------------------------

-- 3a. Permissions assistant:use and assistant:configure (category `assistant`).
INSERT INTO `permissions` (`key`, `description`, `category`, `created_at`, `updated_at`) VALUES
    ('assistant:use', 'Use the AI assistant; tools are limited to the user''s own permissions', 'assistant', NOW(3), NOW(3)),
    ('assistant:configure', 'Enable the AI assistant for the organization, set its budget and retention, view its usage', 'assistant', NOW(3), NOW(3))
AS new
ON DUPLICATE KEY UPDATE
    `description` = new.`description`,
    `category` = new.`category`,
    `updated_at` = IF(`permissions`.`description` <=> new.`description` AND `permissions`.`category` <=> new.`category`, `permissions`.`updated_at`, new.`updated_at`);

-- 3b. assistant:use for every system role except mailbox_user (the end-user role does not chat
--     in AI-1). organization_admin and super_admin also receive it from the seed through
--     TENANT_PERMISSIONS / ALL_PERMISSIONS.
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` = 'assistant:use'
WHERE r.`organization_id` IS NULL
  AND r.`key` IN ('super_admin', 'platform_admin', 'organization_admin', 'domain_admin',
                  'security_analyst', 'quarantine_reviewer', 'compliance_auditor',
                  'read_only_user', 'compliance_officer');

-- 3c. assistant:configure for super_admin and organization_admin only.
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` = 'assistant:configure'
WHERE r.`organization_id` IS NULL AND r.`key` IN ('super_admin', 'organization_admin');
