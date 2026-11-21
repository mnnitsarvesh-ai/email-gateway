-- Step AI-2: AI assistant action confirmations
-- (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md §3, D1-D3, D7; ADR-0093 as amended
-- in AI-2).
--
-- Additive only (one new table, none partitioned: 176 tables, 41 partitioned; one enum value):
--   * ai_chat_tool_executions.status gains `pending_confirmation` (the proposal of a write tool;
--     the confirmed write is a separate execution row). The value is appended at the end of the
--     list, existing values and their order are unchanged, so the change is ALGORITHM=INSTANT
--     (metadata only; the ENUM keeps its 1-byte storage) and no existing row is touched.
--   * ai_chat_action_confirmations: one row per proposed write waiting for the user's
--     confirmation. The single-use token is never stored, only its SHA-256 (`token_hash`);
--     `action_digest` binds the stored request, preconditions and identity. Content columns
--     (`request`, `preconditions`, `summary`) are purged with the conversation's content.
--   * Foreign keys: organizations RESTRICT (the organization purge deletes the rows before the
--     executions, AssistantTenantDataRepository); conversation, turn and proposal execution
--     CASCADE (rows are hard-deleted with their execution). No FK on `user_id` (the conversation
--     cascades) or on `result_execution_id` (the confirmed write's execution).
--   * Indexes: UQ public_id (the confirmed write's Idempotency-Key), UQ execution_id (one
--     confirmation per proposal), (organization_id, user_id, status, expires_at) (owner lookups),
--     (conversation_id, status, reported_at) (pending cap and the next turn's action updates),
--     (status, expires_at) (expiry sweep), (status, decided_at) (outcome-unknown sweep of
--     `executing` rows), (turn_id) (backs the turn foreign key).
--
-- Locking: the table is created empty; adding its foreign keys takes a short metadata lock on
-- organizations, ai_chat_conversations, ai_chat_turns and ai_chat_tool_executions. The ENUM
-- change is INSTANT (MySQL refuses instead of copying if it ever could not be).
--
-- Rollback (never automatic; after rolling the api and the portal back, AI-2 being the only
-- reader and writer of the table and of the new status value):
--   DROP TABLE ai_chat_action_confirmations;
--   The `pending_confirmation` value may stay (an older api never writes it). To remove it,
--   first delete (or re-status) the rows that carry it, then
--   ALTER TABLE ai_chat_tool_executions MODIFY `status`
--     ENUM('succeeded', 'failed', 'refused', 'timeout') NOT NULL;
--   Then delete the migration's `_prisma_migrations` row. See docs/database/README.md.

-- 1. ai_chat_tool_executions.status: append `pending_confirmation` (D7).
ALTER TABLE `ai_chat_tool_executions` MODIFY `status` ENUM('succeeded', 'failed', 'refused', 'timeout', 'pending_confirmation') NOT NULL, ALGORITHM=INSTANT;

-- 2. ai_chat_action_confirmations (§3).
CREATE TABLE `ai_chat_action_confirmations` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `platform_override_id` CHAR(36) NULL,
    `session_family_id` CHAR(36) NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `turn_id` BIGINT UNSIGNED NULL,
    `execution_id` BIGINT UNSIGNED NOT NULL,
    `result_execution_id` BIGINT UNSIGNED NULL,
    `tool_name` VARCHAR(96) NOT NULL,
    `operation_id` VARCHAR(128) NOT NULL,
    `http_method` ENUM('GET', 'POST', 'PUT', 'PATCH', 'DELETE') NOT NULL,
    `risk` ENUM('low', 'medium', 'high') NOT NULL,
    `requires_reauth` BOOLEAN NOT NULL,
    `request` JSON NULL,
    `preconditions` JSON NULL,
    `summary` JSON NULL,
    `state_digest` CHAR(64) NULL,
    `action_digest` CHAR(64) NOT NULL,
    `token_hash` CHAR(64) NOT NULL,
    `status` ENUM('pending', 'executing', 'executed', 'failed', 'expired', 'cancelled') NOT NULL DEFAULT 'pending',
    `failed_attempts` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `reauth_used` BOOLEAN NOT NULL DEFAULT false,
    `expires_at` DATETIME(3) NOT NULL,
    `decided_at` DATETIME(3) NULL,
    `executed_at` DATETIME(3) NULL,
    `reported_at` DATETIME(3) NULL,
    `result_http_status` SMALLINT UNSIGNED NULL,
    `error_code` VARCHAR(64) NULL,
    `correlation_id` VARCHAR(128) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ai_chat_action_confirmations_public_id_key`(`public_id`),
    UNIQUE INDEX `ai_chat_action_confirmations_execution_id_key`(`execution_id`),
    INDEX `ai_chat_action_confirmations_organization_id_user_id_status__idx`(`organization_id`, `user_id`, `status`, `expires_at`),
    INDEX `ai_chat_action_confirmations_conversation_id_status_reported_idx`(`conversation_id`, `status`, `reported_at`),
    INDEX `ai_chat_action_confirmations_status_expires_at_idx`(`status`, `expires_at`),
    INDEX `ai_chat_action_confirmations_status_decided_at_idx`(`status`, `decided_at`),
    INDEX `ai_chat_action_confirmations_turn_id_idx`(`turn_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. Foreign keys (empty table).
ALTER TABLE `ai_chat_action_confirmations` ADD CONSTRAINT `ai_chat_action_confirmations_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_action_confirmations` ADD CONSTRAINT `ai_chat_action_confirmations_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_action_confirmations` ADD CONSTRAINT `ai_chat_action_confirmations_turn_id_fkey` FOREIGN KEY (`turn_id`) REFERENCES `ai_chat_turns`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_action_confirmations` ADD CONSTRAINT `ai_chat_action_confirmations_execution_id_fkey` FOREIGN KEY (`execution_id`) REFERENCES `ai_chat_tool_executions`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
