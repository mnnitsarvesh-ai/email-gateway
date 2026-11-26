-- Step AI-6: AI assistant hardening and operations
-- (docs/plan/steps/34-ai-chat-hardening-operations.md §3, D1-D7; ADR-0096, ADR-0097, ADR-0094
-- amendment AI-6, ADR-0095 amendment AI-6). Migration 42.
--
-- Additive (178 -> 183 tables, still 41 partitioned; no permission, one data section):
--   * ENUM values appended (existing values and their order unchanged, ALGORITHM=INSTANT):
--     ai_chat_settings.data_sharing += 'pseudonymized' (D3), ai_chat_reports.status += 'queued'
--     (D5: asynchronous report waiting for its job).
--   * New columns (ALGORITHM=INSTANT): ai_chat_settings.user_daily_token_budget (D1),
--     use_tenant_key and tenant_key_fallback_to_platform (D6, D7); ai_chat_turns.data_sharing
--     (D3), key_source (D6, D7) and fallback_from (D6). Defaults reproduce the AI-5 behaviour
--     (`metadata`, `platform`, no fallback, no user budget, no tenant key).
--   * New tables (none partitioned):
--     ai_chat_usage_user_daily (D1: usage per organization, UTC day, user, provider, model and key
--       source; upserted with ai_chat_usage_daily in the turn's closing transaction),
--     ai_chat_feedback (D2: one rating per assistant message; `comment` is content, purged),
--     ai_chat_pseudonyms (D3: token <-> value per conversation; `value` is content, rows deleted
--       at the content purge),
--     ai_chat_provider_keys (D7: the organization's encrypted provider key, one row per
--       organization; never plaintext, I27),
--     ai_chat_report_jobs (D5: one background generation per queued report; session id and auth
--       methods only, no credential, I26).
--   * Foreign keys: organizations RESTRICT on all five (the organization purge deletes them
--     first; AssistantTenantDataRepository); conversation_id -> ai_chat_conversations CASCADE
--     (feedback, pseudonyms, report jobs); ai_chat_feedback.message_id -> ai_chat_messages
--     CASCADE; ai_chat_report_jobs.report_id -> ai_chat_reports CASCADE. No FK on user ids
--     (users are soft-deleted; the trail survives), turn_id, execution_id or set_by_user_id.
--   * New indexes on existing tables (ALGORITHM=INPLACE LOCK=NONE: online, concurrent DML kept):
--     ai_chat_conversations (organization_id, last_turn_at, id) (D4 metadata-only admin list),
--     ai_chat_tool_executions (organization_id, user_id, created_at) and
--       (organization_id, tool_name, created_at) (D4 audit search),
--     ai_chat_turns (organization_id, user_id, started_at) (per-user views).
--   * Data section: ai_chat_usage_user_daily is backfilled from ai_chat_turns with exactly what
--     UsageRepository.add counts per turn (TurnEngineService.finish): every turn closed by the
--     turn engine (`completed`, `failed`, `cancelled` with `finished_at`), but not turns the
--     sweeper abandoned (`failed` with `assistant_turn_abandoned`, which never reach the usage
--     upsert); day = UTC day of `finished_at`; provider and model as stored on the turn; the four
--     token columns summed; cost_micros = SUM (NULL when no counted turn had a price);
--     key_source = 'platform' (every turn before AI-6 used the platform key). Turns already
--     hard-deleted by the execution retention cannot be backfilled (ai_chat_usage_daily keeps
--     their organization totals). Idempotent only on an empty table: it runs once, inside this
--     migration, before any AI-6 api writes the table.
--
-- Locking: the ENUM appends and column additions are metadata-only (INSTANT; MySQL refuses
-- rather than copies if INSTANT were impossible); the four secondary indexes are built online;
-- the five tables are created empty; adding their foreign keys takes short metadata locks on
-- organizations, ai_chat_conversations, ai_chat_messages and ai_chat_reports. The backfill reads
-- ai_chat_turns once (low volume: one row per chat turn).
--
-- Rollback (never automatic; after rolling the api, the api-assistant Deployment and the portal
-- back to AI-5; an AI-5 api ignores the new columns and tables):
--   UPDATE ai_chat_settings SET data_sharing = 'metadata' WHERE data_sharing = 'pseudonymized';
--   UPDATE ai_chat_reports SET status = 'failed', error_code = 'assistant_report_job_expired'
--     WHERE status = 'queued';
--   DROP TABLE ai_chat_report_jobs;
--   DROP TABLE ai_chat_provider_keys;
--   DROP TABLE ai_chat_pseudonyms;
--   DROP TABLE ai_chat_feedback;
--   DROP TABLE ai_chat_usage_user_daily;
--   ALTER TABLE ai_chat_turns DROP COLUMN data_sharing, DROP COLUMN key_source,
--     DROP COLUMN fallback_from;
--   ALTER TABLE ai_chat_settings DROP COLUMN user_daily_token_budget, DROP COLUMN use_tenant_key,
--     DROP COLUMN tenant_key_fallback_to_platform;
--   -- only when no row uses the new values any more:
--   ALTER TABLE ai_chat_settings MODIFY `data_sharing` ENUM('metadata') NOT NULL DEFAULT 'metadata';
--   ALTER TABLE ai_chat_reports MODIFY `status` ENUM('pending', 'available', 'failed', 'purged')
--     NOT NULL DEFAULT 'pending';
--   DROP INDEX ai_chat_conversations_organization_id_last_turn_at_id_idx ON ai_chat_conversations;
--   DROP INDEX ai_chat_tool_executions_organization_id_user_id_created_at_idx
--     ON ai_chat_tool_executions;
--   DROP INDEX ai_chat_tool_executions_organization_id_tool_name_created_at_idx
--     ON ai_chat_tool_executions;
--   DROP INDEX ai_chat_turns_organization_id_user_id_started_at_idx ON ai_chat_turns;
--   Then delete the migration's `_prisma_migrations` row; purge the RabbitMQ queue
--   `assistant.reports` (topology v16) if it still holds job messages. See docs/database/README.md.

-- 1. ENUM values appended and new columns (§3; ALGORITHM=INSTANT).
ALTER TABLE `ai_chat_reports` MODIFY `status` ENUM('pending', 'available', 'failed', 'purged', 'queued') NOT NULL DEFAULT 'pending',
    ALGORITHM=INSTANT;

ALTER TABLE `ai_chat_settings` ADD COLUMN `tenant_key_fallback_to_platform` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `use_tenant_key` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `user_daily_token_budget` INTEGER UNSIGNED NULL,
    MODIFY `data_sharing` ENUM('metadata', 'pseudonymized') NOT NULL DEFAULT 'metadata',
    ALGORITHM=INSTANT;

ALTER TABLE `ai_chat_turns` ADD COLUMN `data_sharing` ENUM('metadata', 'pseudonymized') NOT NULL DEFAULT 'metadata',
    ADD COLUMN `fallback_from` VARCHAR(32) NULL,
    ADD COLUMN `key_source` ENUM('platform', 'tenant') NOT NULL DEFAULT 'platform',
    ALGORITHM=INSTANT;

-- 2. ai_chat_usage_user_daily (§3, D1).
CREATE TABLE `ai_chat_usage_user_daily` (
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `day` DATE NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `provider` VARCHAR(32) NOT NULL,
    `model` VARCHAR(64) NOT NULL,
    `key_source` ENUM('platform', 'tenant') NOT NULL,
    `turns` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `input_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `output_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `cache_read_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `cache_write_tokens` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `cost_micros` BIGINT UNSIGNED NULL,
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `ai_chat_usage_user_daily_organization_id_user_id_day_idx`(`organization_id`, `user_id`, `day`),
    PRIMARY KEY (`organization_id`, `day`, `user_id`, `provider`, `model`, `key_source`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. ai_chat_feedback (§3, D2).
CREATE TABLE `ai_chat_feedback` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `turn_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `rating` ENUM('up', 'down') NOT NULL,
    `reason` ENUM('incorrect', 'incomplete', 'not_helpful', 'wrong_action', 'unsafe', 'too_slow', 'other') NULL,
    `comment` VARCHAR(500) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ai_chat_feedback_public_id_key`(`public_id`),
    UNIQUE INDEX `ai_chat_feedback_message_id_key`(`message_id`),
    INDEX `ai_chat_feedback_organization_id_created_at_idx`(`organization_id`, `created_at`),
    INDEX `ai_chat_feedback_organization_id_rating_created_at_idx`(`organization_id`, `rating`, `created_at`),
    INDEX `ai_chat_feedback_conversation_id_idx`(`conversation_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. ai_chat_pseudonyms (§3, D3).
CREATE TABLE `ai_chat_pseudonyms` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('email', 'ip', 'domain', 'name') NOT NULL,
    `token` VARCHAR(24) NOT NULL,
    `value` VARCHAR(320) NOT NULL,
    `value_sha256` CHAR(64) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ai_chat_pseudonyms_organization_id_created_at_idx`(`organization_id`, `created_at`),
    UNIQUE INDEX `ai_chat_pseudonyms_conversation_id_token_key`(`conversation_id`, `token`),
    UNIQUE INDEX `ai_chat_pseudonyms_conversation_id_kind_value_sha256_key`(`conversation_id`, `kind`, `value_sha256`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. ai_chat_provider_keys (§3, D7).
CREATE TABLE `ai_chat_provider_keys` (
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `provider` ENUM('anthropic', 'openai') NOT NULL,
    `model` VARCHAR(64) NOT NULL,
    `key_ciphertext` VARCHAR(1024) NOT NULL,
    `key_kid` VARCHAR(8) NOT NULL,
    `key_fingerprint` CHAR(16) NOT NULL,
    `key_version` INTEGER UNSIGNED NOT NULL,
    `status` ENUM('valid', 'invalid', 'unverified') NOT NULL,
    `last_validated_at` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `set_by_user_id` BIGINT UNSIGNED NOT NULL,
    `set_at` DATETIME(3) NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`organization_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. ai_chat_report_jobs (§3, D5).
CREATE TABLE `ai_chat_report_jobs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `conversation_id` BIGINT UNSIGNED NOT NULL,
    `report_id` BIGINT UNSIGNED NOT NULL,
    `execution_id` BIGINT UNSIGNED NOT NULL,
    `session_id` CHAR(36) NOT NULL,
    `auth_methods` VARCHAR(16) NOT NULL,
    `home_organization_public_id` CHAR(36) NOT NULL,
    `platform_override_id` CHAR(36) NULL,
    `arguments` JSON NOT NULL,
    `organization_label` VARCHAR(120) NULL,
    `status` ENUM('queued', 'running', 'succeeded', 'failed', 'cancelled') NOT NULL DEFAULT 'queued',
    `attempts` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `lease_until` DATETIME(3) NULL,
    `error_code` VARCHAR(64) NULL,
    `correlation_id` VARCHAR(128) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `reported_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `started_at` DATETIME(3) NULL,
    `finished_at` DATETIME(3) NULL,
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ai_chat_report_jobs_public_id_key`(`public_id`),
    UNIQUE INDEX `ai_chat_report_jobs_report_id_key`(`report_id`),
    INDEX `ai_chat_report_jobs_status_expires_at_idx`(`status`, `expires_at`),
    INDEX `ai_chat_report_jobs_conversation_id_status_reported_at_idx`(`conversation_id`, `status`, `reported_at`),
    INDEX `ai_chat_report_jobs_organization_id_created_at_idx`(`organization_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. Secondary indexes on existing tables (§3, D4; online).
CREATE INDEX `ai_chat_conversations_organization_id_last_turn_at_id_idx` ON `ai_chat_conversations`(`organization_id`, `last_turn_at`, `id`) ALGORITHM=INPLACE LOCK=NONE;

CREATE INDEX `ai_chat_tool_executions_organization_id_user_id_created_at_idx` ON `ai_chat_tool_executions`(`organization_id`, `user_id`, `created_at`) ALGORITHM=INPLACE LOCK=NONE;

CREATE INDEX `ai_chat_tool_executions_organization_id_tool_name_created_at_idx` ON `ai_chat_tool_executions`(`organization_id`, `tool_name`, `created_at`) ALGORITHM=INPLACE LOCK=NONE;

CREATE INDEX `ai_chat_turns_organization_id_user_id_started_at_idx` ON `ai_chat_turns`(`organization_id`, `user_id`, `started_at`) ALGORITHM=INPLACE LOCK=NONE;

-- 8. Foreign keys (empty tables).
ALTER TABLE `ai_chat_usage_user_daily` ADD CONSTRAINT `ai_chat_usage_user_daily_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_feedback` ADD CONSTRAINT `ai_chat_feedback_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_feedback` ADD CONSTRAINT `ai_chat_feedback_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_feedback` ADD CONSTRAINT `ai_chat_feedback_message_id_fkey` FOREIGN KEY (`message_id`) REFERENCES `ai_chat_messages`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_pseudonyms` ADD CONSTRAINT `ai_chat_pseudonyms_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_pseudonyms` ADD CONSTRAINT `ai_chat_pseudonyms_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_provider_keys` ADD CONSTRAINT `ai_chat_provider_keys_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_report_jobs` ADD CONSTRAINT `ai_chat_report_jobs_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ai_chat_report_jobs` ADD CONSTRAINT `ai_chat_report_jobs_conversation_id_fkey` FOREIGN KEY (`conversation_id`) REFERENCES `ai_chat_conversations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `ai_chat_report_jobs` ADD CONSTRAINT `ai_chat_report_jobs_report_id_fkey` FOREIGN KEY (`report_id`) REFERENCES `ai_chat_reports`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- 9. Data: backfill ai_chat_usage_user_daily from the stored turns (D1; see the header).
INSERT INTO `ai_chat_usage_user_daily`
    (`organization_id`, `day`, `user_id`, `provider`, `model`, `key_source`, `turns`,
     `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `cost_micros`,
     `updated_at`)
SELECT `organization_id`, DATE(`finished_at`), `user_id`, `provider`, `model`, 'platform',
       COUNT(*), SUM(`input_tokens`), SUM(`output_tokens`), SUM(`cache_read_tokens`),
       SUM(`cache_write_tokens`), SUM(`cost_micros`), CURRENT_TIMESTAMP(3)
  FROM `ai_chat_turns`
 WHERE `status` IN ('completed', 'failed', 'cancelled')
   AND `finished_at` IS NOT NULL
   AND NOT (`status` = 'failed' AND `error_code` <=> 'assistant_turn_abandoned')
 GROUP BY `organization_id`, DATE(`finished_at`), `user_id`, `provider`, `model`;
