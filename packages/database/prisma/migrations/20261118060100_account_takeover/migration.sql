-- Step 8.4: Account takeover detection core, part 2 of 2: the ATO tables
-- (docs/plan/steps/24-account-takeover-core.md §3.2, D1-D3, D6, D8-D15, D22, D23;
-- ADR-0070 .. ADR-0074). Requires 20261118060000_security_incidents.
--
-- What changes (sixteen new tables, four of them partitioned: 151 tables, 39 partitioned; two
-- columns added to existing partitioned tables):
--   * bec_scan_results (PARTITIONED, existing; altered, never re-created): ADD COLUMN
--     `outbound_observations` JSON NULL (D6: counts and booleans of the BEC engine's outbound
--     observation mode; the verdict, codes and score are unchanged).
--   * policy_execution_logs (PARTITIONED, existing; altered, never re-created): ADD COLUMN
--     `ato_facts` JSON NULL (D23: the `ato-policy-facts/1` block used by the evaluation; NULL
--     when absent, so every stored `input_sha256` stays reproducible).
--   * New tables (not partitioned): ato_settings, ato_settings_versions, ato_accounts,
--     ato_account_baselines, ato_risk_overrides, ato_trusted_contexts, ato_incident_details (the
--     ATO category detail of a security incident), ato_response_actions,
--     ato_response_action_logs, ato_smtp_restrictions, ato_provider_integrations,
--     ato_account_identities.
--   * New PARTITIONED tables (ADR-0014: composite primary key ending with the partition column,
--     every unique key includes it, no foreign keys in either direction; created with the single
--     catch-all partition pmax that `pnpm db:partitions apply` splits):
--       ato_auth_events            RANGE COLUMNS(occurred_at) — 3 months, tier detail
--       ato_account_activity_daily RANGE COLUMNS(day_start)   — 6 months, tier core
--       ato_risk_signals           RANGE COLUMNS(detected_at) — 13 months, tier core
--       ato_risk_scores            RANGE COLUMNS(computed_at) — 13 months, tier core
--   * Generated STORED columns (Prisma: plain nullable TINYINT marked READ-ONLY, never written):
--       ato_response_actions.active_marker  = 1 for pending_approval / approved / executing /
--         rollback_requested (unique (organization_id, dedupe_hash, active_marker): one
--         non-terminal action per incident, type and target);
--       ato_smtp_restrictions.active_marker = 1 for active (unique (organization_id,
--         subject_hash, active_marker): one active restriction per subject).
--   * Enums (new; append-only): AtoAccountKind, AtoAccountStatus, AtoRiskLevel, AtoAuthSource,
--     AtoAuthChannel, AtoAuthOutcome, AtoGeoStatus, AtoSignalCategory, AtoSignalStrength,
--     AtoSignalStatus, AtoSignalSourceKind, AtoScoreTrigger, AtoOverrideVerdict,
--     AtoTrustedContextKind, AtoTrustedContextSource, AtoResponseImpact, AtoResponseStatus,
--     AtoResponseAuthorization, AtoProviderStatus, AtoActionLogPhase, AtoActionLogOutcome,
--     AtoRestrictionKind, AtoRestrictionScope, AtoRestrictionMode, AtoRestrictionStatus,
--     AtoLiftedByType, AtoProviderIntegrationStatus (MySQL ENUM columns).
--
-- No new user, tenant, domain or mailbox table (D1): ato_accounts references users.id,
-- smtp_connectors.id or a lower-cased mailbox address without foreign keys (the trail survives
-- deletion). No message content, password, token, SASL secret, raw SMTP username, subject, body
-- or recipient address in any table (registrable domains, hashes, codes and counts only).
-- No data is written: the feature `ato_detection` is off for every organization (seed, D21).
--
-- Foreign keys: tenant tables → organizations RESTRICT (ato_settings, ato_settings_versions,
-- ato_accounts, ato_risk_overrides, ato_response_actions, ato_smtp_restrictions,
-- ato_provider_integrations; the organization purge removes them explicitly);
-- ato_settings.updated_by_user_id → users SET NULL; account children → ato_accounts CASCADE
-- (baselines, overrides, trusted contexts, identities) or RESTRICT (incident details, response
-- actions: the retention purge deletes them first); ato_incident_details.incident_id →
-- security_incidents CASCADE; ato_response_actions.incident_id → security_incidents RESTRICT;
-- ato_response_action_logs.action_id → ato_response_actions CASCADE. No FK: the partitioned
-- tables (both directions), ato_accounts.user_id / connector_id / domain_id /
-- active_incident_id / override_id, every *_by_user_id except ato_settings.updated_by_user_id.
--
-- Locking (online DDL; MySQL 8.4):
--   1. bec_scan_results ADD COLUMN (NULL, no default): ALGORITHM=INSTANT on every partition
--      (metadata only). Fallback if MySQL ever refuses INSTANT for the table (for example after
--      64 row versions): ALGORITHM=INPLACE, LOCK=NONE (a rebuild with concurrent DML); not
--      needed on MySQL 8.4 locally (verified on the throwaway and the main schema, step 8.4 §13).
--   2. policy_execution_logs ADD COLUMN: the same.
--   3.-18. new tables: created empty; their foreign keys (19.) added to empty tables.
-- Each algorithm is stated explicitly, so an unexpected rebuild fails instead of copying
-- silently. DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the api, ato-worker, smtp-adapter, email-worker and policy-engine
-- back): DROP the sixteen tables (action logs, then actions, incident details, then the other
-- account children, then ato_accounts, ato_settings_versions, ato_settings), and
-- ALTER TABLE bec_scan_results DROP COLUMN outbound_observations, ALGORITHM=INSTANT;
-- ALTER TABLE policy_execution_logs DROP COLUMN ato_facts, ALGORITHM=INSTANT.

-- 1. bec_scan_results (PARTITIONED; altered): BEC outbound observations (D6).
ALTER TABLE `bec_scan_results` ADD COLUMN `outbound_observations` JSON NULL,
    ALGORITHM=INSTANT;

-- 2. policy_execution_logs (PARTITIONED; altered): the ATO policy facts of the evaluation (D23).
ALTER TABLE `policy_execution_logs` ADD COLUMN `ato_facts` JSON NULL,
    ALGORITHM=INSTANT;

-- 3. ato_settings (§4.3; one row per organization).
CREATE TABLE `ato_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `settings` JSON NOT NULL,
    `settings_sha256` CHAR(64) NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `learning_started_at` DATETIME(3) NOT NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. ato_settings_versions (append-only history).
CREATE TABLE `ato_settings_versions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL,
    `settings` JSON NOT NULL,
    `settings_sha256` CHAR(64) NOT NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ato_settings_versions_organization_id_version_key`(`organization_id`, `version`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. ato_accounts (D1: monitored subjects).
CREATE TABLE `ato_accounts` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('mailbox', 'gateway_user', 'smtp_connector') NOT NULL,
    `subject_hash` CHAR(64) NOT NULL,
    `address` VARCHAR(320) NULL,
    `domain_id` BIGINT UNSIGNED NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `connector_id` BIGINT UNSIGNED NULL,
    `status` ENUM('active', 'retired') NOT NULL DEFAULT 'active',
    `protected` BOOLEAN NOT NULL DEFAULT false,
    `protected_reason` VARCHAR(512) NULL,
    `protected_by_user_id` BIGINT UNSIGNED NULL,
    `protected_at` DATETIME(3) NULL,
    `risk_score` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `risk_level` ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    `risk_updated_at` DATETIME(3) NULL,
    `risk_explanation` JSON NULL,
    `last_signal_at` DATETIME(3) NULL,
    `active_incident_id` BIGINT UNSIGNED NULL,
    `override_id` BIGINT UNSIGNED NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `last_auth_success_at` DATETIME(3) NULL,
    `last_auth_geo` JSON NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_accounts_public_id_key`(`public_id`),
    INDEX `ato_accounts_organization_id_risk_score_id_idx`(`organization_id`, `risk_score`, `id`),
    INDEX `ato_accounts_organization_id_last_signal_at_id_idx`(`organization_id`, `last_signal_at`, `id`),
    INDEX `ato_accounts_organization_id_address_id_idx`(`organization_id`, `address`, `id`),
    INDEX `ato_accounts_organization_id_kind_last_seen_at_idx`(`organization_id`, `kind`, `last_seen_at`),
    INDEX `ato_accounts_organization_id_domain_id_risk_score_id_idx`(`organization_id`, `domain_id`, `risk_score`, `id`),
    INDEX `ato_accounts_risk_updated_at_risk_score_idx`(`risk_updated_at`, `risk_score`),
    UNIQUE INDEX `ato_accounts_organization_id_kind_subject_hash_key`(`organization_id`, `kind`, `subject_hash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. ato_account_baselines (D9).
CREATE TABLE `ato_account_baselines` (
    `account_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `baseline` JSON NOT NULL,
    `version` VARCHAR(32) NOT NULL,
    `event_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `active_days` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `mature` BOOLEAN NOT NULL DEFAULT false,
    `matured_at` DATETIME(3) NULL,
    `window_start` DATETIME(3) NOT NULL,
    `window_end` DATETIME(3) NOT NULL,
    `rebuilt_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `ato_account_baselines_organization_id_rebuilt_at_idx`(`organization_id`, `rebuilt_at`),
    PRIMARY KEY (`account_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. ato_account_activity_daily (D9).
-- Partitioned (monthly) by RANGE COLUMNS(day_start); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes day_start.
-- Created with the single catch-all partition pmax (retention 6 months, tier core).
CREATE TABLE `ato_account_activity_daily` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `day_start` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `auth_success` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `auth_failure` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `messages` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `recipients` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `external_recipients` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `internal_recipients` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `attachments` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `findings` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `max_hour_messages` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `hour_counts` JSON NOT NULL,
    `ip_prefixes` JSON NOT NULL,
    `recipient_domains` JSON NOT NULL,
    `attachment_types` JSON NOT NULL,
    `peers` JSON NOT NULL,
    `content` JSON NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `ato_account_activity_daily_organization_id_day_start_idx`(`organization_id`, `day_start`),
    UNIQUE INDEX `ato_account_activity_daily_organization_id_account_id_day_st_key`(`organization_id`, `account_id`, `day_start`),
    PRIMARY KEY (`id`, `day_start`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`day_start`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 8. ato_auth_events (D5, D7).
-- Partitioned (monthly) by RANGE COLUMNS(occurred_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes occurred_at.
-- Created with the single catch-all partition pmax (retention 3 months, tier detail).
CREATE TABLE `ato_auth_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `occurred_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NULL,
    `source` ENUM('portal_login', 'portal_mfa', 'smtp_auth', 'idp_sign_in') NOT NULL,
    `channel` ENUM('portal', 'api', 'smtp', 'idp') NOT NULL,
    `outcome` ENUM('success', 'failure', 'locked', 'mfa_required', 'mfa_failure', 'rate_limited', 'throttled', 'blocked') NOT NULL,
    `failure_code` VARCHAR(64) NULL,
    `ip_address` VARCHAR(45) NULL,
    `ip_prefix` VARCHAR(49) NULL,
    `country_code` CHAR(2) NULL,
    `region` VARCHAR(64) NULL,
    `city` VARCHAR(64) NULL,
    `latitude` DECIMAL(8, 4) NULL,
    `longitude` DECIMAL(9, 4) NULL,
    `accuracy_km` SMALLINT UNSIGNED NULL,
    `geo_status` ENUM('located', 'not_found', 'private', 'unavailable', 'stale') NOT NULL,
    `asn` INTEGER UNSIGNED NULL,
    `asn_org` VARCHAR(128) NULL,
    `anonymizer_flags` SMALLINT UNSIGNED NULL,
    `reputation` JSON NULL,
    `device_hash` CHAR(16) NULL,
    `device_label` VARCHAR(96) NULL,
    `mechanism` VARCHAR(16) NULL,
    `attempt_count` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `last_occurred_at` DATETIME(3) NOT NULL,
    `source_ref` VARCHAR(64) NULL,
    `dedupe_key` CHAR(64) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ato_auth_events_organization_id_account_id_occurred_at_id_idx`(`organization_id`, `account_id`, `occurred_at`, `id`),
    INDEX `ato_auth_events_organization_id_occurred_at_id_idx`(`organization_id`, `occurred_at`, `id`),
    INDEX `ato_auth_events_organization_id_ip_address_occurred_at_idx`(`organization_id`, `ip_address`, `occurred_at`),
    UNIQUE INDEX `ato_auth_events_organization_id_dedupe_key_occurred_at_key`(`organization_id`, `dedupe_key`, `occurred_at`),
    PRIMARY KEY (`id`, `occurred_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`occurred_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 9. ato_risk_signals (D10).
-- Partitioned (monthly) by RANGE COLUMNS(detected_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes detected_at.
-- Created with the single catch-all partition pmax (retention 13 months, tier core).
CREATE TABLE `ato_risk_signals` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `detected_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `rule_code` VARCHAR(64) NOT NULL,
    `category` ENUM('authentication', 'access_context', 'geography', 'threat_intel', 'account_change', 'outbound_behaviour', 'outbound_content', 'mailbox_configuration', 'oauth_activity', 'provider_risk', 'correlation') NOT NULL,
    `strength` ENUM('weak', 'moderate', 'strong') NOT NULL,
    `weight` TINYINT UNSIGNED NOT NULL,
    `status` ENUM('active', 'dismissed', 'informational') NOT NULL DEFAULT 'active',
    `dedupe_key` CHAR(64) NOT NULL,
    `occurrences` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `first_occurred_at` DATETIME(3) NOT NULL,
    `last_occurred_at` DATETIME(3) NOT NULL,
    `evidence` JSON NOT NULL,
    `source_kind` ENUM('auth_event', 'message', 'telemetry', 'audit', 'provider', 'correlation', 'window') NOT NULL,
    `source_ref` VARCHAR(64) NULL,
    `message_id` BIGINT UNSIGNED NULL,
    `message_received_at` DATETIME(3) NULL,
    `auth_event_id` BIGINT UNSIGNED NULL,
    `auth_event_occurred_at` DATETIME(3) NULL,
    `incident_id` BIGINT UNSIGNED NULL,
    `rules_version` VARCHAR(16) NOT NULL,
    `settings_version` INTEGER UNSIGNED NOT NULL,
    `dismissed_at` DATETIME(3) NULL,
    `dismissed_by_user_id` BIGINT UNSIGNED NULL,
    `dismiss_reason` VARCHAR(512) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `ato_risk_signals_organization_id_account_id_detected_at_id_idx`(`organization_id`, `account_id`, `detected_at`, `id`),
    INDEX `ato_risk_signals_organization_id_account_id_dedupe_key_idx`(`organization_id`, `account_id`, `dedupe_key`),
    INDEX `ato_risk_signals_organization_id_incident_id_detected_at_idx`(`organization_id`, `incident_id`, `detected_at`),
    INDEX `ato_risk_signals_organization_id_detected_at_id_idx`(`organization_id`, `detected_at`, `id`),
    INDEX `ato_risk_signals_organization_id_category_detected_at_idx`(`organization_id`, `category`, `detected_at`),
    PRIMARY KEY (`id`, `detected_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`detected_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 10. ato_risk_scores (D11).
-- Partitioned (monthly) by RANGE COLUMNS(computed_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes computed_at.
-- Created with the single catch-all partition pmax (retention 13 months, tier core).
CREATE TABLE `ato_risk_scores` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `computed_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `score` TINYINT UNSIGNED NOT NULL,
    `level` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `previous_score` TINYINT UNSIGNED NOT NULL,
    `previous_level` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `trigger` ENUM('signal', 'decay', 'override', 'dismissal', 'settings', 'feedback') NOT NULL,
    `explanation` JSON NOT NULL,
    `scorer_version` VARCHAR(16) NOT NULL,
    `rules_version` VARCHAR(16) NOT NULL,
    `settings_version` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ato_risk_scores_organization_id_account_id_computed_at_id_idx`(`organization_id`, `account_id`, `computed_at`, `id`),
    INDEX `ato_risk_scores_organization_id_computed_at_level_idx`(`organization_id`, `computed_at`, `level`),
    PRIMARY KEY (`id`, `computed_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`computed_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 11. ato_risk_overrides (D11).
CREATE TABLE `ato_risk_overrides` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `verdict` ENUM('benign', 'compromised') NOT NULL,
    `reason` VARCHAR(1000) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `cleared_at` DATETIME(3) NULL,
    `cleared_by_user_id` BIGINT UNSIGNED NULL,
    `clear_reason` VARCHAR(1000) NULL,
    `contradicted_at` DATETIME(3) NULL,

    UNIQUE INDEX `ato_risk_overrides_public_id_key`(`public_id`),
    INDEX `ato_risk_overrides_organization_id_account_id_created_at_idx`(`organization_id`, `account_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 12. ato_trusted_contexts.
CREATE TABLE `ato_trusted_contexts` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('ip_cidr', 'asn', 'country', 'device') NOT NULL,
    `value` VARCHAR(64) NOT NULL,
    `ip_version` TINYINT UNSIGNED NULL,
    `range_start` VARBINARY(16) NULL,
    `range_end` VARBINARY(16) NULL,
    `reason` VARCHAR(512) NOT NULL,
    `source` ENUM('analyst', 'false_positive_feedback') NOT NULL,
    `incident_id` BIGINT UNSIGNED NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `expires_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_trusted_contexts_public_id_key`(`public_id`),
    INDEX `ato_trusted_contexts_organization_id_account_id_idx`(`organization_id`, `account_id`),
    UNIQUE INDEX `ato_trusted_contexts_account_id_kind_value_key`(`account_id`, `kind`, `value`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 13. ato_incident_details (D12: the ATO category detail of a security incident).
CREATE TABLE `ato_incident_details` (
    `incident_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `risk_score_at_open` TINYINT UNSIGNED NOT NULL,
    `peak_risk_score` TINYINT UNSIGNED NOT NULL,
    `detection_reason` JSON NOT NULL,
    `recommended_actions` JSON NOT NULL,
    `related_ips` JSON NOT NULL,
    `geo_summary` JSON NULL,
    `device_summary` JSON NULL,
    `signal_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `auth_event_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `message_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `finding_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `last_signals_event_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `ato_incident_details_organization_id_account_id_idx`(`organization_id`, `account_id`),
    PRIMARY KEY (`incident_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 14. ato_response_actions (D13).
CREATE TABLE `ato_response_actions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `incident_id` BIGINT UNSIGNED NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `action_type` VARCHAR(48) NOT NULL,
    `provider` VARCHAR(32) NOT NULL,
    `impact` ENUM('low', 'medium', 'high') NOT NULL,
    `target` JSON NOT NULL,
    `params` JSON NOT NULL,
    `status` ENUM('pending_approval', 'approved', 'executing', 'succeeded', 'failed', 'rejected', 'cancelled', 'expired', 'unsupported', 'rollback_requested', 'rolled_back', 'rollback_failed', 'attested') NOT NULL,
    `requires_approval` BOOLEAN NOT NULL,
    `authorization` ENUM('manual', 'automation_policy', 'low_impact_default') NOT NULL,
    `requested_by_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `requested_by_id` VARCHAR(64) NULL,
    `request_reason` VARCHAR(1000) NULL,
    `approved_by_user_id` BIGINT UNSIGNED NULL,
    `decided_at` DATETIME(3) NULL,
    `decision_reason` VARCHAR(1000) NULL,
    `approval_expires_at` DATETIME(3) NULL,
    `executed_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `effective_until` DATETIME(3) NULL,
    `next_check_at` DATETIME(3) NULL,
    `provider_reference` VARCHAR(128) NULL,
    `provider_status` ENUM('applied', 'confirmed', 'pending', 'unconfirmed', 'unsupported', 'failed') NULL,
    `result_code` VARCHAR(64) NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `restriction_id` BIGINT UNSIGNED NULL,
    `rolled_back_by_user_id` BIGINT UNSIGNED NULL,
    `rollback_reason` VARCHAR(1000) NULL,
    `dedupe_hash` CHAR(64) NOT NULL,
    `active_marker` TINYINT UNSIGNED
        GENERATED ALWAYS AS (IF(`status` IN ('pending_approval', 'approved', 'executing', 'rollback_requested'), 1, NULL)) STORED NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_response_actions_public_id_key`(`public_id`),
    INDEX `ato_response_actions_organization_id_status_created_at_id_idx`(`organization_id`, `status`, `created_at`, `id`),
    INDEX `ato_response_actions_organization_id_incident_id_idx`(`organization_id`, `incident_id`),
    INDEX `ato_response_actions_organization_id_account_id_created_at_idx`(`organization_id`, `account_id`, `created_at`),
    INDEX `ato_response_actions_status_approval_expires_at_idx`(`status`, `approval_expires_at`),
    INDEX `ato_response_actions_status_next_check_at_idx`(`status`, `next_check_at`),
    UNIQUE INDEX `ato_response_actions_organization_id_dedupe_hash_active_mark_key`(`organization_id`, `dedupe_hash`, `active_marker`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 15. ato_response_action_logs (D13).
CREATE TABLE `ato_response_action_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `action_id` BIGINT UNSIGNED NOT NULL,
    `phase` ENUM('authorize', 'execute', 'confirm', 'rollback') NOT NULL,
    `attempt_no` SMALLINT UNSIGNED NOT NULL,
    `outcome` ENUM('succeeded', 'pending', 'failed', 'unsupported', 'retry_scheduled', 'skipped') NOT NULL,
    `provider_status` VARCHAR(32) NULL,
    `error_code` VARCHAR(64) NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ato_response_action_logs_action_id_created_at_idx`(`action_id`, `created_at`),
    INDEX `ato_response_action_logs_created_at_idx`(`created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 16. ato_smtp_restrictions (D14).
CREATE TABLE `ato_smtp_restrictions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('send_block', 'auth_block') NOT NULL,
    `scope` ENUM('mailbox', 'connector', 'connector_ip') NOT NULL,
    `connector_id` BIGINT UNSIGNED NULL,
    `mailbox_sha256` CHAR(64) NULL,
    `mailbox_address` VARCHAR(320) NULL,
    `ip_cidr` VARCHAR(49) NULL,
    `ip_version` TINYINT UNSIGNED NULL,
    `range_start` VARBINARY(16) NULL,
    `range_end` VARBINARY(16) NULL,
    `mode` ENUM('reject', 'defer') NOT NULL,
    `status` ENUM('active', 'lifted', 'expired') NOT NULL,
    `reason_code` VARCHAR(64) NOT NULL,
    `response_action_id` BIGINT UNSIGNED NULL,
    `starts_at` DATETIME(3) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `lifted_at` DATETIME(3) NULL,
    `lifted_by_type` ENUM('user', 'system') NULL,
    `lifted_by_id` VARCHAR(64) NULL,
    `lift_reason` VARCHAR(512) NULL,
    `subject_hash` CHAR(64) NOT NULL,
    `active_marker` TINYINT UNSIGNED
        GENERATED ALWAYS AS (IF(`status` = 'active', 1, NULL)) STORED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_smtp_restrictions_public_id_key`(`public_id`),
    INDEX `ato_smtp_restrictions_organization_id_status_expires_at_idx`(`organization_id`, `status`, `expires_at`),
    INDEX `ato_smtp_restrictions_status_expires_at_idx`(`status`, `expires_at`),
    UNIQUE INDEX `ato_smtp_restrictions_organization_id_subject_hash_active_ma_key`(`organization_id`, `subject_hash`, `active_marker`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 17. ato_provider_integrations (D15).
CREATE TABLE `ato_provider_integrations` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `provider` VARCHAR(32) NOT NULL,
    `connector_ref` VARCHAR(64) NULL,
    `binding_key` CHAR(64) NOT NULL,
    `status` ENUM('active', 'paused', 'error', 'disabled') NOT NULL DEFAULT 'active',
    `capabilities` JSON NOT NULL,
    `cursors` JSON NOT NULL,
    `last_success_at` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `consecutive_failures` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `next_poll_at` DATETIME(3) NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_provider_integrations_public_id_key`(`public_id`),
    INDEX `ato_provider_integrations_status_next_poll_at_idx`(`status`, `next_poll_at`),
    UNIQUE INDEX `ato_provider_integrations_organization_id_binding_key_key`(`organization_id`, `binding_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 18. ato_account_identities (D1, 8.5 adapters).
CREATE TABLE `ato_account_identities` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NOT NULL,
    `provider` VARCHAR(32) NOT NULL,
    `external_id` VARCHAR(128) NOT NULL,
    `external_id_hash` CHAR(64) NOT NULL,
    `user_principal_name` VARCHAR(320) NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,

    INDEX `ato_account_identities_account_id_idx`(`account_id`),
    UNIQUE INDEX `ato_account_identities_organization_id_provider_external_id__key`(`organization_id`, `provider`, `external_id_hash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 19. Foreign keys (added to the empty tables).
ALTER TABLE `ato_settings` ADD CONSTRAINT `ato_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_settings` ADD CONSTRAINT `ato_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `ato_settings_versions` ADD CONSTRAINT `ato_settings_versions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_accounts` ADD CONSTRAINT `ato_accounts_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_account_baselines` ADD CONSTRAINT `ato_account_baselines_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_risk_overrides` ADD CONSTRAINT `ato_risk_overrides_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_risk_overrides` ADD CONSTRAINT `ato_risk_overrides_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_trusted_contexts` ADD CONSTRAINT `ato_trusted_contexts_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_incident_details` ADD CONSTRAINT `ato_incident_details_incident_id_fkey` FOREIGN KEY (`incident_id`) REFERENCES `security_incidents`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_incident_details` ADD CONSTRAINT `ato_incident_details_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_response_actions` ADD CONSTRAINT `ato_response_actions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_response_actions` ADD CONSTRAINT `ato_response_actions_incident_id_fkey` FOREIGN KEY (`incident_id`) REFERENCES `security_incidents`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_response_actions` ADD CONSTRAINT `ato_response_actions_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_response_action_logs` ADD CONSTRAINT `ato_response_action_logs_action_id_fkey` FOREIGN KEY (`action_id`) REFERENCES `ato_response_actions`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_smtp_restrictions` ADD CONSTRAINT `ato_smtp_restrictions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_provider_integrations` ADD CONSTRAINT `ato_provider_integrations_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_account_identities` ADD CONSTRAINT `ato_account_identities_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
