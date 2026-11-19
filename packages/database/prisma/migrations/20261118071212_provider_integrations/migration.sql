-- Step 8.2: Microsoft 365 and Google Workspace connectors
-- (docs/plan/steps/25-m365-google-connectors.md §3, D1-D12; ADR-0076 .. ADR-0081).
--
-- What changes (eleven new tables, none partitioned; one changed table):
--   * smtp_connectors (step 2.2; altered): `auth_type` gains the appended value `provider_relay`
--     (step 8.2 D7, ADR-0078); new column `provider_connection_id` (NULL; provider_relay
--     connectors only) with a unique key (one relay connector per connection) and a foreign key
--     to provider_connections ON DELETE RESTRICT (a connection with a relay connector cannot be
--     deleted; the organization purge clears the link first, §3.3).
--   * New tenant tables: provider_connections (D1, D4; `active_tenant_key` unique: one
--     non-disabled connection per provider tenant platform-wide, I10), provider_connection_grants
--     (D2, D5; encrypted credentials, ADR-0077), provider_consent_states (D3; SHA-256 of the
--     single-use state only), provider_connection_domains (D4; `domain_id` unique: a domain is
--     linked to at most one connection), provider_validation_runs (D10), provider_probe_observations
--     (D10; bounded evidence, never message content, I8), provider_health_checks and
--     provider_health_events (D11, D12), provider_relay_counters (D7, D18).
--   * New platform tables: provider_egress_range_sets and provider_egress_ranges (D7; versioned
--     operator imports, seeded with a snapshot by `pnpm db:seed`).
--   * Enums (new; append-only from now on): IntegrationProvider, ProviderConnectionStatus,
--     ProviderOutboundMode, ProviderHealthStatus, ProviderAuthMethod, ProviderGrantStatus,
--     ProviderDomainVerification, ProviderValidationKind, ProviderValidationStatus,
--     ProviderCheckStatus, ProviderCheckSeverity, ProviderTenantHeaderResult, ProviderDkimResult,
--     ProviderProofResult, ProviderEgressSetStatus, ProviderActorType (MySQL ENUM columns).
--
-- References only tables that exist at 00051ee (organizations, users, domains, smtp_connectors);
-- nothing of steps 8.1 or 8.4. No backfill: every new column is NULL or has a constant default,
-- and every new table starts empty.
--
-- Foreign keys: provider_connections.organization_id → organizations RESTRICT (the organization
-- purge deletes the provider rows explicitly, §3.3); provider_connections.created_by_user_id →
-- users SET NULL; children of a connection → provider_connections CASCADE;
-- provider_consent_states.grant_id → provider_connection_grants CASCADE and .user_id → users
-- CASCADE (a deleted user's pending consent goes with it); provider_connection_domains.domain_id
-- → domains CASCADE; provider_probe_observations.validation_run_id → provider_validation_runs
-- SET NULL (evidence outlives a pruned run); provider_egress_ranges.set_id →
-- provider_egress_range_sets CASCADE. No FK on the actor columns `disabled_by_user_id`,
-- `consented_by_user_id`, `inbound_applied_by_user_id` (the trail survives the user) nor on the
-- children's `organization_id` (always equal to the parent connection's, written by code).
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1. smtp_connectors MODIFY auth_type (one value appended, same 1-byte ENUM storage):
--      ALGORITHM=INSTANT (metadata only).
--   2. smtp_connectors ADD COLUMN provider_connection_id (NULL): ALGORITHM=INSTANT.
--   3. smtp_connectors unique index: ALGORITHM=INPLACE, LOCK=NONE.
--   4.-14. new tables: created empty.
--   15. foreign keys of the new tables: added to empty tables (default algorithm).
--   16. smtp_connectors ADD FOREIGN KEY: default algorithm (COPY: MySQL adds a foreign key with
--       foreign_key_checks = 1 only by copying); the table is tiny (tenant configuration rows),
--       as for email_policies in step 5.2.
-- Each algorithm is stated explicitly where MySQL supports it, so an unexpected rebuild fails
-- instead of copying silently. DDL auto-commits: if the migration fails part-way, inspect, fix and
-- resolve it (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the api, smtp-adapter, delivery-worker and integration-worker back, and
-- after deleting every smtp_connectors row with auth_type = 'provider_relay'): drop the
-- smtp_connectors FK, unique index and column; MODIFY auth_type back to the three values
-- (COPY); DROP the eleven new tables (children first: provider_egress_ranges, the connection
-- children, provider_connection_grants after provider_consent_states, then provider_connections
-- and provider_egress_range_sets).

-- 1. smtp_connectors: append the provider_relay auth type (step 8.2 D7).
ALTER TABLE `smtp_connectors`
    MODIFY `auth_type` ENUM('sasl', 'source_ip', 'client_certificate', 'provider_relay') NOT NULL,
    ALGORITHM=INSTANT;

-- 2. smtp_connectors: the provider connection of a provider_relay connector.
ALTER TABLE `smtp_connectors` ADD COLUMN `provider_connection_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 3. smtp_connectors: one relay connector per connection.
ALTER TABLE `smtp_connectors`
    ADD UNIQUE INDEX `smtp_connectors_provider_connection_id_key`(`provider_connection_id`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 4. provider_connections (new).
CREATE TABLE `provider_connections` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `provider` ENUM('microsoft_365', 'google_workspace') NOT NULL,
    `display_name` VARCHAR(128) NOT NULL,
    `status` ENUM('draft', 'connecting', 'configuring', 'active', 'disabled') NOT NULL DEFAULT 'draft',
    `external_tenant_id` VARCHAR(64) NULL,
    `external_tenant_name` VARCHAR(256) NULL,
    `tenant_verified_at` DATETIME(3) NULL,
    `active_tenant_key` VARCHAR(100) NULL,
    `outbound_mode` ENUM('off', 'probe_only', 'active', 'suspended') NOT NULL DEFAULT 'off',
    `internal_routing` BOOLEAN NOT NULL DEFAULT false,
    `relay_proof` JSON NULL,
    `route_token_version` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    `route_token_pending_version` SMALLINT UNSIGNED NULL,
    `attestations` JSON NULL,
    `health_status` ENUM('unknown', 'healthy', 'warning', 'critical') NOT NULL DEFAULT 'unknown',
    `health_checked_at` DATETIME(3) NULL,
    `health_changed_at` DATETIME(3) NULL,
    `next_health_check_at` DATETIME(3) NULL,
    `health_claimed_until` DATETIME(3) NULL,
    `last_relay_accepted_at` DATETIME(3) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `disabled_at` DATETIME(3) NULL,
    `disabled_by_user_id` BIGINT UNSIGNED NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `provider_connections_public_id_key`(`public_id`),
    UNIQUE INDEX `provider_connections_active_tenant_key_key`(`active_tenant_key`),
    INDEX `provider_connections_organization_id_status_idx`(`organization_id`, `status`),
    INDEX `provider_connections_status_next_health_check_at_idx`(`status`, `next_health_check_at`),
    UNIQUE INDEX `provider_connections_organization_id_display_name_key`(`organization_id`, `display_name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. provider_connection_grants (new).
CREATE TABLE `provider_connection_grants` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `profile` VARCHAR(48) NOT NULL,
    `profile_version` SMALLINT UNSIGNED NOT NULL,
    `auth_method` ENUM('platform_app', 'customer_app_secret', 'platform_service_account', 'customer_service_account') NOT NULL,
    `status` ENUM('pending_consent', 'verifying', 'active', 'error', 'revoked') NOT NULL DEFAULT 'pending_consent',
    `client_id` VARCHAR(128) NULL,
    `subject_email` VARCHAR(320) NULL,
    `credential_ciphertext` TEXT NULL,
    `credential_key_id` VARCHAR(8) NULL,
    `credential_version` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `credential_fingerprint` CHAR(64) NULL,
    `credential_set_at` DATETIME(3) NULL,
    `credential_expires_at` DATETIME(3) NULL,
    `requested_permissions` JSON NOT NULL,
    `observed_permissions` JSON NULL,
    `missing_permissions` JSON NULL,
    `excess_permissions` JSON NULL,
    `claimed_tenant_id` VARCHAR(64) NULL,
    `consented_at` DATETIME(3) NULL,
    `consented_by_user_id` BIGINT UNSIGNED NULL,
    `verify_requested_at` DATETIME(3) NULL,
    `verified_at` DATETIME(3) NULL,
    `verify_claimed_until` DATETIME(3) NULL,
    `last_token_at` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `consecutive_failures` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `provider_connection_grants_public_id_key`(`public_id`),
    INDEX `provider_connection_grants_status_verify_requested_at_idx`(`status`, `verify_requested_at`),
    INDEX `provider_connection_grants_organization_id_connection_id_idx`(`organization_id`, `connection_id`),
    INDEX `provider_connection_grants_credential_key_id_idx`(`credential_key_id`),
    UNIQUE INDEX `provider_connection_grants_connection_id_profile_key`(`connection_id`, `profile`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. provider_consent_states (new).
CREATE TABLE `provider_consent_states` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `grant_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `state_sha256` CHAR(64) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `used_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `provider_consent_states_state_sha256_key`(`state_sha256`),
    INDEX `provider_consent_states_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. provider_connection_domains (new).
CREATE TABLE `provider_connection_domains` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `provider_verification` ENUM('unknown', 'verified', 'unverified', 'absent', 'alias') NOT NULL DEFAULT 'unknown',
    `provider_checked_at` DATETIME(3) NULL,
    `provider_mx_host` VARCHAR(253) NULL,
    `inbound_applied_at` DATETIME(3) NULL,
    `inbound_applied_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `provider_connection_domains_domain_id_key`(`domain_id`),
    INDEX `provider_connection_domains_connection_id_idx`(`connection_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. provider_validation_runs (new).
CREATE TABLE `provider_validation_runs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('full', 'credentials', 'inbound', 'outbound') NOT NULL,
    `status` ENUM('queued', 'running', 'awaiting_probe', 'passed', 'warning', 'failed', 'expired', 'cancelled') NOT NULL DEFAULT 'queued',
    `requested_by_type` ENUM('user', 'system', 'api_key') NOT NULL,
    `requested_by_id` VARCHAR(64) NULL,
    `probe_token_sha256` CHAR(64) NULL,
    `probe_expires_at` DATETIME(3) NULL,
    `results` JSON NULL,
    `summary` JSON NULL,
    `claimed_until` DATETIME(3) NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `provider_validation_runs_public_id_key`(`public_id`),
    UNIQUE INDEX `provider_validation_runs_probe_token_sha256_key`(`probe_token_sha256`),
    INDEX `provider_validation_runs_connection_id_created_at_idx`(`connection_id`, `created_at`),
    INDEX `provider_validation_runs_status_created_at_idx`(`status`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. provider_probe_observations (new).
CREATE TABLE `provider_probe_observations` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `validation_run_id` BIGINT UNSIGNED NULL,
    `token_sha256` CHAR(64) NOT NULL,
    `queue_id` VARCHAR(32) NOT NULL,
    `provider` ENUM('microsoft_365', 'google_workspace') NOT NULL,
    `client_ip` VARCHAR(45) NOT NULL,
    `tls_protocol` VARCHAR(16) NULL,
    `tls_cipher` VARCHAR(64) NULL,
    `envelope_from_domain` VARCHAR(253) NOT NULL,
    `header_from_domain` VARCHAR(253) NULL,
    `tenant_header` ENUM('match', 'mismatch', 'absent', 'not_applicable') NOT NULL,
    `dkim` ENUM('aligned_pass', 'unaligned_pass', 'fail', 'none', 'temperror', 'replayed', 'stale') NOT NULL,
    `dkim_domains` JSON NOT NULL,
    `dkim_age_seconds` INTEGER NULL,
    `proof_result` ENUM('pass', 'fail', 'temperror') NOT NULL,
    `failure_code` VARCHAR(64) NULL,
    `received_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `provider_probe_observations_connection_id_received_at_idx`(`connection_id`, `received_at`),
    UNIQUE INDEX `provider_probe_observations_token_sha256_queue_id_key`(`token_sha256`, `queue_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. provider_health_checks (new).
CREATE TABLE `provider_health_checks` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `check_code` VARCHAR(64) NOT NULL,
    `subject` VARCHAR(253) NOT NULL DEFAULT '',
    `status` ENUM('pass', 'warn', 'fail', 'skipped', 'error') NOT NULL,
    `severity` ENUM('info', 'warning', 'critical') NOT NULL,
    `evidence` JSON NULL,
    `first_failed_at` DATETIME(3) NULL,
    `checked_at` DATETIME(3) NOT NULL,
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `provider_health_checks_connection_id_check_code_subject_key`(`connection_id`, `check_code`, `subject`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 11. provider_health_events (new).
CREATE TABLE `provider_health_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `from_status` ENUM('unknown', 'healthy', 'warning', 'critical') NOT NULL,
    `to_status` ENUM('unknown', 'healthy', 'warning', 'critical') NOT NULL,
    `failing_checks` JSON NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `provider_health_events_connection_id_created_at_idx`(`connection_id`, `created_at`),
    INDEX `provider_health_events_created_at_idx`(`created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 12. provider_relay_counters (new).
CREATE TABLE `provider_relay_counters` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connection_id` BIGINT UNSIGNED NOT NULL,
    `hour_start` DATETIME(3) NOT NULL,
    `accepted` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `proof_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `temp_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `probes` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `provider_relay_counters_hour_start_idx`(`hour_start`),
    UNIQUE INDEX `provider_relay_counters_connection_id_hour_start_key`(`connection_id`, `hour_start`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 13. provider_egress_range_sets (new).
CREATE TABLE `provider_egress_range_sets` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `provider` ENUM('microsoft_365', 'google_workspace') NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL,
    `status` ENUM('active', 'superseded') NOT NULL,
    `source` VARCHAR(512) NOT NULL,
    `published_at` DATETIME(3) NULL,
    `sha256` CHAR(64) NOT NULL,
    `range_count` INTEGER UNSIGNED NOT NULL,
    `imported_by` VARCHAR(64) NOT NULL,
    `imported_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `provider_egress_range_sets_provider_status_idx`(`provider`, `status`),
    UNIQUE INDEX `provider_egress_range_sets_provider_version_key`(`provider`, `version`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 14. provider_egress_ranges (new).
CREATE TABLE `provider_egress_ranges` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `set_id` BIGINT UNSIGNED NOT NULL,
    `provider` ENUM('microsoft_365', 'google_workspace') NOT NULL,
    `cidr` VARCHAR(49) NOT NULL,
    `ip_version` TINYINT UNSIGNED NOT NULL,
    `range_start` VARBINARY(16) NOT NULL,
    `range_end` VARBINARY(16) NOT NULL,

    INDEX `provider_egress_ranges_provider_ip_version_range_start_idx`(`provider`, `ip_version`, `range_start`),
    UNIQUE INDEX `provider_egress_ranges_set_id_cidr_key`(`set_id`, `cidr`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 15. Foreign keys of the new tables (empty tables).
-- AddForeignKey
ALTER TABLE `provider_connections` ADD CONSTRAINT `provider_connections_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_connections` ADD CONSTRAINT `provider_connections_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_connection_grants` ADD CONSTRAINT `provider_connection_grants_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_consent_states` ADD CONSTRAINT `provider_consent_states_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_consent_states` ADD CONSTRAINT `provider_consent_states_grant_id_fkey` FOREIGN KEY (`grant_id`) REFERENCES `provider_connection_grants`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_consent_states` ADD CONSTRAINT `provider_consent_states_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_connection_domains` ADD CONSTRAINT `provider_connection_domains_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_connection_domains` ADD CONSTRAINT `provider_connection_domains_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_validation_runs` ADD CONSTRAINT `provider_validation_runs_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_probe_observations` ADD CONSTRAINT `provider_probe_observations_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_probe_observations` ADD CONSTRAINT `provider_probe_observations_validation_run_id_fkey` FOREIGN KEY (`validation_run_id`) REFERENCES `provider_validation_runs`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_health_checks` ADD CONSTRAINT `provider_health_checks_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_health_events` ADD CONSTRAINT `provider_health_events_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_relay_counters` ADD CONSTRAINT `provider_relay_counters_connection_id_fkey` FOREIGN KEY (`connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `provider_egress_ranges` ADD CONSTRAINT `provider_egress_ranges_set_id_fkey` FOREIGN KEY (`set_id`) REFERENCES `provider_egress_range_sets`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- 16. smtp_connectors → provider_connections (RESTRICT; default algorithm, see the header).
ALTER TABLE `smtp_connectors` ADD CONSTRAINT `smtp_connectors_provider_connection_id_fkey` FOREIGN KEY (`provider_connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

