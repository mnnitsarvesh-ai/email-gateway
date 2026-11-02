-- CreateTable
CREATE TABLE `organization_plans` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `code` VARCHAR(32) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `description` VARCHAR(512) NULL,
    `is_active` BOOLEAN NOT NULL DEFAULT true,
    `default_limits` JSON NOT NULL,
    `default_features` JSON NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `organization_plans_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `organizations` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `slug` VARCHAR(63) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `kind` ENUM('customer', 'platform') NOT NULL DEFAULT 'customer',
    `status` ENUM('active', 'suspended', 'deleted', 'pending_deletion') NOT NULL DEFAULT 'active',
    `plan_id` BIGINT UNSIGNED NOT NULL,
    `deployment_mode` ENUM('saas', 'dedicated') NOT NULL DEFAULT 'saas',
    `data_region` VARCHAR(32) NOT NULL,
    `deleted_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `organizations_public_id_key`(`public_id`),
    UNIQUE INDEX `organizations_slug_key`(`slug`),
    INDEX `organizations_status_idx`(`status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `organization_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `timezone` VARCHAR(64) NOT NULL DEFAULT 'UTC',
    `locale` VARCHAR(16) NOT NULL DEFAULT 'en',
    `quarantine_retention_days` SMALLINT UNSIGNED NOT NULL DEFAULT 30,
    `digest_enabled` BOOLEAN NOT NULL DEFAULT true,
    `digest_schedule` VARCHAR(64) NOT NULL DEFAULT '0 8 * * *',
    `notification_email` VARCHAR(320) NULL,
    `preferences` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `organization_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `organization_limits` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `limit_key` VARCHAR(64) NOT NULL,
    `limit_value` BIGINT UNSIGNED NOT NULL,
    `source` ENUM('plan', 'override') NOT NULL DEFAULT 'plan',
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `organization_limits_organization_id_limit_key_key`(`organization_id`, `limit_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `organization_features` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `feature_key` VARCHAR(64) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `config` JSON NULL,
    `source` ENUM('plan', 'override') NOT NULL DEFAULT 'plan',
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `organization_features_organization_id_feature_key_key`(`organization_id`, `feature_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `organization_deployments` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `deployment_mode` ENUM('saas', 'dedicated') NOT NULL,
    `region` VARCHAR(32) NOT NULL,
    `environment` VARCHAR(32) NOT NULL,
    `status` ENUM('provisioning', 'active', 'degraded', 'decommissioning', 'decommissioned') NOT NULL DEFAULT 'provisioning',
    `endpoint_hostname` VARCHAR(255) NULL,
    `mx_hostname` VARCHAR(255) NULL,
    `release_version` VARCHAR(64) NULL,
    `config` JSON NULL,
    `provisioned_at` DATETIME(3) NULL,
    `decommissioned_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `organization_deployments_organization_id_status_idx`(`organization_id`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `users` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `email` VARCHAR(320) NOT NULL,
    `display_name` VARCHAR(255) NOT NULL,
    `status` ENUM('invited', 'active', 'disabled', 'locked') NOT NULL DEFAULT 'invited',
    `password_hash` VARCHAR(255) NULL,
    `mfa_enabled` BOOLEAN NOT NULL DEFAULT false,
    `mfa_secret_ciphertext` VARCHAR(512) NULL,
    `failed_login_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `locked_until` DATETIME(3) NULL,
    `password_changed_at` DATETIME(3) NULL,
    `last_login_at` DATETIME(3) NULL,
    `deleted_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `users_public_id_key`(`public_id`),
    INDEX `users_organization_id_status_idx`(`organization_id`, `status`),
    UNIQUE INDEX `users_organization_id_email_key`(`organization_id`, `email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `roles` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NULL,
    `key` VARCHAR(64) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `description` VARCHAR(512) NULL,
    `is_system` BOOLEAN NOT NULL DEFAULT false,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `roles_key_idx`(`key`),
    UNIQUE INDEX `roles_organization_id_key_key`(`organization_id`, `key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `permissions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `key` VARCHAR(100) NOT NULL,
    `description` VARCHAR(255) NOT NULL,
    `category` VARCHAR(64) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `permissions_key_key`(`key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `role_permissions` (
    `role_id` BIGINT UNSIGNED NOT NULL,
    `permission_id` BIGINT UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `role_permissions_permission_id_idx`(`permission_id`),
    PRIMARY KEY (`role_id`, `permission_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `user_roles` (
    `user_id` BIGINT UNSIGNED NOT NULL,
    `role_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `granted_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `user_roles_organization_id_role_id_idx`(`organization_id`, `role_id`),
    INDEX `user_roles_role_id_idx`(`role_id`),
    PRIMARY KEY (`user_id`, `role_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `user_sessions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `refresh_token_hash` CHAR(64) NOT NULL,
    `family_id` CHAR(36) NOT NULL,
    `ip_address` VARCHAR(45) NULL,
    `user_agent` VARCHAR(512) NULL,
    `last_used_at` DATETIME(3) NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `revoked_at` DATETIME(3) NULL,
    `revoked_reason` VARCHAR(64) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `user_sessions_refresh_token_hash_key`(`refresh_token_hash`),
    INDEX `user_sessions_user_id_revoked_at_idx`(`user_id`, `revoked_at`),
    INDEX `user_sessions_family_id_idx`(`family_id`),
    INDEX `user_sessions_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `api_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `key_prefix` VARCHAR(16) NOT NULL,
    `key_hash` CHAR(64) NOT NULL,
    `scopes` JSON NOT NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `last_used_at` DATETIME(3) NULL,
    `expires_at` DATETIME(3) NULL,
    `revoked_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_keys_public_id_key`(`public_id`),
    UNIQUE INDEX `api_keys_key_prefix_key`(`key_prefix`),
    INDEX `api_keys_organization_id_revoked_at_idx`(`organization_id`, `revoked_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `login_audit_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `email_attempted` VARCHAR(320) NOT NULL,
    `outcome` ENUM('success', 'failure', 'locked', 'mfa_required', 'mfa_failure') NOT NULL,
    `failure_reason` VARCHAR(64) NULL,
    `ip_address` VARCHAR(45) NULL,
    `user_agent` VARCHAR(512) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `login_audit_logs_organization_id_created_at_idx`(`organization_id`, `created_at`),
    INDEX `login_audit_logs_user_id_created_at_idx`(`user_id`, `created_at`),
    INDEX `login_audit_logs_created_at_idx`(`created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domains` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(253) NOT NULL,
    `status` ENUM('pending_verification', 'verified', 'failed', 'disabled') NOT NULL DEFAULT 'pending_verification',
    `inbound_enabled` BOOLEAN NOT NULL DEFAULT true,
    `outbound_enabled` BOOLEAN NOT NULL DEFAULT false,
    `verified_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `domains_public_id_key`(`public_id`),
    UNIQUE INDEX `domains_name_key`(`name`),
    INDEX `domains_organization_id_status_idx`(`organization_id`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_verifications` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `method` ENUM('dns_txt', 'dns_cname') NOT NULL DEFAULT 'dns_txt',
    `token` VARCHAR(128) NOT NULL,
    `status` ENUM('pending', 'verified', 'failed', 'expired') NOT NULL DEFAULT 'pending',
    `attempts` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `next_check_at` DATETIME(3) NULL,
    `last_checked_at` DATETIME(3) NULL,
    `last_error` VARCHAR(512) NULL,
    `verified_at` DATETIME(3) NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `domain_verifications_domain_id_status_idx`(`domain_id`, `status`),
    INDEX `domain_verifications_status_next_check_at_idx`(`status`, `next_check_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_dns_records` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `purpose` ENUM('verification', 'mx', 'spf', 'dkim', 'dmarc', 'mta_sts', 'tls_rpt') NOT NULL,
    `record_type` ENUM('MX', 'TXT', 'CNAME') NOT NULL,
    `host` VARCHAR(255) NOT NULL,
    `expected_value` TEXT NOT NULL,
    `observed_value` TEXT NULL,
    `status` ENUM('pending', 'valid', 'invalid', 'missing') NOT NULL DEFAULT 'pending',
    `last_checked_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `domain_dns_records_domain_id_purpose_idx`(`domain_id`, `purpose`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_dkim_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `selector` VARCHAR(63) NOT NULL,
    `algorithm` ENUM('rsa_2048', 'ed25519') NOT NULL,
    `public_key` TEXT NOT NULL,
    `private_key_ref` VARCHAR(512) NOT NULL,
    `status` ENUM('pending', 'active', 'rotating', 'retired', 'revoked') NOT NULL DEFAULT 'pending',
    `activated_at` DATETIME(3) NULL,
    `retired_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `domain_dkim_keys_organization_id_status_idx`(`organization_id`, `status`),
    UNIQUE INDEX `domain_dkim_keys_domain_id_selector_key`(`domain_id`, `selector`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_mx_records` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `priority` SMALLINT UNSIGNED NOT NULL,
    `host` VARCHAR(255) NOT NULL,
    `points_to_gateway` BOOLEAN NOT NULL DEFAULT false,
    `last_seen_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `domain_mx_records_domain_id_host_key`(`domain_id`, `host`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_mail_servers` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `role` ENUM('inbound_destination', 'outbound_source') NOT NULL,
    `host` VARCHAR(255) NULL,
    `port` SMALLINT UNSIGNED NOT NULL DEFAULT 25,
    `ip_cidr` VARCHAR(64) NULL,
    `priority` SMALLINT UNSIGNED NOT NULL DEFAULT 10,
    `tls_mode` ENUM('none', 'opportunistic', 'required', 'verify') NOT NULL DEFAULT 'opportunistic',
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `domain_mail_servers_domain_id_role_priority_idx`(`domain_id`, `role`, `priority`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `max_message_size_bytes` INTEGER UNSIGNED NULL,
    `reject_unknown_recipients` BOOLEAN NOT NULL DEFAULT false,
    `recipient_validation` ENUM('none', 'list', 'smtp_callout', 'ldap') NOT NULL DEFAULT 'none',
    `settings` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `domain_settings_domain_id_key`(`domain_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `message_identities` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `ingest_key` VARCHAR(128) NOT NULL,
    `received_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `message_identities_public_id_key`(`public_id`),
    UNIQUE INDEX `message_identities_organization_id_ingest_key_key`(`organization_id`, `ingest_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_messages` (
    `id` BIGINT UNSIGNED NOT NULL,
    `received_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NULL,
    `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    `status` ENUM('received', 'scanning', 'scanned', 'policy_evaluated', 'quarantined', 'delivery_queued', 'delivered', 'partially_delivered', 'discarded', 'failed') NOT NULL DEFAULT 'received',
    `status_changed_at` DATETIME(3) NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `internet_message_id` VARCHAR(998) NULL,
    `envelope_from` VARCHAR(320) NOT NULL,
    `header_from` VARCHAR(320) NULL,
    `subject` VARCHAR(998) NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `recipient_count` SMALLINT UNSIGNED NOT NULL,
    `attachment_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `eml_object_key` VARCHAR(512) NOT NULL,
    `eml_sha256` CHAR(64) NOT NULL,
    `client_ip` VARCHAR(45) NULL,
    `client_helo` VARCHAR(255) NULL,
    `mta_queue_id` VARCHAR(32) NULL,
    `final_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard') NULL,
    `risk_score` SMALLINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `email_messages_organization_id_received_at_id_idx`(`organization_id`, `received_at`, `id`),
    INDEX `email_messages_status_status_changed_at_idx`(`status`, `status_changed_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_recipients` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `rcpt_seq` SMALLINT UNSIGNED NOT NULL,
    `address` VARCHAR(320) NOT NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `status` ENUM('pending', 'delivered', 'quarantined', 'discarded', 'deferred', 'failed', 'bounced') NOT NULL DEFAULT 'pending',
    `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard') NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `email_recipients_organization_id_address_received_at_idx`(`organization_id`, `address`(100), `received_at`),
    UNIQUE INDEX `email_recipients_message_id_rcpt_seq_received_at_key`(`message_id`, `rcpt_seq`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_headers` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `seq` SMALLINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `value` VARCHAR(2048) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `email_headers_message_id_seq_received_at_key`(`message_id`, `seq`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_attachments` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `part_index` SMALLINT UNSIGNED NOT NULL,
    `parent_part_index` SMALLINT UNSIGNED NULL,
    `filename` VARCHAR(255) NULL,
    `declared_content_type` VARCHAR(255) NULL,
    `detected_content_type` VARCHAR(255) NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `sha256` CHAR(64) NOT NULL,
    `object_key` VARCHAR(512) NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'error', 'skipped') NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `email_attachments_organization_id_sha256_idx`(`organization_id`, `sha256`),
    UNIQUE INDEX `email_attachments_message_id_part_index_received_at_key`(`message_id`, `part_index`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `event_type` VARCHAR(64) NOT NULL,
    `occurred_at` DATETIME(3) NOT NULL,
    `source_service` VARCHAR(64) NOT NULL,
    `event_id` CHAR(36) NULL,
    `actor_type` ENUM('system', 'user', 'api_key') NOT NULL DEFAULT 'system',
    `actor_id` VARCHAR(64) NULL,
    `details` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `email_events_message_id_received_at_idx`(`message_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_message_status_history` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL,
    `from_status` ENUM('received', 'scanning', 'scanned', 'policy_evaluated', 'quarantined', 'delivery_queued', 'delivered', 'partially_delivered', 'discarded', 'failed') NULL,
    `to_status` ENUM('received', 'scanning', 'scanned', 'policy_evaluated', 'quarantined', 'delivery_queued', 'delivered', 'partially_delivered', 'discarded', 'failed') NOT NULL,
    `reason_code` VARCHAR(64) NULL,
    `event_id` CHAR(36) NULL,
    `changed_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `email_message_status_history_message_id_version_received_at_key`(`message_id`, `version`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_scans` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_kind` ENUM('initial', 'rescan', 'release_revalidation', 'retro') NOT NULL DEFAULT 'initial',
    `attempt` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    `status` ENUM('pending', 'running', 'completed', 'failed', 'timed_out') NOT NULL DEFAULT 'pending',
    `verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    `risk_score` SMALLINT UNSIGNED NULL,
    `scoring_version` VARCHAR(32) NULL,
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `email_scans_message_id_scan_kind_attempt_received_at_key`(`message_id`, `scan_kind`, `attempt`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `scan_engine_results` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `engine` VARCHAR(32) NOT NULL,
    `engine_version` VARCHAR(64) NULL,
    `outcome` ENUM('clean', 'suspicious', 'malicious', 'error', 'timeout', 'skipped') NOT NULL,
    `score` DECIMAL(8, 3) NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `evidence` JSON NULL,
    `completed_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `scan_engine_results_scan_id_engine_received_at_key`(`scan_id`, `engine`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `threat_indicators` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NULL,
    `indicator_type` ENUM('ip', 'domain', 'url', 'email', 'file_sha256') NOT NULL,
    `value` VARCHAR(2048) NOT NULL,
    `value_sha256` CHAR(64) NOT NULL,
    `source` VARCHAR(64) NOT NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `confidence` TINYINT UNSIGNED NOT NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `expires_at` DATETIME(3) NULL,
    `metadata` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `threat_indicators_indicator_type_value_sha256_idx`(`indicator_type`, `value_sha256`),
    INDEX `threat_indicators_organization_id_indicator_type_idx`(`organization_id`, `indicator_type`),
    UNIQUE INDEX `threat_indicators_source_indicator_type_value_sha256_key`(`source`, `indicator_type`, `value_sha256`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ip_reputation` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip_address` VARCHAR(45) NOT NULL,
    `score` SMALLINT NOT NULL,
    `categories` JSON NULL,
    `source` VARCHAR(64) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `expires_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ip_reputation_ip_address_key`(`ip_address`),
    INDEX `ip_reputation_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `domain_reputation` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `domain` VARCHAR(253) NOT NULL,
    `score` SMALLINT NOT NULL,
    `categories` JSON NULL,
    `registered_at` DATETIME(3) NULL,
    `source` VARCHAR(64) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `expires_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `domain_reputation_domain_key`(`domain`),
    INDEX `domain_reputation_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `url_reputation` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `url_sha256` CHAR(64) NOT NULL,
    `url` VARCHAR(2048) NOT NULL,
    `host` VARCHAR(253) NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown') NOT NULL DEFAULT 'unknown',
    `score` SMALLINT NOT NULL,
    `categories` JSON NULL,
    `source` VARCHAR(64) NOT NULL,
    `last_checked_at` DATETIME(3) NOT NULL,
    `expires_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `url_reputation_url_sha256_key`(`url_sha256`),
    INDEX `url_reputation_host_idx`(`host`),
    INDEX `url_reputation_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `malware_signatures` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `sha256` CHAR(64) NOT NULL,
    `md5` CHAR(32) NULL,
    `family` VARCHAR(128) NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `source` VARCHAR(64) NOT NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `malware_signatures_sha256_key`(`sha256`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `yara_rules` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NULL,
    `rule_key` VARCHAR(191) NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `content` MEDIUMTEXT NOT NULL,
    `content_sha256` CHAR(64) NOT NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `yara_rules_rule_key_key`(`rule_key`),
    INDEX `yara_rules_organization_id_enabled_idx`(`organization_id`, `enabled`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `email_policies` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `description` VARCHAR(512) NULL,
    `direction` ENUM('inbound', 'outbound', 'internal', 'any') NOT NULL,
    `priority` INTEGER NOT NULL,
    `status` ENUM('draft', 'active', 'disabled', 'archived') NOT NULL DEFAULT 'draft',
    `active_version_id` BIGINT UNSIGNED NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `deleted_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `email_policies_public_id_key`(`public_id`),
    INDEX `email_policies_organization_id_status_direction_priority_idx`(`organization_id`, `status`, `direction`, `priority`),
    UNIQUE INDEX `email_policies_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `policy_versions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `policy_id` BIGINT UNSIGNED NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL,
    `status` ENUM('draft', 'published', 'superseded', 'rolled_back') NOT NULL DEFAULT 'draft',
    `definition` JSON NOT NULL,
    `definition_sha256` CHAR(64) NOT NULL,
    `change_note` VARCHAR(512) NULL,
    `published_at` DATETIME(3) NULL,
    `published_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `policy_versions_organization_id_status_idx`(`organization_id`, `status`),
    UNIQUE INDEX `policy_versions_policy_id_version_key`(`policy_id`, `version`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `policy_conditions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `policy_version_id` BIGINT UNSIGNED NOT NULL,
    `seq` SMALLINT UNSIGNED NOT NULL,
    `group_seq` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `field` VARCHAR(64) NOT NULL,
    `operator` ENUM('eq', 'neq', 'in', 'not_in', 'contains', 'not_contains', 'matches', 'gt', 'gte', 'lt', 'lte', 'exists') NOT NULL,
    `value` JSON NOT NULL,
    `negate` BOOLEAN NOT NULL DEFAULT false,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `policy_conditions_policy_version_id_seq_key`(`policy_version_id`, `seq`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `policy_actions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `policy_version_id` BIGINT UNSIGNED NOT NULL,
    `seq` SMALLINT UNSIGNED NOT NULL,
    `action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'redirect', 'notify', 'add_header', 'bcc') NOT NULL,
    `params` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `policy_actions_policy_version_id_seq_key`(`policy_version_id`, `seq`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `policy_exceptions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `policy_id` BIGINT UNSIGNED NULL,
    `exception_type` ENUM('allow_sender', 'block_sender', 'allow_domain', 'block_domain', 'allow_ip', 'block_ip', 'skip_engine') NOT NULL,
    `match_value` VARCHAR(320) NOT NULL,
    `recipient_scope` VARCHAR(320) NULL,
    `reason` VARCHAR(512) NULL,
    `expires_at` DATETIME(3) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `policy_exceptions_organization_id_exception_type_match_value_idx`(`organization_id`, `exception_type`, `match_value`(100)),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `policy_execution_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `evaluation_seq` SMALLINT UNSIGNED NOT NULL,
    `decisive_policy_version_id` BIGINT UNSIGNED NULL,
    `action` ENUM('deliver', 'tag', 'quarantine', 'discard') NOT NULL,
    `matched_policy_version_ids` JSON NOT NULL,
    `trace` JSON NULL,
    `duration_us` INTEGER UNSIGNED NOT NULL,
    `evaluated_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `policy_execution_logs_message_id_evaluation_seq_received_at_key`(`message_id`, `evaluation_seq`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `delivery_routes` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NULL,
    `direction` ENUM('inbound', 'outbound') NOT NULL,
    `match_type` ENUM('default', 'domain', 'recipient') NOT NULL,
    `match_value` VARCHAR(320) NULL,
    `mail_server_id` BIGINT UNSIGNED NULL,
    `smart_host` VARCHAR(255) NULL,
    `port` SMALLINT UNSIGNED NULL,
    `tls_mode` ENUM('none', 'opportunistic', 'required', 'verify') NOT NULL DEFAULT 'opportunistic',
    `priority` INTEGER NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `delivery_routes_organization_id_direction_enabled_priority_idx`(`organization_id`, `direction`, `enabled`, `priority`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_deliveries` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `recipient_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `delivery_seq` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `route_id` BIGINT UNSIGNED NULL,
    `status` ENUM('pending', 'in_progress', 'delivered', 'deferred', 'bounced', 'failed', 'suppressed') NOT NULL DEFAULT 'pending',
    `attempt_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `last_attempt_at` DATETIME(3) NULL,
    `delivered_at` DATETIME(3) NULL,
    `remote_host` VARCHAR(255) NULL,
    `final_smtp_code` SMALLINT UNSIGNED NULL,
    `final_smtp_response` VARCHAR(512) NULL,
    `outbound_queue_id` VARCHAR(32) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `email_deliveries_message_id_received_at_idx`(`message_id`, `received_at`),
    INDEX `email_deliveries_status_last_attempt_at_idx`(`status`, `last_attempt_at`),
    UNIQUE INDEX `email_deliveries_recipient_id_delivery_seq_received_at_key`(`recipient_id`, `delivery_seq`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `delivery_attempts` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `delivery_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `attempt_no` SMALLINT UNSIGNED NOT NULL,
    `started_at` DATETIME(3) NOT NULL,
    `completed_at` DATETIME(3) NULL,
    `remote_host` VARCHAR(255) NULL,
    `remote_ip` VARCHAR(45) NULL,
    `smtp_code` SMALLINT UNSIGNED NULL,
    `enhanced_status` VARCHAR(16) NULL,
    `smtp_response` VARCHAR(512) NULL,
    `outcome` ENUM('success', 'deferred', 'bounced', 'error') NOT NULL,
    `tls_protocol` VARCHAR(16) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `delivery_attempts_delivery_id_attempt_no_received_at_key`(`delivery_id`, `attempt_no`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `delivery_suppressions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `address` VARCHAR(320) NOT NULL,
    `reason` ENUM('hard_bounce', 'complaint', 'manual', 'unsubscribe') NOT NULL,
    `source` VARCHAR(64) NULL,
    `expires_at` DATETIME(3) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `delivery_suppressions_expires_at_idx`(`expires_at`),
    UNIQUE INDEX `delivery_suppressions_organization_id_address_key`(`organization_id`, `address`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(occurred_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes occurred_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `bounce_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `occurred_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NULL,
    `message_received_at` DATETIME(3) NULL,
    `recipient_address` VARCHAR(320) NOT NULL,
    `bounce_type` ENUM('hard', 'soft', 'complaint', 'unknown') NOT NULL,
    `smtp_code` SMALLINT UNSIGNED NULL,
    `enhanced_status` VARCHAR(16) NULL,
    `diagnostic` VARCHAR(1024) NULL,
    `reporting_mta` VARCHAR(255) NULL,
    `dsn_object_key` VARCHAR(512) NULL,
    `dedupe_key` CHAR(64) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `bounce_events_organization_id_recipient_address_occurred_at_idx`(`organization_id`, `recipient_address`(100), `occurred_at`),
    UNIQUE INDEX `bounce_events_organization_id_dedupe_key_occurred_at_key`(`organization_id`, `dedupe_key`, `occurred_at`),
    PRIMARY KEY (`id`, `occurred_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`occurred_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `quarantine_messages` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `recipient_id` BIGINT UNSIGNED NOT NULL,
    `recipient_address` VARCHAR(320) NOT NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `reason` ENUM('spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp', 'policy', 'suspicious', 'engine_unavailable') NOT NULL,
    `policy_version_id` BIGINT UNSIGNED NULL,
    `status` ENUM('quarantined', 'release_requested', 'released', 'deleted', 'expired') NOT NULL DEFAULT 'quarantined',
    `envelope_from` VARCHAR(320) NOT NULL,
    `subject` VARCHAR(998) NULL,
    `risk_score` SMALLINT UNSIGNED NULL,
    `eml_object_key` VARCHAR(512) NOT NULL,
    `quarantined_at` DATETIME(3) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `released_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `quarantine_messages_public_id_key`(`public_id`),
    INDEX `quarantine_messages_organization_id_status_quarantined_at_idx`(`organization_id`, `status`, `quarantined_at`),
    INDEX `quarantine_messages_organization_id_recipient_address_status_idx`(`organization_id`, `recipient_address`(100), `status`),
    INDEX `quarantine_messages_status_expires_at_idx`(`status`, `expires_at`),
    UNIQUE INDEX `quarantine_messages_message_id_recipient_id_key`(`message_id`, `recipient_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `quarantine_actions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `quarantine_message_id` BIGINT UNSIGNED NOT NULL,
    `action` ENUM('release', 'delete', 'request_release', 'approve_release', 'deny_release', 'report_false_positive', 'expire', 'preview') NOT NULL,
    `actor_type` ENUM('system', 'user', 'api_key') NOT NULL,
    `actor_user_id` BIGINT UNSIGNED NULL,
    `reason` VARCHAR(512) NULL,
    `idempotency_key` VARCHAR(64) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `quarantine_actions_quarantine_message_id_created_at_idx`(`quarantine_message_id`, `created_at`),
    UNIQUE INDEX `quarantine_actions_organization_id_idempotency_key_key`(`organization_id`, `idempotency_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `quarantine_release_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `quarantine_message_id` BIGINT UNSIGNED NOT NULL,
    `action_id` BIGINT UNSIGNED NOT NULL,
    `released_to` VARCHAR(320) NOT NULL,
    `revalidation_scan_id` BIGINT UNSIGNED NULL,
    `revalidation_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    `delivery_id` BIGINT UNSIGNED NULL,
    `status` ENUM('pending', 'delivered', 'failed', 'blocked_by_revalidation') NOT NULL DEFAULT 'pending',
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `quarantine_release_logs_action_id_key`(`action_id`),
    INDEX `quarantine_release_logs_organization_id_created_at_idx`(`organization_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `archive_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `scope` ENUM('all', 'inbound', 'outbound', 'internal') NOT NULL DEFAULT 'all',
    `default_retention_policy_id` BIGINT UNSIGNED NULL,
    `object_lock_mode` ENUM('none', 'governance', 'compliance') NOT NULL DEFAULT 'none',
    `encryption_key_ref` VARCHAR(512) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `archive_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `archive_retention_policies` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `retention_days` INTEGER UNSIGNED NOT NULL,
    `criteria` JSON NULL,
    `priority` INTEGER NOT NULL,
    `is_default` BOOLEAN NOT NULL DEFAULT false,
    `on_expiry` ENUM('delete', 'review') NOT NULL DEFAULT 'delete',
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `archive_retention_policies_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `email_archives` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `archive_object_key` VARCHAR(512) NOT NULL,
    `sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `retention_policy_id` BIGINT UNSIGNED NULL,
    `retain_until` DATETIME(3) NOT NULL,
    `legal_hold` BOOLEAN NOT NULL DEFAULT false,
    `archived_at` DATETIME(3) NOT NULL,
    `deleted_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `email_archives_organization_id_received_at_idx`(`organization_id`, `received_at`),
    INDEX `email_archives_organization_id_retain_until_idx`(`organization_id`, `retain_until`),
    UNIQUE INDEX `email_archives_message_id_received_at_key`(`message_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `archive_legal_holds` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `reason` VARCHAR(1024) NOT NULL,
    `criteria` JSON NOT NULL,
    `status` ENUM('active', 'released') NOT NULL DEFAULT 'active',
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `released_at` DATETIME(3) NULL,
    `released_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `archive_legal_holds_organization_id_status_idx`(`organization_id`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (daily) by RANGE COLUMNS(created_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes created_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `message_outbox` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `event_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `aggregate_type` VARCHAR(64) NOT NULL,
    `aggregate_id` VARCHAR(64) NOT NULL,
    `correlation_id` VARCHAR(128) NOT NULL,
    `payload` JSON NOT NULL,
    `available_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `published_at` DATETIME(3) NULL,
    `attempts` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `last_error` VARCHAR(1024) NULL,

    INDEX `message_outbox_published_at_id_idx`(`published_at`, `id`),
    PRIMARY KEY (`id`, `created_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`created_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `message_idempotency` (
    `consumer` VARCHAR(100) NOT NULL,
    `event_id` CHAR(36) NOT NULL,
    `processed_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `message_idempotency_processed_at_idx`(`processed_at`),
    PRIMARY KEY (`consumer`, `event_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(created_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes created_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `audit_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `organization_id` BIGINT UNSIGNED NULL,
    `actor_type` ENUM('user', 'system', 'api_key') NOT NULL,
    `actor_id` VARCHAR(64) NULL,
    `action` VARCHAR(100) NOT NULL,
    `resource_type` VARCHAR(64) NOT NULL,
    `resource_id` VARCHAR(64) NULL,
    `correlation_id` VARCHAR(128) NULL,
    `source_ip` VARCHAR(45) NULL,
    `metadata` JSON NULL,

    INDEX `audit_logs_organization_id_created_at_idx`(`organization_id`, `created_at`),
    INDEX `audit_logs_resource_type_resource_id_idx`(`resource_type`, `resource_id`),
    PRIMARY KEY (`id`, `created_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`created_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `webhook_subscriptions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `url` VARCHAR(2048) NOT NULL,
    `event_types` JSON NOT NULL,
    `secret_ciphertext` VARCHAR(512) NOT NULL,
    `status` ENUM('active', 'paused', 'disabled') NOT NULL DEFAULT 'active',
    `consecutive_failures` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `last_success_at` DATETIME(3) NULL,
    `last_failure_at` DATETIME(3) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `webhook_subscriptions_public_id_key`(`public_id`),
    INDEX `webhook_subscriptions_organization_id_status_idx`(`organization_id`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Partitioned (monthly) by RANGE COLUMNS(event_occurred_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes event_occurred_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones.
-- CreateTable
CREATE TABLE `webhook_deliveries` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `event_occurred_at` DATETIME(3) NOT NULL,
    `subscription_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `event_id` CHAR(36) NOT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `status` ENUM('pending', 'succeeded', 'failed', 'dead') NOT NULL DEFAULT 'pending',
    `attempt_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `next_attempt_at` DATETIME(3) NULL,
    `last_response_code` SMALLINT UNSIGNED NULL,
    `last_error` VARCHAR(1024) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `webhook_deliveries_status_next_attempt_at_idx`(`status`, `next_attempt_at`),
    UNIQUE INDEX `webhook_deliveries_subscription_id_event_id_event_occurred_a_key`(`subscription_id`, `event_id`, `event_occurred_at`),
    PRIMARY KEY (`id`, `event_occurred_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`event_occurred_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable
CREATE TABLE `system_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `key` VARCHAR(128) NOT NULL,
    `value` JSON NOT NULL,
    `description` VARCHAR(512) NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `system_settings_key_key`(`key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `organizations` ADD CONSTRAINT `organizations_plan_id_fkey` FOREIGN KEY (`plan_id`) REFERENCES `organization_plans`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `organization_settings` ADD CONSTRAINT `organization_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `organization_limits` ADD CONSTRAINT `organization_limits_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `organization_features` ADD CONSTRAINT `organization_features_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `organization_deployments` ADD CONSTRAINT `organization_deployments_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `users` ADD CONSTRAINT `users_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `roles` ADD CONSTRAINT `roles_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `role_permissions` ADD CONSTRAINT `role_permissions_role_id_fkey` FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `role_permissions` ADD CONSTRAINT `role_permissions_permission_id_fkey` FOREIGN KEY (`permission_id`) REFERENCES `permissions`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_roles` ADD CONSTRAINT `user_roles_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_roles` ADD CONSTRAINT `user_roles_role_id_fkey` FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_roles` ADD CONSTRAINT `user_roles_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_roles` ADD CONSTRAINT `user_roles_granted_by_user_id_fkey` FOREIGN KEY (`granted_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_sessions` ADD CONSTRAINT `user_sessions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_sessions` ADD CONSTRAINT `user_sessions_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `api_keys` ADD CONSTRAINT `api_keys_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `api_keys` ADD CONSTRAINT `api_keys_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `login_audit_logs` ADD CONSTRAINT `login_audit_logs_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domains` ADD CONSTRAINT `domains_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_verifications` ADD CONSTRAINT `domain_verifications_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_verifications` ADD CONSTRAINT `domain_verifications_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_dns_records` ADD CONSTRAINT `domain_dns_records_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_dns_records` ADD CONSTRAINT `domain_dns_records_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_dkim_keys` ADD CONSTRAINT `domain_dkim_keys_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_dkim_keys` ADD CONSTRAINT `domain_dkim_keys_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_mx_records` ADD CONSTRAINT `domain_mx_records_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_mx_records` ADD CONSTRAINT `domain_mx_records_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_mail_servers` ADD CONSTRAINT `domain_mail_servers_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_mail_servers` ADD CONSTRAINT `domain_mail_servers_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_settings` ADD CONSTRAINT `domain_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_settings` ADD CONSTRAINT `domain_settings_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `message_identities` ADD CONSTRAINT `message_identities_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `threat_indicators` ADD CONSTRAINT `threat_indicators_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `yara_rules` ADD CONSTRAINT `yara_rules_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `yara_rules` ADD CONSTRAINT `yara_rules_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `email_policies` ADD CONSTRAINT `email_policies_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `email_policies` ADD CONSTRAINT `email_policies_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_versions` ADD CONSTRAINT `policy_versions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_versions` ADD CONSTRAINT `policy_versions_policy_id_fkey` FOREIGN KEY (`policy_id`) REFERENCES `email_policies`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_versions` ADD CONSTRAINT `policy_versions_published_by_user_id_fkey` FOREIGN KEY (`published_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_conditions` ADD CONSTRAINT `policy_conditions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_conditions` ADD CONSTRAINT `policy_conditions_policy_version_id_fkey` FOREIGN KEY (`policy_version_id`) REFERENCES `policy_versions`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_actions` ADD CONSTRAINT `policy_actions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_actions` ADD CONSTRAINT `policy_actions_policy_version_id_fkey` FOREIGN KEY (`policy_version_id`) REFERENCES `policy_versions`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_exceptions` ADD CONSTRAINT `policy_exceptions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_exceptions` ADD CONSTRAINT `policy_exceptions_policy_id_fkey` FOREIGN KEY (`policy_id`) REFERENCES `email_policies`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `policy_exceptions` ADD CONSTRAINT `policy_exceptions_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `delivery_routes` ADD CONSTRAINT `delivery_routes_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `delivery_routes` ADD CONSTRAINT `delivery_routes_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `delivery_routes` ADD CONSTRAINT `delivery_routes_mail_server_id_fkey` FOREIGN KEY (`mail_server_id`) REFERENCES `domain_mail_servers`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `delivery_suppressions` ADD CONSTRAINT `delivery_suppressions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `delivery_suppressions` ADD CONSTRAINT `delivery_suppressions_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_messages` ADD CONSTRAINT `quarantine_messages_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_messages` ADD CONSTRAINT `quarantine_messages_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_actions` ADD CONSTRAINT `quarantine_actions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_actions` ADD CONSTRAINT `quarantine_actions_quarantine_message_id_fkey` FOREIGN KEY (`quarantine_message_id`) REFERENCES `quarantine_messages`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_actions` ADD CONSTRAINT `quarantine_actions_actor_user_id_fkey` FOREIGN KEY (`actor_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_release_logs` ADD CONSTRAINT `quarantine_release_logs_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_release_logs` ADD CONSTRAINT `quarantine_release_logs_quarantine_message_id_fkey` FOREIGN KEY (`quarantine_message_id`) REFERENCES `quarantine_messages`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `quarantine_release_logs` ADD CONSTRAINT `quarantine_release_logs_action_id_fkey` FOREIGN KEY (`action_id`) REFERENCES `quarantine_actions`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `archive_settings` ADD CONSTRAINT `archive_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `archive_settings` ADD CONSTRAINT `archive_settings_default_retention_policy_id_fkey` FOREIGN KEY (`default_retention_policy_id`) REFERENCES `archive_retention_policies`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `archive_retention_policies` ADD CONSTRAINT `archive_retention_policies_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `archive_legal_holds` ADD CONSTRAINT `archive_legal_holds_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `archive_legal_holds` ADD CONSTRAINT `archive_legal_holds_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `archive_legal_holds` ADD CONSTRAINT `archive_legal_holds_released_by_user_id_fkey` FOREIGN KEY (`released_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `webhook_subscriptions` ADD CONSTRAINT `webhook_subscriptions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `webhook_subscriptions` ADD CONSTRAINT `webhook_subscriptions_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `system_settings` ADD CONSTRAINT `system_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

