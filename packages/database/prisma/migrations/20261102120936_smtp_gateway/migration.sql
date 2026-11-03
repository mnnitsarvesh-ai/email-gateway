-- Step 2.2: Postfix SMTP gateway (docs/plan/steps/04-smtp-gateway.md §3, D3, D10, D11;
-- ADR-0019).
--
-- What changes (additive only; no existing table is altered):
--   * domain_recipient_addresses: per-domain recipient allow-list (D3). UNIQUE (domain_id,
--     local_part) is the lookup key of the inbound policy; index (organization_id) for tenant
--     scans and the organization FK.
--   * smtp_connectors: organization-level outbound connectors (D10), one auth method each
--     (sasl | source_ip | client_certificate). sasl_username and cert_fingerprint_sha256 are
--     globally unique (NULLs never collide in MySQL unique keys).
--   * smtp_connector_networks: connector client networks as canonical CIDR text plus 4- or
--     16-byte big-endian range_start/range_end. Index (ip_version, range_start) serves the
--     "greatest range_start <= ip" lookup (D11); ranges never overlap (api-enforced), so one
--     row answers it.
--
-- Comment-only changes in schema.prisma (no DDL): domain_mail_servers.role (outbound_source
-- deprecated), message_identities.ingest_key (D7 format), email_messages.eml_object_key (D8).
--
-- Foreign keys follow the existing conventions: organization RESTRICT, parent row CASCADE,
-- created_by user SET NULL. FKs without an explicit index (created_by_user_id,
-- smtp_connector_networks.organization_id) get MySQL's implicit FK index, as in step 1.1.
-- New empty tables: no locking or backfill concerns.

-- CreateTable
CREATE TABLE `domain_recipient_addresses` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `local_part` VARCHAR(64) NOT NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `domain_recipient_addresses_organization_id_idx`(`organization_id`),
    UNIQUE INDEX `domain_recipient_addresses_domain_id_local_part_key`(`domain_id`, `local_part`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `smtp_connectors` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `auth_type` ENUM('sasl', 'source_ip', 'client_certificate') NOT NULL,
    `status` ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    `sasl_username` VARCHAR(64) NULL,
    `secret_hash` VARCHAR(255) NULL,
    `secret_set_at` DATETIME(3) NULL,
    `cert_fingerprint_sha256` CHAR(64) NULL,
    `require_tls` BOOLEAN NOT NULL DEFAULT true,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `smtp_connectors_public_id_key`(`public_id`),
    UNIQUE INDEX `smtp_connectors_sasl_username_key`(`sasl_username`),
    UNIQUE INDEX `smtp_connectors_cert_fingerprint_sha256_key`(`cert_fingerprint_sha256`),
    INDEX `smtp_connectors_organization_id_status_idx`(`organization_id`, `status`),
    UNIQUE INDEX `smtp_connectors_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `smtp_connector_networks` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `connector_id` BIGINT UNSIGNED NOT NULL,
    `cidr` VARCHAR(49) NOT NULL,
    `ip_version` TINYINT UNSIGNED NOT NULL,
    `range_start` VARBINARY(16) NOT NULL,
    `range_end` VARBINARY(16) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `smtp_connector_networks_ip_version_range_start_idx`(`ip_version`, `range_start`),
    UNIQUE INDEX `smtp_connector_networks_connector_id_cidr_key`(`connector_id`, `cidr`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `domain_recipient_addresses` ADD CONSTRAINT `domain_recipient_addresses_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_recipient_addresses` ADD CONSTRAINT `domain_recipient_addresses_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `domain_recipient_addresses` ADD CONSTRAINT `domain_recipient_addresses_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `smtp_connectors` ADD CONSTRAINT `smtp_connectors_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `smtp_connectors` ADD CONSTRAINT `smtp_connectors_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `smtp_connector_networks` ADD CONSTRAINT `smtp_connector_networks_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `smtp_connector_networks` ADD CONSTRAINT `smtp_connector_networks_connector_id_fkey` FOREIGN KEY (`connector_id`) REFERENCES `smtp_connectors`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
