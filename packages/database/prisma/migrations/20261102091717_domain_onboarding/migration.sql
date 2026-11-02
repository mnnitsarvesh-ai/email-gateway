-- Step 2.1: domain onboarding (docs/plan/steps/03-domain-onboarding.md §3, D3, D6, D9-D11;
-- ADR-0014, ADR-0017, ADR-0018).
--
-- What changes:
--   * DomainStatus gains `active`, `suspended`, `deleted` (appended; `disabled` is deprecated and
--     never written). Domains are soft-deleted from now on.
--   * New enum DnsCheckOutcome (valid, invalid, missing, indeterminate) on the last check of a
--     verification row and of a DNS record row.
--   * domains: lifecycle columns (status_reason, status_changed_at, activated_at, deleted_at),
--     scheduling columns (next_check_at + index, last_checked_at, check_failures).
--   * domains.verified_name is redefined to cover every post-verification state
--     (verified/active/suspended): verified ownership stays globally unique, a deleted domain
--     frees the name.
--   * domains.live_name (new generated column) = name unless deleted. UNIQUE (organization_id,
--     live_name) replaces UNIQUE (organization_id, name): an organization can re-add a domain it
--     deleted (a new row; the deleted row stays as history).
--   * domain_dns_records: record_key (stable key per published record, UNIQUE per domain), the
--     DKIM key it publishes, last outcome/error/evidence, status_changed_at.
--   * domain_dkim_keys: private_key_ciphertext (SecretBox-encrypted PEM, ADR-0018),
--     private_key_ref becomes nullable, retire_after + index (status, retire_after).
--
-- verified_name and live_name are MySQL generated columns. Prisma has no syntax for them, so
-- schema.prisma declares both as plain nullable READ-ONLY columns; their GENERATED clauses live
-- only in migration SQL (here and in 20261102000000_tenant_scoped_uniques). The drift check
-- compares type and nullability only and stays clean.
--
-- Locking: changing a STORED generated column's expression and adding a STORED generated column
-- rebuild the `domains` table (ALGORITHM=COPY). Both are done in one ALTER so the table is
-- rebuilt once. `domains` is small (hundreds to thousands of rows); no partitioned table is
-- touched. Statement order keeps a unique key on (organization_id, ...) and an index leading
-- with organization_id (for its foreign key) at every point.

-- 1. Extend the status enum first (appended values only: an in-place metadata change). MySQL
--    accepts MODIFY of a base column of a generated column as long as the column stays.
ALTER TABLE `domains`
    MODIFY `status` ENUM('pending_verification', 'verified', 'failed', 'disabled', 'active', 'suspended', 'deleted') NOT NULL DEFAULT 'pending_verification';

-- 2. Lifecycle and scheduling columns.
ALTER TABLE `domains`
    ADD COLUMN `status_reason` VARCHAR(512) NULL,
    ADD COLUMN `status_changed_at` DATETIME(3) NULL,
    ADD COLUMN `activated_at` DATETIME(3) NULL,
    ADD COLUMN `deleted_at` DATETIME(3) NULL,
    ADD COLUMN `next_check_at` DATETIME(3) NULL,
    ADD COLUMN `last_checked_at` DATETIME(3) NULL,
    ADD COLUMN `check_failures` INTEGER UNSIGNED NOT NULL DEFAULT 0;

-- 3. Generated columns (one table rebuild). The unique key domains_verified_name_key stays.
ALTER TABLE `domains`
    MODIFY `verified_name` VARCHAR(253)
        GENERATED ALWAYS AS (IF(`status` IN ('verified', 'active', 'suspended'), `name`, NULL)) STORED NULL,
    ADD COLUMN `live_name` VARCHAR(253)
        GENERATED ALWAYS AS (IF(`status` = 'deleted', NULL, `name`)) STORED NULL;

-- 4. The new per-organization unique key exists before the old one is dropped
--    (domains_organization_id_status_idx also keeps an index for the organization_id FK).
CREATE UNIQUE INDEX `domains_organization_id_live_name_key` ON `domains`(`organization_id`, `live_name`);

DROP INDEX `domains_organization_id_name_key` ON `domains`;

-- 5. Due-check scan of the background job (D11): WHERE next_check_at <= now ORDER BY next_check_at.
CREATE INDEX `domains_next_check_at_idx` ON `domains`(`next_check_at`);

-- 6. domain_verifications: outcome and evidence of the last check.
ALTER TABLE `domain_verifications`
    ADD COLUMN `last_outcome` ENUM('valid', 'invalid', 'missing', 'indeterminate') NULL,
    ADD COLUMN `evidence` JSON NULL;

-- 7. domain_dkim_keys: encrypted private key (ADR-0018), optional external reference, rotation.
ALTER TABLE `domain_dkim_keys`
    ADD COLUMN `private_key_ciphertext` TEXT NULL,
    MODIFY `private_key_ref` VARCHAR(512) NULL,
    ADD COLUMN `retire_after` DATETIME(3) NULL;

-- Retirement scan (D11): WHERE status = 'rotating' AND retire_after <= now.
CREATE INDEX `domain_dkim_keys_status_retire_after_idx` ON `domain_dkim_keys`(`status`, `retire_after`);

-- 8. domain_dns_records: record_key is added nullable, backfilled for any existing row (none are
--    written before this step; the backfill keeps the migration safe anyway), then made NOT NULL.
ALTER TABLE `domain_dns_records`
    ADD COLUMN `record_key` VARCHAR(191) NULL,
    ADD COLUMN `dkim_key_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `last_outcome` ENUM('valid', 'invalid', 'missing', 'indeterminate') NULL,
    ADD COLUMN `last_error` VARCHAR(512) NULL,
    ADD COLUMN `evidence` JSON NULL,
    ADD COLUMN `status_changed_at` DATETIME(3) NULL;

UPDATE `domain_dns_records` SET `record_key` = CONCAT(`purpose`, ':', `id`) WHERE `record_key` IS NULL;

ALTER TABLE `domain_dns_records` MODIFY `record_key` VARCHAR(191) NOT NULL;

CREATE UNIQUE INDEX `domain_dns_records_domain_id_record_key_key` ON `domain_dns_records`(`domain_id`, `record_key`);

-- MySQL creates the index for this foreign key (dkim_key_id) automatically.
ALTER TABLE `domain_dns_records` ADD CONSTRAINT `domain_dns_records_dkim_key_id_fkey` FOREIGN KEY (`dkim_key_id`) REFERENCES `domain_dkim_keys`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
