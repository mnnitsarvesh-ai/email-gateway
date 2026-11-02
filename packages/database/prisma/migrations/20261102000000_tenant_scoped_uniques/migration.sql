-- Step 1.1 review fixes (docs/plan/steps/01-database.md, ADR-0014).
--
-- verified_name and org_scope are MySQL generated columns. Prisma has no syntax for generated
-- columns, so schema.prisma declares them as plain nullable columns marked READ-ONLY; the
-- drift check (`prisma migrate diff --from-url ... --to-schema-datamodel`) compares type and
-- nullability only and stays clean. Application code must never write them.

-- domains: a pending claim must not block the real owner (domain squatting). The name is unique
-- per organization; only verified ownership is globally unique, via verified_name.
ALTER TABLE `domains`
    ADD COLUMN `verified_name` VARCHAR(253)
        GENERATED ALWAYS AS (IF(`status` = 'verified', `name`, NULL)) STORED NULL;

CREATE UNIQUE INDEX `domains_organization_id_name_key` ON `domains`(`organization_id`, `name`);

CREATE UNIQUE INDEX `domains_verified_name_key` ON `domains`(`verified_name`);

CREATE INDEX `domains_name_idx` ON `domains`(`name`);

DROP INDEX `domains_name_key` ON `domains`;

-- threat_indicators: the unique key includes the tenant scope, so two organizations can hold the
-- same indicator from the same source without a cross-tenant collision (or a cross-tenant upsert).
-- org_scope = IFNULL(organization_id, 0) also dedupes platform rows, which a nullable
-- organization_id in the key would not (NULLs are distinct). VIRTUAL, because MySQL forbids a
-- STORED generated column whose base column has an ON UPDATE CASCADE foreign key.
ALTER TABLE `threat_indicators`
    ADD COLUMN `org_scope` BIGINT UNSIGNED
        GENERATED ALWAYS AS (IFNULL(`organization_id`, 0)) VIRTUAL NULL;

CREATE UNIQUE INDEX `threat_indicators_org_scope_source_indicator_type_value_sha2_key` ON `threat_indicators`(`org_scope`, `source`, `indicator_type`, `value_sha256`);

DROP INDEX `threat_indicators_source_indicator_type_value_sha256_key` ON `threat_indicators`;

-- maintenance_watermarks: progress of the message_identities retention purge (D3.4), so rows
-- kept for archives or quarantine are scanned once rather than on every run.
CREATE TABLE `maintenance_watermarks` (
    `name` VARCHAR(64) NOT NULL,
    `value` BIGINT UNSIGNED NOT NULL,
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`name`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
