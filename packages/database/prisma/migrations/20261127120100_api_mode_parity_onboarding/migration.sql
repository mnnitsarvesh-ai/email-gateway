-- Step API-4: API-mode parity and onboarding (policy evaluation on API-mode copies, alerts and
-- webhooks, protection by mode, API-mode add-domain wizard)
-- (docs/plan/steps/38-api-mode-parity-onboarding.md §3, A1–A12, B1–B10; ADR-0105, ADR-0106,
-- ADR-0107). Migration 47.
--
-- What changes (one new table, not partitioned: 197 tables, 42 partitioned):
--   * policy_execution_logs (PARTITIONED): `evaluation_mode` ENUM('inline','detect') NOT NULL
--     DEFAULT 'inline' — `detect` rows are the mailbox-worker's evaluations of API-mode copies
--     (recorded, never delivered, held or bounced; A1, P-I1). No new index.
--   * api_message_copies (PARTITIONED): ApiCopyDirection + `outbound` (appended; outbound
--     detection copies on the sender's mailbox, A6), the policy columns `policy_state`,
--     `policy_disposition`, `policy_tagged`, `dlp_action` (A3). No new index.
--   * api_mailboxes: the mailbox scope `scope_state`, `scope_selected`, `scope_evaluated_at` and
--     the index (domain_id, scope_state) (B6).
--   * api_mode_org_settings: `policy_evaluation_enabled`, `outbound_detection_enabled`, both
--     NOT NULL DEFAULT 1 (A1, A6; API4-1, API4-5).
--   * api_remediation_policies: the detect-only start period `detect_only_until`,
--     `detect_only_then`, `detect_only_started_at`, `detect_only_notified_at` and the index
--     (detect_only_until) for the expiry sweep (B7).
--   * api_mode_counters: four hourly counters `policy_evaluations`, `policy_errors`,
--     `outbound_detections`, `copy_detections` (A3, A6, A8, A11).
--   * domains: `ownership_method` ENUM('dns_txt','provider_tenant') NULL (B3, ADR-0107) and the
--     backfill of section 11.
--   * domain_verifications: DomainVerificationMethod + `provider_tenant` (appended), the provider
--     check columns `provider_connection_id` (no FK; purge order §3.3), `provider_result`,
--     `provider_checked_at`, `provider_error_code` and the index (method, status,
--     provider_checked_at) (B3). `token` stays NOT NULL: provider rows store the fixed marker
--     `provider-tenant`, never a secret.
--   * New table api_mode_domain_settings (§3.2; FK organizations RESTRICT, UNIQUE domain_id with
--     FK domains CASCADE): per-domain mailbox scope and first-copy tracking (B6, B8).
--   * No permission, feature or plan change; no partition registry change.
--
-- Backfill (section 11, §3.1): every existing ownership was won through the DNS TXT record (the
-- only method before API-4), so verified / active / suspended domains get `dns_txt`. Pending,
-- failed, disabled and deleted domains keep NULL (never verified, or ownership released).
-- Every other existing row gets the column defaults: `evaluation_mode = inline`,
-- `policy_state = none`, `scope_state = in_scope`, both organization settings on, no
-- detect-only period, counters 0.
--
-- No message content (P-I7): enums, booleans, codes, counts, timings, ids and department public
-- ids only.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-8. ADD COLUMN (appended at the end, nullable or with a constant default) and the appended
--      ENUM values: ALGORITHM=INSTANT (metadata only; an ENUM with < 256 members keeps its 1-byte
--      storage, so appending at the end needs no row change). This includes the partitioned
--      policy_execution_logs and api_message_copies (INSTANT applies to every partition) and the
--      tables with STORED generated columns (domains, api_remediation_policies; the new columns
--      are not referenced by the generation expressions). MySQL refuses rather than copies if
--      INSTANT were impossible (for example after 64 row versions of a table; the fallback then
--      is ALGORITHM=INPLACE, LOCK=NONE, which rebuilds the table online).
--   9. The new table is created empty.
--   10. Secondary indexes on existing tables: ALGORITHM=INPLACE, LOCK=NONE (online index build;
--      reads and writes continue). Each algorithm is stated explicitly, so an unexpected rebuild
--      fails instead of copying silently.
--   11. Backfill: one UPDATE of domains through the (organization_id, status) index; a handful of
--      rows per organization (row locks only).
--   12. Foreign keys are added to the empty new table (the parent tables organizations and
--      domains only take a short metadata lock).
-- DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration; section 11 is idempotent.
--
-- Rollback (never automatic; after rolling the api, mailbox-worker, integration-worker,
-- webhook-worker, notification-worker, policy-engine and the portal back to API-3, and after
-- deleting the `provider_tenant` verification rows and the `outbound` copy rows):
--   DROP TABLE api_mode_domain_settings;
--   DROP INDEX domain_verifications_method_status_provider_checked_at_idx ON domain_verifications;
--   DROP INDEX api_remediation_policies_detect_only_until_idx ON api_remediation_policies;
--   DROP INDEX api_mailboxes_domain_id_scope_state_idx ON api_mailboxes;
--   ALTER TABLE domain_verifications DROP COLUMN provider_connection_id, DROP COLUMN provider_result,
--       DROP COLUMN provider_checked_at, DROP COLUMN provider_error_code, ALGORITHM=INSTANT;
--   ALTER TABLE domains DROP COLUMN ownership_method, ALGORITHM=INSTANT;
--   ALTER TABLE api_mode_counters DROP COLUMN policy_evaluations, DROP COLUMN policy_errors,
--       DROP COLUMN outbound_detections, DROP COLUMN copy_detections, ALGORITHM=INSTANT;
--   ALTER TABLE api_remediation_policies DROP COLUMN detect_only_until, DROP COLUMN detect_only_then,
--       DROP COLUMN detect_only_started_at, DROP COLUMN detect_only_notified_at, ALGORITHM=INSTANT;
--   ALTER TABLE api_mode_org_settings DROP COLUMN policy_evaluation_enabled,
--       DROP COLUMN outbound_detection_enabled, ALGORITHM=INSTANT;
--   ALTER TABLE api_mailboxes DROP COLUMN scope_state, DROP COLUMN scope_selected,
--       DROP COLUMN scope_evaluated_at, ALGORITHM=INSTANT;
--   ALTER TABLE api_message_copies DROP COLUMN policy_state, DROP COLUMN policy_disposition,
--       DROP COLUMN policy_tagged, DROP COLUMN dlp_action, ALGORITHM=INSTANT;
--   ALTER TABLE policy_execution_logs DROP COLUMN evaluation_mode, ALGORITHM=INSTANT;
--     (detect rows must be deleted first, or an older reader would treat them as inline rows)
--   The appended enum values (`outbound`, `provider_tenant`) stay (append-only rule; an older
--   release never writes them). To remove them anyway, first delete every row that uses them,
--   then MODIFY the column back to its API-3 value list. Delete the migration's
--   `_prisma_migrations` row.

-- 1. policy_execution_logs (PARTITIONED): inline gating evaluation or detect evaluation of a copy
--    (A1, ADR-0105). Existing rows are inline.
ALTER TABLE `policy_execution_logs` ADD COLUMN `evaluation_mode` ENUM('inline', 'detect') NOT NULL DEFAULT 'inline',
    ALGORITHM=INSTANT;

-- 2. api_message_copies (PARTITIONED): ApiCopyDirection + `outbound` (appended; A6), the tenant
--    policy state and outcome of the copy (A1, A3). Existing copies: `policy_state = none`.
ALTER TABLE `api_message_copies` ADD COLUMN `dlp_action` ENUM('allow', 'alert', 'require_approval', 'quarantine', 'block') NULL,
    ADD COLUMN `policy_disposition` ENUM('allow', 'require_approval', 'quarantine', 'reject') NULL,
    ADD COLUMN `policy_state` ENUM('none', 'evaluated', 'inline', 'disabled', 'failed', 'not_applicable') NOT NULL DEFAULT 'none',
    ADD COLUMN `policy_tagged` BOOLEAN NOT NULL DEFAULT false,
    MODIFY `direction` ENUM('inbound', 'internal', 'outbound') NOT NULL DEFAULT 'inbound',
    ALGORITHM=INSTANT;

-- 3. api_mailboxes: mailbox scope (B6). Every existing mailbox is in scope (the API-1..API-3
--    behaviour), not selected, never evaluated.
ALTER TABLE `api_mailboxes` ADD COLUMN `scope_evaluated_at` DATETIME(3) NULL,
    ADD COLUMN `scope_selected` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `scope_state` ENUM('in_scope', 'excluded') NOT NULL DEFAULT 'in_scope',
    ALGORITHM=INSTANT;

-- 4. api_mode_org_settings: policy evaluation of copies and outbound detection, both on by
--    default (API4-1, API4-5); equal to ORG_SETTINGS_DEFAULTS of @email-gateway/mailbox-api.
ALTER TABLE `api_mode_org_settings` ADD COLUMN `outbound_detection_enabled` BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN `policy_evaluation_enabled` BOOLEAN NOT NULL DEFAULT true,
    ALGORITHM=INSTANT;

-- 5. api_remediation_policies: the detect-only start period (B7). No existing policy has one.
ALTER TABLE `api_remediation_policies` ADD COLUMN `detect_only_notified_at` DATETIME(3) NULL,
    ADD COLUMN `detect_only_started_at` DATETIME(3) NULL,
    ADD COLUMN `detect_only_then` ENUM('remind', 'enforce') NULL,
    ADD COLUMN `detect_only_until` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

-- 6. api_mode_counters: hourly policy evaluation, error, outbound detection and copy detection
--    counters (A3, A6, A8, A11), added by the counter flush
--    (`INSERT … ON DUPLICATE KEY UPDATE x = x + VALUES(x)`).
ALTER TABLE `api_mode_counters` ADD COLUMN `copy_detections` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `outbound_detections` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `policy_errors` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `policy_evaluations` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ALGORITHM=INSTANT;

-- 7. domains: how ownership was won (B3, ADR-0107); backfilled in section 11.
ALTER TABLE `domains` ADD COLUMN `ownership_method` ENUM('dns_txt', 'provider_tenant') NULL,
    ALGORITHM=INSTANT;

-- 8. domain_verifications: DomainVerificationMethod + `provider_tenant` (appended) and the
--    provider check columns written by the integration-worker (B3).
ALTER TABLE `domain_verifications` ADD COLUMN `provider_checked_at` DATETIME(3) NULL,
    ADD COLUMN `provider_connection_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `provider_error_code` VARCHAR(64) NULL,
    ADD COLUMN `provider_result` ENUM('verified', 'unverified', 'absent', 'alias', 'error') NULL,
    MODIFY `method` ENUM('dns_txt', 'dns_cname', 'provider_tenant') NOT NULL DEFAULT 'dns_txt',
    ALGORITHM=INSTANT;

-- 9. api_mode_domain_settings (§3.2, B6, B8; not partitioned). One row per domain with API-mode
--    scope or onboarding state, created lazily with INSERT … ON DUPLICATE KEY UPDATE on the
--    unique domain_id (api scope PUT, mailbox-worker first copy). No row = scope `all`, no first
--    copy. `scope_department_ids` = JSON array (1..20) of tenant_departments.public_id.
--    `first_copy_id` references the partitioned api_message_copies (no FK). CAS on row_version.
CREATE TABLE `api_mode_domain_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `domain_id` BIGINT UNSIGNED NOT NULL,
    `scope_kind` ENUM('all', 'departments', 'mailboxes') NOT NULL DEFAULT 'all',
    `scope_department_ids` JSON NULL,
    `scope_changed_at` DATETIME(3) NULL,
    `scope_recompute_requested_at` DATETIME(3) NULL,
    `first_copy_id` BIGINT UNSIGNED NULL,
    `first_copy_received_at` DATETIME(3) NULL,
    `first_copy_at` DATETIME(3) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_mode_domain_settings_public_id_key`(`public_id`),
    UNIQUE INDEX `api_mode_domain_settings_domain_id_key`(`domain_id`),
    INDEX `api_mode_domain_settings_organization_id_idx`(`organization_id`),
    INDEX `api_mode_domain_settings_scope_recompute_requested_at_idx`(`scope_recompute_requested_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. Secondary indexes on existing tables (online: INPLACE, LOCK=NONE).
-- 10a. api_mailboxes: scope evaluation and in-scope / excluded counts of a domain (B6).
CREATE INDEX `api_mailboxes_domain_id_scope_state_idx` ON `api_mailboxes`(`domain_id`, `scope_state`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 10b. api_remediation_policies: expiry sweep of detect-only periods (B7).
CREATE INDEX `api_remediation_policies_detect_only_until_idx` ON `api_remediation_policies`(`detect_only_until`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 10c. domain_verifications: the integration-worker's claim of unchecked provider rows and the
--      api scheduler's pick of checked ones (B3).
CREATE INDEX `domain_verifications_method_status_provider_checked_at_idx` ON `domain_verifications`(`method`, `status`, `provider_checked_at`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 11. Backfill (§3.1): all ownership before API-4 was won through the DNS TXT record. Idempotent
--     (only NULL rows). updated_at is left unchanged (no ON UPDATE clause; data correction).
UPDATE `domains` SET `ownership_method` = 'dns_txt'
WHERE `status` IN ('verified', 'active', 'suspended') AND `ownership_method` IS NULL;

-- 12. Foreign keys (the new table only; §3.2). organization_id is covered by its own index,
--     domain_id by the unique key.
ALTER TABLE `api_mode_domain_settings` ADD CONSTRAINT `api_mode_domain_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_mode_domain_settings` ADD CONSTRAINT `api_mode_domain_settings_domain_id_fkey` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
