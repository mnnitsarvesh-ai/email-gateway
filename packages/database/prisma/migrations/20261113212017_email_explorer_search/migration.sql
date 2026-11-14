-- Step 7.2: Email Explorer and Email Details, message search keys, driver indexes, the audit
-- resource plan and saved views (docs/plan/steps/21-email-explorer-details.md §2 E1-E4, §3.1;
-- ADR-0061).
--
-- What changes (tables 120 -> 121; partitioned tables unchanged, 33). email_messages,
-- email_recipients, email_deliveries and audit_logs are PARTITIONED monthly by RANGE
-- COLUMNS(received_at / created_at); they are altered, never re-created, and every secondary
-- index stays local to each partition. quarantine_messages and the new saved_views are not
-- partitioned.
--   1. Search keys: four VIRTUAL generated columns (metadata only, ALGORITHM=INSTANT, nothing
--      stored in the rows). Prisma declares them as plain nullable READ-ONLY fields; their
--      GENERATED clauses live only here, like scan_engine_results.final_engine (step 4.1) and
--      domains.verified_name / live_name (step 2.1). No code may write them (MySQL refuses).
--      * email_messages.subject_key: the subject without leading reply/forward markers (re, fw,
--        fwd, aw, wg, sv, vs, antw, tr, rif, enc, odp, an optional [n], then ':'; repeated),
--        whitespace runs collapsed to one space, trimmed, first 128 code points. Case and
--        accents are ignored by the column collation (utf8mb4_unicode_ci). The api mirrors the
--        expression in apps/api/src/modules/messages/domain/search-keys.ts (parity-tested).
--        The marker pattern uses POSSESSIVE quantifiers (`*+`): the design's
--        `[[:space:]]*(…)[[:space:]]*(\[n\])?[[:space:]]*:` backtracks quadratically and hit
--        MySQL's regexp_time_limit (ER_REGEXP_TIME_OUT 3699) on a subject such as
--        're' + 990 spaces + 'x' (measured on MySQL 8.4.13, 2026-11-14). Because the column is
--        indexed, its expression runs on every INSERT and on every UPDATE of `subject`, so an
--        attacker-chosen subject would have failed ingestion. The possessive form accepts the
--        same language (a space never is '[' or ':', so giving one back cannot help a match)
--        and is linear; deviation recorded in §13 WP1.
--      * email_messages.sender_domain: envelope_from after its last '@' (NULL for the null
--        sender and any value without '@'), first 253 characters.
--      * email_messages.message_id_key: internet_message_id with surrounding spaces, leading
--        '<' and trailing '>' removed, first 255 characters.
--      * email_recipients.address_domain: address after its last '@', first 253 characters.
--   2. Driver indexes of GET /messages (ALGORITHM=INPLACE, LOCK=NONE: online, concurrent
--      inserts keep running; an index on a virtual column materializes the value in the index
--      only): (organization_id, <key>, received_at, id) on envelope_from, header_from,
--      sender_domain, subject_key and message_id_key; (organization_id, address_domain,
--      received_at, message_id) on email_recipients; (organization_id, status, received_at,
--      message_id) on email_deliveries; (organization_id, status, message_received_at,
--      message_id) on quarantine_messages. Each driver reads its index in keyset order
--      (received_at, id) after an equality on its key.
--   3. Audit resource plan: audit_logs (organization_id, resource_type, resource_id,
--      created_at, id), so a resource's audit history (the details page) is read in keyset
--      order at any audit volume (organization_id IS NULL serves the platform rows).
--   4. saved_views: per user, tenant-scoped saved explorer views (not partitioned; FK
--      organizations RESTRICT, users CASCADE).
--
-- Write amplification: email_messages gains five secondary indexes (the generated columns
-- themselves cost nothing at rest; their expressions run when an indexed value is written),
-- email_recipients, email_deliveries, quarantine_messages and audit_logs one each. Measured
-- with `pnpm db:perf` before and after (§13 WP1 of the step note).
--
-- Rollback (manual, forward-only policy): drop the nine indexes, then the four generated
-- columns, then the table:
--   ALTER TABLE email_messages DROP INDEX email_messages_org_envelope_from_received_idx,
--     DROP INDEX email_messages_org_header_from_received_idx,
--     DROP INDEX email_messages_org_sender_domain_received_idx,
--     DROP INDEX email_messages_org_subject_key_received_idx,
--     DROP INDEX email_messages_org_message_id_key_received_idx, ALGORITHM=INPLACE, LOCK=NONE;
--   ALTER TABLE email_recipients DROP INDEX email_recipients_org_address_domain_received_idx;
--   ALTER TABLE email_deliveries DROP INDEX email_deliveries_org_status_received_message_idx;
--   ALTER TABLE quarantine_messages DROP INDEX quarantine_messages_org_status_received_message_idx;
--   ALTER TABLE audit_logs DROP INDEX audit_logs_org_resource_created_idx;
--   ALTER TABLE email_messages DROP COLUMN subject_key, DROP COLUMN sender_domain,
--     DROP COLUMN message_id_key, ALGORITHM=INSTANT;
--   ALTER TABLE email_recipients DROP COLUMN address_domain, ALGORITHM=INSTANT;
--   DROP TABLE saved_views;

-- 1. Search keys: VIRTUAL generated columns (metadata only, INSTANT on the partitioned tables).
ALTER TABLE `email_messages`
  ADD COLUMN `subject_key` VARCHAR(128) GENERATED ALWAYS AS (IF(`subject` IS NULL, NULL,
    LEFT(REGEXP_REPLACE(REGEXP_REPLACE(REGEXP_REPLACE(`subject`,
      '^(?:[[:space:]]*+(?:re|fw|fwd|aw|wg|sv|vs|antw|tr|rif|enc|odp)[[:space:]]*+(?:\\[[0-9]+\\][[:space:]]*+)?:)+',
      '', 1, 1, 'i'), '[[:space:]]+', ' '), '^ | $', ''), 128))) VIRTUAL NULL,
  ADD COLUMN `sender_domain` VARCHAR(253) GENERATED ALWAYS AS (IF(LOCATE('@', `envelope_from`) = 0,
    NULL, LEFT(SUBSTRING_INDEX(`envelope_from`, '@', -1), 253))) VIRTUAL NULL,
  ADD COLUMN `message_id_key` VARCHAR(255) GENERATED ALWAYS AS (IF(`internet_message_id` IS NULL,
    NULL, LEFT(TRIM(TRAILING '>' FROM TRIM(LEADING '<' FROM TRIM(`internet_message_id`))), 255)))
    VIRTUAL NULL,
  ALGORITHM=INSTANT;

-- 2. Driver indexes (online; secondary indexes on virtual columns are materialized in the index).
ALTER TABLE `email_messages`
  ADD INDEX `email_messages_org_envelope_from_received_idx` (`organization_id`, `envelope_from`, `received_at`, `id`),
  ADD INDEX `email_messages_org_header_from_received_idx` (`organization_id`, `header_from`, `received_at`, `id`),
  ADD INDEX `email_messages_org_sender_domain_received_idx` (`organization_id`, `sender_domain`, `received_at`, `id`),
  ADD INDEX `email_messages_org_subject_key_received_idx` (`organization_id`, `subject_key`, `received_at`, `id`),
  ADD INDEX `email_messages_org_message_id_key_received_idx` (`organization_id`, `message_id_key`, `received_at`, `id`),
  ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `email_recipients`
  ADD COLUMN `address_domain` VARCHAR(253) GENERATED ALWAYS AS (IF(LOCATE('@', `address`) = 0,
    NULL, LEFT(SUBSTRING_INDEX(`address`, '@', -1), 253))) VIRTUAL NULL,
  ALGORITHM=INSTANT;
ALTER TABLE `email_recipients`
  ADD INDEX `email_recipients_org_address_domain_received_idx` (`organization_id`, `address_domain`, `received_at`, `message_id`),
  ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `email_deliveries`
  ADD INDEX `email_deliveries_org_status_received_message_idx` (`organization_id`, `status`, `received_at`, `message_id`),
  ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `quarantine_messages`
  ADD INDEX `quarantine_messages_org_status_received_message_idx` (`organization_id`, `status`, `message_received_at`, `message_id`),
  ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `audit_logs`
  ADD INDEX `audit_logs_org_resource_created_idx` (`organization_id`, `resource_type`, `resource_id`, `created_at`, `id`),
  ALGORITHM=INPLACE, LOCK=NONE;

-- 3. Saved explorer views (not partitioned; per user, tenant-scoped). The CREATE TABLE is the
-- form `migrate dev --create-only` generated for the Prisma model (so the drift check is clean).
CREATE TABLE `saved_views` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('message_explorer') NOT NULL,
    `name` VARCHAR(80) NOT NULL,
    `definition` JSON NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `saved_views_public_id_key`(`public_id`),
    INDEX `saved_views_organization_id_user_id_kind_id_idx`(`organization_id`, `user_id`, `kind`, `id`),
    INDEX `saved_views_user_id_idx`(`user_id`),
    UNIQUE INDEX `saved_views_organization_id_user_id_kind_name_key`(`organization_id`, `user_id`, `kind`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `saved_views`
  ADD CONSTRAINT `saved_views_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT `saved_views_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
