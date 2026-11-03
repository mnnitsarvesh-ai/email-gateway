-- Step 2.3: mail routing and per-recipient delivery tracking (docs/plan/steps/05-routing.md §3,
-- R1, R2, R6-R9; ADR-0021).
--
-- What changes:
--   * New enums (inline MySQL ENUM columns): MailDestinationProvider (custom, microsoft_365,
--     google_workspace), ReinjectionListener (reinject_inbound, reinject_outbound),
--     ReinjectionStatus (pending, in_progress, queued, failed), DeliverySignalSource (planner,
--     reinjection, postfix_log, bounce_notice, reconciler).
--   * DeliveryStatus gains `queued`, `expired`, `unknown` (appended; existing values unchanged).
--   * domain_mail_servers: public_id (UUID, API id; existing rows backfilled), provider (default
--     custom), tls_verify_names (Postfix match= list), index (host, port) for the tls_policy map.
--   * email_recipients: direction (routed direction, NULL for rows ingested before step 2.3).
--   * email_deliveries: reinjection_id, direction, destination_key, status_changed_at,
--     last_signal_at, enhanced_status, last_error_class, failure_reason, dsn_queue_id; indexes
--     (outbound_queue_id) for delivery-log matching and (organization_id, received_at, id) for
--     the tenant-wide delivery list.
--   * New tables: mail_destination_presets (platform configuration, seeded), delivery_reinjections
--     and delivery_status_events (PARTITIONED monthly by RANGE COLUMNS(received_at), created with
--     the single pmax partition; `pnpm db:partitions apply` splits it), stream_cursors.
--
-- Partitioned tables follow ADR-0014: composite primary key (id, received_at), no foreign keys
-- in either direction, every unique key ends with received_at.
--
-- Comment-only changes in schema.prisma (no DDL): email_deliveries.outbound_queue_id and
-- bounce_events.message_id (now set by step 2.3), domain_mail_servers.role/host.
--
-- Locking: every column added here is nullable or has a constant default, and the enum change
-- only appends values, so MySQL 8.4 applies the ALTERs on email_deliveries (partitioned) and
-- email_recipients (partitioned) as INSTANT/INPLACE metadata changes; the new secondary indexes
-- are built online (INPLACE, LOCK=NONE). domain_mail_servers is small (a few rows per domain):
-- public_id is added as NULL, backfilled with UUID() and only then made NOT NULL UNIQUE, so the
-- statement never fails on existing rows. Prisma's @default(uuid(7)) is applied client-side;
-- the backfilled values of pre-2.3 rows are UUIDv1 (MySQL UUID()), which is fine for an opaque
-- API id.

-- AlterTable: destination servers (R2)
ALTER TABLE `domain_mail_servers` ADD COLUMN `public_id` CHAR(36) NULL,
    ADD COLUMN `provider` ENUM('custom', 'microsoft_365', 'google_workspace') NOT NULL DEFAULT 'custom',
    ADD COLUMN `tls_verify_names` VARCHAR(512) NULL;

-- Backfill: existing rows get a unique public id (UUID() is evaluated per row).
UPDATE `domain_mail_servers` SET `public_id` = UUID() WHERE `public_id` IS NULL;

ALTER TABLE `domain_mail_servers` MODIFY `public_id` CHAR(36) NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX `domain_mail_servers_public_id_key` ON `domain_mail_servers`(`public_id`);

-- CreateIndex
CREATE INDEX `domain_mail_servers_host_port_idx` ON `domain_mail_servers`(`host`, `port`);

-- AlterTable (partitioned; nullable column, INSTANT)
ALTER TABLE `email_recipients` ADD COLUMN `direction` ENUM('inbound', 'outbound', 'internal') NULL;

-- AlterTable (partitioned; nullable columns and appended enum values)
ALTER TABLE `email_deliveries` ADD COLUMN `reinjection_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `direction` ENUM('inbound', 'outbound', 'internal') NULL,
    ADD COLUMN `destination_key` VARCHAR(300) NULL,
    ADD COLUMN `status_changed_at` DATETIME(3) NULL,
    ADD COLUMN `last_signal_at` DATETIME(3) NULL,
    ADD COLUMN `enhanced_status` VARCHAR(16) NULL,
    ADD COLUMN `last_error_class` VARCHAR(32) NULL,
    ADD COLUMN `failure_reason` VARCHAR(64) NULL,
    ADD COLUMN `dsn_queue_id` VARCHAR(32) NULL,
    MODIFY `status` ENUM('pending', 'in_progress', 'delivered', 'deferred', 'bounced', 'failed', 'suppressed', 'queued', 'expired', 'unknown') NOT NULL DEFAULT 'pending';

-- CreateIndex (delivery-log and DSN matching by postfix-outbound queue id, R9)
CREATE INDEX `email_deliveries_outbound_queue_id_idx` ON `email_deliveries`(`outbound_queue_id`);

-- CreateIndex (tenant-wide delivery list with keyset pagination, R13)
CREATE INDEX `email_deliveries_organization_id_received_at_id_idx` ON `email_deliveries`(`organization_id`, `received_at`, `id`);

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones (retention 6 months, core).
-- CreateTable
CREATE TABLE `delivery_reinjections` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `public_id` CHAR(36) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `delivery_seq` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `listener` ENUM('reinject_inbound', 'reinject_outbound') NOT NULL,
    `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    `destination_key` VARCHAR(300) NOT NULL,
    `eml_object_key` VARCHAR(512) NOT NULL,
    `recipient_count` SMALLINT UNSIGNED NOT NULL,
    `recipient_set_sha256` CHAR(64) NOT NULL,
    `idempotency_key` CHAR(64) NOT NULL,
    `approval_event_id` CHAR(36) NOT NULL,
    `status` ENUM('pending', 'in_progress', 'queued', 'failed') NOT NULL DEFAULT 'pending',
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `next_attempt_at` DATETIME(3) NOT NULL,
    `lease_expires_at` DATETIME(3) NULL,
    `started_at` DATETIME(3) NULL,
    `queued_at` DATETIME(3) NULL,
    `queue_id` VARCHAR(32) NULL,
    `last_error_class` VARCHAR(32) NULL,
    `last_error` VARCHAR(512) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `delivery_reinjections_status_next_attempt_at_idx`(`status`, `next_attempt_at`),
    INDEX `delivery_reinjections_queue_id_idx`(`queue_id`),
    INDEX `delivery_reinjections_public_id_idx`(`public_id`),
    UNIQUE INDEX `delivery_reinjections_message_id_idempotency_key_received_at_key`(`message_id`, `idempotency_key`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones (retention 3 months, detail). Append-only.
-- CreateTable
CREATE TABLE `delivery_status_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `delivery_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `recipient_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `source` ENUM('planner', 'reinjection', 'postfix_log', 'bounce_notice', 'reconciler') NOT NULL,
    `signal_key` CHAR(64) NOT NULL,
    `occurred_at` DATETIME(3) NOT NULL,
    `from_status` ENUM('pending', 'in_progress', 'delivered', 'deferred', 'bounced', 'failed', 'suppressed', 'queued', 'expired', 'unknown') NULL,
    `to_status` ENUM('pending', 'in_progress', 'delivered', 'deferred', 'bounced', 'failed', 'suppressed', 'queued', 'expired', 'unknown') NOT NULL,
    `applied` BOOLEAN NOT NULL,
    `queue_id` VARCHAR(32) NULL,
    `smtp_code` SMALLINT UNSIGNED NULL,
    `enhanced_status` VARCHAR(16) NULL,
    `remote_host` VARCHAR(255) NULL,
    `error_class` VARCHAR(32) NULL,
    `detail` VARCHAR(1024) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `delivery_status_events_message_id_received_at_idx`(`message_id`, `received_at`),
    UNIQUE INDEX `delivery_status_events_delivery_id_signal_key_received_at_key`(`delivery_id`, `signal_key`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- CreateTable (platform configuration data, seeded; R2)
CREATE TABLE `mail_destination_presets` (
    `provider` ENUM('custom', 'microsoft_365', 'google_workspace') NOT NULL,
    `display_name` VARCHAR(128) NOT NULL,
    `host_patterns` JSON NOT NULL,
    `host_hint` VARCHAR(255) NULL,
    `default_servers` JSON NULL,
    `port` SMALLINT UNSIGNED NOT NULL,
    `tls_mode` ENUM('none', 'opportunistic', 'required', 'verify') NOT NULL,
    `tls_verify_names` VARCHAR(512) NOT NULL,
    `max_servers` TINYINT UNSIGNED NOT NULL,
    `documentation_url` VARCHAR(512) NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`provider`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable (stream consumer positions; R6, R9)
CREATE TABLE `stream_cursors` (
    `name` VARCHAR(128) NOT NULL,
    `position_id` BIGINT UNSIGNED NULL,
    `file_id` VARCHAR(128) NULL,
    `file_offset` BIGINT UNSIGNED NULL,
    `last_event_at` DATETIME(3) NULL,
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`name`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
