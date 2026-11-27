-- Step API-3 review fix (design note 37 §16, C6/P2; ADR-0103): separation of duties for the purge
-- approval threshold.
--
-- PUT /api-mode/settings (remediation:write) may raise purge_approval_mailboxes up to 10 000, and
-- security_analyst / organization_admin hold both remediation:write and remediation:purge. Without
-- these columns one person could lift the second-approver rule and then purge alone. The api now
-- records who last raised the threshold and the value in effect before that raise; that
-- principal's own purges are still checked against the earlier value (min(current, before)), so
-- a raise only takes effect for other people.
--
--   purge_approval_raised_by     principal key `user:<publicId>` / `api_key:<publicId>` (no
--                                content; NULL = the threshold is not above the earlier value)
--   purge_approval_before_raise  the threshold in effect before that principal's raise
--
-- No backfill: existing rows (if any) keep NULL in both columns, i.e. their current threshold
-- applies to everyone, as before this migration.
--
-- Locking (MySQL 8.4): two nullable columns appended at the end of a small, non-partitioned table:
-- ALGORITHM=INSTANT (metadata only). MySQL refuses rather than copies if INSTANT were impossible;
-- the fallback is ALGORITHM=INPLACE, LOCK=NONE.
--
-- Rollback (never automatic; after rolling the api back):
--   ALTER TABLE api_mode_org_settings DROP COLUMN purge_approval_before_raise,
--     DROP COLUMN purge_approval_raised_by, ALGORITHM=INSTANT;

-- AlterTable
ALTER TABLE `api_mode_org_settings` ADD COLUMN `purge_approval_before_raise` INTEGER UNSIGNED NULL,
    ADD COLUMN `purge_approval_raised_by` VARCHAR(80) NULL,
    ALGORITHM=INSTANT;
