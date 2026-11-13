-- Step 7.1: Complete admin dashboard, covering indexes of the portal reports
-- (docs/plan/steps/20-admin-portal.md §3.2, §3.3; P15).
--
-- What changes (no table, column, partitioning or data; still 114 tables). The three tables are
-- PARTITIONED monthly by RANGE COLUMNS(received_at); they are altered, never re-created, and the
-- secondary indexes stay local to every partition:
--   * email_messages_org_received_dir_verdict_idx
--       (organization_id, received_at, direction, final_verdict, final_action)
--       -> (…, final_action, domain_id)
--     GET /reports/top-domains groups inbound messages by domain_id and final_verdict; with
--     domain_id covered the report reads index entries only. Redefined under its existing name
--     in ONE statement (DROP and ADD swapped atomically, as rest_api_index_coverage did), so
--     `FORCE INDEX (email_messages_org_received_dir_verdict_idx)` in a running api image never
--     names a missing index during a rolling deploy. 8 more bytes per entry.
--   * email_deliveries_org_received_status_idx (organization_id, received_at, status, delivered_at)
--     GET /reports/delivery: status counts per bucket and the delivery latency histogram
--     (delivered_at - received_at) index-only.
--   * email_scans_org_received_kind_status_idx
--       (organization_id, received_at, scan_kind, status, completed_at)
--     GET /reports/processing: initial scan rounds by status and the time to verdict histogram
--     (completed_at - received_at) index-only.
--
-- ALGORITHM=INPLACE, LOCK=NONE: online DDL, concurrent inserts keep running. Write
-- amplification measured with `pnpm db:perf` before and after (§13 of the step note).
--
-- Rollback (manual, forward-only policy): redefine the email_messages index with the previous
-- column list in one ALTER and drop the two new indexes.

-- Top attacked domains (§3.3) index-only: domain_id appended to the 6.1 covering index.
ALTER TABLE `email_messages`
  DROP INDEX `email_messages_org_received_dir_verdict_idx`,
  ADD INDEX `email_messages_org_received_dir_verdict_idx`
    (`organization_id`, `received_at`, `direction`, `final_verdict`, `final_action`, `domain_id`),
  ALGORITHM=INPLACE, LOCK=NONE;

-- Delivery report index-only.
ALTER TABLE `email_deliveries`
  ADD INDEX `email_deliveries_org_received_status_idx`
    (`organization_id`, `received_at`, `status`, `delivered_at`),
  ALGORITHM=INPLACE, LOCK=NONE;

-- Processing report index-only.
ALTER TABLE `email_scans`
  ADD INDEX `email_scans_org_received_kind_status_idx`
    (`organization_id`, `received_at`, `scan_kind`, `status`, `completed_at`),
  ALGORITHM=INPLACE, LOCK=NONE;
