-- Step 6.1: Complete REST API (`/api/v1`)
-- (docs/plan/steps/18-rest-api.md §3.1, D5, D9, D12; ADR-0050 .. ADR-0053).
--
-- What changes (no new table, no data rewritten; still 114 tables, 31 partitioned):
--   * api_idempotency_keys (not partitioned): column `state` ENUM('completed','pending'),
--     DEFAULT 'completed' so every existing row (a stored 2xx response of the transactional
--     mechanism) keeps its meaning. `pending` rows are reservations of the step 6.1
--     IdempotencyInterceptor (D9): status_code 0, response JSON null, a short expiry.
--     ALGORITHM=INSTANT (metadata only).
--   * email_messages (PARTITIONED monthly by RANGE COLUMNS(received_at); altered, never
--     re-created): two secondary indexes, local to every partition:
--       email_messages_org_verdict_received_idx (organization_id, final_verdict, received_at, id)
--         — the verdict plan of GET /messages (D5 plan 2);
--       email_messages_org_received_dir_verdict_idx
--         (organization_id, received_at, direction, final_verdict)
--         — index-only report counts (D12).
--     ALGORITHM=INPLACE, LOCK=NONE: online DDL, concurrent inserts keep running.
--   * delivery_suppressions (not partitioned): index (organization_id, id) for the keyset list
--     newest first per organization (GET /recipients/suppressions). INPLACE, LOCK=NONE.
--
-- Rollback (manual, forward-only policy): DROP the three indexes and the column; nothing else
-- depends on them.

-- api_idempotency_keys: reservation state of the interceptor (D9). INSTANT.
ALTER TABLE `api_idempotency_keys`
  ADD COLUMN `state` ENUM('completed', 'pending') NOT NULL DEFAULT 'completed',
  ALGORITHM=INSTANT;

-- email_messages: verdict-filtered message list (D5 plan 2) and index-only report counts (D12).
ALTER TABLE `email_messages`
  ADD INDEX `email_messages_org_verdict_received_idx`
    (`organization_id`, `final_verdict`, `received_at`, `id`),
  ADD INDEX `email_messages_org_received_dir_verdict_idx`
    (`organization_id`, `received_at`, `direction`, `final_verdict`),
  ALGORITHM=INPLACE, LOCK=NONE;

-- delivery_suppressions: keyset list newest first per organization (WP2).
ALTER TABLE `delivery_suppressions`
  ADD INDEX `delivery_suppressions_organization_id_id_idx` (`organization_id`, `id`),
  ALGORITHM=INPLACE, LOCK=NONE;
