-- Step 6.1: Complete REST API, index coverage of two v1 reads
-- (docs/plan/steps/18-rest-api.md §3.1, §13.2; D6, D12).
--
-- What changes (no table, column or data; still 114 tables, 31 partitioned). Both tables are
-- PARTITIONED monthly by RANGE COLUMNS(received_at); they are altered, never re-created, and the
-- secondary indexes stay local to every partition:
--   * email_attachments_organization_id_sha256_idx
--       (organization_id, sha256) -> (organization_id, sha256, received_at, id)
--     GET /attachments?sha256= orders by received_at DESC, id DESC. With the old index InnoDB
--     appended the primary key (id, received_at), so the index order was (…, id, received_at)
--     and MySQL read and sorted every row of the hash in the window before LIMIT (filesort; no
--     upper bound for a common hash). The keyset now follows the index: a page reads about
--     `limit` entries. Hash lookups by (organization_id, sha256) keep using the prefix.
--   * email_messages_org_received_dir_verdict_idx
--       (organization_id, received_at, direction, final_verdict)
--       -> (organization_id, received_at, direction, final_verdict, final_action)
--     The threats report groups by verdict AND action; final_action was not covered, so every
--     message of the window cost a primary-key lookup (D12 index-only counts). One more ENUM
--     byte per entry; the traffic and billing counts use the same index as before.
--
-- The index names are kept (DROP and ADD of the same name in one ALTER, swapped atomically) so
-- that `FORCE INDEX (<name>)` in a running api image never names a missing index during a
-- rolling deploy. ALGORITHM=INPLACE, LOCK=NONE: online DDL, concurrent inserts keep running.
--
-- Rollback (manual, forward-only policy): the same ALTER with the previous column lists.

-- email_attachments: keyset order of the hash search from the index (D6).
ALTER TABLE `email_attachments`
  DROP INDEX `email_attachments_organization_id_sha256_idx`,
  ADD INDEX `email_attachments_organization_id_sha256_idx`
    (`organization_id`, `sha256`, `received_at`, `id`),
  ALGORITHM=INPLACE, LOCK=NONE;

-- email_messages: index-only threats outcomes by verdict and action (D12).
ALTER TABLE `email_messages`
  DROP INDEX `email_messages_org_received_dir_verdict_idx`,
  ADD INDEX `email_messages_org_received_dir_verdict_idx`
    (`organization_id`, `received_at`, `direction`, `final_verdict`, `final_action`),
  ALGORITHM=INPLACE, LOCK=NONE;
