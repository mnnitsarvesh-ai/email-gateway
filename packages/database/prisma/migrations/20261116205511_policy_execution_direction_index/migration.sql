-- Step 7.3: Policy builder UI, review fix: a bounded direction-filtered read of
-- policy_execution_logs (docs/plan/steps/22-policy-builder.md §4.3, §14.8).
--
-- What changes (no table, column or data; still 121 tables, 33 partitioned). The table is
-- PARTITIONED monthly by RANGE COLUMNS(received_at); it is altered, never re-created, and the
-- new secondary index is local to every partition:
--   * policy_execution_logs_organization_id_direction_received_at_idx
--       (organization_id, direction, received_at)   [+ the primary key's id, appended by InnoDB]
--     POST /policies/dry-run (sample) and GET /policies/executions filter on `direction` and
--     order by (received_at DESC, id DESC) with a LIMIT. No index contained `direction`, so a
--     tenant with little traffic in the requested direction made MySQL walk every
--     (organization_id, received_at) entry of the window, with a clustered-row lookup each,
--     before the LIMIT was met. With this index the read is an index range scan of the
--     direction's entries in the window, in the order of the keyset: about LIMIT entries.
--
-- ALGORITHM=INPLACE, LOCK=NONE: online DDL, concurrent inserts keep running.
--
-- Rollback (manual, forward-only policy):
--   ALTER TABLE `policy_execution_logs`
--     DROP INDEX `policy_execution_logs_organization_id_direction_received_at_idx`,
--     ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `policy_execution_logs`
  ADD INDEX `policy_execution_logs_organization_id_direction_received_at_idx`
    (`organization_id`, `direction`, `received_at`),
  ALGORITHM=INPLACE, LOCK=NONE;
