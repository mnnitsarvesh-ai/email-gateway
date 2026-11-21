-- Step AI-2 review fix: when a confirmed write starts
-- (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md D2 step 13, D7; ADR-0093 as amended
-- in AI-2).
--
-- Additive only (one nullable column, no index, no backfill; 176 tables, 41 partitioned):
--   * ai_chat_action_confirmations.execution_started_at: set by the confirm request with a
--     conditional UPDATE (`WHERE status = 'executing' AND execution_started_at IS NULL`) right
--     before it sends the write. A confirm whose row the outcome-unknown sweep already failed
--     loses that claim and sends nothing. The sweep measures the write from this column and the
--     precondition re-read (up to 25 sequential reads) from `decided_at`, so a slow re-read is
--     never marked outcome unknown while its request is still running. The existing
--     (status, decided_at) index narrows the sweep to the few `executing` rows.
--
-- Locking: ADD COLUMN of a nullable column without a default is ALGORITHM=INSTANT on MySQL 8.4
-- (metadata only, no table copy, no row touched).
--
-- Rollback (never automatic; after rolling the api back, AI-2 being the only reader and writer):
--   ALTER TABLE ai_chat_action_confirmations DROP COLUMN execution_started_at;

ALTER TABLE `ai_chat_action_confirmations` ADD COLUMN `execution_started_at` DATETIME(3) NULL, ALGORITHM=INSTANT;
