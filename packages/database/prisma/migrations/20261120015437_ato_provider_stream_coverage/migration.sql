-- Step 8.5 review fix (closing round, finding "backfill re-ingestion"): the provider-time interval
-- a stream already ingested, so a backfill that re-reads it (POST /ato/providers/{id}/backfill on a
-- live stream, or binding a removed connection again with backfillDays) does not process the same
-- provider events a second time after the 6 h Redis seen-set has expired.
--
--   covered_from  start of the contiguous provider-time range the stream has ingested (its first
--                 window, or the start of a backfill that joined that range); NULL on rows created
--                 before this migration (readers fall back to backfill_from / created_at).
--   replay_from   during a backfill: events with occurred_at in [replay_from, replay_until) were
--   replay_until  processed by the earlier ingestion and are skipped by the ato-worker stream
--                 runner (result `replayed`); both cleared when the backfill completes.
--
-- No index (read only with the stream row by primary key); no data change; table count unchanged.
ALTER TABLE `ato_provider_streams`
    ADD COLUMN `covered_from` DATETIME(3) NULL,
    ADD COLUMN `replay_from` DATETIME(3) NULL,
    ADD COLUMN `replay_until` DATETIME(3) NULL,
    ALGORITHM=INSTANT;
