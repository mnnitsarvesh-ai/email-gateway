-- Step 2.3 review fix: the recipients of one reinjection are read by (reinjection_id,
-- received_at) on hot paths (token matching of bounce notices, queue-id binding, the
-- status tailer's queue-active handling and the reconciler). Without this index those
-- queries scanned the whole month partition of email_deliveries.
-- Online secondary index (InnoDB INPLACE, no table lock); applies to every partition.

-- CreateIndex
CREATE INDEX `email_deliveries_reinjection_id_received_at_idx` ON `email_deliveries`(`reinjection_id`, `received_at`) ALGORITHM=INPLACE LOCK=NONE;
