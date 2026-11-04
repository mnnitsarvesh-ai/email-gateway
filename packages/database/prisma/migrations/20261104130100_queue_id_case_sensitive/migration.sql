-- Step 3.3 L15: case-sensitive Postfix queue ids (docs/plan/steps/08-message-lifecycle.md §3.2).
--
-- Postfix long queue ids are case-sensitive (`4jKFxV5fmHz12JnW` and `4jKFxV5fMHz12Jnw` are two
-- different queue files), but the queue-id columns had the table collation utf8mb4_unicode_ci, so
-- every lookup (delivery recorder resolveDelivery, smtp-adapter bounce matching) treated them as
-- equal. The five queue-id columns become utf8mb4_bin. The character set is unchanged (utf8mb4),
-- so no data is converted; existing values keep their bytes.
--
-- Partitioning is preserved: ALTER TABLE ... MODIFY on a partitioned table rewrites each partition
-- and keeps the PARTITION BY clause (it is not repeated here). Algorithms (MySQL 8.4, verified on a
-- throwaway schema, recorded in docs/database/schema-reference.md):
--   * email_messages.mta_queue_id and delivery_status_events.queue_id are not indexed: INPLACE;
--   * email_deliveries.outbound_queue_id (indexed) + dsn_queue_id, and delivery_reinjections.queue_id
--     (indexed): COPY (MySQL cannot change the collation of an indexed column in place), which
--     rebuilds those tables partition by partition and rebuilds their secondary indexes.
-- Prisma does not model column collation, so schema.prisma only documents it (no drift).

-- AlterTable
ALTER TABLE `email_messages`
    MODIFY `mta_queue_id` VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    ALGORITHM=INPLACE;

-- AlterTable
ALTER TABLE `email_deliveries`
    MODIFY `outbound_queue_id` VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    MODIFY `dsn_queue_id` VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    ALGORITHM=COPY;

-- AlterTable
ALTER TABLE `delivery_reinjections`
    MODIFY `queue_id` VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    ALGORITHM=COPY;

-- AlterTable
ALTER TABLE `delivery_status_events`
    MODIFY `queue_id` VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    ALGORITHM=INPLACE;
