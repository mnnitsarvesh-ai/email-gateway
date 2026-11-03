# Query examples

The hot queries of the platform (D8 in [the step design](../plan/steps/01-database.md#d8-performance-test)), as SQL and, where practical, as Prisma. `pnpm db:perf` runs exactly this SQL and records the plans, the partitions read and the timings in [performance-report.md](performance-report.md).

Rules that every query on a partitioned table follows ([partitioning.md](partitioning.md)):

- Constrain the partition column: an exact `received_at` for one message (from the registry or the event payload), or a range for lists. Without it, every partition is probed.
- Tenant-scoped queries filter by `organization_id` taken from the authenticated context, and the index leads with it.
- Ids are `bigint` in Prisma. Convert with `formatId` before they leave the service.
- Control-plane list and report reads in the api use `PrismaReadService.client` (the replica, with writer fallback). Read-after-write paths use the writer ([replication.md](replication.md#routing-rules)).

## Q1: Tenant message list, last 24 h, keyset pagination

```sql
-- first page
SELECT id, received_at, status, direction, envelope_from, subject, final_verdict, risk_score
  FROM email_messages
 WHERE organization_id = ? AND received_at >= ? AND received_at < ?
 ORDER BY received_at DESC, id DESC
 LIMIT 50;
-- next page: cursor = (received_at, id) of the last row
SELECT ... FROM email_messages
 WHERE organization_id = ? AND received_at >= ?
   AND (received_at < ? OR (received_at = ? AND id < ?))
 ORDER BY received_at DESC, id DESC
 LIMIT 50;
```

```ts
const page = await reader.client.emailMessage.findMany({
  where: {
    organizationId,
    receivedAt: { gte: since },
    ...(cursor && {
      OR: [
        { receivedAt: { lt: cursor.receivedAt } },
        { receivedAt: cursor.receivedAt, id: { lt: cursor.id } },
      ],
    }),
  },
  orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
  take: 50,
});
```

**Pruning:** the partitions overlapping the window (1, or 2 around a month boundary). Backward range scan on `(organization_id, received_at, id)`, no filesort. Keyset pagination never uses `OFFSET`. The cursor is written as an expanded `OR` rather than a row constructor `(received_at, id) < (?, ?)`, which keeps the plan a plain range scan with the `organization_id` prefix (verified in the performance report).

## Q2: Message detail by `public_id`

```sql
SELECT id, organization_id, received_at FROM message_identities WHERE public_id = ?;
SELECT * FROM email_messages WHERE id = ? AND received_at = ? AND organization_id = ?;
SELECT id, rcpt_seq, address, status, final_action
  FROM email_recipients WHERE message_id = ? AND received_at = ? ORDER BY rcpt_seq;
```

```ts
const identity = await prisma.messageIdentity.findUnique({ where: { publicId } });
if (!identity || identity.organizationId !== organizationId) throw new NotFoundException();
const message = await prisma.emailMessage.findUnique({
  where: { id_receivedAt: { id: identity.id, receivedAt: identity.receivedAt } },
});
const recipients = await prisma.emailRecipient.findMany({
  where: { messageId: identity.id, receivedAt: identity.receivedAt },
  orderBy: { rcptSeq: 'asc' },
});
```

**Pruning:** one partition per table. The registry is a unique-key lookup, and the message is a primary-key `const` lookup. A registry row from another organization is answered as "not found", never "forbidden".

## Q3: Scans and engine results for a message

```sql
SELECT s.id AS scan_id, s.scan_kind, s.verdict, s.risk_score,
       r.engine, r.outcome, r.score, r.duration_ms
  FROM email_scans s
  JOIN scan_engine_results r ON r.scan_id = s.id AND r.received_at = s.received_at
 WHERE s.message_id = ? AND s.received_at = ?
 ORDER BY s.id, r.engine;
```

Prisma has no relation between partitioned tables, so it is two queries: `emailScan.findMany({ where: { messageId, receivedAt } })`, then `scanEngineResult.findMany({ where: { scanId: { in: ids }, receivedAt } })`. **Pruning:** one partition each. The join uses the `(scan_id, engine, received_at)` unique key, and the join condition repeats `received_at` so the inner table prunes too.

## Q4: Status history and events for a message

```sql
SELECT version, from_status, to_status, reason_code, changed_at
  FROM email_message_status_history WHERE message_id = ? AND received_at = ? ORDER BY version;
SELECT event_type, occurred_at, source_service, details
  FROM email_events WHERE message_id = ? AND received_at = ? ORDER BY occurred_at, id;
```

```ts
prisma.emailMessageStatusHistory.findMany({
  where: { messageId, receivedAt },
  orderBy: { version: 'asc' },
});
prisma.emailEvent.findMany({
  where: { messageId, receivedAt },
  orderBy: [{ occurredAt: 'asc' }, { id: 'asc' }],
});
```

**Pruning:** one partition each, via `(message_id, version, received_at)` and `(message_id, received_at)`.

## Q5: Quarantine list for an organization

```sql
SELECT id, public_id, recipient_address, envelope_from, subject, reason, risk_score, quarantined_at
  FROM quarantine_messages
 WHERE organization_id = ? AND status = 'quarantined'
 ORDER BY quarantined_at DESC
 LIMIT 50;
```

```ts
reader.client.quarantineMessage.findMany({
  where: { organizationId, status: 'quarantined' },
  orderBy: { quarantinedAt: 'desc' },
  take: 50,
});
```

`quarantine_messages` is not partitioned. Backward scan of `(organization_id, status, quarantined_at)`. Paginate with a `(quarantined_at, id)` keyset as in Q1.

## Q6: End-user quarantine by recipient address

```sql
SELECT id, public_id, envelope_from, subject, reason, quarantined_at, expires_at
  FROM quarantine_messages
 WHERE organization_id = ? AND recipient_address = ? AND status = 'quarantined'
 ORDER BY quarantined_at DESC
 LIMIT 50;
```

Prisma: `quarantineMessage.findMany({ where: { organizationId, recipientAddress, status: 'quarantined' }, orderBy: { quarantinedAt: 'desc' }, take: 50 })`. Uses the prefix index `(organization_id, recipient_address(100), status)`; the full address is re-checked on the row, and the matching rows are sorted (a small filesort). The address comes from the authenticated end user, never from a parameter they can change.

## Q7: Stuck-message reconciliation

```sql
SELECT id, received_at, organization_id, status, status_changed_at
  FROM email_messages
 WHERE status IN ('scanning', 'policy_evaluated', 'delivery_queued')
   AND status_changed_at < NOW(3) - INTERVAL 15 MINUTE
 ORDER BY status_changed_at
 LIMIT 500;
```

A platform job, not tenant-scoped. **Pruning:** none (no `received_at` predicate), so the `(status, status_changed_at)` index is probed in every partition. It reads only the few matching entries, so it stays cheap. To bound it, add `received_at >= NOW() - INTERVAL 2 DAY`: a message stuck for longer is handled by an alert, not by this job.

## Q8: Outbox relay poll

```sql
SELECT id, created_at, event_id, event_type, organization_id, payload
  FROM message_outbox
 WHERE published_at IS NULL
 ORDER BY id
 LIMIT 100
 FOR UPDATE SKIP LOCKED;
```

Raw SQL in Prisma (`$queryRaw`), inside a transaction that marks the rows published. `SKIP LOCKED` lets several relay instances poll without blocking each other. **Pruning:** none: the `(published_at, id)` index is read in each daily partition (about 15 in steady state), and only unpublished rows match. Mark rows with `UPDATE … WHERE id = ? AND created_at = ?` so the update prunes.

## Q9: Idempotency insert, including the duplicate path

```sql
INSERT INTO message_idempotency (consumer, event_id) VALUES (?, ?);
-- a redelivery fails with ER_DUP_ENTRY (1062)
```

```ts
const result = await processOnce(prisma, 'policy-engine.evaluate', envelope.eventId, async (tx) => {
  // side effects, in the same transaction as the ledger row
});
if (result.status === 'duplicate') return; // already processed
```

A primary-key insert on `(consumer, event_id)`. `processOnce` maps Prisma's `P2002` to `duplicate` and rolls back.

## Q10: Attachment hash hunt within an organization

```sql
SELECT message_id, received_at, filename, size_bytes, verdict
  FROM email_attachments
 WHERE organization_id = ? AND sha256 = ?
 ORDER BY received_at DESC
 LIMIT 200;
```

Prisma: `emailAttachment.findMany({ where: { organizationId, sha256 }, orderBy: { receivedAt: 'desc' }, take: 200 })`. **Pruning:** none unless the caller adds a `received_at` range, so `(organization_id, sha256)` is probed in every partition. That is acceptable for an investigation tool; add a time range when the UI has one.

## Q11: Delivery status counts per organization, last day

```sql
SELECT d.status, COUNT(*) AS deliveries
  FROM email_messages m
  JOIN email_deliveries d ON d.message_id = m.id AND d.received_at = m.received_at
 WHERE m.organization_id = ? AND m.received_at >= ? AND m.received_at < ?
 GROUP BY d.status;
```

`email_deliveries` has no `organization_id` index on purpose (see [indexing.md](indexing.md)), so the query drives from `email_messages (organization_id, received_at, id)` and joins on `(message_id, received_at)`. **Pruning:** the last day's partitions on both sides. Use `$queryRaw` in Prisma. Dashboards over longer periods come from ClickHouse, not MySQL.

## Q12: Audit log for an organization over a time range

```sql
SELECT id, created_at, actor_type, actor_id, action, resource_type, resource_id
  FROM audit_logs
 WHERE organization_id = ? AND created_at >= ? AND created_at < ?
 ORDER BY created_at DESC
 LIMIT 100;
```

Prisma: `auditLog.findMany({ where: { organizationId, createdAt: { gte: from, lt: to } }, orderBy: { createdAt: 'desc' }, take: 100 })`. **Pruning:** the partitions overlapping the range. Range scan on `(organization_id, created_at)`.

## Q13: Tenant resolution by recipient domain (mail path)

```sql
SELECT d.id, d.public_id, d.organization_id, d.name, d.status, d.inbound_enabled, d.outbound_enabled, o.status
  FROM domains d JOIN organizations o ON o.id = d.organization_id
 WHERE d.verified_name = ?;   -- then require d.status = 'active' AND o.status = 'active'
```

Use `resolveActiveDomain(writer, rawName)` from `@email-gateway/database` (step 2.1 D13): it normalizes the name like the api stores it (`normalizeDomainName`: case, trailing dot, IDN), runs `domain.findUnique({ where: { verifiedName } })` with the organization's status, and returns the owner only when the domain is `active` and the organization is `active`. `verified_name` is a MySQL generated column (`name` while `status` is `verified`, `active` or `suspended`, otherwise NULL) with a unique index, so the lookup is a `const` single-row read and **only the owner** can match: several organizations may hold a pending claim on the same `name` (unique per `(organization_id, live_name)`), and a pending claim never resolves a tenant. Never resolve a tenant with `WHERE name = ?`. Callers then check `inbound_enabled` / `outbound_enabled` for the direction. It runs for every SMTP transaction, so the ingestion step (3.x) can cache it in Redis.

**Post-queue owner** (step 2.2 D7, D13): `resolveDomainOwner(writer, rawName)` runs the same single-row lookup with the same normalization, but also resolves `suspended` domains and organizations (it returns `status` and `organizationStatus` with the owner). LMTP ingestion and the bounce handler use it for mail Postfix has already accepted in-session, so a suspension between acceptance and ingestion never loses a message; `pending_verification`, `verified` (not activated), `failed`, `disabled`, `deleted` domains and `pending_deletion`/`deleted` organizations still resolve to `null`. In-session decisions keep using `resolveActiveDomain`. Both are writer-only.

## Q14: Suppression check

```sql
SELECT reason, expires_at FROM delivery_suppressions WHERE organization_id = ? AND address = ?;
```

Prisma: `deliverySuppression.findUnique({ where: { organizationId_address: { organizationId, address } } })`. A unique-index lookup; a miss costs the same as a hit. Treat a row with `expires_at` in the past as not suppressed.

## Q15: Stored headers of one message

```sql
SELECT seq, name, value FROM email_headers
 WHERE message_id = ? AND received_at = ?
 ORDER BY seq;
```

Prisma: `emailHeader.findMany({ where: { messageId, receivedAt }, orderBy: { seq: 'asc' } })`. `(id, received_at)` come from the registry (Q2). **Pruning:** one partition. Unique `(message_id, seq, received_at)`.

## Q16: Tenant archive search, last 7 days

```sql
SELECT id, message_id, received_at, size_bytes, retain_until
  FROM email_archives
 WHERE organization_id = ? AND received_at >= ? AND received_at < ? AND deleted_at IS NULL
 ORDER BY received_at DESC
 LIMIT 50;
```

Prisma: `emailArchive.findMany({ where: { organizationId, receivedAt: { gte: from, lt: to }, deletedAt: null }, orderBy: { receivedAt: 'desc' }, take: 50 })`. **Pruning:** the partitions overlapping the range. Range scan on `(organization_id, received_at)`. Full-text archive search is OpenSearch (step 8.x), not MySQL.

## Q17: Bounce history of one recipient

```sql
SELECT occurred_at, bounce_type, smtp_code, enhanced_status
  FROM bounce_events
 WHERE organization_id = ? AND recipient_address = ? AND occurred_at >= ?
 ORDER BY occurred_at DESC
 LIMIT 20;
```

Prisma: `bounceEvent.findMany({ where: { organizationId, recipientAddress, occurredAt: { gte: since } }, orderBy: { occurredAt: 'desc' }, take: 20 })`. Index `(organization_id, recipient_address(100), occurred_at)`. **Pruning:** partitions from `since` onwards (the empty future partitions are included because the range is open-ended; add an upper bound to prune them too).

## Q18: Webhook retry queue

```sql
SELECT id, event_occurred_at, subscription_id, organization_id, attempt_count
  FROM webhook_deliveries
 WHERE status = 'pending' AND next_attempt_at <= ?
 ORDER BY next_attempt_at
 LIMIT 100;
```

Prisma: `webhookDelivery.findMany({ where: { status: 'pending', nextAttemptAt: { lte: now } }, orderBy: { nextAttemptAt: 'asc' }, take: 100 })`. A platform-level worker query (notification-worker), not tenant-scoped. Index `(status, next_attempt_at)`. **Pruning:** none (no partition key in the predicate), so every partition's index is probed with a short range read; the performance report shows this stays sub-millisecond at 2 months of retention.
