import { uuidv7, sqlTime, type LoadSample } from './load';
import { type SqlClient } from '../partitioning/executor';

/**
 * Q25–Q30: the step 8.1 archive-worker queries (journal sweep, policy reconciler, capture
 * scheduler, expiry, disposal and index-queue claims; `archiveQueries`).
 * Q1–Q14 from D8 plus Q15–Q18 for the remaining high-volume tables (headers, archives,
 * bounces, webhook deliveries) and Q24 (query-examples.md) for the step 5.3 quarantine search filters (Q9; on the
 * entries of `--quarantine-entries` when given),
 * bounces, webhook deliveries), the same SQL as docs/database/query-examples.md. Parameters are picked from
 * the loaded data so every query returns realistic results.
 */

export interface QueryStep {
  label: string;
  sql: string;
  params: unknown[];
  /** The step is expected to fail (e.g. the duplicate idempotency insert). */
  expectError?: RegExp;
  /** Produces fresh params per execution (e.g. a new event id). */
  freshParams?: () => unknown[];
}

export interface PerfQuery {
  id: string;
  title: string;
  note: string;
  steps: QueryStep[];
}

const HOUR_MS = 60 * 60 * 1000;

export async function buildQueries(
  client: SqlClient,
  sample: LoadSample,
  now: Date,
): Promise<PerfQuery[]> {
  const org = sample.organizationId;
  const nowMs = now.getTime();
  const since24h = sqlTime(nowMs - 24 * HOUR_MS);
  const until = sqlTime(nowMs + 1000);
  const msg = sample.message;

  const firstPage = await client.$queryRawUnsafe<{ id: bigint; received_at: Date }[]>(
    `SELECT id, received_at FROM email_messages
      WHERE organization_id = ? AND received_at >= ? AND received_at < ?
      ORDER BY received_at DESC, id DESC LIMIT 50`,
    org,
    since24h,
    until,
  );
  const last = firstPage.at(-1);
  const cursorTime = last ? sqlTime(new Date(last.received_at).getTime()) : until;
  const cursorId = last ? last.id : 0n;

  const [topRecipient] = await client.$queryRawUnsafe<{ address: string }[]>(
    `SELECT recipient_address AS address FROM quarantine_messages
      WHERE organization_id = ? AND status = 'held'
      GROUP BY recipient_address ORDER BY COUNT(*) DESC LIMIT 1`,
    org,
  );
  // Step 5.3 Q9: every search has a bounded quarantined_at range (≤ 62 days).
  const quarantineFrom = sqlTime(nowMs - 62 * 24 * HOUR_MS);
  const [topSender] = await client.$queryRawUnsafe<{ address: string }[]>(
    `SELECT envelope_from AS address FROM quarantine_messages WHERE organization_id = ?
      GROUP BY envelope_from ORDER BY COUNT(*) DESC LIMIT 1`,
    org,
  );
  const fallback: QuarantineSearchSample = {
    recipient: topRecipient?.address ?? '',
    sender: topSender?.address ?? '',
    policyPublicId: '00000000-0000-7000-8000-000000000000',
    from: quarantineFrom,
    to: until,
  };
  const [hash] = await client.$queryRawUnsafe<{ sha256: string }[]>(
    `SELECT sha256 FROM email_attachments WHERE organization_id = ? AND received_at >= ? LIMIT 1`,
    org,
    sqlTime(nowMs - 7 * 24 * HOUR_MS),
  );
  // Step 8.1 sweep cursors: the first message / evaluation of the last 24 h, so each forward
  // read starts in the middle of the data like a running sweep.
  const [sweepCursor] = await client.$queryRawUnsafe<{ id: bigint; received_at: Date }[]>(
    `SELECT id, received_at FROM email_messages WHERE received_at >= ? ORDER BY received_at, id LIMIT 1`,
    since24h,
  );
  const [reconcileCursor] = await client.$queryRawUnsafe<{ id: bigint; received_at: Date }[]>(
    `SELECT id, received_at FROM policy_execution_logs WHERE received_at >= ? ORDER BY received_at, id LIMIT 1`,
    since24h,
  );
  const [archiveOrg] = await client.$queryRawUnsafe<{ organization_id: bigint }[]>(
    `SELECT organization_id FROM email_archives GROUP BY organization_id ORDER BY COUNT(*) DESC LIMIT 1`,
  );
  const duplicateEventId = uuidv7(nowMs);
  await client.$executeRawUnsafe(
    'INSERT INTO message_idempotency (consumer, event_id) VALUES (?, ?)',
    'perf.duplicate',
    duplicateEventId,
  );

  return [
    {
      id: 'Q1',
      title: 'Tenant message list, last 24 h, keyset pagination',
      note: 'Prunes to the partitions overlapping the last 24 h; backward range scan on (organization_id, received_at, id).',
      steps: [
        {
          label: 'first page',
          sql: `SELECT id, received_at, status, direction, envelope_from, subject, final_verdict, risk_score
  FROM email_messages
 WHERE organization_id = ? AND received_at >= ? AND received_at < ?
 ORDER BY received_at DESC, id DESC
 LIMIT 50`,
          params: [org, since24h, until],
        },
        {
          label: 'next page (keyset cursor = last row of the previous page)',
          sql: `SELECT id, received_at, status, direction, envelope_from, subject, final_verdict, risk_score
  FROM email_messages
 WHERE organization_id = ? AND received_at >= ?
   AND (received_at < ? OR (received_at = ? AND id < ?))
 ORDER BY received_at DESC, id DESC
 LIMIT 50`,
          params: [org, since24h, cursorTime, cursorTime, cursorId],
        },
      ],
    },
    {
      id: 'Q2',
      title: 'Message detail by public_id (registry → message → recipients)',
      note: 'The registry lookup yields (id, received_at), so both partitioned reads prune to one partition.',
      steps: [
        {
          label: 'registry',
          sql: `SELECT id, organization_id, received_at FROM message_identities WHERE public_id = ?`,
          params: [msg.publicId],
        },
        {
          label: 'message',
          sql: `SELECT * FROM email_messages WHERE id = ? AND received_at = ? AND organization_id = ?`,
          params: [msg.id, msg.receivedAt, msg.organizationId],
        },
        {
          label: 'recipients',
          sql: `SELECT id, rcpt_seq, address, status, final_action
  FROM email_recipients
 WHERE message_id = ? AND received_at = ?
 ORDER BY rcpt_seq`,
          params: [msg.id, msg.receivedAt],
        },
      ],
    },
    {
      id: 'Q3',
      title: 'Scans and engine results for a message',
      note: 'Both tables prune to the message partition; the rounds come from the (message_id, lifecycle_round, received_at) unique key, the engine rows (attempts and the final result) from the (scan_id, engine, attempt, received_at) unique key.',
      steps: [
        {
          label: 'scans + engine results',
          sql: `SELECT s.id AS scan_id, s.lifecycle_round, s.scan_kind, s.status, s.scan_verdict,
       r.engine, r.attempt, r.is_final, r.outcome, r.score, r.duration_ms
  FROM email_scans s
  JOIN scan_engine_results r ON r.scan_id = s.id AND r.received_at = s.received_at
 WHERE s.message_id = ? AND s.received_at = ?
 ORDER BY s.lifecycle_round DESC, r.engine, r.attempt`,
          params: [msg.id, msg.receivedAt],
        },
      ],
    },
    {
      id: 'Q4',
      title: 'Status history and events for a message',
      note: 'One partition each, via the (message_id, …, received_at) keys.',
      steps: [
        {
          label: 'status history',
          sql: `SELECT version, from_status, to_status, reason_code, changed_at
  FROM email_message_status_history
 WHERE message_id = ? AND received_at = ?
 ORDER BY version`,
          params: [msg.id, msg.receivedAt],
        },
        {
          label: 'events',
          sql: `SELECT event_type, occurred_at, source_service, details
  FROM email_events
 WHERE message_id = ? AND received_at = ?
 ORDER BY occurred_at, id`,
          params: [msg.id, msg.receivedAt],
        },
      ],
    },
    {
      id: 'Q5',
      title: 'Quarantine search for an organization (state filter, newest first, keyset)',
      note: 'quarantine_messages is not partitioned (step 5.3 Q9). A dominant state (held ≈ 55 %) is read by a backward scan of (organization_id, quarantined_at, id) filtering the state (≈ 2 index entries per row returned, no sort); a rare state uses (organization_id, status, quarantined_at, id). Never reads `subject` (retired).',
      steps: [
        {
          label: 'quarantine search',
          sql: `SELECT id, public_id, recipient_address, envelope_from, reason, risk_score, quarantined_at
  FROM quarantine_messages
 WHERE organization_id = ? AND status = 'held' AND quarantined_at >= ? AND quarantined_at < ?
 ORDER BY quarantined_at DESC, id DESC
 LIMIT 50`,
          params: [org, quarantineFrom, until],
        },
      ],
    },
    {
      id: 'Q6',
      title: 'End-user quarantine by recipient address',
      note: 'Prefix index (organization_id, recipient_address(100), quarantined_at, id) (step 5.3 Q9, Q15); the address is re-checked on the row, the state is filtered on the row.',
      steps: [
        {
          label: 'own quarantine',
          sql: `SELECT id, public_id, envelope_from, reason, status, quarantined_at, expires_at
  FROM quarantine_messages
 WHERE organization_id = ? AND recipient_address = ? AND quarantined_at >= ? AND quarantined_at < ?
   AND status IN ('held', 'pending_approval')
 ORDER BY quarantined_at DESC, id DESC
 LIMIT 50`,
          params: [org, topRecipient?.address ?? '', quarantineFrom, until],
        },
      ],
    },
    {
      id: 'Q7',
      title: 'Stuck-message reconciliation',
      note: 'No partition-column predicate, so every partition is probed through (status, status_changed_at). Acceptable for a periodic job; it reads only the few matching index entries.',
      steps: [
        {
          label: 'stuck messages',
          sql: `SELECT id, received_at, organization_id, status, status_changed_at
  FROM email_messages
 WHERE status IN ('scanning', 'policy_evaluated', 'delivery_pending')
   AND status_changed_at < ?
 ORDER BY status_changed_at
 LIMIT 500`,
          params: [sqlTime(nowMs - 15 * 60 * 1000)],
        },
      ],
    },
    {
      id: 'Q8',
      title: 'Outbox relay poll',
      note: 'Reads (published_at, id) in every daily partition; unpublished rows are few, so each probe is short.',
      steps: [
        {
          label: 'poll',
          sql: `SELECT id, created_at, event_id, event_type, organization_id, payload
  FROM message_outbox
 WHERE published_at IS NULL
 ORDER BY id
 LIMIT 100
 FOR UPDATE SKIP LOCKED`,
          params: [],
        },
      ],
    },
    {
      id: 'Q9',
      title: 'Idempotency insert, including the duplicate path',
      note: 'Primary-key insert; the duplicate fails with ER_DUP_ENTRY (1062), which processOnce maps to "duplicate".',
      steps: [
        {
          label: 'first delivery (new event id per run)',
          sql: `INSERT INTO message_idempotency (consumer, event_id) VALUES (?, ?)`,
          params: ['perf.new', uuidv7(nowMs)],
          freshParams: () => ['perf.new', uuidv7(Date.now())],
        },
        {
          label: 'redelivery (duplicate key)',
          sql: `INSERT INTO message_idempotency (consumer, event_id) VALUES (?, ?)`,
          params: ['perf.duplicate', duplicateEventId],
          expectError: /1062|Duplicate entry|Unique constraint/i,
        },
      ],
    },
    {
      id: 'Q10',
      title: 'Attachment hash hunt within an organization',
      note: 'Index (organization_id, sha256) in every partition (no time predicate). Add a received_at range to prune when the UI allows it.',
      steps: [
        {
          label: 'hash hunt',
          sql: `SELECT message_id, received_at, filename, size_bytes, verdict
  FROM email_attachments
 WHERE organization_id = ? AND sha256 = ?
 ORDER BY received_at DESC
 LIMIT 200`,
          params: [org, hash?.sha256 ?? ''],
        },
      ],
    },
    {
      id: 'Q11',
      title: 'Delivery status counts per organization, last day',
      note: 'email_deliveries has no organization index by design (write-heavy), so the query drives from email_messages (organization_id, received_at, id) and joins on (message_id, received_at).',
      steps: [
        {
          label: 'status counts',
          sql: `SELECT d.status, COUNT(*) AS deliveries
  FROM email_messages m
  JOIN email_deliveries d ON d.message_id = m.id AND d.received_at = m.received_at
 WHERE m.organization_id = ? AND m.received_at >= ? AND m.received_at < ?
 GROUP BY d.status`,
          params: [org, since24h, until],
        },
      ],
    },
    {
      id: 'Q12',
      title: 'Audit log for an organization over a time range',
      note: 'Prunes to the partitions overlapping the range; range scan on (organization_id, created_at).',
      steps: [
        {
          label: 'audit range',
          sql: `SELECT id, created_at, actor_type, actor_id, action, resource_type, resource_id
  FROM audit_logs
 WHERE organization_id = ? AND created_at >= ? AND created_at < ?
 ORDER BY created_at DESC
 LIMIT 100`,
          params: [org, sqlTime(nowMs - 7 * 24 * HOUR_MS), until],
        },
      ],
    },
    {
      id: 'Q13',
      title: 'Tenant resolution by recipient domain (mail path)',
      note: 'Unique index on the generated domains.verified_name: only a verified owner matches, so a pending claim never resolves a tenant.',
      steps: [
        {
          label: 'domain lookup',
          sql: `SELECT id, organization_id, inbound_enabled FROM domains WHERE verified_name = ? AND inbound_enabled = 1`,
          params: [sample.domainName],
        },
      ],
    },
    {
      id: 'Q14',
      title: 'Suppression check (organization_id, address)',
      note: 'Unique index lookup; a miss is as cheap as a hit.',
      steps: [
        {
          label: 'hit',
          sql: `SELECT reason, expires_at FROM delivery_suppressions WHERE organization_id = ? AND address = ?`,
          params: [sample.suppressedAddress.organizationId, sample.suppressedAddress.address],
        },
        {
          label: 'miss',
          sql: `SELECT reason, expires_at FROM delivery_suppressions WHERE organization_id = ? AND address = ?`,
          params: [sample.suppressedAddress.organizationId, 'nobody@nowhere.example'],
        },
      ],
    },
    {
      id: 'Q15',
      title: 'Stored headers of one message',
      note: 'Unique (message_id, seq, received_at); received_at from the registry prunes to one partition.',
      steps: [
        {
          label: 'headers',
          sql: `SELECT seq, name, value FROM email_headers
 WHERE message_id = ? AND received_at = ?
 ORDER BY seq`,
          params: [msg.id, msg.receivedAt],
        },
      ],
    },
    {
      id: 'Q16',
      title: 'Tenant archive search, last 7 days',
      note: 'Range scan on (organization_id, received_at), pruned to the partitions overlapping the window.',
      steps: [
        {
          label: 'first page',
          sql: `SELECT id, message_id, received_at, size_bytes, retain_until
  FROM email_archives
 WHERE organization_id = ? AND received_at >= ? AND received_at < ? AND deleted_at IS NULL
 ORDER BY received_at DESC
 LIMIT 50`,
          params: [org, sqlTime(nowMs - 7 * 24 * HOUR_MS), until],
        },
      ],
    },
    {
      id: 'Q17',
      title: 'Bounce history of one recipient, last 30 days',
      note: 'Index (organization_id, recipient_address(100), occurred_at), pruned by occurred_at.',
      steps: [
        {
          label: 'history',
          sql: `SELECT occurred_at, bounce_type, smtp_code, enhanced_status
  FROM bounce_events
 WHERE organization_id = ? AND recipient_address = ? AND occurred_at >= ?
 ORDER BY occurred_at DESC
 LIMIT 20`,
          params: [org, sample.bouncedAddress, sqlTime(nowMs - 30 * 24 * HOUR_MS)],
        },
      ],
    },
    {
      id: 'Q18',
      title: 'Webhook retry queue (due pending deliveries)',
      note: 'Index (status, next_attempt_at). No partition key in the predicate, so every partition index is probed; each probe is a short range read.',
      steps: [
        {
          label: 'due',
          sql: `SELECT id, event_occurred_at, subscription_id, organization_id, attempt_count
  FROM webhook_deliveries
 WHERE status = 'pending' AND next_attempt_at <= ?
 ORDER BY next_attempt_at
 LIMIT 100`,
          params: [sqlTime(nowMs + 2 * HOUR_MS)],
        },
      ],
    },
    {
      id: 'Q24',
      title: 'Quarantine search filters (step 5.3 Q9, keyset, bounded range)',
      note: 'Each filter starts from an (organization_id, <filter>, quarantined_at[, id]) index prefix: default view (organization_id, quarantined_at, id); recipient (organization_id, recipient_address(100), quarantined_at, id); sender (organization_id, envelope_from(100), quarantined_at); state (organization_id, status, quarantined_at, id); decisive policy (organization_id, decisive_policy_public_id, quarantined_at).',
      steps: quarantineSearchSteps(org, sample.quarantine ?? fallback),
    },
    ...archiveQueries({
      nowMs,
      organizationId: archiveOrg?.organization_id ?? org,
      sweepCursor: sweepCursor
        ? { id: sweepCursor.id, receivedAt: new Date(sweepCursor.received_at).getTime() }
        : { id: 0n, receivedAt: nowMs - 24 * HOUR_MS },
      reconcileCursor: reconcileCursor
        ? { id: reconcileCursor.id, receivedAt: new Date(reconcileCursor.received_at).getTime() }
        : { id: 0n, receivedAt: nowMs - 24 * HOUR_MS },
    }),
  ];
}

/** Inputs of the step 8.1 archive queries (Q25–Q30). */
export interface ArchiveQueryInputs {
  nowMs: number;
  /** An organization with archive records. */
  organizationId: bigint;
  /** Journal completeness sweep cursor: last processed email_messages (id, received_at). */
  sweepCursor: { id: bigint; receivedAt: number };
  /** Policy reconciler cursor: last processed policy_execution_logs (id, received_at). */
  reconcileCursor: { id: bigint; receivedAt: number };
}

const DAY_MS = 24 * HOUR_MS;

/**
 * Step 8.1 (docs/plan/steps/23-journaling-archiving.md A2, A13, A14, A16): the archive-worker's
 * hot queries, as WP3 issues them. Defaults of §4.8: sweep batch 1000, safety lag 120 s (journal)
 * / 300 s (policy), lifecycle batch 200, index batch 500.
 */
export function archiveQueries(q: ArchiveQueryInputs): PerfQuery[] {
  const now = sqlTime(q.nowMs);
  return [
    {
      id: 'Q25',
      title: 'Journal completeness sweep, forward cursor over email_messages (step 8.1 A2)',
      note: 'PRIMARY (id, received_at) range per partition; received_at >= cursor − 1 day prunes to the recent partitions; ordered merge of the per-partition PK scans, LIMIT 1000.',
      steps: [
        {
          label: 'next batch',
          sql: `SELECT id, received_at, organization_id, direction, status
  FROM email_messages
 WHERE id > ? AND received_at >= ? AND created_at <= ?
 ORDER BY id
 LIMIT 1000`,
          params: [
            q.sweepCursor.id,
            sqlTime(q.sweepCursor.receivedAt - DAY_MS),
            sqlTime(q.nowMs - 120_000),
          ],
        },
      ],
    },
    {
      id: 'Q26',
      title: 'Policy ARCHIVE reconciler, forward cursor over policy_execution_logs (step 8.1 A2)',
      note: 'Same shape as Q25 on policy_execution_logs: PRIMARY (id, received_at) range, pruned by received_at; the ARCHIVE action filter is applied to the 1000 rows in the worker.',
      steps: [
        {
          label: 'next batch',
          sql: `SELECT id, received_at, organization_id, message_id, actions
  FROM policy_execution_logs
 WHERE id > ? AND received_at >= ? AND created_at <= ?
 ORDER BY id
 LIMIT 1000`,
          params: [
            q.reconcileCursor.id,
            sqlTime(q.reconcileCursor.receivedAt - DAY_MS),
            sqlTime(q.nowMs - 300_000),
          ],
        },
      ],
    },
    {
      id: 'Q27',
      title: 'Capture scheduler: due intents (step 8.1 A2)',
      note: 'Index (status, next_check_at): two short ranges (pending, captured_open) in every live partition (2 months retention: 3 partitions plus pmax); FOR UPDATE SKIP LOCKED.',
      steps: [
        {
          label: 'claim',
          sql: `SELECT id, received_at, organization_id, message_id, status
  FROM archive_capture_intents
 WHERE status IN ('pending', 'captured_open') AND next_check_at <= ?
 ORDER BY next_check_at
 LIMIT 20
 FOR UPDATE SKIP LOCKED`,
          params: [now],
        },
      ],
    },
    {
      id: 'Q28',
      title: 'Lifecycle: expired records of one organization (step 8.1 A13)',
      note: 'Index (organization_id, status, retain_until): one range per partition (email_archives is never dropped, so every monthly partition is probed; each probe is a short range read).',
      steps: [
        {
          label: 'expiry batch',
          sql: `SELECT id, received_at, retain_until, expiry_action, lock_mode
  FROM email_archives
 WHERE organization_id = ? AND status = 'active' AND retain_until <= ?
 ORDER BY retain_until
 LIMIT 200`,
          params: [q.organizationId, now],
        },
        {
          label: 'review queue',
          sql: `SELECT id, received_at, message_public_id, retain_until
  FROM email_archives
 WHERE organization_id = ? AND status = 'expiry_review'
 ORDER BY retain_until
 LIMIT 50`,
          params: [q.organizationId],
        },
      ],
    },
    {
      id: 'Q29',
      title: 'Disposal pipeline claim (step 8.1 A14)',
      note: 'Index (state, next_attempt_at): one short range per open state in every partition (never dropped); FOR UPDATE SKIP LOCKED.',
      steps: [
        {
          label: 'claim',
          sql: `SELECT id, requested_at, organization_id, archive_record_id, state
  FROM archive_disposals
 WHERE state IN ('shredded', 'objects_deleted', 'index_deleted') AND next_attempt_at <= ?
 ORDER BY next_attempt_at
 LIMIT 50
 FOR UPDATE SKIP LOCKED`,
          params: [now],
        },
      ],
    },
    {
      id: 'Q30',
      title: 'Search index queue claim (step 8.1 A16)',
      note: 'Unpartitioned transient queue; index (available_at, id) gives the claim order without a sort; FOR UPDATE SKIP LOCKED.',
      steps: [
        {
          label: 'claim',
          sql: `SELECT id, organization_id, message_id, received_at, op
  FROM archive_index_queue
 WHERE available_at <= ?
 ORDER BY available_at, id
 LIMIT 500
 FOR UPDATE SKIP LOCKED`,
          params: [now],
        },
      ],
    },
  ];
}

/** Filter values for Q24 (from `loadQuarantineEntries` or the generic data). */
export interface QuarantineSearchSample {
  recipient: string;
  sender: string;
  policyPublicId: string;
  from: string;
  to: string;
}

/** The five Q9 search shapes the api integration test checks with EXPLAIN (WP4). */
export function quarantineSearchSteps(
  organizationId: bigint,
  q: QuarantineSearchSample,
): QueryStep[] {
  const select = `SELECT id, public_id, recipient_address, envelope_from, reason, status, risk_level, quarantined_at, expires_at
  FROM quarantine_messages`;
  const tail = `
 ORDER BY quarantined_at DESC, id DESC
 LIMIT 50`;
  const range = 'quarantined_at >= ? AND quarantined_at < ?';
  return [
    {
      label: 'default view',
      sql: `${select}
 WHERE organization_id = ? AND ${range}${tail}`,
      params: [organizationId, q.from, q.to],
    },
    {
      label: 'recipient',
      sql: `${select}
 WHERE organization_id = ? AND recipient_address = ? AND ${range}${tail}`,
      params: [organizationId, q.recipient, q.from, q.to],
    },
    {
      label: 'sender',
      sql: `${select}
 WHERE organization_id = ? AND envelope_from = ? AND ${range}${tail}`,
      params: [organizationId, q.sender, q.from, q.to],
    },
    {
      label: 'state',
      sql: `${select}
 WHERE organization_id = ? AND status = 'held' AND ${range}${tail}`,
      params: [organizationId, q.from, q.to],
    },
    {
      label: 'decisive policy',
      sql: `${select}
 WHERE organization_id = ? AND decisive_policy_public_id = ? AND ${range}${tail}`,
      params: [organizationId, q.policyPublicId, q.from, q.to],
    },
  ];
}
