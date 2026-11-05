import { uuidv7, sqlTime, type LoadSample } from './load';
import { type SqlClient } from '../partitioning/executor';

/**
 * Q1–Q14 from D8 plus Q15–Q18 for the remaining high-volume tables (headers, archives,
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
      WHERE organization_id = ? AND status = 'quarantined'
      GROUP BY recipient_address ORDER BY COUNT(*) DESC LIMIT 1`,
    org,
  );
  const [hash] = await client.$queryRawUnsafe<{ sha256: string }[]>(
    `SELECT sha256 FROM email_attachments WHERE organization_id = ? AND received_at >= ? LIMIT 1`,
    org,
    sqlTime(nowMs - 7 * 24 * HOUR_MS),
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
      title: 'Quarantine list for an organization (newest first)',
      note: 'quarantine_messages is not partitioned; backward scan of (organization_id, status, quarantined_at).',
      steps: [
        {
          label: 'quarantine list',
          sql: `SELECT id, public_id, recipient_address, envelope_from, subject, reason, risk_score, quarantined_at
  FROM quarantine_messages
 WHERE organization_id = ? AND status = 'quarantined'
 ORDER BY quarantined_at DESC
 LIMIT 50`,
          params: [org],
        },
      ],
    },
    {
      id: 'Q6',
      title: 'End-user quarantine by recipient address',
      note: 'Prefix index (organization_id, recipient_address(100), status); the address is re-checked on the row.',
      steps: [
        {
          label: 'own quarantine',
          sql: `SELECT id, public_id, envelope_from, subject, reason, quarantined_at, expires_at
  FROM quarantine_messages
 WHERE organization_id = ? AND recipient_address = ? AND status = 'quarantined'
 ORDER BY quarantined_at DESC
 LIMIT 50`,
          params: [org, topRecipient?.address ?? ''],
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
  ];
}
