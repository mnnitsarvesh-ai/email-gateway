import { createRandom, pickCdf, sqlTime, uuidv7, zipfCdf } from './load';
import { type SqlClient } from '../partitioning/executor';

/**
 * Synthetic quarantine entries (step 5.3 §3, §9.2): the column set of a `quarantine_messages`
 * row as the 5.3 writers produce it (never `subject`: retired, §2.0), shared by the perf loader
 * (`loadSyntheticData`) and `loadQuarantineEntries`, which fills one organization with N entries
 * for the search-plan (EXPLAIN) checks of the api integration test (Q9). Test/perf data only:
 * ids, enums, codes and synthetic addresses; no message content.
 */

export const QUARANTINE_ENTRY_COLUMNS = [
  'public_id',
  'organization_id',
  'message_id',
  'message_received_at',
  'lifecycle_round',
  'scan_id',
  'evaluation_seq',
  'recipient_id',
  'rcpt_seq',
  'recipient_address',
  'user_id',
  'direction',
  'kind',
  'origin',
  'reason',
  'status',
  'envelope_from',
  'header_from',
  'has_attachments',
  'attachment_count',
  'size_bytes',
  'risk_score',
  'risk_level',
  'recommended_action',
  'risk_verdict',
  'has_hard_block',
  'hard_blocks',
  'reason_codes',
  'floor_reasons',
  'primary_engine',
  'decision_source',
  'decisive_policy_public_id',
  'decisive_policy_version_no',
  'decisive_rule_id',
  'explanation',
  'explanation_text',
  'eml_object_key',
  'quarantined_at',
  'expires_at',
  'state_changed_at',
  'released_at',
  'terminal_reason',
  'row_version',
  'created_at',
  'updated_at',
] as const;

export type QuarantineState =
  | 'held'
  | 'pending_approval'
  | 'releasing'
  | 'released'
  | 'rejected'
  | 'deleted'
  | 'expired'
  | 'superseded';

export type QuarantineReasonValue =
  | 'spam'
  | 'bulk'
  | 'phishing'
  | 'malware'
  | 'bec'
  | 'dlp'
  | 'policy'
  | 'suspicious'
  | 'engine_unavailable'
  | 'manual';

export interface QuarantineEntryFacts {
  organizationId: bigint;
  messageId: bigint;
  /** Epoch ms of `email_messages.received_at`. */
  receivedMs: number;
  lifecycleRound: number;
  scanId: bigint | null;
  recipientId: bigint;
  rcptSeq: number;
  recipientAddress: string;
  direction: 'inbound' | 'outbound' | 'internal';
  kind: 'quarantine' | 'review';
  origin: 'policy' | 'manual' | 'adopted';
  reason: QuarantineReasonValue;
  state: QuarantineState;
  envelopeFrom: string;
  attachmentCount: number;
  sizeBytes: number;
  riskScore: number;
  /** Tenant rule decisive: `{ policyPublicId, versionNo, ruleId }`; else the platform/floor. */
  decisive: { policyPublicId: string; versionNo: number; ruleId: string } | null;
  /** Epoch ms of the evaluation that created the entry. */
  quarantinedMs: number;
  /** Epoch ms of the last state change (≥ quarantinedMs). */
  stateChangedMs: number;
  holdDays: number;
}

const TERMINAL: ReadonlySet<QuarantineState> = new Set([
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
]);
const DAY_MS = 24 * 60 * 60 * 1000;

const ENGINE_BY_REASON: Record<QuarantineReasonValue, string> = {
  spam: 'rspamd',
  bulk: 'rspamd',
  phishing: 'url',
  malware: 'attachment',
  bec: 'bec',
  dlp: 'dlp',
  policy: 'policy',
  suspicious: 'rspamd',
  engine_unavailable: 'none',
  manual: 'none',
};
const VERDICT_BY_REASON: Record<QuarantineReasonValue, string> = {
  spam: 'spam',
  bulk: 'bulk',
  phishing: 'phishing',
  malware: 'malware',
  bec: 'bec',
  dlp: 'dlp_violation',
  policy: 'suspicious',
  suspicious: 'suspicious',
  engine_unavailable: 'unknown',
  manual: 'suspicious',
};

/** Risk level of a 0..1000 score (the 5.1 default bands). */
function levelOf(score: number): string {
  if (score >= 900) return 'critical';
  if (score >= 700) return 'high';
  if (score >= 400) return 'medium';
  if (score >= 200) return 'low';
  return 'none';
}

const ACTION_BY_LEVEL: Record<string, string> = {
  none: 'deliver',
  low: 'tag',
  medium: 'require_approval',
  high: 'quarantine',
  critical: 'block',
};

/** One `quarantine_messages` row in QUARANTINE_ENTRY_COLUMNS order. */
export function quarantineEntryRow(f: QuarantineEntryFacts): unknown[] {
  const received = sqlTime(f.receivedMs);
  const day = received.slice(0, 10).replaceAll('-', '/');
  const hardBlock = f.reason === 'malware' || (f.reason === 'phishing' && f.riskScore >= 900);
  const hardBlocks = hardBlock
    ? [f.reason === 'malware' ? 'hb.malware.attachment' : 'hb.phishing.url']
    : [];
  const floorReasons = hardBlock
    ? ['hard_block']
    : f.reason === 'engine_unavailable'
      ? ['engine_failure']
      : [];
  const decisionSource = f.decisive ? 'tenant_rule' : hardBlock ? 'floor' : 'platform_default';
  const level = levelOf(f.riskScore);
  const disposition = f.kind === 'review' ? 'require_approval' : 'quarantine';
  const terminal = TERMINAL.has(f.state);
  return [
    uuidv7(f.quarantinedMs),
    f.organizationId,
    f.messageId,
    received,
    f.lifecycleRound,
    f.scanId,
    f.lifecycleRound,
    f.recipientId,
    f.rcptSeq,
    f.recipientAddress,
    null,
    f.direction,
    f.kind,
    f.origin,
    f.reason,
    f.state,
    f.envelopeFrom,
    f.envelopeFrom,
    f.attachmentCount > 0,
    f.attachmentCount,
    f.sizeBytes,
    f.riskScore,
    level,
    ACTION_BY_LEVEL[level],
    VERDICT_BY_REASON[f.reason],
    hardBlock,
    JSON.stringify(hardBlocks),
    JSON.stringify([`policy.disposition.${disposition}`]),
    JSON.stringify(floorReasons),
    f.decisive ? 'policy' : ENGINE_BY_REASON[f.reason],
    decisionSource,
    f.decisive?.policyPublicId ?? null,
    f.decisive?.versionNo ?? null,
    f.decisive?.ruleId ?? null,
    JSON.stringify([{ code: 'summary', params: { disposition } }]),
    `Final disposition ${disposition} (synthetic perf data).`,
    `org/${f.organizationId}/messages/${day}/${f.messageId}.eml`,
    sqlTime(f.quarantinedMs),
    sqlTime(f.quarantinedMs + (f.kind === 'review' ? 7 : f.holdDays) * DAY_MS),
    sqlTime(f.stateChangedMs),
    f.state === 'released' ? sqlTime(f.stateChangedMs) : null,
    terminal && f.state !== 'released' ? f.state : null,
    terminal ? 2 : 1,
    sqlTime(f.quarantinedMs),
    sqlTime(f.stateChangedMs),
  ];
}

export interface QuarantineLoadOptions {
  /** An existing organizations.id (the only foreign key the rows need). */
  organizationId: bigint;
  /** Number of entries to insert. */
  count: number;
  now: Date;
  /** Entries are spread over [now − days, now]; default 90. */
  days?: number;
  /** PRNG seed; default 53. */
  seed?: number;
  /**
   * First synthetic message id (`message_id`/`recipient_id` have no FK); default 9e12, far above
   * any id the perf loader or a test creates. Entries of one call use consecutive ids from it.
   */
  firstMessageId?: bigint;
  /** Distinct recipient mailboxes (Zipf, s = 1.05); default 5 000. */
  recipients?: number;
  /** Distinct envelope senders (Zipf, s = 1.2); default 2 000. */
  senders?: number;
  /** Distinct decisive tenant policies (Zipf, s = 1.3); default 20. */
  policies?: number;
  /** Recipient domain; default `perf-quarantine.example`. */
  domain?: string;
  onProgress?: (done: number, total: number) => void;
}

export interface QuarantineLoadResult {
  rows: number;
  ms: number;
  /**
   * Values the search-plan checks can filter on, each present in the loaded data and
   * **selective** (a typical, not the most frequent, value: the 50th most frequent recipient,
   * the 20th sender, the 5th decisive policy; the most frequent one when fewer exist), so a plan
   * check exercises the filter's index rather than a scan that a very frequent value makes
   * cheap. `from`/`to` bound every loaded `quarantined_at`.
   */
  sample: {
    recipient: string;
    sender: string;
    policyPublicId: string;
    from: string;
    to: string;
  };
}

/** States (with weights) of a realistic store: mostly held, a tail of terminal states. */
const STATE_WEIGHTS: [QuarantineState, number][] = [
  ['held', 0.55],
  ['pending_approval', 0.05],
  ['releasing', 0.002],
  ['released', 0.15],
  ['rejected', 0.05],
  ['deleted', 0.05],
  ['expired', 0.128],
  ['superseded', 0.02],
];
const REASON_WEIGHTS: [QuarantineReasonValue, number][] = [
  ['spam', 0.45],
  ['bulk', 0.2],
  ['phishing', 0.1],
  ['malware', 0.03],
  ['bec', 0.03],
  ['dlp', 0.04],
  ['policy', 0.1],
  ['suspicious', 0.04],
  ['engine_unavailable', 0.005],
  ['manual', 0.005],
];
const RECIPIENTS_PER_MESSAGE_CDF = [0.75, 0.93, 1];
const ROWS_PER_STATEMENT = 1000;

function weighted<T>(table: readonly [T, number][], r: number): T {
  let rest = r;
  for (const [value, weight] of table) {
    if (rest < weight) return value;
    rest -= weight;
  }
  return table[table.length - 1]![0];
}

/** Deterministic UUID-shaped id (lower-case, version 7 nibble) from an integer. */
function syntheticUuid(n: number): string {
  const h = n.toString(16).padStart(12, '0').slice(-12);
  return `01900000-0000-7000-8000-${h}`;
}

/**
 * Inserts `count` quarantine entries for one organization (step 5.3 §9.2): realistic
 * distributions of state, reason, kind, direction (85 % inbound), recipient (Zipf over
 * `recipients` mailboxes), sender (Zipf over `senders`), decisive tenant policy (≈ 30 %, Zipf over
 * `policies`), risk and date (uniform over `days`, diurnal weighting). 1–3 recipients per
 * message (unique `(message_id, lifecycle_round, rcpt_seq)`). Multi-row INSERTs of 1 000 rows.
 * Never writes `subject`. Idempotency: the caller chooses a fresh `firstMessageId` per call.
 */
export async function loadQuarantineEntries(
  client: SqlClient,
  opts: QuarantineLoadOptions,
): Promise<QuarantineLoadResult> {
  if (!Number.isInteger(opts.count) || opts.count < 1) throw new Error('count must be ≥ 1');
  const rand = createRandom(opts.seed ?? 53);
  const days = opts.days ?? 90;
  const domain = opts.domain ?? 'perf-quarantine.example';
  const recipientCdf = zipfCdf(opts.recipients ?? 5000, 1.05);
  const senderCdf = zipfCdf(opts.senders ?? 2000, 1.2);
  const policyCdf = zipfCdf(opts.policies ?? 20, 1.3);
  const nowMs = opts.now.getTime();
  const startMs = nowMs - days * DAY_MS;
  const firstMessageId = opts.firstMessageId ?? 9_000_000_000_000n;
  const started = performance.now();

  const recipientHits = new Map<number, number>();
  const senderHits = new Map<number, number>();
  const policyHits = new Map<number, number>();
  const bump = (map: Map<number, number>, key: number) => map.set(key, (map.get(key) ?? 0) + 1);
  const columns = QUARANTINE_ENTRY_COLUMNS.map((c) => `\`${c}\``).join(', ');
  const tuple = `(${QUARANTINE_ENTRY_COLUMNS.map(() => '?').join(', ')})`;

  let done = 0;
  let message = 0n;
  let minMs = Number.POSITIVE_INFINITY;
  let maxMs = 0;
  while (done < opts.count) {
    const batch: unknown[][] = [];
    while (batch.length < ROWS_PER_STATEMENT && done + batch.length < opts.count) {
      const messageId = firstMessageId + message;
      message += 1n;
      // Diurnal: retry a uniform draw outside business hours with probability 0.65.
      let receivedMs = startMs + Math.floor(rand() * (nowMs - startMs - 60_000));
      const hour = new Date(receivedMs).getUTCHours();
      if ((hour < 3 || hour > 12) && rand() < 0.65) {
        receivedMs = startMs + Math.floor(rand() * (nowMs - startMs - 60_000));
      }
      const reason = weighted(REASON_WEIGHTS, rand());
      const direction = rand() < 0.85 ? 'inbound' : rand() < 0.7 ? 'outbound' : 'internal';
      const sender = pickCdf(senderCdf, rand());
      bump(senderHits, sender);
      const decisive =
        reason === 'policy' || reason === 'dlp' || rand() < 0.2
          ? (() => {
              const p = pickCdf(policyCdf, rand());
              bump(policyHits, p);
              return {
                policyPublicId: syntheticUuid(p + 1),
                versionNo: 1 + (p % 4),
                ruleId: `rule-${p % 7}`,
              };
            })()
          : null;
      const riskScore =
        reason === 'malware' || reason === 'phishing'
          ? 850 + Math.floor(rand() * 150)
          : 300 + Math.floor(rand() * 600);
      const attachmentCount =
        reason === 'malware' ? 1 + Math.floor(rand() * 2) : rand() < 0.3 ? 1 : 0;
      const sizeBytes = Math.floor(4000 * Math.exp(rand() * 7));
      const recipientCount = pickCdf(RECIPIENTS_PER_MESSAGE_CDF, rand()) + 1;
      const used = new Set<number>();
      for (let seq = 0; seq < recipientCount && done + batch.length < opts.count; seq += 1) {
        let r = pickCdf(recipientCdf, rand());
        while (used.has(r)) r = (r + 1) % (opts.recipients ?? 5000);
        used.add(r);
        bump(recipientHits, r);
        const state = weighted(STATE_WEIGHTS, rand());
        const kind = state === 'pending_approval' && rand() < 0.8 ? 'review' : 'quarantine';
        const quarantinedMs = receivedMs + 2000 + Math.floor(rand() * 8000);
        const stateChangedMs =
          state === 'held' || state === 'pending_approval'
            ? quarantinedMs
            : Math.min(nowMs, quarantinedMs + Math.floor(rand() * 10 * DAY_MS));
        minMs = Math.min(minMs, quarantinedMs);
        maxMs = Math.max(maxMs, quarantinedMs);
        batch.push(
          quarantineEntryRow({
            organizationId: opts.organizationId,
            messageId,
            receivedMs,
            lifecycleRound: 0,
            scanId: null,
            recipientId: messageId * 4n + BigInt(seq),
            rcptSeq: seq,
            recipientAddress: `user${r}@${domain}`,
            direction,
            kind,
            origin: reason === 'manual' ? 'manual' : 'policy',
            reason,
            state,
            envelopeFrom: `sender${sender}@sender${sender % 97}.example`,
            attachmentCount,
            sizeBytes,
            riskScore,
            decisive,
            quarantinedMs,
            stateChangedMs,
            holdDays: 30,
          }),
        );
      }
    }
    await client.$executeRawUnsafe(
      `INSERT INTO \`quarantine_messages\` (${columns}) VALUES ${batch.map(() => tuple).join(', ')}`,
      ...batch.flat(),
    );
    done += batch.length;
    opts.onProgress?.(done, opts.count);
  }

  const ranked = (map: Map<number, number>, rank: number) => {
    const sorted = [...map.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0]);
    return sorted[Math.min(rank, sorted.length - 1)]?.[0] ?? 0;
  };
  const sender = ranked(senderHits, 19);
  return {
    rows: done,
    ms: performance.now() - started,
    sample: {
      recipient: `user${ranked(recipientHits, 49)}@${domain}`,
      sender: `sender${sender}@sender${sender % 97}.example`,
      policyPublicId: syntheticUuid(ranked(policyHits, 4) + 1),
      from: sqlTime(minMs),
      to: sqlTime(maxMs + 1),
    },
  };
}
