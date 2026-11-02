import { randomBytes } from 'node:crypto';
import { type SqlClient } from '../partitioning/executor';

/**
 * Synthetic data for the performance test (D8). Messages are generated in time order, so
 * registry ids grow with received_at exactly as in production, and every child row copies its
 * message's received_at. Distributions are skewed the way real tenants are: a Zipf spread of
 * volume across organizations and recipients, a diurnal traffic curve, 1–4 recipients
 * (avg ≈ 1.5), 0–2 attachments, 1.1 scans with 5 engine results each, 6 events and 5 status
 * transitions per message, one delivery per delivered recipient with ≈ 1.2 attempts, and
 * quarantine for ≈ 5% of recipients. Rows are inserted with multi-row INSERTs of at most
 * ROWS_PER_STATEMENT rows and placeholders only.
 */

export const ROWS_PER_STATEMENT = 1000;
const MESSAGES_PER_CHUNK = 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

export interface LoadOptions {
  messages: number;
  organizations: number;
  /** Data is spread over [now − days, now]. */
  days: number;
  now: Date;
  seed: number;
  onProgress?: (done: number, total: number) => void;
}

export interface TableLoadStat {
  table: string;
  rows: number;
  ms: number;
}

/** Values the query suite needs, picked from the generated data. */
export interface LoadSample {
  organizationId: bigint;
  message: { id: bigint; publicId: string; receivedAt: string; organizationId: bigint };
  domainName: string;
  suppressedAddress: { organizationId: bigint; address: string };
  /** A recipient of the sample organization with at least one bounce. */
  bouncedAddress: string;
}

export interface LoadResult {
  stats: TableLoadStat[];
  sample: LoadSample;
  totalMs: number;
}

/** Deterministic PRNG (mulberry32) so runs with the same seed have the same shape. */
export function createRandom(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Cumulative Zipf weights over `n` items with exponent `s`. */
export function zipfCdf(n: number, s: number): number[] {
  const weights = Array.from({ length: n }, (_, i) => 1 / Math.pow(i + 1, s));
  const total = weights.reduce((a, b) => a + b, 0);
  let acc = 0;
  return weights.map((w) => (acc += w / total));
}

export function pickCdf(cdf: readonly number[], r: number): number {
  let lo = 0;
  let hi = cdf.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (r <= cdf[mid]!) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

/** UUIDv7 for a given millisecond timestamp. */
export function uuidv7(ms: number): string {
  const b = randomBytes(16);
  b.writeUIntBE(ms, 0, 6);
  b[6] = (b[6]! & 0x0f) | 0x70;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const hex64 = () => randomBytes(32).toString('hex');

/** DATETIME(3) literal in UTC. */
export function sqlTime(ms: number): string {
  return new Date(ms).toISOString().replace('T', ' ').replace('Z', '');
}

type Row = unknown[];

class Loader {
  readonly stats = new Map<string, TableLoadStat>();
  constructor(private readonly client: SqlClient) {}

  /**
   * Inserts rows in statements of ROWS_PER_STATEMENT. With `returnIds`, returns the
   * AUTO_INCREMENT id of every row: the client has a single connection and nothing else
   * writes to the perf schema, so ids within one statement are consecutive from
   * LAST_INSERT_ID() (innodb_autoinc_lock_mode=2, simple inserts).
   */
  async insert(
    table: string,
    columns: string[],
    rows: Row[],
    returnIds = false,
  ): Promise<bigint[]> {
    const ids: bigint[] = [];
    const stat = this.stats.get(table) ?? { table, rows: 0, ms: 0 };
    this.stats.set(table, stat);
    const tuple = `(${columns.map(() => '?').join(', ')})`;
    for (let offset = 0; offset < rows.length; offset += ROWS_PER_STATEMENT) {
      const batch = rows.slice(offset, offset + ROWS_PER_STATEMENT);
      const sql =
        `INSERT INTO \`${table}\` (${columns.map((c) => `\`${c}\``).join(', ')}) VALUES ` +
        batch.map(() => tuple).join(', ');
      const started = performance.now();
      const affected = await this.client.$executeRawUnsafe(sql, ...batch.flat());
      if (returnIds) {
        const [row] = await this.client.$queryRawUnsafe<{ id: bigint | number }[]>(
          'SELECT LAST_INSERT_ID() AS id',
        );
        const first = BigInt(row!.id);
        for (let i = 0; i < batch.length; i += 1) ids.push(first + BigInt(i));
      }
      stat.ms += performance.now() - started;
      if (affected !== batch.length) {
        throw new Error(`${table}: inserted ${affected} rows, expected ${batch.length}`);
      }
      stat.rows += batch.length;
    }
    return ids;
  }
}

const VERDICTS: [string, number][] = [
  ['clean', 0.8],
  ['spam', 0.1],
  ['bulk', 0.05],
  ['phishing', 0.02],
  ['malware', 0.005],
  ['suspicious', 0.025],
];
const QUARANTINE_P: Record<string, number> = {
  phishing: 1,
  malware: 1,
  spam: 0.3,
  suspicious: 0.3,
};
const RECIPIENTS_CDF = [0.65, 0.87, 0.95, 1];
const ATTACHMENTS_CDF = [0.45, 0.8, 1];
const ENGINES = ['rspamd', 'clamav', 'yara', 'url', 'reputation'];
const EVENT_TYPES = [
  'message.received',
  'scan.started',
  'scan.completed',
  'policy.evaluated',
  'delivery.queued',
  'delivery.completed',
];
const STUCK_STATUSES = ['scanning', 'policy_evaluated', 'delivery_queued'];
const CONTENT_TYPES = ['application/pdf', 'image/png', 'application/zip', 'text/calendar'];

/** Diurnal weight by UTC hour (peaks in Indian business hours, 03:30–12:30 UTC). */
/** Allow-listed headers stored per message (step 3.x keeps a fixed set, values truncated). */
const HEADER_NAMES = [
  'Received',
  'From',
  'To',
  'Subject',
  'Date',
  'Message-ID',
  'Authentication-Results',
  'DKIM-Signature',
];
/** Share of delivered recipients that later bounce (asynchronous DSN). */
const BOUNCE_P = 0.01;
/** Archive retention used for synthetic archive rows (7 years). */
const ARCHIVE_RETENTION_MS = 7 * 365 * 24 * 60 * 60 * 1000;
const HOUR_WEIGHT = Array.from({ length: 24 }, (_, h) => (h >= 3 && h <= 12 ? 1 : 0.35));

export async function loadSyntheticData(client: SqlClient, opts: LoadOptions): Promise<LoadResult> {
  const rand = createRandom(opts.seed);
  const loader = new Loader(client);
  const started = performance.now();
  const nowMs = opts.now.getTime();
  const startMs = nowMs - opts.days * DAY_MS;
  const pick = <T>(items: readonly T[]) => items[Math.floor(rand() * items.length)]!;

  // --- Control plane: plan, organizations, domains, suppressions --------------------------
  const ts = sqlTime(startMs);
  const [planId] = await loader.insert(
    'organization_plans',
    ['code', 'name', 'is_active', 'default_limits', 'default_features', 'created_at', 'updated_at'],
    [['perf', 'Perf', true, '{}', '{}', ts, ts]],
    true,
  );
  const orgRows: Row[] = Array.from({ length: opts.organizations }, (_, i) => [
    uuidv7(startMs),
    `perf-org-${String(i + 1).padStart(2, '0')}`,
    `Perf organization ${i + 1}`,
    'customer',
    'active',
    planId,
    'saas',
    'ap-south-1',
    ts,
    ts,
  ]);
  const orgIds = await loader.insert(
    'organizations',
    [
      'public_id',
      'slug',
      'name',
      'kind',
      'status',
      'plan_id',
      'deployment_mode',
      'data_region',
      'created_at',
      'updated_at',
    ],
    orgRows,
    true,
  );
  const domainsByOrg: { id: bigint; name: string }[][] = [];
  const domainRows: Row[] = [];
  const domainNames: string[] = [];
  orgIds.forEach((orgId, i) => {
    const count = 1 + Math.floor(rand() * 3);
    for (let d = 0; d < count; d += 1) {
      const name = `org${String(i + 1).padStart(2, '0')}-${String.fromCharCode(97 + d)}.perf.test`;
      domainNames.push(name);
      domainRows.push([uuidv7(startMs), orgId, name, 'verified', true, false, ts, ts, ts]);
    }
  });
  const domainIds = await loader.insert(
    'domains',
    [
      'public_id',
      'organization_id',
      'name',
      'status',
      'inbound_enabled',
      'outbound_enabled',
      'verified_at',
      'created_at',
      'updated_at',
    ],
    domainRows,
    true,
  );
  let cursor = 0;
  orgIds.forEach((orgId, i) => {
    const list: { id: bigint; name: string }[] = [];
    while (cursor < domainRows.length && domainRows[cursor]![1] === orgId) {
      list.push({ id: domainIds[cursor]!, name: domainNames[cursor]! });
      cursor += 1;
    }
    domainsByOrg[i] = list;
  });

  // Every even-numbered organization (including the sample one) archives all mail and has
  // one webhook subscription receiving a delivery per message.
  const featured = (org: number) => org % 2 === 0;
  const subscriptionRows: Row[] = [];
  const subscriptionOrgs: number[] = [];
  orgIds.forEach((orgId, i) => {
    if (!featured(i)) return;
    subscriptionRows.push([
      uuidv7(startMs),
      orgId,
      'Perf SIEM',
      `https://siem${i}.example/hooks/gateway`,
      JSON.stringify(['message.processed']),
      `perf-ciphertext-${i}`,
      ts,
      ts,
    ]);
    subscriptionOrgs.push(i);
  });
  const subscriptionIds = await loader.insert(
    'webhook_subscriptions',
    [
      'public_id',
      'organization_id',
      'name',
      'url',
      'event_types',
      'secret_ciphertext',
      'created_at',
      'updated_at',
    ],
    subscriptionRows,
    true,
  );
  const subscriptionByOrg = new Map(subscriptionOrgs.map((org, k) => [org, subscriptionIds[k]!]));

  const ADDRESS_POOL = 500;
  const addressCdf = zipfCdf(ADDRESS_POOL, 1.05);
  const address = (org: number) => {
    const user = pickCdf(addressCdf, rand());
    return `user${user}@${domainsByOrg[org]![user % domainsByOrg[org]!.length]!.name}`;
  };

  const suppressionRows: Row[] = [];
  const suppressed = new Set<string>();
  orgIds.forEach((orgId, i) => {
    for (let k = 0; k < 250; k += 1) {
      const addr = `bounced${k}@remote${k % 37}.example`;
      const key = `${i}:${addr}`;
      if (suppressed.has(key)) continue;
      suppressed.add(key);
      const reason = k % 10 === 0 ? 'complaint' : 'hard_bounce';
      suppressionRows.push([orgId, addr, reason, 'perf', null, ts, ts]);
    }
  });
  await loader.insert(
    'delivery_suppressions',
    ['organization_id', 'address', 'reason', 'source', 'expires_at', 'created_at', 'updated_at'],
    suppressionRows,
  );

  // --- Message timestamps, sorted, with a diurnal curve -----------------------------------
  const times = new Float64Array(opts.messages);
  for (let i = 0; i < opts.messages;) {
    const t = startMs + rand() * (nowMs - startMs);
    if (rand() <= HOUR_WEIGHT[new Date(t).getUTCHours()]!) times[i++] = Math.floor(t);
  }
  times.sort();

  const orgCdf = zipfCdf(opts.organizations, 1.1);
  const attachmentPool = Array.from({ length: 5000 }, hex64);
  const attachmentCdf = zipfCdf(attachmentPool.length, 0.9);
  let sample: LoadSample['message'] | undefined;
  const sampleOrg = orgIds[0]!;
  let bouncedAddress: string | undefined;

  for (let base = 0; base < opts.messages; base += MESSAGES_PER_CHUNK) {
    const count = Math.min(MESSAGES_PER_CHUNK, opts.messages - base);
    const msgs = Array.from({ length: count }, (_, k) => {
      const receivedMs = times[base + k]!;
      const org = pickCdf(orgCdf, rand());
      let r = rand();
      let verdict = 'clean';
      for (const [v, p] of VERDICTS) {
        if (r < p) {
          verdict = v;
          break;
        }
        r -= p;
      }
      const recipients = pickCdf(RECIPIENTS_CDF, rand()) + 1;
      const quarantined = Array.from(
        { length: recipients },
        () => rand() < (QUARANTINE_P[verdict] ?? 0),
      );
      return {
        receivedMs,
        received: sqlTime(receivedMs),
        org,
        orgId: orgIds[org]!,
        domain: pick(domainsByOrg[org]!),
        verdict,
        recipients,
        quarantined,
        attachments: pickCdf(ATTACHMENTS_CDF, rand()),
        publicId: uuidv7(receivedMs),
      };
    });

    const ids = await loader.insert(
      'message_identities',
      ['public_id', 'organization_id', 'ingest_key', 'received_at', 'created_at'],
      msgs.map((m, k) => [m.publicId, m.orgId, `perf-${base + k}`, m.received, m.received]),
      true,
    );

    const messageRows: Row[] = [];
    const recipientRows: Row[] = [];
    const recipientOwners: { m: number; seq: number; quarantined: boolean; address: string }[] = [];
    const attachmentRows: Row[] = [];
    const scanRows: Row[] = [];
    const scanOwners: number[] = [];
    const eventRows: Row[] = [];
    const historyRows: Row[] = [];
    const outboxRows: Row[] = [];
    const idempotencyRows: Row[] = [];
    const headerRows: Row[] = [];
    const policyLogRows: Row[] = [];
    const archiveRows: Row[] = [];
    const webhookRows: Row[] = [];

    msgs.forEach((m, k) => {
      const id = ids[k]!;
      const allQuarantined = m.quarantined.every(Boolean);
      const age = nowMs - m.receivedMs;
      let status = allQuarantined ? 'quarantined' : 'delivered';
      if (!allQuarantined && age < 2 * DAY_MS && rand() < 0.002) status = pick(STUCK_STATUSES);
      else if (!allQuarantined && rand() < 0.003) status = 'failed';
      const action = allQuarantined ? 'quarantine' : m.verdict === 'clean' ? 'deliver' : 'tag';
      const changedMs = m.receivedMs + 2000 + Math.floor(rand() * 8000);
      const risk =
        m.verdict === 'clean' ? Math.floor(rand() * 200) : 400 + Math.floor(rand() * 600);
      const size = Math.floor(4000 * Math.exp(rand() * 7));
      if (
        !sample &&
        m.orgId === sampleOrg &&
        m.recipients >= 2 &&
        base + k >= opts.messages * 0.98
      ) {
        sample = { id, publicId: m.publicId, receivedAt: m.received, organizationId: m.orgId };
      }
      const day = m.received.slice(0, 10).replaceAll('-', '/');
      messageRows.push([
        id,
        m.received,
        m.orgId,
        m.domain.id,
        k % 8 === 0 ? 'outbound' : 'inbound',
        status,
        sqlTime(changedMs),
        5,
        `<${m.publicId}@sender.example>`,
        `sender${k % 97}@sender${k % 13}.example`,
        `sender${k % 97}@sender${k % 13}.example`,
        `Synthetic message ${base + k}`,
        size,
        m.recipients,
        m.attachments,
        `org/${m.orgId}/messages/${day}/${id}.eml`,
        hex64(),
        `203.0.113.${k % 250}`,
        `mta${k % 13}.sender.example`,
        null,
        m.verdict,
        action,
        risk,
        m.received,
        sqlTime(changedMs),
      ]);
      for (let seq = 0; seq < m.recipients; seq += 1) {
        const addr = address(m.org);
        const q = m.quarantined[seq]!;
        recipientRows.push([
          m.received,
          id,
          m.orgId,
          seq,
          addr,
          null,
          q ? 'quarantined' : status === 'failed' ? 'failed' : 'delivered',
          q ? 'quarantine' : action,
          m.received,
          sqlTime(changedMs),
        ]);
        recipientOwners.push({ m: k, seq, quarantined: q, address: addr });
      }
      for (let a = 0; a < m.attachments; a += 1) {
        attachmentRows.push([
          m.received,
          id,
          m.orgId,
          a + 1,
          null,
          `attachment-${a}.bin`,
          pick(CONTENT_TYPES),
          pick(CONTENT_TYPES),
          1000 + Math.floor(rand() * 2_000_000),
          attachmentPool[pickCdf(attachmentCdf, rand())],
          null,
          m.verdict === 'malware' ? 'malicious' : 'clean',
          m.received,
          m.received,
        ]);
      }
      const scans = rand() < 0.1 ? 2 : 1;
      for (let s = 0; s < scans; s += 1) {
        scanRows.push([
          m.received,
          id,
          m.orgId,
          s === 0 ? 'initial' : 'rescan',
          1,
          'completed',
          m.verdict,
          risk,
          'v1',
          m.received,
          sqlTime(m.receivedMs + 1500),
          m.received,
          m.received,
        ]);
        scanOwners.push(k);
      }
      EVENT_TYPES.forEach((type, e) => {
        eventRows.push([
          m.received,
          id,
          m.orgId,
          type,
          sqlTime(m.receivedMs + e * 400),
          'perf',
          uuidv7(m.receivedMs),
          'system',
          null,
          e === 2 ? JSON.stringify({ verdict: m.verdict, risk }) : null,
          m.received,
        ]);
      });
      const path = ['received', 'scanning', 'scanned', 'policy_evaluated', status];
      path.forEach((to, v) => {
        historyRows.push([
          m.received,
          id,
          m.orgId,
          v + 1,
          v === 0 ? null : path[v - 1],
          to,
          null,
          null,
          sqlTime(m.receivedMs + v * 400),
          m.received,
        ]);
      });
      if (age < 8 * DAY_MS) {
        const unpublished = base + k >= opts.messages - 1000;
        outboxRows.push([
          m.received,
          uuidv7(m.receivedMs),
          m.orgId,
          'message.received',
          'message',
          String(id),
          uuidv7(m.receivedMs),
          JSON.stringify({ messageId: String(id), receivedAt: m.received }),
          m.received,
          unpublished ? null : sqlTime(m.receivedMs + 50),
          unpublished ? 0 : 1,
        ]);
      }
      if (age < 35 * DAY_MS) {
        for (const consumer of ['email-worker.scan', 'policy-engine.evaluate']) {
          idempotencyRows.push([consumer, uuidv7(m.receivedMs), sqlTime(m.receivedMs + 300)]);
        }
      }
      HEADER_NAMES.forEach((name, seq) => {
        headerRows.push([
          m.received,
          id,
          m.orgId,
          seq,
          name,
          name === 'Subject'
            ? `Synthetic message ${base + k}`
            : name === 'Message-ID'
              ? `<${m.publicId}@sender.example>`
              : `${name.toLowerCase()} value for message ${base + k}; synthetic perf data`,
          m.received,
        ]);
      });
      policyLogRows.push([
        m.received,
        id,
        m.orgId,
        1,
        null,
        action,
        JSON.stringify(m.verdict === 'clean' ? [] : [String(1 + (k % 7))]),
        null,
        200 + Math.floor(rand() * 1800),
        sqlTime(m.receivedMs + 1800),
        m.received,
      ]);
      if (featured(m.org)) {
        archiveRows.push([
          m.received,
          id,
          m.orgId,
          `org/${m.orgId}/archive/${day}/${id}.eml`,
          hex64(),
          size,
          null,
          sqlTime(m.receivedMs + ARCHIVE_RETENTION_MS),
          false,
          sqlTime(m.receivedMs + 60_000),
          null,
          m.received,
          m.received,
        ]);
        const fresh = age < HOUR_MS;
        const failed = !fresh && rand() < 0.01;
        webhookRows.push([
          sqlTime(changedMs),
          subscriptionByOrg.get(m.org),
          m.orgId,
          uuidv7(changedMs),
          'message.processed',
          fresh ? 'pending' : failed ? 'failed' : 'succeeded',
          fresh ? 0 : 1,
          fresh || failed ? sqlTime(changedMs + 60_000) : null,
          fresh ? null : failed ? 503 : 200,
          failed ? 'HTTP 503 from receiver' : null,
          fresh ? null : sqlTime(changedMs + 400),
          sqlTime(changedMs),
          sqlTime(changedMs),
        ]);
      }
    });

    await loader.insert(
      'email_messages',
      [
        'id',
        'received_at',
        'organization_id',
        'domain_id',
        'direction',
        'status',
        'status_changed_at',
        'version',
        'internet_message_id',
        'envelope_from',
        'header_from',
        'subject',
        'size_bytes',
        'recipient_count',
        'attachment_count',
        'eml_object_key',
        'eml_sha256',
        'client_ip',
        'client_helo',
        'mta_queue_id',
        'final_verdict',
        'final_action',
        'risk_score',
        'created_at',
        'updated_at',
      ],
      messageRows,
    );
    const recipientIds = await loader.insert(
      'email_recipients',
      [
        'received_at',
        'message_id',
        'organization_id',
        'rcpt_seq',
        'address',
        'user_id',
        'status',
        'final_action',
        'created_at',
        'updated_at',
      ],
      recipientRows,
      true,
    );
    await loader.insert(
      'email_attachments',
      [
        'received_at',
        'message_id',
        'organization_id',
        'part_index',
        'parent_part_index',
        'filename',
        'declared_content_type',
        'detected_content_type',
        'size_bytes',
        'sha256',
        'object_key',
        'verdict',
        'created_at',
        'updated_at',
      ],
      attachmentRows,
    );
    const scanIds = await loader.insert(
      'email_scans',
      [
        'received_at',
        'message_id',
        'organization_id',
        'scan_kind',
        'attempt',
        'status',
        'verdict',
        'risk_score',
        'scoring_version',
        'started_at',
        'completed_at',
        'created_at',
        'updated_at',
      ],
      scanRows,
      true,
    );
    const engineRows: Row[] = [];
    scanIds.forEach((scanId, s) => {
      const m = msgs[scanOwners[s]!]!;
      for (const engine of ENGINES) {
        const malicious = m.verdict === 'malware' && engine === 'clamav';
        engineRows.push([
          m.received,
          scanId,
          ids[scanOwners[s]!],
          m.orgId,
          engine,
          '1.0',
          malicious ? 'malicious' : 'clean',
          (rand() * 10).toFixed(3),
          5 + Math.floor(rand() * 400),
          malicious ? JSON.stringify({ signature: 'Perf.Test.Malware' }) : null,
          sqlTime(m.receivedMs + 1200),
          m.received,
        ]);
      }
    });
    await loader.insert(
      'scan_engine_results',
      [
        'received_at',
        'scan_id',
        'message_id',
        'organization_id',
        'engine',
        'engine_version',
        'outcome',
        'score',
        'duration_ms',
        'evidence',
        'completed_at',
        'created_at',
      ],
      engineRows,
    );
    await loader.insert(
      'email_events',
      [
        'received_at',
        'message_id',
        'organization_id',
        'event_type',
        'occurred_at',
        'source_service',
        'event_id',
        'actor_type',
        'actor_id',
        'details',
        'created_at',
      ],
      eventRows,
    );
    await loader.insert(
      'email_message_status_history',
      [
        'received_at',
        'message_id',
        'organization_id',
        'version',
        'from_status',
        'to_status',
        'reason_code',
        'event_id',
        'changed_at',
        'created_at',
      ],
      historyRows,
    );

    const deliveryRows: Row[] = [];
    const deliveryOwners: number[] = [];
    const quarantineRows: Row[] = [];
    const bounceRows: Row[] = [];
    recipientOwners.forEach((owner, r) => {
      const m = msgs[owner.m]!;
      const recipientId = recipientIds[r]!;
      if (owner.quarantined) {
        const qMs = m.receivedMs + 3000;
        quarantineRows.push([
          uuidv7(qMs),
          m.orgId,
          ids[owner.m],
          m.received,
          recipientId,
          owner.address,
          null,
          m.verdict === 'phishing' || m.verdict === 'malware'
            ? m.verdict
            : m.verdict === 'spam'
              ? 'spam'
              : 'suspicious',
          null,
          'quarantined',
          `sender@sender.example`,
          `Synthetic message ${base + owner.m}`,
          700,
          `org/${m.orgId}/messages/${m.received.slice(0, 10).replaceAll('-', '/')}/${ids[owner.m]}.eml`,
          sqlTime(qMs),
          sqlTime(qMs + 30 * DAY_MS),
          null,
          sqlTime(qMs),
          sqlTime(qMs),
        ]);
        return;
      }
      const attempts = rand() < 0.2 ? 2 : 1;
      const lastMs = m.receivedMs + 5000 + (attempts - 1) * 300_000;
      if (rand() < BOUNCE_P) {
        const hard = rand() < 0.7;
        const bounceMs = lastMs + 600_000;
        bounceRows.push([
          sqlTime(bounceMs),
          m.orgId,
          ids[owner.m],
          m.received,
          owner.address,
          hard ? 'hard' : 'soft',
          hard ? 550 : 452,
          hard ? '5.1.1' : '4.2.2',
          hard ? '550 5.1.1 User unknown' : '452 4.2.2 Mailbox full',
          'mx.recipient.example',
          null,
          hex64(),
          sqlTime(bounceMs),
        ]);
        if (!bouncedAddress && m.orgId === sampleOrg) bouncedAddress = owner.address;
      }
      deliveryRows.push([
        m.received,
        ids[owner.m],
        recipientId,
        m.orgId,
        0,
        null,
        'delivered',
        attempts,
        sqlTime(lastMs),
        sqlTime(lastMs),
        `mx${owner.seq}.recipient.example`,
        250,
        '250 2.0.0 OK',
        null,
        m.received,
        sqlTime(lastMs),
      ]);
      deliveryOwners.push(r);
    });
    const deliveryIds = await loader.insert(
      'email_deliveries',
      [
        'received_at',
        'message_id',
        'recipient_id',
        'organization_id',
        'delivery_seq',
        'route_id',
        'status',
        'attempt_count',
        'last_attempt_at',
        'delivered_at',
        'remote_host',
        'final_smtp_code',
        'final_smtp_response',
        'outbound_queue_id',
        'created_at',
        'updated_at',
      ],
      deliveryRows,
      true,
    );
    const attemptRows: Row[] = [];
    deliveryIds.forEach((deliveryId, d) => {
      const row = deliveryRows[d]!;
      const owner = recipientOwners[deliveryOwners[d]!]!;
      const m = msgs[owner.m]!;
      const attempts = row[7] as number;
      for (let a = 1; a <= attempts; a += 1) {
        const ok = a === attempts;
        const at = m.receivedMs + 5000 + (a - 1) * 300_000;
        attemptRows.push([
          m.received,
          deliveryId,
          ids[owner.m],
          m.orgId,
          a,
          sqlTime(at),
          sqlTime(at + 800),
          row[10],
          '198.51.100.25',
          ok ? 250 : 451,
          ok ? '2.0.0' : '4.7.1',
          ok ? '250 2.0.0 OK' : '451 4.7.1 Try again later',
          ok ? 'success' : 'deferred',
          'TLSv1.3',
          m.received,
        ]);
      }
    });
    await loader.insert(
      'delivery_attempts',
      [
        'received_at',
        'delivery_id',
        'message_id',
        'organization_id',
        'attempt_no',
        'started_at',
        'completed_at',
        'remote_host',
        'remote_ip',
        'smtp_code',
        'enhanced_status',
        'smtp_response',
        'outcome',
        'tls_protocol',
        'created_at',
      ],
      attemptRows,
    );
    await loader.insert(
      'quarantine_messages',
      [
        'public_id',
        'organization_id',
        'message_id',
        'message_received_at',
        'recipient_id',
        'recipient_address',
        'user_id',
        'reason',
        'policy_version_id',
        'status',
        'envelope_from',
        'subject',
        'risk_score',
        'eml_object_key',
        'quarantined_at',
        'expires_at',
        'released_at',
        'created_at',
        'updated_at',
      ],
      quarantineRows,
    );
    await loader.insert(
      'message_outbox',
      [
        'created_at',
        'event_id',
        'organization_id',
        'event_type',
        'aggregate_type',
        'aggregate_id',
        'correlation_id',
        'payload',
        'available_at',
        'published_at',
        'attempts',
      ],
      outboxRows,
    );
    await loader.insert(
      'message_idempotency',
      ['consumer', 'event_id', 'processed_at'],
      idempotencyRows,
    );
    await loader.insert(
      'email_headers',
      ['received_at', 'message_id', 'organization_id', 'seq', 'name', 'value', 'created_at'],
      headerRows,
    );
    await loader.insert(
      'policy_execution_logs',
      [
        'received_at',
        'message_id',
        'organization_id',
        'evaluation_seq',
        'decisive_policy_version_id',
        'action',
        'matched_policy_version_ids',
        'trace',
        'duration_us',
        'evaluated_at',
        'created_at',
      ],
      policyLogRows,
    );
    await loader.insert(
      'email_archives',
      [
        'received_at',
        'message_id',
        'organization_id',
        'archive_object_key',
        'sha256',
        'size_bytes',
        'retention_policy_id',
        'retain_until',
        'legal_hold',
        'archived_at',
        'deleted_at',
        'created_at',
        'updated_at',
      ],
      archiveRows,
    );
    await loader.insert(
      'webhook_deliveries',
      [
        'event_occurred_at',
        'subscription_id',
        'organization_id',
        'event_id',
        'event_type',
        'status',
        'attempt_count',
        'next_attempt_at',
        'last_response_code',
        'last_error',
        'completed_at',
        'created_at',
        'updated_at',
      ],
      webhookRows,
    );
    await loader.insert(
      'bounce_events',
      [
        'occurred_at',
        'organization_id',
        'message_id',
        'message_received_at',
        'recipient_address',
        'bounce_type',
        'smtp_code',
        'enhanced_status',
        'diagnostic',
        'reporting_mta',
        'dsn_object_key',
        'dedupe_key',
        'created_at',
      ],
      bounceRows,
    );

    opts.onProgress?.(base + count, opts.messages);
  }

  // --- Audit log: ~10 actions per organization-day, Zipf-weighted --------------------------
  const auditRows: Row[] = [];
  for (let day = 0; day < opts.days; day += 1) {
    for (let o = 0; o < opts.organizations; o += 1) {
      const n = Math.max(
        1,
        Math.round(10 * opts.organizations * (orgCdf[o]! - (orgCdf[o - 1] ?? 0))),
      );
      for (let k = 0; k < n; k += 1) {
        const at = startMs + day * DAY_MS + Math.floor(rand() * DAY_MS);
        if (at > nowMs) continue;
        auditRows.push([
          sqlTime(at),
          orgIds[o],
          'user',
          String(1 + (k % 5)),
          pick(['policy.update', 'quarantine.release', 'user.invite', 'domain.verify']),
          'policy',
          String(1 + (k % 50)),
          uuidv7(at),
          '192.0.2.10',
          null,
        ]);
      }
    }
  }
  auditRows.sort((a, b) => (a[0] as string).localeCompare(b[0] as string));
  await loader.insert(
    'audit_logs',
    [
      'created_at',
      'organization_id',
      'actor_type',
      'actor_id',
      'action',
      'resource_type',
      'resource_id',
      'correlation_id',
      'source_ip',
      'metadata',
    ],
    auditRows,
  );

  if (!sample) throw new Error('No sample message found; increase --messages');
  if (!bouncedAddress) throw new Error('No bounced recipient found; increase --messages');
  const firstSuppression = suppressionRows[0]!;
  return {
    stats: [...loader.stats.values()],
    sample: {
      organizationId: sampleOrg,
      message: sample,
      domainName: domainsByOrg[0]![0]!.name,
      suppressedAddress: {
        organizationId: firstSuppression[0] as bigint,
        address: firstSuppression[1] as string,
      },
      bouncedAddress,
    },
    totalMs: performance.now() - started,
  };
}
