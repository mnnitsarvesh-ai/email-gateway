import { MetricsService } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import { createLogger, type Logger } from '@email-gateway/logger';
import { RiskProfileProvider } from './profile-provider';
import { RiskMetrics } from './risk-metrics';
import { RiskRoundReader } from './risk-reader';
import { RiskScorer } from './risk-scorer';

/**
 * Test support (unit tests only): an in-memory stand-in for the Prisma calls of the risk path
 * and of `ScanRepository`'s completion and sweep (raw `email_scans` / result-row reads by
 * `(scan_id, received_at)`, typed finals, message, profile rows, `message_risk_scores` with its
 * unique key). Every write is appended to `log` so tests can check the order of statements.
 */

export const ORG = 7n;
export const MESSAGE = 11n;
export const SCAN = 21n;
export const RECEIVED = new Date('2026-11-10T09:00:00.000Z');
export const COMPLETED = new Date('2026-11-10T09:00:05.000Z');
export const VERSION_PUBLIC_ID = '0196f3a0-0000-7000-8000-00000000c0de';

type Row = Record<string, unknown>;

export interface FakeFinal {
  engine: string;
  outcome: string;
  errorCode?: string | null;
  reasonCodes?: string[];
  score?: string | null;
  attempt?: number;
  isFinal?: boolean;
  scanId?: bigint;
  organizationId?: bigint;
  messageId?: bigint;
}

const same = (a: unknown, b: unknown): boolean =>
  a instanceof Date && b instanceof Date ? a.getTime() === b.getTime() : a === b;

export class FakeRiskDb {
  readonly log: string[] = [];
  scans: Row[] = [];
  results: Row[] = [];
  messages: Row[] = [];
  auth: Row[] = [];
  bec: Row[] = [];
  dlp: Row[] = [];
  versions: Row[] = [];
  profiles: Row[] = [];
  readonly riskRows: Row[] = [];
  readonly scanUpdates: Row[] = [];
  readonly outbox: Row[] = [];
  readonly ledger = new Set<string>();
  /** Replaces the rows a raw read of `table` returns (simulates a Prisma wrong read). */
  tamper: ((table: string, rows: Row[]) => Row[]) | null = null;
  /** Makes the next `message_risk_scores` insert throw (a database error). */
  failRiskInsert: Error | null = null;

  constructor() {
    this.scans.push({
      id: SCAN,
      received_at: RECEIVED,
      message_id: MESSAGE,
      organization_id: ORG,
      status: 'running',
      lifecycle_round: 0,
      scan_kind: 'initial',
      required_engines: ['rspamd'],
      started_at: RECEIVED,
      deadline_at: new Date(RECEIVED.getTime() + 60_000),
      risk_profile_version_id: null,
    });
    this.messages.push({
      id: MESSAGE,
      receivedAt: RECEIVED,
      organizationId: ORG,
      direction: 'inbound',
      attachmentCount: 0,
      recipientCount: 1,
    });
  }

  get scan(): Row {
    return this.scans[0]!;
  }

  addFinal(final: FakeFinal): void {
    this.results.push({
      scanId: final.scanId ?? SCAN,
      receivedAt: RECEIVED,
      messageId: final.messageId ?? MESSAGE,
      organizationId: final.organizationId ?? ORG,
      engine: final.engine,
      outcome: final.outcome,
      errorCode: final.errorCode ?? null,
      reasonCodes: final.reasonCodes ?? [],
      score: final.score ?? null,
      engineVersion: `${final.engine}/1`,
      settingsVersion: `${final.engine}-map/1`,
      attempt: final.attempt ?? 1,
      isFinal: final.isFinal ?? true,
      completedAt: COMPLETED,
    });
  }

  addAuth(over: Row = {}): void {
    this.auth.push({
      scan_id: SCAN,
      received_at: RECEIVED,
      message_id: MESSAGE,
      organization_id: ORG,
      engine: 'rspamd',
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      dmarc_policy: 'reject',
      arc: 'none',
      ...over,
    });
  }

  addVersion(over: Row = {}): void {
    this.versions.push({
      id: 501n,
      organizationId: ORG,
      status: 'published',
      publicId: VERSION_PUBLIC_ID,
      versionNo: 3,
      baseProfile: 'rsk-default/1',
      overrides: { thresholds: { medium: 250 } },
      ...over,
    });
  }

  private raw(strings: TemplateStringsArray, values: unknown[]): Row[] {
    const sql = strings.join('?');
    const [scanId, receivedAt] = values;
    const byScan = (rows: Row[]) =>
      rows.filter((r) => r.scan_id === scanId && same(r.received_at, receivedAt));
    let table = '';
    let rows: Row[] = [];
    if (sql.includes('FROM email_scans')) {
      table = 'email_scans';
      rows = this.scans.filter((r) => r.id === scanId && same(r.received_at, receivedAt));
    } else if (sql.includes('FROM scan_engine_results')) {
      table = 'scan_engine_results';
      rows = this.results
        .filter((r) => r.scanId === scanId && same(r.receivedAt, receivedAt) && r.isFinal)
        .map((r) => ({
          scan_id: r.scanId,
          received_at: r.receivedAt,
          message_id: r.messageId,
          organization_id: r.organizationId,
          engine: r.engine,
          outcome: r.outcome,
          error_code: r.errorCode,
          reason_codes: JSON.stringify(r.reasonCodes),
          score: r.score,
          engine_version: r.engineVersion,
          settings_version: r.settingsVersion,
          attempt: r.attempt,
          completed_at: r.completedAt,
          is_final: 1,
        }));
    } else if (sql.includes('FROM email_auth_results')) {
      table = 'email_auth_results';
      rows = byScan(this.auth);
    } else if (sql.includes('FROM bec_scan_results')) {
      table = 'bec_scan_results';
      rows = byScan(this.bec);
    } else if (sql.includes('FROM dlp_scan_results')) {
      table = 'dlp_scan_results';
      rows = byScan(this.dlp);
    } else {
      throw new Error(`unexpected raw query: ${sql}`);
    }
    rows = rows.map((r) => ({ ...r }));
    return this.tamper ? this.tamper(table, rows) : rows;
  }

  tx(): Prisma.TransactionClient {
    return {
      $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) =>
        Promise.resolve(this.raw(strings, values)),
      messageIdempotency: {
        create: ({ data }: { data: { consumer: string; eventId: string } }) => {
          const key = `${data.consumer}|${data.eventId}`;
          if (this.ledger.has(key)) {
            return Promise.reject(
              new Prisma.PrismaClientKnownRequestError('duplicate ledger row', {
                code: 'P2002',
                clientVersion: 'test',
              }),
            );
          }
          this.ledger.add(key);
          return Promise.resolve({});
        },
      },
      scanEngineResult: {
        findMany: ({ where }: { where: Row }) =>
          Promise.resolve(
            this.results.filter(
              (r) =>
                r.scanId === where.scanId &&
                same(r.receivedAt, where.receivedAt) &&
                (where.isFinal === undefined || r.isFinal === where.isFinal) &&
                (where.engine === undefined || r.engine === where.engine),
            ),
          ),
        create: ({ data }: { data: Row }) => {
          this.log.push(`final:${String(data.engine)}`);
          this.results.push({ ...data, score: data.score ?? null });
          return Promise.resolve({ id: 1n });
        },
      },
      emailScan: {
        createMany: ({ data }: { data: Row[] }) => {
          let count = 0;
          for (const row of data) {
            const exists = this.scans.some(
              (s) =>
                s.message_id === row.messageId &&
                s.lifecycle_round === row.lifecycleRound &&
                same(s.received_at, row.receivedAt),
            );
            if (exists) continue;
            count += 1;
            this.log.push('scan:open');
            this.scans.push({
              id: SCAN + BigInt(this.scans.length),
              received_at: row.receivedAt,
              message_id: row.messageId,
              organization_id: row.organizationId,
              status: row.status,
              lifecycle_round: row.lifecycleRound,
              scan_kind: row.scanKind,
              required_engines: row.requiredEngines,
              started_at: row.startedAt,
              deadline_at: row.deadlineAt,
              risk_profile_version_id: row.riskProfileVersionId ?? null,
            });
          }
          return Promise.resolve({ count });
        },
        findFirst: ({ where }: { where: Row }) => {
          const s = this.scans.find(
            (r) =>
              r.message_id === where.messageId &&
              same(r.received_at, where.receivedAt) &&
              r.organization_id === where.organizationId &&
              r.lifecycle_round === where.lifecycleRound,
          );
          return Promise.resolve(
            s
              ? {
                  id: s.id,
                  receivedAt: s.received_at,
                  messageId: s.message_id,
                  organizationId: s.organization_id,
                  status: s.status,
                  lifecycleRound: s.lifecycle_round,
                  scanKind: s.scan_kind,
                  requiredEngines: s.required_engines,
                  startedAt: s.started_at,
                  deadlineAt: s.deadline_at,
                  riskProfileVersionId: s.risk_profile_version_id,
                }
              : null,
          );
        },
        updateMany: ({ where, data }: { where: Row; data: Row }) => {
          const row = this.scans.find(
            (r) => r.id === where.id && same(r.received_at, where.receivedAt),
          );
          if (!row || (where.status !== undefined && row.status !== where.status)) {
            return Promise.resolve({ count: 0 });
          }
          if (typeof data.status === 'string') row.status = data.status;
          this.scanUpdates.push({ ...data });
          this.log.push(data.riskScore !== undefined ? 'scan:risk' : 'scan:complete');
          return Promise.resolve({ count: 1 });
        },
      },
      emailMessage: {
        findFirst: ({ where }: { where: Row }) =>
          Promise.resolve(
            this.messages.find(
              (m) =>
                m.id === where.id &&
                same(m.receivedAt, where.receivedAt) &&
                m.organizationId === where.organizationId,
            ) ?? null,
          ),
      },
      riskScoringProfile: {
        findUnique: ({ where }: { where: Row }) =>
          Promise.resolve(
            this.profiles.find((p) => p.organizationId === where.organizationId) ?? null,
          ),
      },
      riskScoringProfileVersion: {
        findUnique: ({ where }: { where: Row }) =>
          Promise.resolve(this.versions.find((v) => v.id === where.id) ?? null),
      },
      messageRiskScore: {
        createMany: ({ data }: { data: Row[] }) => {
          if (this.failRiskInsert) {
            const error = this.failRiskInsert;
            this.failRiskInsert = null;
            return Promise.reject(error);
          }
          let count = 0;
          for (const row of data) {
            const exists = this.riskRows.some(
              (r) =>
                r.scanId === row.scanId &&
                r.revision === row.revision &&
                same(r.receivedAt, row.receivedAt),
            );
            this.log.push(`risk:${String(row.revision)}${exists ? ':duplicate' : ''}`);
            if (!exists) {
              this.riskRows.push({ ...row });
              count += 1;
            }
          }
          return Promise.resolve({ count });
        },
      },
      messageOutbox: {
        create: ({ data }: { data: Row }) => {
          this.log.push(`outbox:${String(data.eventType)}`);
          this.outbox.push(data);
          return Promise.resolve({ id: 1n });
        },
      },
    } as unknown as Prisma.TransactionClient;
  }

  /** A client whose interactive transactions run on `tx()` (rolled back writes are not undone). */
  client(): PrismaClient {
    const tx = this.tx();
    return {
      ...tx,
      $transaction: (fn: (t: Prisma.TransactionClient) => Promise<unknown>) => fn(tx),
      emailScan: {
        ...(tx as unknown as { emailScan: object }).emailScan,
        findMany: () =>
          Promise.resolve(
            this.scans
              .filter((s) => s.status === 'running')
              .map((s) => ({
                id: s.id,
                receivedAt: s.received_at,
                messageId: s.message_id,
                organizationId: s.organization_id,
              })),
          ),
      },
    } as unknown as PrismaClient;
  }
}

export const silentLogger: Logger = createLogger({ service: 'risk-test', level: 'silent' });

export function riskSetup(options: { maxEntries?: number; clockStepNs?: bigint } = {}) {
  const registry = new MetricsService({
    service: `risk-test-${Math.random().toString(36).slice(2)}`,
  });
  const metrics = RiskMetrics.for(registry);
  const provider = new RiskProfileProvider({
    platformId: 'rsk-default/1',
    maxEntries: options.maxEntries ?? 100,
    onInconsistent: (read) => metrics.inconsistent(read),
  });
  const reader = new RiskRoundReader((read) => metrics.inconsistent(read));
  let now = 0n;
  const step = options.clockStepNs ?? 1_500_000n;
  const scorer = new RiskScorer({
    provider,
    reader,
    metrics,
    logger: silentLogger,
    platformId: 'rsk-default/1',
    clock: () => (now += step),
  });
  return { registry, metrics, provider, reader, scorer };
}

/** The value of one series (0 when absent). */
export async function series(
  registry: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const text = await registry.metrics();
  const wanted = Object.entries(labels).map(([k, v]) => `${k}="${v}"`);
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`) && !line.startsWith(`${name} `)) continue;
    if (wanted.every((w) => line.includes(w)))
      total += Number(line.slice(line.lastIndexOf(' ') + 1));
  }
  return total;
}

/** The round of the fake's scan row. */
export const round = (over: Partial<Record<string, unknown>> = {}) => ({
  scanId: SCAN,
  receivedAt: RECEIVED,
  messageId: MESSAGE,
  organizationId: ORG,
  round: 0,
  scanKind: 'initial' as const,
  requiredEngines: ['rspamd'],
  riskProfileVersionId: null as bigint | null,
  ...over,
});
