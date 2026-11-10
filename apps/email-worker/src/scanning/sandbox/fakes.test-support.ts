import { MetricsService } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import type { SandboxAnalysisStatus } from '@email-gateway/security-contracts';
import { SandboxMetrics } from './sandbox-metrics';
import {
  type AnalysisCompletion,
  type AnalysisRow,
  type AnalysisSummary,
  type ArtifactPurgeRow,
  DUPLICATE,
  DuplicateLedgerError,
  type FinalRow,
  isTerminalAnalysis,
  type NewAnalysis,
  type NewArtifact,
  type OutboxRow,
  type SandboxStore,
  type SandboxTx,
  scanKey,
  type ScanLockRow,
  type SubmissionRef,
  type SubmissionRow,
  type SubmissionTerminal,
  type TenantGateRows,
} from './sandbox-store';
import type { SandboxObjects } from './sample-stager';

export const silent: Logger = createLogger({ service: 'sandbox-test', level: 'silent' });

export const newSandboxMetrics = (): { metrics: SandboxMetrics; registry: MetricsService } => {
  const registry = new MetricsService({ service: 'sandbox-test' });
  return { metrics: SandboxMetrics.for(registry), registry };
};

/** The value of one series of a registry (0 when absent). */
export async function counter(
  registry: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const text = await registry.metrics();
  const wanted = Object.entries(labels).map(([k, v]) => `${k}="${v}"`);
  for (const line of text.split('\n')) {
    if (!line.startsWith(name)) continue;
    const rest = line.slice(name.length);
    if (!(rest.startsWith('{') || rest.startsWith(' '))) continue;
    if (wanted.every((w) => line.includes(w))) return Number(line.slice(line.lastIndexOf(' ') + 1));
  }
  return 0;
}

export interface FakeSubmission extends SubmissionRow {
  createdAt: Date;
  externalRef: string | null;
  completedAt: Date | null;
}

export interface FakeAnalysis extends AnalysisRow {
  report: unknown;
  analyzerVersion: string | null;
  mapVersion: string | null;
  notExecutedReason: string | null;
  errorCode: string | null;
  durationMs: number | null;
  resultEventId: string | null;
}

export interface FakeArtifact extends NewArtifact {
  id: bigint;
  analysisId: bigint;
  wrappedKey: string;
  purgedAt: Date | null;
  purgeReason: string | null;
  objectDeletedAt: Date | null;
  shredded: boolean;
}

interface State {
  submissions: Map<bigint, FakeSubmission>;
  analyses: Map<bigint, FakeAnalysis>;
  artifacts: Map<bigint, FakeArtifact>;
  scans: Map<string, ScanLockRow>;
  finals: Map<string, FinalRow>;
  outbox: OutboxRow[];
  ledger: Set<string>;
  hashes: Map<string, { publicId: string; expiresAt: Date }>;
  features: Map<bigint, boolean>;
  settings: Map<bigint, { settings: unknown; version: number }>;
  nextId: bigint;
}

/** The result token hash of analyses the fake creates as `dispatched` (tests sign with it). */
export const FAKE_RESULT_TOKEN_SHA256 = 'e7'.repeat(32);

/**
 * In-memory `SandboxStore` with the semantics the Prisma store gets from MySQL: transactions run
 * one at a time (row locks serialize the callers that matter here) and roll back on a throw, the
 * unique `dedupe_key`, the unique final per round, the ledger, and every state condition of the
 * writes. `log` records the order of shredding and object deletes. Unit tests only.
 */
export class FakeSandboxStore implements SandboxStore {
  state: State = {
    submissions: new Map(),
    analyses: new Map(),
    artifacts: new Map(),
    scans: new Map(),
    finals: new Map(),
    outbox: [],
    ledger: new Set(),
    hashes: new Map(),
    features: new Map(),
    settings: new Map(),
    nextId: 1n,
  };
  readonly log: string[] = [];
  /**
   * The row locks and row writes of every transaction, in order (`analysis:<id>`, `scan:<id>`,
   * `submission:<id>`): the lock-order tests check analysis → scan → submission.
   */
  readonly locks: string[] = [];
  /** Runs right before an analysis insert (simulates a concurrent dispatcher). */
  beforeCreateAnalysis: ((input: NewAnalysis) => void) | null = null;
  /** Makes the next submission read return a row of another submission (wrong read). */
  wrongSubmissionRead = false;
  private chain: Promise<unknown> = Promise.resolve();

  id(): bigint {
    const id = this.state.nextId;
    this.state.nextId += 1n;
    return id;
  }

  addScan(scan: ScanLockRow): void {
    this.state.scans.set(scanKey(scan.scanId, scan.receivedAt), scan);
  }

  addSubmission(
    row: Partial<FakeSubmission> &
      Pick<FakeSubmission, 'scanId' | 'receivedAt' | 'organizationId' | 'messageId'>,
  ): FakeSubmission {
    const id = row.id ?? this.id();
    const submission: FakeSubmission = {
      id,
      partIndex: 1,
      sha256: 'a'.repeat(64),
      sizeBytes: 100,
      detectedType: 'script_shell',
      objectKey: `org/${row.organizationId.toString()}/part/2026/11/08/${row.messageId.toString()}/1.att`,
      status: 'pending',
      analysisId: null,
      settingsVersion: null,
      sandboxVerdict: null,
      sandboxReasonCodes: [],
      skipReason: null,
      createdAt: new Date(),
      externalRef: null,
      completedAt: null,
      ...row,
    };
    this.state.submissions.set(id, submission);
    return submission;
  }

  addAnalysis(
    row: Partial<FakeAnalysis> & Pick<FakeAnalysis, 'sha256' | 'organizationId'>,
  ): FakeAnalysis {
    const id = row.id ?? this.id();
    const publicId = row.publicId ?? `0190f3a0-0000-7000-8000-${id.toString().padStart(12, '0')}`;
    const analysis: FakeAnalysis = {
      id,
      publicId,
      sizeBytes: 100,
      detectedType: 'script_shell',
      profile: 'execute',
      analysisKey: '0123456789abcdef',
      dedupeKey: null,
      status: 'dispatched',
      sampleObjectKey: `samples/2026/11/${publicId}.bin`,
      sampleDeletedAt: null,
      requestedEventId: null,
      dispatchedAt: new Date(),
      resultTokenSha256: FAKE_RESULT_TOKEN_SHA256,
      deadlineAt: new Date(Date.now() + 900_000),
      completedAt: null,
      verdict: null,
      reasonCodes: [],
      backend: null,
      backendVersion: null,
      isolation: null,
      executed: null,
      controllerVersion: null,
      reuseUntil: null,
      expiresAt: new Date(Date.now() + 180 * 86_400_000),
      report: null,
      analyzerVersion: null,
      mapVersion: null,
      notExecutedReason: null,
      errorCode: null,
      durationMs: null,
      resultEventId: null,
      ...row,
    };
    this.state.analyses.set(id, analysis);
    return analysis;
  }

  submission(id: bigint): FakeSubmission {
    return this.state.submissions.get(id)!;
  }

  analysis(id: bigint): FakeAnalysis {
    return this.state.analyses.get(id)!;
  }

  analysesBySha(sha256: string): FakeAnalysis[] {
    return [...this.state.analyses.values()].filter((a) => a.sha256 === sha256);
  }

  final(scanId: bigint, receivedAt: Date): FinalRow | undefined {
    return this.state.finals.get(scanKey(scanId, receivedAt));
  }

  outboxOf(eventType: string): OutboxRow[] {
    return this.state.outbox.filter((o) => o.eventType === eventType);
  }

  // SandboxStore -------------------------------------------------------------------------------

  isProcessed(consumer: string, eventId: string): Promise<boolean> {
    return Promise.resolve(this.state.ledger.has(`${consumer}|${eventId}`));
  }

  async recordNoop(consumer: string, eventId: string): Promise<boolean> {
    const result = await this.transaction((tx) => tx.ledger(consumer, eventId));
    return result !== DUPLICATE;
  }

  transaction<T>(fn: (tx: SandboxTx) => Promise<T>): Promise<T | typeof DUPLICATE> {
    const run = async (): Promise<T | typeof DUPLICATE> => {
      const saved = structuredClone(this.state);
      const logLength = this.log.length;
      try {
        return await fn(new FakeTx(this));
      } catch (error) {
        this.state = saved;
        this.log.length = logLength;
        if (error instanceof DuplicateLedgerError) return DUPLICATE;
        throw error;
      }
    };
    const next = this.chain.then(run, run);
    this.chain = next.catch(() => undefined);
    return next;
  }

  markSampleDeleted(analysisId: bigint, key: string, now: Date): Promise<boolean> {
    const a = this.state.analyses.get(analysisId);
    if (!a || a.sampleObjectKey !== key || a.sampleDeletedAt !== null)
      return Promise.resolve(false);
    a.sampleDeletedAt = now;
    return Promise.resolve(true);
  }

  samplesToDelete(limit: number): Promise<{ id: bigint; key: string }[]> {
    return Promise.resolve(
      [...this.state.analyses.values()]
        .filter(
          (a) =>
            isTerminalAnalysis(a.status) &&
            a.sampleObjectKey !== null &&
            a.sampleDeletedAt === null,
        )
        .slice(0, limit)
        .map((a) => ({ id: a.id, key: a.sampleObjectKey! })),
    );
  }

  artifactsToDelete(limit: number): Promise<ArtifactPurgeRow[]> {
    return Promise.resolve(
      [...this.state.artifacts.values()]
        .filter((a) => a.purgedAt !== null && a.shredded && a.objectDeletedAt === null)
        .slice(0, limit)
        .map((a) => ({ id: a.id, analysisId: a.analysisId, objectKey: a.objectKey })),
    );
  }

  markArtifactObjectDeleted(id: bigint, key: string, now: Date): Promise<boolean> {
    const a = this.state.artifacts.get(id);
    if (!a || a.objectKey !== key || !a.shredded || a.objectDeletedAt !== null)
      return Promise.resolve(false);
    a.objectDeletedAt = now;
    return Promise.resolve(true);
  }
}

class FakeTx implements SandboxTx {
  constructor(private readonly store: FakeSandboxStore) {}

  private get s(): State {
    return this.store.state;
  }

  ledger(consumer: string, eventId: string): Promise<void> {
    const key = `${consumer}|${eventId}`;
    if (this.s.ledger.has(key)) return Promise.reject(new DuplicateLedgerError());
    this.s.ledger.add(key);
    return Promise.resolve();
  }

  loadSubmission(ref: SubmissionRef): Promise<SubmissionRow | null> {
    if (this.store.wrongSubmissionRead) {
      this.store.wrongSubmissionRead = false;
      const other = [...this.s.submissions.values()].find((r) => r.id !== ref.id);
      if (other)
        return Promise.resolve({
          ...other,
          id: ref.id,
          receivedAt: ref.receivedAt,
          sha256: 'f'.repeat(64),
        });
    }
    const row = this.s.submissions.get(ref.id);
    return Promise.resolve(
      row && row.receivedAt.getTime() === ref.receivedAt.getTime() ? { ...row } : null,
    );
  }

  tenantGate(organizationId: bigint): Promise<TenantGateRows> {
    return Promise.resolve({
      feature: this.s.features.get(organizationId) === true,
      settings: this.s.settings.get(organizationId) ?? null,
    });
  }

  lockAnalysisByDedupe(dedupeKey: string): Promise<AnalysisRow | null> {
    const row = [...this.s.analyses.values()].find((a) => a.dedupeKey === dedupeKey);
    if (row) this.store.locks.push(`analysis:${row.id.toString()}`);
    return Promise.resolve(row ? { ...row } : null);
  }

  lockAnalysis(id: bigint): Promise<AnalysisRow | null> {
    const row = this.s.analyses.get(id);
    if (row) this.store.locks.push(`analysis:${id.toString()}`);
    return Promise.resolve(row ? { ...row } : null);
  }

  createAnalysis(input: NewAnalysis): Promise<AnalysisRow | 'duplicate'> {
    this.store.beforeCreateAnalysis?.(input);
    if ([...this.s.analyses.values()].some((a) => a.dedupeKey === input.dedupeKey)) {
      return Promise.resolve('duplicate');
    }
    const row = this.store.addAnalysis({
      ...input,
      status: 'pending',
      dispatchedAt: null,
      resultTokenSha256: null,
    });
    return Promise.resolve({ ...row });
  }

  clearDedupeKey(id: bigint, dedupeKey: string): Promise<void> {
    const row = this.s.analyses.get(id);
    if (row && row.dedupeKey === dedupeKey) row.dedupeKey = null;
    return Promise.resolve();
  }

  linkSubmission(
    ref: SubmissionRef,
    analysisId: bigint,
    settingsVersion: string | null,
  ): Promise<boolean> {
    const row = this.s.submissions.get(ref.id);
    this.store.locks.push(`submission:${ref.id.toString()}`);
    if (
      !row ||
      !(
        (row.status === 'pending' && row.analysisId === null) ||
        (row.status === 'submitted' && row.analysisId === analysisId)
      )
    ) {
      return Promise.resolve(false);
    }
    row.status = 'submitted';
    row.analysisId = analysisId;
    if (settingsVersion !== null) row.settingsVersion = settingsVersion;
    return Promise.resolve(true);
  }

  markDispatched(id: bigint, now: Date, resultTokenSha256: string): Promise<boolean> {
    const row = this.s.analyses.get(id);
    if (!row || row.status !== 'pending') return Promise.resolve(false);
    row.status = 'dispatched';
    row.dispatchedAt = now;
    row.resultTokenSha256 = resultTokenSha256;
    return Promise.resolve(true);
  }

  completeAnalysis(
    id: bigint,
    from: readonly SandboxAnalysisStatus[],
    c: AnalysisCompletion,
  ): Promise<boolean> {
    const row = this.s.analyses.get(id);
    if (!row || !from.includes(row.status)) return Promise.resolve(false);
    row.status = c.status;
    row.verdict = c.verdict;
    row.reasonCodes = [...c.reasonCodes];
    if (c.report !== undefined) row.report = c.report;
    if (c.backend !== undefined) row.backend = c.backend;
    if (c.backendVersion !== undefined) row.backendVersion = c.backendVersion;
    if (c.isolation !== undefined) row.isolation = c.isolation;
    if (c.executed !== undefined) row.executed = c.executed;
    if (c.controllerVersion !== undefined) row.controllerVersion = c.controllerVersion;
    if (c.analyzerVersion !== undefined) row.analyzerVersion = c.analyzerVersion;
    if (c.mapVersion !== undefined) row.mapVersion = c.mapVersion;
    if (c.notExecutedReason !== undefined) row.notExecutedReason = c.notExecutedReason;
    if (c.errorCode !== undefined) row.errorCode = c.errorCode;
    if (c.durationMs !== undefined) row.durationMs = c.durationMs;
    if (c.resultEventId !== undefined) row.resultEventId = c.resultEventId;
    row.completedAt = c.completedAt;
    row.reuseUntil = c.reuseUntil;
    if (c.clearDedupeKey) row.dedupeKey = null;
    return Promise.resolve(true);
  }

  insertArtifacts(analysisId: bigint, rows: readonly NewArtifact[]): Promise<void> {
    for (const row of rows) {
      if (
        [...this.s.artifacts.values()].some((a) => a.analysisId === analysisId && a.seq === row.seq)
      ) {
        return Promise.reject(Object.assign(new Error('unique'), { code: 'P2002' }));
      }
      const id = this.store.id();
      this.s.artifacts.set(id, {
        ...row,
        id,
        analysisId,
        purgedAt: null,
        purgeReason: null,
        objectDeletedAt: null,
        shredded: false,
      });
    }
    return Promise.resolve();
  }

  linkedSubmitted(analysisId: bigint, limit: number): Promise<SubmissionRow[]> {
    return Promise.resolve(
      [...this.s.submissions.values()]
        .filter((r) => r.analysisId === analysisId && r.status === 'submitted')
        .sort((a, b) => (a.id < b.id ? -1 : 1))
        .slice(0, limit)
        .map((r) => ({ ...r })),
    );
  }

  analysesByIds(ids: readonly bigint[]): Promise<Map<bigint, AnalysisRow>> {
    const result = new Map<bigint, AnalysisRow>();
    for (const id of ids) {
      const row = this.s.analyses.get(id);
      if (row) result.set(id, { ...row });
    }
    return Promise.resolve(result);
  }

  lockScans(
    refs: readonly { scanId: bigint; receivedAt: Date }[],
  ): Promise<Map<string, ScanLockRow>> {
    const result = new Map<string, ScanLockRow>();
    for (const ref of refs) {
      const key = scanKey(ref.scanId, ref.receivedAt);
      const row = this.s.scans.get(key);
      this.store.locks.push(`scan:${ref.scanId.toString()}`);
      if (row) result.set(key, { ...row });
    }
    return Promise.resolve(result);
  }

  finishSubmission(ref: SubmissionRef, data: SubmissionTerminal): Promise<boolean> {
    const row = this.s.submissions.get(ref.id);
    this.store.locks.push(`submission:${ref.id.toString()}`);
    if (!row || (row.status !== 'pending' && row.status !== 'submitted'))
      return Promise.resolve(false);
    row.status = data.status;
    row.sandboxVerdict = data.verdict;
    row.sandboxReasonCodes = [...data.reasonCodes];
    row.skipReason = data.skipReason;
    row.completedAt = data.completedAt;
    row.externalRef = data.externalRef;
    if (data.settingsVersion !== undefined) row.settingsVersion = data.settingsVersion;
    return Promise.resolve(true);
  }

  roundSubmissions(scan: ScanLockRow): Promise<SubmissionRow[]> {
    return Promise.resolve(
      [...this.s.submissions.values()]
        .filter(
          (r) => r.scanId === scan.scanId && r.receivedAt.getTime() === scan.receivedAt.getTime(),
        )
        .sort((a, b) => a.partIndex - b.partIndex)
        .map((r) => ({ ...r })),
    );
  }

  analysisSummaries(ids: readonly bigint[]): Promise<Map<bigint, AnalysisSummary>> {
    const result = new Map<bigint, AnalysisSummary>();
    for (const id of ids) {
      const a = this.s.analyses.get(id);
      if (a) {
        result.set(id, {
          id,
          executed: a.executed,
          isolation: a.isolation,
          controllerVersion: a.controllerVersion,
          backend: a.backend,
          backendVersion: a.backendVersion,
        });
      }
    }
    return Promise.resolve(result);
  }

  insertFinal(scan: ScanLockRow, final: FinalRow): Promise<boolean> {
    const key = scanKey(scan.scanId, scan.receivedAt);
    if (this.s.finals.has(key)) return Promise.resolve(false);
    this.s.finals.set(key, { ...final });
    return Promise.resolve(true);
  }

  writeOutbox(row: OutboxRow): Promise<void> {
    this.s.outbox.push(structuredClone(row));
    return Promise.resolve();
  }

  publishHash(sha256: string, publicId: string, _now: Date, expiresAt: Date): Promise<boolean> {
    if (this.s.hashes.has(sha256)) return Promise.resolve(false);
    this.s.hashes.set(sha256, { publicId, expiresAt });
    return Promise.resolve(true);
  }

  pendingSubmissionsBefore(cutoff: Date, limit: number): Promise<SubmissionRow[]> {
    return Promise.resolve(
      [...this.s.submissions.values()]
        .filter((r) => r.status === 'pending' && r.createdAt.getTime() < cutoff.getTime())
        .slice(0, limit)
        .map((r) => ({ ...r })),
    );
  }

  overdueAnalyses(now: Date, limit: number): Promise<bigint[]> {
    return Promise.resolve(
      [...this.s.analyses.values()]
        .filter(
          (a) =>
            (a.status === 'pending' || a.status === 'dispatched') &&
            a.deadlineAt.getTime() < now.getTime(),
        )
        .slice(0, limit)
        .map((a) => a.id),
    );
  }

  submittedWithTerminalAnalysis(limit: number): Promise<SubmissionRow[]> {
    return Promise.resolve(
      [...this.s.submissions.values()]
        .filter((r) => {
          if (r.status !== 'submitted' || r.analysisId === null) return false;
          const a = this.s.analyses.get(r.analysisId);
          return a !== undefined && isTerminalAnalysis(a.status);
        })
        .slice(0, limit)
        .map((r) => ({ ...r })),
    );
  }

  shredExpiredArtifacts(now: Date, limit: number): Promise<number> {
    let count = 0;
    for (const a of this.s.artifacts.values()) {
      if (count >= limit) break;
      if (a.purgedAt === null && a.expiresAt.getTime() < now.getTime()) {
        a.shredded = true;
        a.wrappedKey = '';
        a.purgedAt = now;
        a.purgeReason = 'retention';
        this.store.log.push(`shred:${a.objectKey}`);
        count += 1;
      }
    }
    return Promise.resolve(count);
  }

  deletableAnalyses(now: Date, limit: number): Promise<bigint[]> {
    return Promise.resolve(
      [...this.s.analyses.values()]
        .filter(
          (a) =>
            a.expiresAt.getTime() < now.getTime() &&
            isTerminalAnalysis(a.status) &&
            (a.sampleObjectKey === null || a.sampleDeletedAt !== null) &&
            ![...this.s.artifacts.values()].some(
              (x) => x.analysisId === a.id && x.objectDeletedAt === null,
            ),
        )
        .slice(0, limit)
        .map((a) => a.id),
    );
  }

  deleteAnalysis(id: bigint, now: Date): Promise<boolean> {
    const a = this.s.analyses.get(id);
    if (!a || !isTerminalAnalysis(a.status) || a.expiresAt.getTime() >= now.getTime())
      return Promise.resolve(false);
    for (const [key, x] of this.s.artifacts) if (x.analysisId === id) this.s.artifacts.delete(key);
    this.s.analyses.delete(id);
    return Promise.resolve(true);
  }
}

/** In-memory sandbox bucket: puts, deletes and an optional failure per operation. */
export class FakeSandboxObjects implements SandboxObjects {
  readonly objects = new Map<string, Buffer>();
  readonly deleted: string[] = [];
  failDeletes = 0;
  failPuts = 0;

  constructor(private readonly log: string[] = []) {}

  put(key: string, body: Buffer): Promise<void> {
    if (this.failPuts > 0) {
      this.failPuts -= 1;
      return Promise.reject(
        Object.assign(new Error('s3 down'), { $metadata: { httpStatusCode: 503 } }),
      );
    }
    this.objects.set(key, Buffer.from(body));
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    if (this.failDeletes > 0) {
      this.failDeletes -= 1;
      return Promise.reject(
        Object.assign(new Error('s3 down'), { $metadata: { httpStatusCode: 503 } }),
      );
    }
    this.objects.delete(key);
    this.deleted.push(key);
    this.log.push(`delete:${key}`);
    return Promise.resolve();
  }

  check(): Promise<void> {
    return Promise.resolve();
  }
}
