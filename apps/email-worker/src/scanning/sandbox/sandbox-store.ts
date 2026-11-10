import { isUniqueViolation, withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type {
  ArtifactKind,
  EngineOutcome,
  SandboxAnalysisStatus,
  SandboxProfile,
  SandboxSubmissionStatus,
  SandboxVerdict,
} from '@email-gateway/security-contracts';
import type { SandboxRead } from './sandbox-metrics';

/**
 * Every MySQL access of the sandbox engine (step 4.6 X13–X16, §6), on the **writer** only, with
 * the step 4.2 §6 mitigation of the Prisma wrong-read defect: every deciding read selects and
 * verifies its identifying columns (a row of another id, scan, analysis or status throws
 * `InconsistentSandboxReadError`, retryable), every interactive transaction runs with the
 * SCAN_DB_TIMEOUT_MS budget (`withTransactionDefaults`, never Prisma's 5 s default), and every
 * write repeats its state condition (`updateMany … WHERE status IN (…)`).
 *
 * Locks: rows that decide are read with `SELECT … FOR UPDATE` (analysis, scan) or `FOR SHARE`
 * (the submissions of a round when its final is decided), so they see the latest committed
 * versions whatever the transaction's REPEATABLE READ snapshot is. Lock order of every caller:
 * analysis → scan (`email_scans`, ascending id) → submissions; nothing here takes the message
 * row lock, so the order of the round's own transactions (message → scan) cannot cycle with it.
 */

/** A writer read returned rows that do not belong to the request; transient (retried). */
export class InconsistentSandboxReadError extends Error {
  override readonly name = 'InconsistentSandboxReadError';

  constructor(
    readonly read: SandboxRead,
    readonly check: string,
  ) {
    super(`inconsistent ${read} read: ${check}`);
  }
}

/** The ledger row of an event exists already (a concurrent or earlier delivery). */
export class DuplicateLedgerError extends Error {
  override readonly name = 'DuplicateLedgerError';
}

export const TERMINAL_ANALYSIS_STATUSES = [
  'completed',
  'not_executed',
  'failed',
  'expired',
] as const;
export const isTerminalAnalysis = (status: string): boolean =>
  (TERMINAL_ANALYSIS_STATUSES as readonly string[]).includes(status);

export interface SubmissionRef {
  id: bigint;
  receivedAt: Date;
}

export interface SubmissionRow extends SubmissionRef {
  organizationId: bigint;
  messageId: bigint;
  scanId: bigint;
  partIndex: number;
  sha256: string;
  sizeBytes: number;
  detectedType: string;
  objectKey: string;
  status: SandboxSubmissionStatus;
  analysisId: bigint | null;
  settingsVersion: string | null;
  sandboxVerdict: string | null;
  sandboxReasonCodes: string[];
  skipReason: string | null;
}

export interface AnalysisRow {
  id: bigint;
  publicId: string;
  sha256: string;
  sizeBytes: number;
  detectedType: string;
  profile: SandboxProfile;
  analysisKey: string;
  dedupeKey: string | null;
  status: SandboxAnalysisStatus;
  organizationId: bigint;
  sampleObjectKey: string | null;
  sampleDeletedAt: Date | null;
  requestedEventId: string | null;
  dispatchedAt: Date | null;
  /** SHA-256 (hex) of the one-time result token, set at dispatch (X11). */
  resultTokenSha256: string | null;
  deadlineAt: Date;
  completedAt: Date | null;
  verdict: SandboxVerdict | null;
  reasonCodes: string[];
  backend: string | null;
  backendVersion: string | null;
  isolation: string | null;
  executed: boolean | null;
  controllerVersion: string | null;
  reuseUntil: Date | null;
  expiresAt: Date;
}

export interface ScanLockRow {
  scanId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  messageId: bigint;
  lifecycleRound: number;
}

export interface NewAnalysis {
  publicId: string;
  sha256: string;
  sizeBytes: number;
  detectedType: string;
  profile: SandboxProfile;
  analysisKey: string;
  dedupeKey: string;
  organizationId: bigint;
  sampleObjectKey: string;
  requestedEventId: string;
  deadlineAt: Date;
  expiresAt: Date;
}

/** The terminal fields written to an analysis (results consumer, staging failure, expiry). */
export interface AnalysisCompletion {
  status: Extract<SandboxAnalysisStatus, 'completed' | 'not_executed' | 'failed' | 'expired'>;
  verdict: SandboxVerdict;
  reasonCodes: string[];
  report?: unknown;
  backend?: string | null;
  backendVersion?: string | null;
  isolation?: string | null;
  executed?: boolean | null;
  controllerVersion?: string | null;
  analyzerVersion?: string | null;
  mapVersion?: string | null;
  notExecutedReason?: string | null;
  errorCode?: string | null;
  durationMs?: number | null;
  resultEventId?: string | null;
  completedAt: Date;
  reuseUntil: Date | null;
  /** Clear `dedupe_key` (failures, expiries, no reuse window). */
  clearDedupeKey: boolean;
}

export interface SubmissionTerminal {
  status: Extract<SandboxSubmissionStatus, 'completed' | 'failed' | 'expired' | 'skipped'>;
  verdict: SandboxVerdict | null;
  reasonCodes: string[];
  skipReason: string | null;
  completedAt: Date;
  externalRef: string | null;
  /** Written with a skip (dispatch-time settings); kept otherwise. */
  settingsVersion?: string | null;
}

export interface NewArtifact {
  seq: number;
  kind: ArtifactKind;
  contentType: string;
  objectKey: string;
  objectSha256: string;
  plainSha256: string;
  sizeBytes: number;
  wrappedKey: string;
  keyId: string;
  algorithm: string;
  expiresAt: Date;
}

export interface OutboxRow {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  correlationId: string;
  payload: unknown;
}

export interface FinalRow {
  outcome: EngineOutcome;
  engineVersion: string;
  reasonCodes: string[];
  evidence: Record<string, unknown>;
  settingsVersion: string | null;
  completedAt: Date;
}

export interface TenantGateRows {
  /** `organization_features.enabled` of `attachment_sandbox` (false without a row). */
  feature: boolean;
  /** The tenant's `scan_engine_settings` row of engine `sandbox`. */
  settings: { settings: unknown; version: number } | null;
}

/** Summary of an analysis for the round final (versions of the most severe one). */
export interface AnalysisSummary {
  id: bigint;
  executed: boolean | null;
  isolation: string | null;
  controllerVersion: string | null;
  backend: string | null;
  backendVersion: string | null;
}

export interface ArtifactPurgeRow {
  id: bigint;
  analysisId: bigint;
  objectKey: string;
}

/** The operations of one writer transaction (`SandboxStore.transaction`). */
export interface SandboxTx {
  ledger(consumer: string, eventId: string): Promise<void>;
  loadSubmission(ref: SubmissionRef): Promise<SubmissionRow | null>;
  tenantGate(organizationId: bigint): Promise<TenantGateRows>;
  lockAnalysisByDedupe(dedupeKey: string): Promise<AnalysisRow | null>;
  lockAnalysis(id: bigint): Promise<AnalysisRow | null>;
  /** `'duplicate'` on a unique violation of `dedupe_key` (a concurrent dispatcher). */
  createAnalysis(input: NewAnalysis): Promise<AnalysisRow | 'duplicate'>;
  clearDedupeKey(id: bigint, dedupeKey: string): Promise<void>;
  /** `pending` (or already linked to this analysis) → `submitted` with `analysis_id`. */
  linkSubmission(
    ref: SubmissionRef,
    analysisId: bigint,
    settingsVersion: string | null,
  ): Promise<boolean>;
  /** `pending → dispatched` with the task's result token hash (X11); false when not pending. */
  markDispatched(id: bigint, now: Date, resultTokenSha256: string): Promise<boolean>;
  completeAnalysis(
    id: bigint,
    from: readonly SandboxAnalysisStatus[],
    completion: AnalysisCompletion,
  ): Promise<boolean>;
  insertArtifacts(analysisId: bigint, rows: readonly NewArtifact[]): Promise<void>;
  /** `submitted` submissions linked to the analysis (≤ limit). */
  linkedSubmitted(analysisId: bigint, limit: number): Promise<SubmissionRow[]>;
  analysesByIds(ids: readonly bigint[]): Promise<Map<bigint, AnalysisRow>>;
  /** `email_scans` rows `FOR UPDATE` in ascending id order (absent rows are left out). */
  lockScans(
    refs: readonly { scanId: bigint; receivedAt: Date }[],
  ): Promise<Map<string, ScanLockRow>>;
  finishSubmission(ref: SubmissionRef, data: SubmissionTerminal): Promise<boolean>;
  /** Every submission of a round (`FOR SHARE`, ordered by part index). */
  roundSubmissions(scan: ScanLockRow): Promise<SubmissionRow[]>;
  /** Version summaries (`FOR SHARE`) of the analyses of a round whose submissions are terminal. */
  analysisSummaries(ids: readonly bigint[]): Promise<Map<bigint, AnalysisSummary>>;
  /** The round's `sandbox` final; false when it exists (unique `(scan, final_engine)`). */
  insertFinal(scan: ScanLockRow, final: FinalRow): Promise<boolean>;
  writeOutbox(row: OutboxRow): Promise<void>;
  publishHash(sha256: string, publicId: string, now: Date, expiresAt: Date): Promise<boolean>;

  // Sweeper reads (X16), bounded, optionally restricted to organizations (tests).
  pendingSubmissionsBefore(cutoff: Date, limit: number): Promise<SubmissionRow[]>;
  overdueAnalyses(now: Date, limit: number): Promise<bigint[]>;
  submittedWithTerminalAnalysis(limit: number): Promise<SubmissionRow[]>;
  shredExpiredArtifacts(now: Date, limit: number): Promise<number>;
  deletableAnalyses(now: Date, limit: number): Promise<bigint[]>;
  deleteAnalysis(id: bigint, now: Date): Promise<boolean>;
}

export const DUPLICATE = Symbol('duplicate');

/** The sandbox engine's view of the writer. */
export interface SandboxStore {
  isProcessed(consumer: string, eventId: string): Promise<boolean>;
  /** The ledger row of a no-op (rejected or skipped event); false when it existed. */
  recordNoop(consumer: string, eventId: string): Promise<boolean>;
  /** One writer transaction; `DUPLICATE` when `tx.ledger` met an existing row (rolled back). */
  transaction<T>(fn: (tx: SandboxTx) => Promise<T>): Promise<T | typeof DUPLICATE>;
  markSampleDeleted(analysisId: bigint, key: string, now: Date): Promise<boolean>;
  samplesToDelete(limit: number): Promise<{ id: bigint; key: string }[]>;
  artifactsToDelete(limit: number): Promise<ArtifactPurgeRow[]>;
  markArtifactObjectDeleted(id: bigint, key: string, now: Date): Promise<boolean>;
}

const sameTime = (a: Date, b: Date): boolean => a.getTime() === b.getTime();

function stringArray(value: unknown): string[] {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
}

const json = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;
const asDate = (value: unknown): Date | null =>
  value === null || value === undefined
    ? null
    : value instanceof Date
      ? value
      : typeof value === 'string' || typeof value === 'number'
        ? new Date(value)
        : null;
const asBool = (value: unknown): boolean | null =>
  value === null || value === undefined ? null : Boolean(Number(value));
const str = (value: unknown): string | null =>
  typeof value === 'string'
    ? value
    : typeof value === 'number' || typeof value === 'bigint'
      ? value.toString()
      : null;

const ANALYSIS_COLUMNS = Prisma.sql`id, public_id, sha256, size_bytes, detected_type, profile, analysis_key,
  dedupe_key, status, organization_id, sample_object_key, sample_deleted_at, requested_event_id,
  dispatched_at, result_token_sha256, deadline_at, completed_at, verdict, reason_codes, backend, backend_version,
  isolation, executed, controller_version, reuse_until, expires_at`;

type RawRow = Record<string, unknown>;

function toAnalysis(row: RawRow): AnalysisRow {
  return {
    id: BigInt(row.id as bigint),
    publicId: String(row.public_id),
    sha256: String(row.sha256),
    sizeBytes: Number(row.size_bytes),
    detectedType: String(row.detected_type),
    profile: String(row.profile) as SandboxProfile,
    analysisKey: String(row.analysis_key),
    dedupeKey: str(row.dedupe_key),
    status: String(row.status) as SandboxAnalysisStatus,
    organizationId: BigInt(row.organization_id as bigint),
    sampleObjectKey: str(row.sample_object_key),
    sampleDeletedAt: asDate(row.sample_deleted_at),
    requestedEventId: str(row.requested_event_id),
    dispatchedAt: asDate(row.dispatched_at),
    resultTokenSha256: str(row.result_token_sha256),
    deadlineAt: asDate(row.deadline_at)!,
    completedAt: asDate(row.completed_at),
    verdict: str(row.verdict) as SandboxVerdict | null,
    reasonCodes: stringArray(row.reason_codes),
    backend: str(row.backend),
    backendVersion: str(row.backend_version),
    isolation: str(row.isolation),
    executed: asBool(row.executed),
    controllerVersion: str(row.controller_version),
    reuseUntil: asDate(row.reuse_until),
    expiresAt: asDate(row.expires_at)!,
  };
}

const SUBMISSION_SELECT = {
  id: true,
  receivedAt: true,
  organizationId: true,
  messageId: true,
  scanId: true,
  partIndex: true,
  sha256: true,
  sizeBytes: true,
  detectedType: true,
  objectKey: true,
  status: true,
  analysisId: true,
  settingsVersion: true,
  sandboxVerdict: true,
  sandboxReasonCodes: true,
  skipReason: true,
} as const;

type PrismaSubmission = Prisma.SandboxSubmissionGetPayload<{ select: typeof SUBMISSION_SELECT }>;

const toSubmission = (row: PrismaSubmission): SubmissionRow => ({
  ...row,
  status: row.status,
  sandboxReasonCodes: stringArray(row.sandboxReasonCodes),
});

function rawSubmission(row: RawRow): SubmissionRow {
  return {
    id: BigInt(row.id as bigint),
    receivedAt: asDate(row.received_at)!,
    organizationId: BigInt(row.organization_id as bigint),
    messageId: BigInt(row.message_id as bigint),
    scanId: BigInt(row.scan_id as bigint),
    partIndex: Number(row.part_index),
    sha256: String(row.sha256),
    sizeBytes: Number(row.size_bytes),
    detectedType: String(row.detected_type),
    objectKey: String(row.object_key),
    status: String(row.status) as SandboxSubmissionStatus,
    analysisId: row.analysis_id === null ? null : BigInt(row.analysis_id as bigint),
    settingsVersion: str(row.settings_version),
    sandboxVerdict: str(row.sandbox_verdict),
    sandboxReasonCodes: stringArray(row.sandbox_reason_codes),
    skipReason: str(row.skip_reason),
  };
}

const SUBMISSION_COLUMNS = Prisma.sql`id, received_at, organization_id, message_id, scan_id, part_index,
  sha256, size_bytes, detected_type, object_key, status, analysis_id, settings_version,
  sandbox_verdict, sandbox_reason_codes, skip_reason`;

export const scanKey = (scanId: bigint, receivedAt: Date): string =>
  `${scanId.toString()}@${receivedAt.getTime()}`;

class PrismaSandboxTx implements SandboxTx {
  constructor(
    private readonly tx: Prisma.TransactionClient,
    private readonly organizationIds: readonly bigint[] | undefined,
  ) {}

  private orgSql(column: Prisma.Sql): Prisma.Sql {
    const ids = this.organizationIds;
    return ids && ids.length > 0
      ? Prisma.sql`AND ${column} IN (${Prisma.join(ids)})`
      : Prisma.empty;
  }

  private get orgWhere() {
    const ids = this.organizationIds;
    return ids ? { organizationId: { in: [...ids] } } : {};
  }

  async ledger(consumer: string, eventId: string): Promise<void> {
    try {
      await this.tx.messageIdempotency.create({ data: { consumer, eventId } });
    } catch (error) {
      if (isUniqueViolation(error)) throw new DuplicateLedgerError();
      throw error;
    }
  }

  async loadSubmission(ref: SubmissionRef): Promise<SubmissionRow | null> {
    const row = await this.tx.sandboxSubmission.findFirst({
      where: { id: ref.id, receivedAt: ref.receivedAt },
      select: SUBMISSION_SELECT,
    });
    if (!row) return null;
    if (
      row.id !== ref.id ||
      !(row.receivedAt instanceof Date) ||
      !sameTime(row.receivedAt, ref.receivedAt)
    ) {
      throw new InconsistentSandboxReadError('submission', 'identity echo');
    }
    return toSubmission(row);
  }

  async tenantGate(organizationId: bigint): Promise<TenantGateRows> {
    const feature = await this.tx.organizationFeature.findUnique({
      where: { organizationId_featureKey: { organizationId, featureKey: 'attachment_sandbox' } },
      select: { organizationId: true, featureKey: true, enabled: true },
    });
    if (
      feature &&
      (feature.organizationId !== organizationId || feature.featureKey !== 'attachment_sandbox')
    ) {
      throw new InconsistentSandboxReadError('submission', 'feature echo');
    }
    const settings = await this.tx.scanEngineSetting.findUnique({
      where: { organizationId_engine: { organizationId, engine: 'sandbox' } },
      select: { organizationId: true, engine: true, settings: true, version: true },
    });
    if (settings && (settings.organizationId !== organizationId || settings.engine !== 'sandbox')) {
      throw new InconsistentSandboxReadError('submission', 'settings echo');
    }
    return {
      feature: feature?.enabled === true,
      settings: settings ? { settings: settings.settings, version: settings.version } : null,
    };
  }

  async lockAnalysisByDedupe(dedupeKey: string): Promise<AnalysisRow | null> {
    const rows = await this.tx.$queryRaw<RawRow[]>`
      SELECT ${ANALYSIS_COLUMNS} FROM sandbox_analyses WHERE dedupe_key = ${dedupeKey} FOR UPDATE`;
    if (rows.length > 1)
      throw new InconsistentSandboxReadError('analysis', 'dedupe key not unique');
    const row = rows[0];
    if (!row) return null;
    const analysis = toAnalysis(row);
    if (analysis.dedupeKey !== dedupeKey) {
      throw new InconsistentSandboxReadError('analysis', 'dedupe key echo');
    }
    return analysis;
  }

  async lockAnalysis(id: bigint): Promise<AnalysisRow | null> {
    const rows = await this.tx.$queryRaw<RawRow[]>`
      SELECT ${ANALYSIS_COLUMNS} FROM sandbox_analyses WHERE id = ${id} FOR UPDATE`;
    const row = rows[0];
    if (!row) return null;
    const analysis = toAnalysis(row);
    if (analysis.id !== id || rows.length > 1) {
      throw new InconsistentSandboxReadError('analysis', 'identity echo');
    }
    return analysis;
  }

  async createAnalysis(input: NewAnalysis): Promise<AnalysisRow | 'duplicate'> {
    try {
      await this.tx.sandboxAnalysis.create({
        data: { ...input, status: 'pending' },
        select: { id: true },
      });
    } catch (error) {
      if (isUniqueViolation(error)) return 'duplicate';
      throw error;
    }
    const created = await this.lockAnalysisByDedupe(input.dedupeKey);
    if (!created || created.publicId !== input.publicId) {
      throw new InconsistentSandboxReadError('analysis', 'created row echo');
    }
    return created;
  }

  async clearDedupeKey(id: bigint, dedupeKey: string): Promise<void> {
    await this.tx.sandboxAnalysis.updateMany({
      where: { id, dedupeKey },
      data: { dedupeKey: null },
    });
  }

  async linkSubmission(
    ref: SubmissionRef,
    analysisId: bigint,
    settingsVersion: string | null,
  ): Promise<boolean> {
    const updated = await this.tx.sandboxSubmission.updateMany({
      where: {
        id: ref.id,
        receivedAt: ref.receivedAt,
        OR: [
          { status: 'pending', analysisId: null },
          { status: 'submitted', analysisId },
        ],
      },
      data: {
        status: 'submitted',
        analysisId,
        ...(settingsVersion !== null ? { settingsVersion } : {}),
      },
    });
    return updated.count === 1;
  }

  async markDispatched(id: bigint, now: Date, resultTokenSha256: string): Promise<boolean> {
    const updated = await this.tx.sandboxAnalysis.updateMany({
      where: { id, status: 'pending' },
      data: { status: 'dispatched', dispatchedAt: now, resultTokenSha256 },
    });
    return updated.count === 1;
  }

  async completeAnalysis(
    id: bigint,
    from: readonly SandboxAnalysisStatus[],
    c: AnalysisCompletion,
  ): Promise<boolean> {
    const updated = await this.tx.sandboxAnalysis.updateMany({
      where: { id, status: { in: [...from] } },
      data: {
        status: c.status,
        verdict: c.verdict,
        reasonCodes: json(c.reasonCodes),
        ...(c.report !== undefined ? { report: json(c.report) } : {}),
        ...(c.backend !== undefined ? { backend: c.backend } : {}),
        ...(c.backendVersion !== undefined ? { backendVersion: c.backendVersion } : {}),
        ...(c.isolation !== undefined ? { isolation: c.isolation } : {}),
        ...(c.executed !== undefined ? { executed: c.executed } : {}),
        ...(c.controllerVersion !== undefined ? { controllerVersion: c.controllerVersion } : {}),
        ...(c.analyzerVersion !== undefined ? { analyzerVersion: c.analyzerVersion } : {}),
        ...(c.mapVersion !== undefined ? { mapVersion: c.mapVersion } : {}),
        ...(c.notExecutedReason !== undefined ? { notExecutedReason: c.notExecutedReason } : {}),
        ...(c.errorCode !== undefined ? { errorCode: c.errorCode } : {}),
        ...(c.durationMs !== undefined ? { durationMs: c.durationMs } : {}),
        ...(c.resultEventId !== undefined ? { resultEventId: c.resultEventId } : {}),
        completedAt: c.completedAt,
        reuseUntil: c.reuseUntil,
        ...(c.clearDedupeKey ? { dedupeKey: null } : {}),
      },
    });
    return updated.count === 1;
  }

  async insertArtifacts(analysisId: bigint, rows: readonly NewArtifact[]): Promise<void> {
    if (rows.length === 0) return;
    await this.tx.sandboxArtifact.createMany({
      data: rows.map((row) => ({ ...row, analysisId })),
    });
  }

  async linkedSubmitted(analysisId: bigint, limit: number): Promise<SubmissionRow[]> {
    const rows = await this.tx.sandboxSubmission.findMany({
      where: { analysisId, status: 'submitted' },
      orderBy: { id: 'asc' },
      take: limit,
      select: SUBMISSION_SELECT,
    });
    if (rows.some((r) => r.analysisId !== analysisId || r.status !== 'submitted')) {
      throw new InconsistentSandboxReadError('linked_submissions', 'analysis echo');
    }
    return rows.map(toSubmission);
  }

  async analysesByIds(ids: readonly bigint[]): Promise<Map<bigint, AnalysisRow>> {
    const unique = [...new Set(ids)];
    const result = new Map<bigint, AnalysisRow>();
    if (unique.length === 0) return result;
    const rows = await this.tx.$queryRaw<RawRow[]>`
      SELECT ${ANALYSIS_COLUMNS} FROM sandbox_analyses WHERE id IN (${Prisma.join(unique)})`;
    for (const raw of rows) {
      const analysis = toAnalysis(raw);
      if (!unique.includes(analysis.id)) {
        throw new InconsistentSandboxReadError('analysis', 'identity echo');
      }
      result.set(analysis.id, analysis);
    }
    return result;
  }

  async lockScans(
    refs: readonly { scanId: bigint; receivedAt: Date }[],
  ): Promise<Map<string, ScanLockRow>> {
    const distinct = new Map<string, { scanId: bigint; receivedAt: Date }>();
    for (const ref of refs) distinct.set(scanKey(ref.scanId, ref.receivedAt), ref);
    const ordered = [...distinct.values()].sort((a, b) =>
      a.scanId < b.scanId
        ? -1
        : a.scanId > b.scanId
          ? 1
          : a.receivedAt.getTime() - b.receivedAt.getTime(),
    );
    const result = new Map<string, ScanLockRow>();
    for (const ref of ordered) {
      const rows = await this.tx.$queryRaw<RawRow[]>`
        SELECT id, received_at, organization_id, message_id, lifecycle_round
        FROM email_scans WHERE id = ${ref.scanId} AND received_at = ${ref.receivedAt} FOR UPDATE`;
      const row = rows[0];
      if (!row) continue;
      const lock: ScanLockRow = {
        scanId: BigInt(row.id as bigint),
        receivedAt: asDate(row.received_at)!,
        organizationId: BigInt(row.organization_id as bigint),
        messageId: BigInt(row.message_id as bigint),
        lifecycleRound: Number(row.lifecycle_round),
      };
      if (lock.scanId !== ref.scanId || !sameTime(lock.receivedAt, ref.receivedAt)) {
        throw new InconsistentSandboxReadError('scan', 'identity echo');
      }
      result.set(scanKey(lock.scanId, lock.receivedAt), lock);
    }
    return result;
  }

  async finishSubmission(ref: SubmissionRef, data: SubmissionTerminal): Promise<boolean> {
    const updated = await this.tx.sandboxSubmission.updateMany({
      where: { id: ref.id, receivedAt: ref.receivedAt, status: { in: ['pending', 'submitted'] } },
      data: {
        status: data.status,
        sandboxVerdict: data.verdict,
        sandboxReasonCodes: json(data.reasonCodes),
        skipReason: data.skipReason,
        completedAt: data.completedAt,
        externalRef: data.externalRef,
        ...(data.settingsVersion !== undefined ? { settingsVersion: data.settingsVersion } : {}),
      },
    });
    return updated.count === 1;
  }

  async roundSubmissions(scan: ScanLockRow): Promise<SubmissionRow[]> {
    const rows = await this.tx.$queryRaw<RawRow[]>`
      SELECT ${SUBMISSION_COLUMNS} FROM sandbox_submissions
      WHERE scan_id = ${scan.scanId} AND received_at = ${scan.receivedAt}
      ORDER BY part_index, id FOR SHARE`;
    const result = rows.map(rawSubmission);
    if (result.some((r) => r.scanId !== scan.scanId || !sameTime(r.receivedAt, scan.receivedAt))) {
      throw new InconsistentSandboxReadError('linked_submissions', 'scan echo');
    }
    return result;
  }

  async analysisSummaries(ids: readonly bigint[]): Promise<Map<bigint, AnalysisSummary>> {
    const unique = [...new Set(ids)];
    const result = new Map<bigint, AnalysisSummary>();
    if (unique.length === 0) return result;
    const rows = await this.tx.$queryRaw<RawRow[]>`
      SELECT id, executed, isolation, controller_version, backend, backend_version
      FROM sandbox_analyses WHERE id IN (${Prisma.join(unique)}) FOR SHARE`;
    for (const row of rows) {
      const id = BigInt(row.id as bigint);
      if (!unique.includes(id)) throw new InconsistentSandboxReadError('analysis', 'identity echo');
      result.set(id, {
        id,
        executed: asBool(row.executed),
        isolation: str(row.isolation),
        controllerVersion: str(row.controller_version),
        backend: str(row.backend),
        backendVersion: str(row.backend_version),
      });
    }
    return result;
  }

  async insertFinal(scan: ScanLockRow, final: FinalRow): Promise<boolean> {
    const created = await this.tx.scanEngineResult.createMany({
      data: [
        {
          receivedAt: scan.receivedAt,
          scanId: scan.scanId,
          messageId: scan.messageId,
          organizationId: scan.organizationId,
          engine: 'sandbox',
          engineVersion: final.engineVersion,
          outcome: final.outcome,
          score: null,
          requiredScore: null,
          action: null,
          durationMs: 0,
          evidence: json(final.evidence),
          completedAt: final.completedAt,
          attempt: 1,
          isFinal: true,
          reasonCodes: json(final.reasonCodes),
          errorCode: null,
          settingsVersion: final.settingsVersion,
        },
      ],
      // Unique (scan_id, final_engine, received_at): a final written earlier is kept.
      skipDuplicates: true,
    });
    return created.count === 1;
  }

  async writeOutbox(row: OutboxRow): Promise<void> {
    await this.tx.messageOutbox.create({
      data: { ...row, payload: json(row.payload) },
      select: { id: true },
    });
  }

  async publishHash(
    sha256: string,
    publicId: string,
    now: Date,
    expiresAt: Date,
  ): Promise<boolean> {
    const created = await this.tx.malwareSignature.createMany({
      data: [
        {
          sha256,
          severity: 'high',
          source: 'sandbox',
          reason: `sandbox analysis ${publicId}`,
          firstSeenAt: now,
          lastSeenAt: now,
          expiresAt,
        },
      ],
      skipDuplicates: true,
    });
    return created.count === 1;
  }

  async pendingSubmissionsBefore(cutoff: Date, limit: number): Promise<SubmissionRow[]> {
    const rows = await this.tx.sandboxSubmission.findMany({
      where: { ...this.orgWhere, status: 'pending', createdAt: { lt: cutoff } },
      orderBy: { createdAt: 'asc' },
      take: limit,
      select: { ...SUBMISSION_SELECT, createdAt: true },
    });
    if (rows.some((r) => r.status !== 'pending' || r.createdAt.getTime() >= cutoff.getTime())) {
      throw new InconsistentSandboxReadError('submission', 'pending expiry echo');
    }
    return rows.map(({ createdAt: _createdAt, ...row }) => toSubmission(row));
  }

  async overdueAnalyses(now: Date, limit: number): Promise<bigint[]> {
    const rows = await this.tx.sandboxAnalysis.findMany({
      where: {
        ...this.orgWhere,
        status: { in: ['pending', 'dispatched'] },
        deadlineAt: { lt: now },
      },
      orderBy: { deadlineAt: 'asc' },
      take: limit,
      select: { id: true },
    });
    return rows.map((r) => r.id);
  }

  async submittedWithTerminalAnalysis(limit: number): Promise<SubmissionRow[]> {
    const rows = await this.tx.$queryRaw<RawRow[]>`
      SELECT s.id, s.received_at, s.organization_id, s.message_id, s.scan_id, s.part_index,
             s.sha256, s.size_bytes, s.detected_type, s.object_key, s.status, s.analysis_id,
             s.settings_version, s.sandbox_verdict, s.sandbox_reason_codes, s.skip_reason
      FROM sandbox_submissions s
      JOIN sandbox_analyses a ON a.id = s.analysis_id
      WHERE s.status = 'submitted'
        AND a.status IN ('completed', 'not_executed', 'failed', 'expired')
        ${this.orgSql(Prisma.sql`s.organization_id`)}
      ORDER BY s.id
      LIMIT ${limit}`;
    const result = rows.map(rawSubmission);
    if (result.some((r) => r.status !== 'submitted' || r.analysisId === null)) {
      throw new InconsistentSandboxReadError('linked_submissions', 'catch-up echo');
    }
    return result;
  }

  async shredExpiredArtifacts(now: Date, limit: number): Promise<number> {
    const ids = this.organizationIds;
    const rows = await this.tx.sandboxArtifact.findMany({
      where: {
        purgedAt: null,
        expiresAt: { lt: now },
        ...(ids ? { analysis: { organizationId: { in: [...ids] } } } : {}),
      },
      orderBy: { expiresAt: 'asc' },
      take: limit,
      select: { id: true, purgedAt: true, expiresAt: true },
    });
    if (rows.some((r) => r.purgedAt !== null || r.expiresAt.getTime() >= now.getTime())) {
      throw new InconsistentSandboxReadError('analysis', 'artifact expiry echo');
    }
    if (rows.length === 0) return 0;
    // Crypto-shredding first: the wrapped data key is gone from this commit on (X16 (e)).
    const updated = await this.tx.sandboxArtifact.updateMany({
      where: { id: { in: rows.map((r) => r.id) }, purgedAt: null, expiresAt: { lt: now } },
      data: { wrappedKey: null, purgedAt: now, purgeReason: 'retention' },
    });
    return updated.count;
  }

  async deletableAnalyses(now: Date, limit: number): Promise<bigint[]> {
    const rows = await this.tx.sandboxAnalysis.findMany({
      where: {
        ...this.orgWhere,
        expiresAt: { lt: now },
        status: { in: [...TERMINAL_ANALYSIS_STATUSES] },
        OR: [{ sampleObjectKey: null }, { sampleDeletedAt: { not: null } }],
        artifacts: { none: { objectDeletedAt: null } },
      },
      orderBy: { expiresAt: 'asc' },
      take: limit,
      select: { id: true },
    });
    return rows.map((r) => r.id);
  }

  async deleteAnalysis(id: bigint, now: Date): Promise<boolean> {
    const locked = await this.lockAnalysis(id);
    if (
      !locked ||
      !isTerminalAnalysis(locked.status) ||
      locked.expiresAt.getTime() >= now.getTime() ||
      (locked.sampleObjectKey !== null && locked.sampleDeletedAt === null)
    ) {
      return false;
    }
    const open = await this.tx.sandboxArtifact.count({
      where: { analysisId: id, objectDeletedAt: null },
    });
    if (open > 0) return false;
    await this.tx.sandboxArtifact.deleteMany({
      where: { analysisId: id, objectDeletedAt: { not: null } },
    });
    const deleted = await this.tx.sandboxAnalysis.deleteMany({
      where: { id, status: { in: [...TERMINAL_ANALYSIS_STATUSES] } },
    });
    return deleted.count === 1;
  }
}

export interface PrismaSandboxStoreOptions {
  /** SCAN_DB_TIMEOUT_MS (timeout and maxWait of every interactive transaction, §6). */
  txTimeoutMs: number;
  /** Restricts the sweeper reads to these organizations (integration tests on the shared writer). */
  organizationIds?: readonly bigint[];
}

export class PrismaSandboxStore implements SandboxStore {
  private readonly txPrisma: PrismaClient;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: PrismaSandboxStoreOptions,
  ) {
    this.txPrisma = withTransactionDefaults(prisma, { timeoutMs: options.txTimeoutMs });
  }

  private get orgWhere() {
    const ids = this.options.organizationIds;
    return ids ? { organizationId: { in: [...ids] } } : {};
  }

  async isProcessed(consumer: string, eventId: string): Promise<boolean> {
    const row = await this.prisma.messageIdempotency.findUnique({
      where: { consumer_eventId: { consumer, eventId } },
      select: { consumer: true, eventId: true },
    });
    return row !== null && row.consumer === consumer && row.eventId === eventId;
  }

  async recordNoop(consumer: string, eventId: string): Promise<boolean> {
    const result = await this.transaction((tx) => tx.ledger(consumer, eventId));
    return result !== DUPLICATE;
  }

  async transaction<T>(fn: (tx: SandboxTx) => Promise<T>): Promise<T | typeof DUPLICATE> {
    try {
      return await this.txPrisma.$transaction((tx) =>
        fn(new PrismaSandboxTx(tx, this.options.organizationIds)),
      );
    } catch (error) {
      if (error instanceof DuplicateLedgerError) return DUPLICATE;
      throw error;
    }
  }

  async markSampleDeleted(analysisId: bigint, key: string, now: Date): Promise<boolean> {
    const updated = await this.prisma.sandboxAnalysis.updateMany({
      where: { id: analysisId, sampleObjectKey: key, sampleDeletedAt: null },
      data: { sampleDeletedAt: now },
    });
    return updated.count === 1;
  }

  async samplesToDelete(limit: number): Promise<{ id: bigint; key: string }[]> {
    const rows = await this.prisma.sandboxAnalysis.findMany({
      where: {
        ...this.orgWhere,
        status: { in: [...TERMINAL_ANALYSIS_STATUSES] },
        sampleObjectKey: { not: null },
        sampleDeletedAt: null,
      },
      orderBy: { id: 'asc' },
      take: limit,
      select: { id: true, sampleObjectKey: true, sampleDeletedAt: true, status: true },
    });
    if (
      rows.some(
        (r) =>
          r.sampleObjectKey === null || r.sampleDeletedAt !== null || !isTerminalAnalysis(r.status),
      )
    ) {
      throw new InconsistentSandboxReadError('analysis', 'sample purge echo');
    }
    return rows.map((r) => ({ id: r.id, key: r.sampleObjectKey! }));
  }

  async artifactsToDelete(limit: number): Promise<ArtifactPurgeRow[]> {
    const ids = this.options.organizationIds;
    const rows = await this.prisma.sandboxArtifact.findMany({
      where: {
        purgedAt: { not: null },
        wrappedKey: null,
        objectDeletedAt: null,
        ...(ids ? { analysis: { organizationId: { in: [...ids] } } } : {}),
      },
      orderBy: { id: 'asc' },
      take: limit,
      select: {
        id: true,
        analysisId: true,
        objectKey: true,
        wrappedKey: true,
        purgedAt: true,
        objectDeletedAt: true,
      },
    });
    if (
      rows.some((r) => r.wrappedKey !== null || r.purgedAt === null || r.objectDeletedAt !== null)
    ) {
      throw new InconsistentSandboxReadError('analysis', 'artifact purge echo');
    }
    return rows.map((r) => ({ id: r.id, analysisId: r.analysisId, objectKey: r.objectKey }));
  }

  async markArtifactObjectDeleted(id: bigint, key: string, now: Date): Promise<boolean> {
    const updated = await this.prisma.sandboxArtifact.updateMany({
      where: {
        id,
        objectKey: key,
        wrappedKey: null,
        purgedAt: { not: null },
        objectDeletedAt: null,
      },
      data: { objectDeletedAt: now },
    });
    return updated.count === 1;
  }
}
