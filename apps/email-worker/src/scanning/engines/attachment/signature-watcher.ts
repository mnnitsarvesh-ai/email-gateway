import {
  isUniqueViolation,
  sleep as defaultSleep,
  withTransactionDefaults,
} from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { errorFields } from '../../../mime-ingestion/error-fields';
import type { LeaderLock } from '../../deadline-sweeper';
import type { AttachmentMetrics, SignatureComponent } from './attachment-metrics';

/** One cluster-wide leader of the signature watcher (A13). */
export const SIGNATURE_WATCHER_LOCK = 'scan:attachment-signatures';
/** `scan_signature_versions.engine` of the attachment engine's components. */
export const SIGNATURE_ENGINE = 'attachment';
/** Message states a rescan job selects by default (A13). */
export const DEFAULT_RESCAN_STATES = ['scanned', 'scan_failed', 'quarantined', 'held_for_review'];

export interface ComponentVersion {
  component: SignatureComponent;
  version: string;
}

/**
 * The current component versions (A13): clamd `VERSION` (database and engine) and the worker's
 * own YARA bundle id. A seam: integration tests simulate a change with their own provider.
 */
export interface VersionSource {
  current(
    signal: AbortSignal,
  ): Promise<{ versions: ComponentVersion[]; clamavDbTime: Date | null }>;
}

export type SignatureRescanMode = 'off' | 'record' | 'rescan';

export interface SignatureWatcherOptions {
  prisma: PrismaClient;
  locks: LeaderLock;
  source: VersionSource;
  metrics: AttachmentMetrics;
  logger: Logger;
  /** ATTACHMENT_SIGNATURE_POLL_MS. */
  intervalMs: number;
  /** ATTACHMENT_SIGNATURE_RESCAN. */
  mode: SignatureRescanMode;
  /** ATTACHMENT_RESCAN_WINDOW_HOURS: the detector job's window ends at the change. */
  windowHours: number;
  /** ATTACHMENT_RESCAN_MAX_MESSAGES. */
  maxMessages: number;
  /** SCAN_DB_TIMEOUT_MS: budget of the version + job transaction. */
  txTimeoutMs: number;
  lockName?: string;
  /** `scan_signature_versions.engine` (integration tests use a per-run value). */
  engine?: string;
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface WatchReport {
  outcome: 'not_leader' | 'unavailable' | 'database_error' | 'polled';
  changes: Array<{ component: SignatureComponent; from: string; to: string; jobCreated: boolean }>;
}

const VERSION_TIMEOUT_MS = 10_000;

/**
 * The signature-update detector (step 4.2 A13): while this process holds
 * `GET_LOCK('scan:attachment-signatures')`, every ATTACHMENT_SIGNATURE_POLL_MS it reads the
 * component versions, upserts `scan_signature_versions (engine, component, version,
 * first_seen_at, last_seen_at)` and treats a new version of a component that had a previous one
 * as a change: log (versions only), `scan_attachment_signature_changes_total{component}`, and
 * per ATTACHMENT_SIGNATURE_RESCAN an `attachment_rescan_jobs` row (`record` → `skipped`, an
 * audit trail; `rescan` → `pending`; `off` → none) with the unique dedupe key
 * `sig:<component>:<version>`, so the fleet creates one job per change. The new version row and
 * its job are written in one writer transaction: a failed job insert rolls the version back, so
 * the next poll detects the change again (a change is never recorded without its job). Errors
 * back off; the loop continues.
 */
export class SignatureWatcher {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly engine: string;
  private readonly txPrisma: PrismaClient;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;

  constructor(private readonly options: SignatureWatcherOptions) {
    this.lockName = options.lockName ?? SIGNATURE_WATCHER_LOCK;
    this.engine = options.engine ?? SIGNATURE_ENGINE;
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.logger = options.logger.child({ component: 'attachment-signature-watcher' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    const signal = this.abort.signal;
    this.loop = (async () => {
      while (!signal.aborted) {
        await this.poll(signal).catch((error: unknown) =>
          this.logger.warn(errorFields(error), 'signature watcher pass failed'),
        );
        if (!(await this.sleepFn(this.options.intervalMs, signal))) break;
      }
    })();
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One pass (also called directly by tests). */
  async poll(signal: AbortSignal = new AbortController().signal): Promise<WatchReport> {
    const report: WatchReport = { outcome: 'polled', changes: [] };
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch {
      return { ...report, outcome: 'database_error' };
    }
    if (!leader) return { ...report, outcome: 'not_leader' };
    let current: Awaited<ReturnType<VersionSource['current']>>;
    try {
      current = await this.options.source.current(
        AbortSignal.any([signal, AbortSignal.timeout(VERSION_TIMEOUT_MS)]),
      );
    } catch {
      return { ...report, outcome: 'unavailable' };
    }
    const now = this.now();
    if (current.clamavDbTime) {
      this.options.metrics.clamavDbAge.set(
        Math.max(0, (now.getTime() - current.clamavDbTime.getTime()) / 1000),
      );
    }
    try {
      for (const { component, version } of current.versions) {
        this.options.metrics.signature(component, version);
        const change = await this.record(component, version, now);
        if (change) report.changes.push(change);
      }
    } catch (error) {
      this.logger.warn(errorFields(error), 'signature watcher database error');
      return { ...report, outcome: 'database_error' };
    }
    return report;
  }

  private async record(
    component: SignatureComponent,
    version: string,
    now: Date,
  ): Promise<WatchReport['changes'][number] | null> {
    const { prisma } = this.options;
    const key = { engine: this.engine, component, version };
    const existing = await prisma.scanSignatureVersion.findUnique({
      where: { engine_component_version: key },
      select: { id: true },
    });
    if (existing) {
      await prisma.scanSignatureVersion.update({
        where: { id: existing.id },
        data: { lastSeenAt: now },
        select: { id: true },
      });
      return null;
    }
    const previous = await prisma.scanSignatureVersion.findFirst({
      where: { engine: this.engine, component },
      orderBy: [{ lastSeenAt: 'desc' }, { id: 'desc' }],
      select: { version: true },
    });
    const job = previous ? this.jobFor(component, previous.version, version, now) : null;
    let jobCreated: boolean;
    try {
      jobCreated = await this.txPrisma.$transaction(async (tx) => {
        await tx.scanSignatureVersion.create({
          data: { ...key, firstSeenAt: now, lastSeenAt: now },
          select: { id: true },
        });
        if (!job) return false;
        const created = await tx.attachmentRescanJob.createMany({
          data: [job],
          skipDuplicates: true,
        });
        return created.count > 0;
      });
    } catch (error) {
      // Another replica recorded it first (it reports the change).
      if (isUniqueViolation(error)) return null;
      throw error;
    }
    if (!previous) {
      this.logger.info({ component, version }, 'signature component version recorded');
      return null;
    }
    this.options.metrics.signatureChanges.inc({ component });
    this.logger.info(
      { component, from: previous.version, to: version, mode: this.options.mode },
      'signature version changed',
    );
    return { component, from: previous.version, to: version, jobCreated };
  }

  /** The job of a change per ATTACHMENT_SIGNATURE_RESCAN (`off` → none). */
  private jobFor(
    component: SignatureComponent,
    from: string,
    to: string,
    now: Date,
  ): Prisma.AttachmentRescanJobCreateManyInput | null {
    if (this.options.mode === 'off') return null;
    return {
      trigger: 'signature_update',
      status: this.options.mode === 'rescan' ? 'pending' : 'skipped',
      dedupeKey: `sig:${component}:${to}`.slice(0, 128),
      organizationId: null,
      windowStart: new Date(now.getTime() - this.options.windowHours * 3_600_000),
      windowEnd: now,
      states: DEFAULT_RESCAN_STATES,
      component,
      fromVersion: from.slice(0, 128),
      toVersion: to.slice(0, 128),
      maxMessages: this.options.maxMessages,
      reason: `signature update of ${component}`,
      ...(this.options.mode === 'record' ? { completedAt: now } : {}),
    };
  }
}
