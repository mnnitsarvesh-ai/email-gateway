import {
  Inject,
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
  Optional,
} from '@nestjs/common';
import { PrismaClient } from '@email-gateway/database';
import type { HealthDetails } from '@email-gateway/shared-types';
import type { HealthIndicator } from '../health/health-indicator';
import { DATABASE_READ_OPTIONS, type DatabaseReadOptions } from './database.options';
import { PrismaService } from './prisma.service';

/**
 * Optional provider of a `(url) => PrismaClient` factory for the replica client. Tests use it to
 * run without a real MySQL; production uses the default `new PrismaClient({ datasourceUrl })`.
 */
export const READER_CLIENT_FACTORY = Symbol('READER_CLIENT_FACTORY');
export type ReaderClientFactory = (url: string) => PrismaClient;

const defaultReaderClientFactory: ReaderClientFactory = (url) =>
  new PrismaClient({ datasourceUrl: url });

/** A probe that takes longer than this counts as a failed probe. */
export const READER_PROBE_TIMEOUT_MS = 2_000;

export type ReaderMode = 'reader' | 'writer-fallback' | 'writer-only';

export interface ReaderStatus {
  /** `reader`: reads use the replica. `writer-fallback`: replica unusable. `writer-only`: none configured. */
  mode: ReaderMode;
  /** `Seconds_Behind_Source` from the last probe; null when unknown or not probed. */
  lagSeconds: number | null;
  maxLagSeconds: number;
  /** Why reads are not on the replica (writer-fallback only). */
  reason?: string;
  /** ISO timestamp of the last completed probe. */
  checkedAt?: string;
}

/** One row of `SHOW REPLICA STATUS`; only the columns the probe reads. */
type ReplicaStatusRow = Record<string, unknown>;

/**
 * MySQL 8.4 positions of the columns the probe reads. Prisma's raw queries return the result of
 * `SHOW` statements with positional keys (`f0`, `f1`, …) instead of column names, so the probe
 * reads the named column when present and falls back to its documented position.
 */
const REPLICA_STATUS_POSITION = {
  Replica_IO_Running: 'f10',
  Replica_SQL_Running: 'f11',
  Seconds_Behind_Source: 'f32',
} as const;

function replicaColumn(row: ReplicaStatusRow, name: keyof typeof REPLICA_STATUS_POSITION): unknown {
  return name in row ? row[name] : row[REPLICA_STATUS_POSITION[name]];
}

/**
 * Control-plane reads (lists, search, reports, dashboards) go through `client`, which is the
 * read replica while it is healthy and the writer otherwise. Read-after-write paths, anything in
 * a transaction and authorization decisions right after a write must use PrismaService.
 *
 * Data-plane services never register this service (ADR-0014): replica lag must not affect a
 * mail decision. It does not extend PrismaClient, so it cannot be mistaken for the writer.
 */
@Injectable()
export class PrismaReadService implements OnModuleInit, OnModuleDestroy, HealthIndicator {
  readonly healthName = 'mysql-reader';

  private readonly logger = new Logger(PrismaReadService.name);
  private readonly reader: PrismaClient | undefined;
  private current: ReaderStatus;
  private loggedMode: ReaderMode | undefined;
  private timer: NodeJS.Timeout | undefined;
  private inFlight: Promise<ReaderStatus> | undefined;

  constructor(
    private readonly writer: PrismaService,
    @Inject(DATABASE_READ_OPTIONS) private readonly options: DatabaseReadOptions,
    @Optional()
    @Inject(READER_CLIENT_FACTORY)
    createReaderClient: ReaderClientFactory = defaultReaderClientFactory,
  ) {
    // PrismaClient connects lazily on first query, so a down replica cannot fail construction.
    this.reader = options.url ? createReaderClient(options.url) : undefined;
    this.current = this.reader
      ? this.fallback('not probed yet', null)
      : { mode: 'writer-only', lagSeconds: null, maxLagSeconds: options.maxLagSeconds };
  }

  /** The client to read from right now: the replica in mode `reader`, otherwise the writer. */
  get client(): PrismaClient {
    return this.current.mode === 'reader' && this.reader ? this.reader : this.writer;
  }

  status(): ReaderStatus {
    return { ...this.current };
  }

  async onModuleInit(): Promise<void> {
    if (!this.reader) {
      this.transition(this.current);
      return;
    }
    // Never throws: probe() turns every failure into writer-fallback.
    await this.probe();
    this.timer = setInterval(() => void this.probe(), this.options.lagCheckIntervalMs);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    clearInterval(this.timer);
    this.timer = undefined;
    if (!this.reader) return;
    try {
      await this.reader.$disconnect();
    } catch (err) {
      this.logger.warn(`Read replica disconnect failed: ${describeError(err)}`);
    }
  }

  /** Probes the replica afresh. Always resolves: an unusable replica is reported, not failed. */
  async checkHealth(): Promise<HealthDetails> {
    const status = await this.probe();
    const details: HealthDetails = {
      mode: status.mode,
      lagSeconds: status.lagSeconds,
      maxLagSeconds: status.maxLagSeconds,
    };
    if (status.reason) details.reason = status.reason;
    return details;
  }

  /**
   * Runs `SHOW REPLICA STATUS` on the replica and updates the mode. Concurrent callers share
   * the probe in flight. Never rejects.
   */
  probe(): Promise<ReaderStatus> {
    if (!this.reader) return Promise.resolve(this.status());
    this.inFlight ??= this.runProbe(this.reader).finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  private async runProbe(reader: PrismaClient): Promise<ReaderStatus> {
    let next: ReaderStatus;
    try {
      const rows = await withTimeout(
        reader.$queryRawUnsafe<ReplicaStatusRow[]>('SHOW REPLICA STATUS'),
        READER_PROBE_TIMEOUT_MS,
      );
      next = this.evaluate(rows);
    } catch (err) {
      next = this.fallback(`reader unreachable: ${describeError(err)}`, null);
    }
    next.checkedAt = new Date().toISOString();
    this.current = next;
    this.transition(next);
    return { ...next };
  }

  private evaluate(rows: ReplicaStatusRow[]): ReaderStatus {
    if (!Array.isArray(rows) || rows.length === 0) return this.fallback('not a replica', null);

    // Multi-source replication returns one row per channel; every channel must be healthy.
    let worstLag = 0;
    for (const row of rows) {
      const lag = toLagSeconds(replicaColumn(row, 'Seconds_Behind_Source'));
      if (
        !isYes(replicaColumn(row, 'Replica_IO_Running')) ||
        !isYes(replicaColumn(row, 'Replica_SQL_Running'))
      ) {
        return this.fallback('replication stopped', lag);
      }
      if (lag === null) return this.fallback('lag unknown', null);
      worstLag = Math.max(worstLag, lag);
    }

    const max = this.options.maxLagSeconds;
    if (worstLag > max) return this.fallback(`lag ${worstLag}s > max ${max}s`, worstLag);
    return { mode: 'reader', lagSeconds: worstLag, maxLagSeconds: max };
  }

  private fallback(reason: string, lagSeconds: number | null): ReaderStatus {
    return {
      mode: 'writer-fallback',
      lagSeconds,
      maxLagSeconds: this.options.maxLagSeconds,
      reason,
    };
  }

  /** Logs mode changes only, never per probe or per query, and never the URL. */
  private transition(next: ReaderStatus): void {
    if (next.mode === this.loggedMode) return;
    this.loggedMode = next.mode;
    const lag = next.lagSeconds === null ? 'unknown' : `${next.lagSeconds}s`;
    switch (next.mode) {
      case 'writer-fallback':
        this.logger.warn(
          `Read replica unusable, reads use the writer: ${next.reason ?? 'unknown'} (lag ${lag}, max ${next.maxLagSeconds}s)`,
        );
        break;
      case 'reader':
        this.logger.log(`Read replica in use (lag ${lag}, max ${next.maxLagSeconds}s)`);
        break;
      case 'writer-only':
        this.logger.log(
          'No read replica configured (DATABASE_READ_URL unset); reads use the writer',
        );
        break;
    }
  }
}

function isYes(value: unknown): boolean {
  return typeof value === 'string' && value.trim().toLowerCase() === 'yes';
}

/** MySQL drivers may return the column as number, bigint, string or null. */
function toLagSeconds(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** One line, bounded, and with any connection URL removed so credentials never reach logs. */
function describeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const message = raw
    .replace(/Invalid `[^`]*` invocation:/g, '')
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/gi, '[redacted-url]')
    .replace(/\s+/g, ' ')
    .trim();
  return (message || 'unknown error').slice(0, 200);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`probe timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
