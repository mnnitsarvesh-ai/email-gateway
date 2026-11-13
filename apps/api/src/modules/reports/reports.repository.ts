import { Inject, Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  type DeliveryStatus,
  type DomainStatus,
  type MessageAction,
  type MessageDirection,
  type MessageVerdict,
  Prisma,
  type QuarantinePrimaryEngine,
  type QuarantineReason,
  type ScanStatus,
  type UrlClickDecision,
} from '@email-gateway/database';
import { API_CONFIG } from '../../api-config.token';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';
import {
  DELIVERY_LATENCY_BOUNDS_MS,
  isConsistentLatency,
  type LatencySamples,
  PROCESSING_LATENCY_BOUNDS_MS,
} from './domain/latency-histogram';
import { isQueryTimeout, ReportQueryTimeoutError } from './domain/report-errors';
import type { ReportGranularity } from './domain/report-window';
import type { DomainVerdictCount } from './domain/top-domains';

export const MESSAGE_DIRECTIONS = [
  'inbound',
  'outbound',
  'internal',
] as const satisfies readonly MessageDirection[];
export const MESSAGE_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const satisfies readonly MessageVerdict[];
export const MESSAGE_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
] as const satisfies readonly MessageAction[];
export const QUARANTINE_REASONS = [
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp',
  'policy',
  'suspicious',
  'engine_unavailable',
  'manual',
] as const satisfies readonly QuarantineReason[];
export const QUARANTINE_PRIMARY_ENGINES = [
  'rspamd',
  'attachment',
  'url',
  'bec',
  'dlp',
  'sandbox',
  'policy',
  'none',
] as const satisfies readonly QuarantinePrimaryEngine[];
export const URL_CLICK_DECISIONS = [
  'allowed',
  'warned',
  'blocked',
  'continued',
  'expired',
  'not_found',
] as const satisfies readonly UrlClickDecision[];

/** `email_deliveries.status` values, in report order (step 7.1 §3.3). */
export const DELIVERY_STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
] as const satisfies readonly DeliveryStatus[];
/** `email_scans.status` values, in report order (step 7.1 §3.3). */
export const SCAN_STATUSES = [
  'pending',
  'running',
  'completed',
  'failed',
  'timed_out',
] as const satisfies readonly ScanStatus[];
export const DOMAIN_STATUSES = [
  'pending_verification',
  'verified',
  'failed',
  'disabled',
  'active',
  'suspended',
  'deleted',
] as const satisfies readonly DomainStatus[];

/**
 * Bucket expressions (code constants, never input): the UTC start of the hour or day of a
 * DATETIME(3) column as `YYYY-MM-DD HH:00:00`. Columns hold UTC (Prisma writes UTC), so no time
 * zone conversion is involved.
 */
const BUCKET_FORMAT: Readonly<Record<ReportGranularity, string>> = Object.freeze({
  hour: '%Y-%m-%d %H:00:00',
  day: '%Y-%m-%d 00:00:00',
});

function bucketExpression(column: 'received_at' | 'clicked_at', granularity: ReportGranularity) {
  return Prisma.raw(`DATE_FORMAT(${column}, '${BUCKET_FORMAT[granularity]}')`);
}

/**
 * Latency columns of the delivery and processing reports (step 7.1 §3.3.1), built from code
 * constants only (the sample condition, the end column and the histogram bounds; never input):
 * the sample count, the sum of the latencies in microseconds (negative clock skew counted as 0)
 * and, per bound, the samples at or below it (`le0`, `le1`, …; cumulative).
 */
function latencyColumns(
  sampleCondition: string,
  endColumn: 'delivered_at' | 'completed_at',
  bounds: readonly number[],
): Prisma.Sql {
  const diff = `TIMESTAMPDIFF(MICROSECOND, received_at, ${endColumn})`;
  const columns = [
    `SUM(CASE WHEN ${sampleCondition} THEN 1 ELSE 0 END) AS samples`,
    `SUM(CASE WHEN ${sampleCondition} THEN GREATEST(${diff}, 0) ELSE 0 END) AS sumUs`,
    ...bounds.map((bound, i) => {
      if (!Number.isSafeInteger(bound) || bound < 1) throw new Error('invalid histogram bound');
      return `SUM(CASE WHEN ${sampleCondition} AND ${diff} <= ${bound * 1000} THEN 1 ELSE 0 END) AS le${i}`;
    }),
  ];
  return Prisma.raw(columns.join(',\n        '));
}

/** Delivered rows with a delivery time are the delivery latency samples. */
const DELIVERY_SAMPLE = "status = 'delivered' AND delivered_at IS NOT NULL";
/** Completed rounds with a completion time are the processing latency samples. */
const PROCESSING_SAMPLE = "status = 'completed' AND completed_at IS NOT NULL";

/** `YYYY-MM-DD HH:MM:SS` (UTC) → Date. */
export function parseBucket(text: string): Date {
  const date = new Date(`${text.replace(' ', 'T')}.000Z`);
  if (Number.isNaN(date.getTime())) throw new InconsistentReadError('report_bucket');
  return date;
}

export interface ReportRange {
  from: Date;
  to: Date;
}

export interface TrafficCountRow {
  bucket: Date;
  direction: MessageDirection;
  verdict: MessageVerdict | null;
  count: number;
}

export interface DirectionCountRow {
  direction: MessageDirection;
  count: number;
}

export interface OutcomeCountRow {
  verdict: MessageVerdict | null;
  action: MessageAction | null;
  count: number;
}

export interface QuarantineCountRow {
  reason: QuarantineReason;
  primaryEngine: QuarantinePrimaryEngine;
  count: number;
}

export interface ClickCountRow {
  bucket: Date;
  decision: UrlClickDecision;
  count: number;
}

/** Deliveries of one bucket and status, with the latency samples of `delivered` rows. */
export interface DeliveryCountRow {
  bucket: Date;
  status: DeliveryStatus;
  count: number;
  latency: LatencySamples;
}

/** Initial scan rounds of one bucket and status, with the latency samples of completed rounds. */
export interface ScanRoundCountRow {
  bucket: Date;
  status: ScanStatus;
  count: number;
  latency: LatencySamples;
}

/** A tenant domain referenced by the top-domains report. */
export interface ReportDomain {
  id: bigint;
  publicId: string;
  name: string;
  status: DomainStatus;
  deleted: boolean;
}

type RawCount = { organizationId: bigint; n: unknown };
type RawLatency = { samples: unknown; sumUs: unknown } & Record<`le${number}`, unknown>;

/**
 * The covering index of the message counts (step 6.1 §3.1):
 * `(organization_id, received_at, direction, final_verdict, final_action)`. Forced: with few
 * rows of an organization the optimizer may prefer `(organization_id, final_verdict,
 * received_at, id)`, which does not cover `direction` and reads every row; the covering index
 * keeps the traffic, direction and outcome counts index-only at any volume.
 */
const MESSAGE_COUNT_INDEX = Prisma.raw('FORCE INDEX (email_messages_org_received_dir_verdict_idx)');

/** Step 7.1 §3.2: `(organization_id, received_at, status, delivered_at)`, index-only. */
const DELIVERY_REPORT_INDEX = Prisma.raw('FORCE INDEX (email_deliveries_org_received_status_idx)');

/** Step 7.1 §3.2: `(organization_id, received_at, scan_kind, status, completed_at)`, index-only. */
const PROCESSING_REPORT_INDEX = Prisma.raw(
  'FORCE INDEX (email_scans_org_received_kind_status_idx)',
);

/**
 * The report SQL (step 6.1 D12), exported so the integration suite EXPLAINs exactly what runs.
 * Every statement starts with the tenant predicate `organization_id = <scope>` and constrains the
 * partition column, carries `MAX_EXECUTION_TIME(<REPORTS_QUERY_TIMEOUT_MS>)` (an integer from the
 * validated config; optimizer hints take no placeholders) and binds every value. The
 * organization id is selected and grouped on (it is constant) for the echo check (D15).
 */
export const reportSql = {
  /** Index-only over `email_messages_org_received_dir_verdict_idx`. */
  traffic(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
    direction: MessageDirection | undefined,
    timeoutMs: number,
  ): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        ${bucketExpression('received_at', granularity)} AS bucket,
        direction, final_verdict AS verdict, COUNT(*) AS n
      FROM email_messages ${MESSAGE_COUNT_INDEX}
      WHERE organization_id = ${scope.organizationId}
        AND received_at >= ${range.from} AND received_at < ${range.to}
        ${direction === undefined ? Prisma.empty : Prisma.sql`AND direction = ${direction}`}
      GROUP BY organization_id, bucket, direction, verdict`;
  },

  /** Messages by direction (billing usage); index-only over the same covering index. */
  directions(scope: TenantScope, range: ReportRange, timeoutMs: number): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        direction, COUNT(*) AS n
      FROM email_messages ${MESSAGE_COUNT_INDEX}
      WHERE organization_id = ${scope.organizationId}
        AND received_at >= ${range.from} AND received_at < ${range.to}
      GROUP BY organization_id, direction`;
  },

  /**
   * Messages by final verdict and action; index-only over the same covering index (its last
   * column is `final_action`, migration rest_api_index_coverage), so a 31-day window of a
   * high-volume tenant reads index entries only, never the rows.
   */
  outcomes(scope: TenantScope, range: ReportRange, timeoutMs: number): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        final_verdict AS verdict, final_action AS action, COUNT(*) AS n
      FROM email_messages ${MESSAGE_COUNT_INDEX}
      WHERE organization_id = ${scope.organizationId}
        AND received_at >= ${range.from} AND received_at < ${range.to}
      GROUP BY organization_id, verdict, action`;
  },

  /** Quarantine entries by reason and primary engine over `(organization_id, quarantined_at, id)`. */
  quarantine(scope: TenantScope, range: ReportRange, timeoutMs: number): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        reason, primary_engine AS primaryEngine, COUNT(*) AS n
      FROM quarantine_messages
      WHERE organization_id = ${scope.organizationId}
        AND quarantined_at >= ${range.from} AND quarantined_at < ${range.to}
      GROUP BY organization_id, reason, primaryEngine`;
  },

  /** URL clicks by bucket and decision over `(organization_id, clicked_at)`. */
  clicks(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
    timeoutMs: number,
  ): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        ${bucketExpression('clicked_at', granularity)} AS bucket,
        decision, COUNT(*) AS n
      FROM url_click_events
      WHERE organization_id = ${scope.organizationId}
        AND clicked_at >= ${range.from} AND clicked_at < ${range.to}
      GROUP BY organization_id, bucket, decision`;
  },

  /**
   * Deliveries (one row per recipient delivery chain) of messages received in the window, by
   * bucket and status, with the delivery latency histogram of `delivered` rows (step 7.1 §3.3);
   * index-only over `email_deliveries_org_received_status_idx`.
   */
  deliveries(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
    timeoutMs: number,
  ): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        ${bucketExpression('received_at', granularity)} AS bucket,
        status, COUNT(*) AS n,
        ${latencyColumns(DELIVERY_SAMPLE, 'delivered_at', DELIVERY_LATENCY_BOUNDS_MS)}
      FROM email_deliveries ${DELIVERY_REPORT_INDEX}
      WHERE organization_id = ${scope.organizationId}
        AND received_at >= ${range.from} AND received_at < ${range.to}
      GROUP BY organization_id, bucket, status`;
  },

  /**
   * Initial scan rounds (`scan_kind = 'initial'`) of messages received in the window, by bucket
   * and status, with the time-to-verdict histogram of completed rounds (step 7.1 §3.3);
   * index-only over `email_scans_org_received_kind_status_idx`.
   */
  scanRounds(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
    timeoutMs: number,
  ): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        ${bucketExpression('received_at', granularity)} AS bucket,
        status, COUNT(*) AS n,
        ${latencyColumns(PROCESSING_SAMPLE, 'completed_at', PROCESSING_LATENCY_BOUNDS_MS)}
      FROM email_scans ${PROCESSING_REPORT_INDEX}
      WHERE organization_id = ${scope.organizationId}
        AND received_at >= ${range.from} AND received_at < ${range.to}
        AND scan_kind = 'initial'
      GROUP BY organization_id, bucket, status`;
  },

  /**
   * Inbound messages by tenant domain and final verdict (step 7.1 §3.3, top attacked domains);
   * index-only over the covering message index (domain_id since migration admin_portal_reports).
   */
  domainVerdicts(scope: TenantScope, range: ReportRange, timeoutMs: number): Prisma.Sql {
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId,
        domain_id AS domainId, final_verdict AS verdict, COUNT(*) AS n
      FROM email_messages ${MESSAGE_COUNT_INDEX}
      WHERE organization_id = ${scope.organizationId}
        AND received_at >= ${range.from} AND received_at < ${range.to}
        AND direction = 'inbound'
      GROUP BY organization_id, domainId, verdict`;
  },

  /** Names and states of referenced domains, inside the tenant only (deleted ones included). */
  domains(scope: TenantScope, ids: readonly bigint[], timeoutMs: number): Prisma.Sql {
    if (ids.length === 0) throw new Error('reportSql.domains: at least one id is required');
    return Prisma.sql`SELECT ${hint(timeoutMs)} organization_id AS organizationId, id,
        public_id AS publicId, name, status, deleted_at AS deletedAt
      FROM domains
      WHERE organization_id = ${scope.organizationId} AND id IN (${Prisma.join([...ids])})`;
  },
};

function hint(timeoutMs: number): Prisma.Sql {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('MAX_EXECUTION_TIME must be a positive integer');
  }
  return Prisma.raw(`/*+ MAX_EXECUTION_TIME(${timeoutMs}) */`);
}

/** A non-negative integer from a COUNT/SUM column (BIGINT, or DECIMAL for SUM). */
function integer(value: unknown, read = 'report_count'): number {
  const n = Number(typeof value === 'bigint' ? value : String(value));
  if (!Number.isSafeInteger(n) || n < 0) throw new InconsistentReadError(read);
  return n;
}

function count(row: RawCount): number {
  return integer(row.n);
}

/** The latency columns of a row (`samples`, `sumUs`, `le0`…), checked for consistency. */
function latencyOf(
  read: string,
  row: RawLatency,
  bounds: readonly number[],
  rowCount: number,
): LatencySamples {
  const sumUs = Number(String(row.sumUs));
  const value: LatencySamples = {
    samples: integer(row.samples, read),
    sumUs,
    cumulative: bounds.map((_, i) => integer(row[`le${i}`], read)),
  };
  if (!Number.isFinite(sumUs) || value.samples > rowCount || !isConsistentLatency(value)) {
    throw new InconsistentReadError(read);
  }
  return value;
}

function oneOf<T extends string>(read: string, allowed: readonly T[], value: unknown): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
    throw new InconsistentReadError(read);
  }
  return value as T;
}

function nullableOneOf<T extends string>(
  read: string,
  allowed: readonly T[],
  value: unknown,
): T | null {
  return value === null ? null : oneOf(read, allowed, value);
}

/** A positive BIGINT id or NULL. */
function nullableId(read: string, value: unknown): bigint | null {
  if (value === null) return null;
  if (typeof value === 'bigint' && value > 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return BigInt(value);
  throw new InconsistentReadError(read);
}

/** Bucket starts of an aligned range lie inside it. */
function inRange(read: string, bucket: Date, range: ReportRange): Date {
  if (bucket.getTime() < range.from.getTime() || bucket.getTime() >= range.to.getTime()) {
    throw new InconsistentReadError(read);
  }
  return bucket;
}

/**
 * Aggregates for the reports and billing usage (step 6.1 D12), on the replica only
 * (`PrismaReadService`). Each query is bounded by its range, `MAX_EXECUTION_TIME` and the caller's
 * cache; a statement interrupted by the timeout is `ReportQueryTimeoutError`. Every row is
 * echo-checked (organization, enum values, bucket inside the range) before it is used (D15).
 */
@Injectable()
export class ReportsRepository {
  constructor(
    private readonly reader: PrismaReadService,
    @Inject(API_CONFIG) private readonly config: Pick<ApiConfig, 'REPORTS_QUERY_TIMEOUT_MS'>,
  ) {}

  async traffic(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
    direction?: MessageDirection,
  ): Promise<TrafficCountRow[]> {
    const rows = await this.query<
      RawCount & { bucket: string; direction: string; verdict: unknown }
    >('traffic', reportSql.traffic(scope, range, granularity, direction, this.timeoutMs));
    assertEcho('report_traffic', rows, { organizationId: scope.organizationId });
    return rows.map((row) => ({
      bucket: inRange('report_traffic', parseBucket(row.bucket), range),
      direction: oneOf(
        'report_traffic',
        direction ? [direction] : MESSAGE_DIRECTIONS,
        row.direction,
      ),
      verdict: nullableOneOf('report_traffic', MESSAGE_VERDICTS, row.verdict),
      count: count(row),
    }));
  }

  async directions(scope: TenantScope, range: ReportRange): Promise<DirectionCountRow[]> {
    const rows = await this.query<RawCount & { direction: string }>(
      'directions',
      reportSql.directions(scope, range, this.timeoutMs),
    );
    assertEcho('report_directions', rows, { organizationId: scope.organizationId });
    return rows.map((row) => ({
      direction: oneOf('report_directions', MESSAGE_DIRECTIONS, row.direction),
      count: count(row),
    }));
  }

  async outcomes(scope: TenantScope, range: ReportRange): Promise<OutcomeCountRow[]> {
    const rows = await this.query<RawCount & { verdict: unknown; action: unknown }>(
      'outcomes',
      reportSql.outcomes(scope, range, this.timeoutMs),
    );
    assertEcho('report_outcomes', rows, { organizationId: scope.organizationId });
    return rows.map((row) => ({
      verdict: nullableOneOf('report_outcomes', MESSAGE_VERDICTS, row.verdict),
      action: nullableOneOf('report_outcomes', MESSAGE_ACTIONS, row.action),
      count: count(row),
    }));
  }

  async quarantine(scope: TenantScope, range: ReportRange): Promise<QuarantineCountRow[]> {
    const rows = await this.query<RawCount & { reason: unknown; primaryEngine: unknown }>(
      'quarantine',
      reportSql.quarantine(scope, range, this.timeoutMs),
    );
    assertEcho('report_quarantine', rows, { organizationId: scope.organizationId });
    return rows.map((row) => ({
      reason: oneOf('report_quarantine', QUARANTINE_REASONS, row.reason),
      primaryEngine: oneOf('report_quarantine', QUARANTINE_PRIMARY_ENGINES, row.primaryEngine),
      count: count(row),
    }));
  }

  async clicks(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
  ): Promise<ClickCountRow[]> {
    const rows = await this.query<RawCount & { bucket: string; decision: unknown }>(
      'clicks',
      reportSql.clicks(scope, range, granularity, this.timeoutMs),
    );
    assertEcho('report_clicks', rows, { organizationId: scope.organizationId });
    return rows.map((row) => ({
      bucket: inRange('report_clicks', parseBucket(row.bucket), range),
      decision: oneOf('report_clicks', URL_CLICK_DECISIONS, row.decision),
      count: count(row),
    }));
  }

  async deliveries(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
  ): Promise<DeliveryCountRow[]> {
    const rows = await this.query<RawCount & RawLatency & { bucket: string; status: unknown }>(
      'deliveries',
      reportSql.deliveries(scope, range, granularity, this.timeoutMs),
    );
    assertEcho('report_deliveries', rows, { organizationId: scope.organizationId });
    return rows.map((row) => {
      const status = oneOf('report_deliveries', DELIVERY_STATUSES, row.status);
      const n = count(row);
      const latency = latencyOf('report_deliveries', row, DELIVERY_LATENCY_BOUNDS_MS, n);
      // Only delivered rows are latency samples.
      if (status !== 'delivered' && latency.samples !== 0) {
        throw new InconsistentReadError('report_deliveries');
      }
      return {
        bucket: inRange('report_deliveries', parseBucket(row.bucket), range),
        status,
        count: n,
        latency,
      };
    });
  }

  async scanRounds(
    scope: TenantScope,
    range: ReportRange,
    granularity: ReportGranularity,
  ): Promise<ScanRoundCountRow[]> {
    const rows = await this.query<RawCount & RawLatency & { bucket: string; status: unknown }>(
      'scan_rounds',
      reportSql.scanRounds(scope, range, granularity, this.timeoutMs),
    );
    assertEcho('report_scan_rounds', rows, { organizationId: scope.organizationId });
    return rows.map((row) => {
      const status = oneOf('report_scan_rounds', SCAN_STATUSES, row.status);
      const n = count(row);
      const latency = latencyOf('report_scan_rounds', row, PROCESSING_LATENCY_BOUNDS_MS, n);
      // Only completed rounds are latency samples.
      if (status !== 'completed' && latency.samples !== 0) {
        throw new InconsistentReadError('report_scan_rounds');
      }
      return {
        bucket: inRange('report_scan_rounds', parseBucket(row.bucket), range),
        status,
        count: n,
        latency,
      };
    });
  }

  async domainVerdicts(scope: TenantScope, range: ReportRange): Promise<DomainVerdictCount[]> {
    const rows = await this.query<RawCount & { domainId: unknown; verdict: unknown }>(
      'domain_verdicts',
      reportSql.domainVerdicts(scope, range, this.timeoutMs),
    );
    assertEcho('report_domain_verdicts', rows, { organizationId: scope.organizationId });
    return rows.map((row) => ({
      domainId: nullableId('report_domain_verdicts', row.domainId),
      verdict: nullableOneOf('report_domain_verdicts', MESSAGE_VERDICTS, row.verdict),
      count: count(row),
    }));
  }

  /**
   * The referenced domains of the caller's organization. Every id must resolve inside the tenant
   * (a message's domain belongs to its organization): a missing one is an inconsistent read
   * (`503 inconsistent_read`), never shown.
   */
  async domains(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, ReportDomain>> {
    const unique = [...new Set(ids)];
    if (unique.length === 0) return new Map();
    const rows = await this.query<{
      organizationId: bigint;
      id: unknown;
      publicId: unknown;
      name: unknown;
      status: unknown;
      deletedAt: unknown;
    }>('domains', reportSql.domains(scope, unique, this.timeoutMs));
    assertEcho('report_domains', rows, { organizationId: scope.organizationId });
    const found = new Map<bigint, ReportDomain>();
    for (const row of rows) {
      const id = nullableId('report_domains', row.id);
      if (id === null || !unique.includes(id) || found.has(id)) {
        throw new InconsistentReadError('report_domains');
      }
      if (typeof row.publicId !== 'string' || typeof row.name !== 'string') {
        throw new InconsistentReadError('report_domains');
      }
      if (row.deletedAt !== null && !(row.deletedAt instanceof Date)) {
        throw new InconsistentReadError('report_domains');
      }
      const status = oneOf('report_domains', DOMAIN_STATUSES, row.status);
      found.set(id, {
        id,
        publicId: row.publicId,
        name: row.name,
        status,
        deleted: row.deletedAt !== null || status === 'deleted',
      });
    }
    if (found.size !== unique.length) throw new InconsistentReadError('report_domains');
    return found;
  }

  private get timeoutMs(): number {
    return this.config.REPORTS_QUERY_TIMEOUT_MS;
  }

  private async query<R>(name: string, sql: Prisma.Sql): Promise<R[]> {
    try {
      return await this.reader.client.$queryRaw<R[]>(sql);
    } catch (err) {
      if (isQueryTimeout(err)) throw new ReportQueryTimeoutError(name);
      throw err;
    }
  }
}
