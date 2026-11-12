import { Inject, Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  type MessageAction,
  type MessageDirection,
  type MessageVerdict,
  Prisma,
  type QuarantinePrimaryEngine,
  type QuarantineReason,
  type UrlClickDecision,
} from '@email-gateway/database';
import { API_CONFIG } from '../../api-config.token';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';
import { isQueryTimeout, ReportQueryTimeoutError } from './domain/report-errors';
import type { ReportGranularity } from './domain/report-window';

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

type RawCount = { organizationId: bigint; n: bigint | number };

/**
 * The covering index of the message counts (step 6.1 §3.1):
 * `(organization_id, received_at, direction, final_verdict, final_action)`. Forced: with few
 * rows of an organization the optimizer may prefer `(organization_id, final_verdict,
 * received_at, id)`, which does not cover `direction` and reads every row; the covering index
 * keeps the traffic, direction and outcome counts index-only at any volume.
 */
const MESSAGE_COUNT_INDEX = Prisma.raw('FORCE INDEX (email_messages_org_received_dir_verdict_idx)');

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
};

function hint(timeoutMs: number): Prisma.Sql {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('MAX_EXECUTION_TIME must be a positive integer');
  }
  return Prisma.raw(`/*+ MAX_EXECUTION_TIME(${timeoutMs}) */`);
}

function count(row: RawCount): number {
  const n = Number(row.n);
  if (!Number.isSafeInteger(n) || n < 0) throw new InconsistentReadError('report_count');
  return n;
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
