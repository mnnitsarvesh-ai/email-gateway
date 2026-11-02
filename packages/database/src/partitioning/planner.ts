import { type PartitionGranularity, type PartitionSpec } from './registry';

/**
 * Pure partition planning (D3). Given a table's spec, its current partitions and the current
 * time, it decides which partitions to create (by splitting `pmax`) and which to drop. All
 * date arithmetic is UTC. Execution lives in executor.ts.
 */

/** An existing partition as read from information_schema.PARTITIONS. */
export interface ExistingPartition {
  name: string;
  /** PARTITION_DESCRIPTION: the upper bound literal, e.g. `'2026-12-01 00:00:00'` or `MAXVALUE`. */
  description: string;
}

export interface NewPartition {
  name: string;
  /** Upper bound as a DATETIME literal without quotes, e.g. `2026-12-01 00:00:00`. */
  lessThan: string;
}

export type PartitionAction =
  { kind: 'split-pmax'; partitions: NewPartition[] } | { kind: 'drop'; partitions: string[] };

export interface PlanOptions {
  /** Monthly tables: partitions exist for the current month plus this many future months. */
  aheadMonths: number;
  /** Daily tables: partitions exist for today plus this many future days. */
  aheadDays: number;
  /**
   * Only used when the table has nothing but `pmax`: the first partition created starts at the
   * period containing this date (default: the current period). It holds every earlier row too.
   */
  bootstrapFrom?: Date;
}

export const DEFAULT_PLAN_OPTIONS: PlanOptions = Object.freeze({ aheadMonths: 3, aheadDays: 7 });

export class PartitionPlanError extends Error {
  constructor(table: string, message: string) {
    super(`${table}: ${message}`);
    this.name = 'PartitionPlanError';
  }
}

const MONTH_NAME = /^p(\d{4})(\d{2})$/;
const DAY_NAME = /^p(\d{4})(\d{2})(\d{2})$/;
const BOUND = /^'?(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.0+)?'?$/;

const pad = (n: number, width = 2) => String(n).padStart(width, '0');

/** Start (00:00 UTC) of the month or day containing `date`. */
export function periodStart(date: Date, granularity: PartitionGranularity): Date {
  return granularity === 'month'
    ? new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1))
    : new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

/** `date` (a period start) moved by `count` periods. */
export function addPeriods(date: Date, granularity: PartitionGranularity, count: number): Date {
  return granularity === 'month'
    ? new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + count, 1))
    : new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() + count));
}

/** `pYYYYMM` for months, `pYYYYMMDD` for days. */
export function partitionName(start: Date, granularity: PartitionGranularity): string {
  const ym = `${start.getUTCFullYear()}${pad(start.getUTCMonth() + 1)}`;
  return granularity === 'month' ? `p${ym}` : `p${ym}${pad(start.getUTCDate())}`;
}

/** Period start encoded in a partition name, or null when the name does not match. */
export function parsePartitionName(name: string, granularity: PartitionGranularity): Date | null {
  const match = (granularity === 'month' ? MONTH_NAME : DAY_NAME).exec(name);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = granularity === 'month' ? 1 : Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  // Reject impossible dates such as p202613 or p20260230 (Date.UTC would roll them over).
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return null;
  }
  return date;
}

/** DATETIME literal (no quotes) for a partition bound. */
export function formatBound(date: Date): string {
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

/** Parses a PARTITION_DESCRIPTION. Returns 'MAXVALUE' for the catch-all, null if unparsable. */
export function parseBound(description: string): Date | 'MAXVALUE' | null {
  const value = description.trim();
  if (value === 'MAXVALUE') return 'MAXVALUE';
  const match = BOUND.exec(value);
  if (!match) return null;
  const [y, mo, d, h, mi, s] = match.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  return new Date(Date.UTC(y, mo - 1, d, h, mi, s));
}

/**
 * The drop cutoff: a partition is expired when its upper bound is ≤ this instant.
 * Months: the first day of (current UTC month − N months), so N = 6 keeps the current month
 * plus 6 full months. Days: today (00:00 UTC) − N days.
 */
export function retentionCutoff(spec: PartitionSpec, now: Date): Date | null {
  if (!spec.drop || spec.retention === null) return null;
  return addPeriods(periodStart(now, spec.granularity), spec.granularity, -spec.retention);
}

interface ParsedPartition {
  name: string;
  start: Date;
  upperBound: Date;
}

function parseExisting(
  spec: PartitionSpec,
  existing: readonly ExistingPartition[],
): ParsedPartition[] {
  const names = new Set<string>();
  const parsed: ParsedPartition[] = [];
  let hasPmax = false;
  for (const partition of existing) {
    if (names.has(partition.name)) {
      throw new PartitionPlanError(spec.table, `duplicate partition ${partition.name}`);
    }
    names.add(partition.name);
    if (partition.name === 'pmax') {
      if (parseBound(partition.description) !== 'MAXVALUE') {
        throw new PartitionPlanError(spec.table, 'pmax is not VALUES LESS THAN (MAXVALUE)');
      }
      hasPmax = true;
      continue;
    }
    const start = parsePartitionName(partition.name, spec.granularity);
    if (!start) {
      throw new PartitionPlanError(
        spec.table,
        `unexpected partition name ${JSON.stringify(partition.name)} for ${spec.granularity}ly partitioning`,
      );
    }
    const upperBound = addPeriods(start, spec.granularity, 1);
    const described = parseBound(partition.description);
    if (!(described instanceof Date) || described.getTime() !== upperBound.getTime()) {
      throw new PartitionPlanError(
        spec.table,
        `partition ${partition.name} has bound ${partition.description}, expected '${formatBound(upperBound)}'`,
      );
    }
    parsed.push({ name: partition.name, start, upperBound });
  }
  if (!hasPmax) {
    throw new PartitionPlanError(spec.table, 'has no pmax partition; it cannot be extended');
  }
  return parsed.sort((a, b) => a.start.getTime() - b.start.getTime());
}

/**
 * Plans the partition changes for one table. Pure and deterministic; throws
 * PartitionPlanError when the table's partitions do not follow the naming convention.
 */
export function planPartitionChanges(
  spec: PartitionSpec,
  existing: readonly ExistingPartition[],
  now: Date,
  opts: PlanOptions = DEFAULT_PLAN_OPTIONS,
): PartitionAction[] {
  const partitions = parseExisting(spec, existing);
  const granularity = spec.granularity;
  const ahead = granularity === 'month' ? opts.aheadMonths : opts.aheadDays;
  const current = periodStart(now, granularity);
  // Upper bound the last dated partition must reach: current period + `ahead` future periods.
  const target = addPeriods(current, granularity, ahead + 1);

  const actions: PartitionAction[] = [];

  const last = partitions.at(-1);
  let next = last ? last.upperBound : periodStart(opts.bootstrapFrom ?? now, granularity);
  if (!last && next.getTime() > current.getTime()) {
    throw new PartitionPlanError(spec.table, 'bootstrap date is in the future');
  }
  const created: NewPartition[] = [];
  while (next.getTime() < target.getTime()) {
    const upper = addPeriods(next, granularity, 1);
    created.push({ name: partitionName(next, granularity), lessThan: formatBound(upper) });
    next = upper;
  }
  if (created.length > 0) actions.push({ kind: 'split-pmax', partitions: created });

  const cutoff = retentionCutoff(spec, now);
  if (cutoff) {
    const expired = partitions
      .filter((p) => p.upperBound.getTime() <= cutoff.getTime())
      .map((p) => p.name);
    if (expired.length > 0) actions.push({ kind: 'drop', partitions: expired });
  }
  return actions;
}
