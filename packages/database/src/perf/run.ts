import { type SqlClient } from '../partitioning/executor';
import { type PerfQuery, type QueryStep } from './queries';
import { text } from './report';

export type ExplainRow = Record<string, unknown>;

export interface StepPlan {
  label: string;
  sql: string;
  params: unknown[];
  explain: ExplainRow[] | string;
  tree: string;
  analyze: string;
}

export interface QueryResult {
  query: PerfQuery;
  plans: StepPlan[];
  timingsMs: number[];
  medianMs: number;
  p95Ms: number;
  rowsReturned: number;
}

const errorText = (err: unknown) =>
  err instanceof Error ? err.message.split('\n')[0]! : String(err);

/** Nearest-rank percentile of an ascending array. */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1]!;
}

/** Traditional EXPLAIN columns, in MySQL's order. */
export const EXPLAIN_COLUMNS = [
  'id',
  'select_type',
  'table',
  'partitions',
  'type',
  'possible_keys',
  'key',
  'key_len',
  'ref',
  'rows',
  'filtered',
  'Extra',
] as const;

/**
 * Prisma returns EXPLAIN (like SHOW) results with positional keys `f0…f11`; map them back to
 * the column names. Rows that already carry names are returned unchanged.
 */
export function normalizeExplainRow(row: ExplainRow): ExplainRow {
  if ('id' in row || !('f0' in row)) return row;
  return Object.fromEntries(EXPLAIN_COLUMNS.map((name, i) => [name, row[`f${i}`]]));
}

async function textPlan(client: SqlClient, prefix: string, step: QueryStep): Promise<string> {
  try {
    const rows = await client.$queryRawUnsafe<Record<string, unknown>[]>(
      `${prefix} ${step.sql}`,
      ...step.params,
    );
    return rows.map((r) => text(Object.values(r)[0])).join('\n');
  } catch (err) {
    return `(not available for this statement: ${errorText(err)})`;
  }
}

async function execute(client: SqlClient, step: QueryStep): Promise<number> {
  const params = step.freshParams ? step.freshParams() : step.params;
  if (/^\s*INSERT/i.test(step.sql)) {
    try {
      await client.$executeRawUnsafe(step.sql, ...params);
      if (step.expectError) throw new Error(`${step.label}: expected an error`);
      return 0;
    } catch (err) {
      if (step.expectError?.test(errorText(err)) || step.expectError?.test(String(err))) return 0;
      throw err;
    }
  }
  const rows = await client.$queryRawUnsafe<unknown[]>(step.sql, ...params);
  return rows.length;
}

export async function runQuery(
  client: SqlClient,
  query: PerfQuery,
  runs: number,
  warmups = 2,
): Promise<QueryResult> {
  const plans: StepPlan[] = [];
  for (const step of query.steps) {
    let explain: ExplainRow[] | string;
    try {
      explain = (
        await client.$queryRawUnsafe<ExplainRow[]>(`EXPLAIN ${step.sql}`, ...step.params)
      ).map(normalizeExplainRow);
    } catch (err) {
      explain = `(EXPLAIN failed: ${errorText(err)})`;
    }
    const tree = await textPlan(client, 'EXPLAIN FORMAT=TREE', step);
    const analyze = /^\s*INSERT/i.test(step.sql)
      ? '(EXPLAIN ANALYZE supports SELECT, TABLE, UPDATE and DELETE only)'
      : await textPlan(client, 'EXPLAIN ANALYZE', step);
    plans.push({ label: step.label, sql: step.sql, params: step.params, explain, tree, analyze });
  }
  let rowsReturned = 0;
  for (let i = 0; i < warmups; i += 1) {
    for (const step of query.steps) await execute(client, step);
  }
  const timingsMs: number[] = [];
  for (let i = 0; i < runs; i += 1) {
    const started = performance.now();
    let rows = 0;
    for (const step of query.steps) rows += await execute(client, step);
    timingsMs.push(performance.now() - started);
    rowsReturned = rows;
  }
  const sorted = [...timingsMs].sort((a, b) => a - b);
  return {
    query,
    plans,
    timingsMs,
    medianMs: percentile(sorted, 50),
    p95Ms: percentile(sorted, 95),
    rowsReturned,
  };
}

export interface LagSampler {
  stop(): Promise<{ maxLagSeconds: number | null; samples: number; unavailable: number }>;
}

/** Samples Seconds_Behind_Source on the replica once per interval. */
export function startLagSampler(reader: SqlClient | null, intervalMs = 1000): LagSampler {
  let maxLag: number | null = null;
  let samples = 0;
  let unavailable = 0;
  let running = false;
  const probe = async () => {
    if (!reader || running) return;
    running = true;
    try {
      const lag = await readLag(reader);
      samples += 1;
      if (lag === null) unavailable += 1;
      else maxLag = Math.max(maxLag ?? 0, lag);
    } catch {
      unavailable += 1;
    } finally {
      running = false;
    }
  };
  const timer = setInterval(() => void probe(), intervalMs);
  timer.unref();
  return {
    async stop() {
      clearInterval(timer);
      await probe();
      return { maxLagSeconds: maxLag, samples, unavailable };
    },
  };
}

/**
 * MySQL 8.4 column positions in `SHOW REPLICA STATUS`. Prisma's raw queries return SHOW
 * results with positional keys (`f0`, `f1`, …) instead of column names, so both forms are read.
 */
const REPLICA_STATUS_POSITION = {
  Replica_IO_Running: 'f10',
  Replica_SQL_Running: 'f11',
  Seconds_Behind_Source: 'f32',
} as const;

export function replicaColumn(
  row: Record<string, unknown>,
  name: keyof typeof REPLICA_STATUS_POSITION,
): unknown {
  return name in row ? row[name] : row[REPLICA_STATUS_POSITION[name]];
}

/** Seconds_Behind_Source, or null when the replica is not replicating. */
export async function readLag(reader: SqlClient): Promise<number | null> {
  const [row] = await reader.$queryRawUnsafe<Record<string, unknown>[]>('SHOW REPLICA STATUS');
  if (!row) return null;
  if (
    replicaColumn(row, 'Replica_IO_Running') !== 'Yes' ||
    replicaColumn(row, 'Replica_SQL_Running') !== 'Yes'
  ) {
    return null;
  }
  const lag = replicaColumn(row, 'Seconds_Behind_Source');
  if (lag === null || lag === undefined || lag === '') return null;
  const n = Number(lag);
  return Number.isFinite(n) ? n : null;
}
