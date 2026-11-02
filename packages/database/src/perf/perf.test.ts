import { describe, expect, it } from 'vitest';
import { createRandom, pickCdf, sqlTime, uuidv7, zipfCdf } from './load';
import { prunedPartitions } from './report';
import { normalizeExplainRow, percentile, replicaColumn } from './run';
import { perfSchemaName, withSchema } from './schema';

describe('perf helpers', () => {
  it('generates UUIDv7 values carrying the timestamp', () => {
    const ms = Date.UTC(2026, 10, 1);
    const id = uuidv7(ms);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(parseInt(id.replaceAll('-', '').slice(0, 12), 16)).toBe(ms);
  });

  it('samples a skewed Zipf distribution deterministically', () => {
    const cdf = zipfCdf(20, 1.1);
    expect(cdf.at(-1)).toBeCloseTo(1);
    const rand = createRandom(1);
    const counts = new Array<number>(20).fill(0);
    for (let i = 0; i < 10_000; i += 1) counts[pickCdf(cdf, rand())]! += 1;
    expect(counts[0]!).toBeGreaterThan(counts[19]! * 10);
    expect(createRandom(7)()).toBe(createRandom(7)());
  });

  it('formats DATETIME(3) literals in UTC', () => {
    expect(sqlTime(Date.UTC(2026, 0, 2, 3, 4, 5, 6))).toBe('2026-01-02 03:04:05.006');
  });

  it('computes nearest-rank percentiles', () => {
    const values = Array.from({ length: 20 }, (_, i) => i + 1);
    expect(percentile(values, 50)).toBe(10);
    expect(percentile(values, 95)).toBe(19);
  });

  it('rewrites the schema of a connection URL without touching credentials', () => {
    expect(
      withSchema('mysql://u:p@h:3306/email_gateway', 'email_gateway_perf', {
        connection_limit: '1',
      }),
    ).toBe('mysql://u:p@h:3306/email_gateway_perf?connection_limit=1');
    expect(() => withSchema('mysql://u:p@h/db', 'x; DROP')).toThrow(/Invalid schema/);
  });

  it('derives the perf schema from the migration URL (the migrator is granted <db>_perf only)', () => {
    expect(perfSchemaName('mysql://u:p@h:3306/email_gateway?connection_limit=1')).toBe(
      'email_gateway_perf',
    );
    expect(() => perfSchemaName('mysql://u:p@h:3306/bad-name')).toThrow(/Invalid schema/);
  });

  it('reads positional (f0…) and named SHOW/EXPLAIN columns', () => {
    expect(replicaColumn({ f10: 'Yes', f32: 3n }, 'Seconds_Behind_Source')).toBe(3n);
    expect(replicaColumn({ Seconds_Behind_Source: 4 }, 'Seconds_Behind_Source')).toBe(4);
    expect(normalizeExplainRow({ f0: 1n, f2: 'm', f3: 'p202611' })).toMatchObject({
      id: 1n,
      table: 'm',
      partitions: 'p202611',
    });
  });

  it('summarises partition pruning per table, resolving aliases', () => {
    const totals = new Map([
      ['email_scans', 9],
      ['scan_engine_results', 9],
    ]);
    const sql = 'SELECT 1 FROM email_scans s JOIN scan_engine_results r ON r.scan_id = s.id';
    expect(
      prunedPartitions(
        [
          { table: 's', partitions: 'p202611' },
          { table: 'r', partitions: 'p202611' },
        ],
        sql,
        totals,
      ),
    ).toEqual([
      '`email_scans`: 1 of 9 partitions (p202611)',
      '`scan_engine_results`: 1 of 9 partitions (p202611)',
    ]);
  });
});
