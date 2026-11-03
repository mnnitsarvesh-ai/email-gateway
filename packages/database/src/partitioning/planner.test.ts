import { describe, expect, it } from 'vitest';
import {
  type ExistingPartition,
  PartitionPlanError,
  addPeriods,
  formatBound,
  parseBound,
  parsePartitionName,
  partitionName,
  planPartitionChanges,
  retentionCutoff,
} from './planner';
import { PARTITION_REGISTRY, type PartitionSpec } from './registry';

const opts = { aheadMonths: 3, aheadDays: 7 };
const pmax: ExistingPartition = { name: 'pmax', description: 'MAXVALUE' };
const spec = (table: string): PartitionSpec => {
  const found = PARTITION_REGISTRY.find((s) => s.table === table);
  if (!found) throw new Error(table);
  return found;
};
const monthly = (...names: string[]): ExistingPartition[] => [
  ...names.map((name) => {
    const start = parsePartitionName(name, 'month')!;
    return { name, description: `'${formatBound(addPeriods(start, 'month', 1))}'` };
  }),
  pmax,
];
const daily = (...names: string[]): ExistingPartition[] => [
  ...names.map((name) => {
    const start = parsePartitionName(name, 'day')!;
    return { name, description: `'${formatBound(addPeriods(start, 'day', 1))}'` };
  }),
  pmax,
];
const utc = (iso: string) => new Date(iso);

describe('registry', () => {
  it('lists the 19 partitioned tables (D3, steps 2.3 and 3.1) with their retention', () => {
    expect(PARTITION_REGISTRY).toHaveLength(19);
    expect(new Set(PARTITION_REGISTRY.map((s) => s.table)).size).toBe(19);
    const byTable = Object.fromEntries(PARTITION_REGISTRY.map((s) => [s.table, s]));
    expect(byTable.email_messages).toMatchObject({
      column: 'received_at',
      granularity: 'month',
      retention: 6,
    });
    expect(byTable.scan_engine_results).toMatchObject({ retention: 3 });
    expect(byTable.bounce_events).toMatchObject({ column: 'occurred_at', retention: 6 });
    expect(byTable.webhook_deliveries).toMatchObject({ column: 'event_occurred_at', retention: 2 });
    expect(byTable.email_archives).toMatchObject({ retention: null, drop: false });
    // Step 2.3 delivery tables.
    expect(byTable.delivery_reinjections).toMatchObject({
      column: 'received_at',
      granularity: 'month',
      retention: 6,
      drop: true,
      tier: 'core',
    });
    expect(byTable.delivery_status_events).toMatchObject({
      column: 'received_at',
      granularity: 'month',
      retention: 3,
      drop: true,
      tier: 'detail',
    });
    // Step 3.1 parse stage table.
    expect(byTable.email_message_parses).toMatchObject({
      column: 'received_at',
      granularity: 'month',
      retention: 6,
      drop: true,
      tier: 'core',
    });
    expect(byTable.audit_logs).toMatchObject({
      column: 'created_at',
      retention: null,
      drop: false,
    });
    expect(byTable.message_outbox).toMatchObject({
      column: 'created_at',
      granularity: 'day',
      retention: 7,
      guard: { kind: 'no-null-rows', column: 'published_at' },
    });
  });
});

describe('partition names and bounds', () => {
  it('formats and parses monthly and daily names in UTC', () => {
    expect(partitionName(utc('2026-12-01T00:00:00Z'), 'month')).toBe('p202612');
    expect(partitionName(utc('2028-02-29T00:00:00Z'), 'day')).toBe('p20280229');
    expect(parsePartitionName('p202612', 'month')).toEqual(utc('2026-12-01T00:00:00Z'));
    expect(parsePartitionName('p20280229', 'day')).toEqual(utc('2028-02-29T00:00:00Z'));
  });

  it('rejects malformed or impossible names', () => {
    expect(parsePartitionName('p202613', 'month')).toBeNull();
    expect(parsePartitionName('p20270229', 'day')).toBeNull(); // 2027 is not a leap year
    expect(parsePartitionName('p20261101', 'month')).toBeNull();
    expect(parsePartitionName('p202611', 'day')).toBeNull();
    expect(parsePartitionName('pmax', 'month')).toBeNull();
    expect(parsePartitionName('x202611', 'month')).toBeNull();
  });

  it('parses PARTITION_DESCRIPTION values', () => {
    expect(parseBound('MAXVALUE')).toBe('MAXVALUE');
    expect(parseBound("'2026-12-01 00:00:00'")).toEqual(utc('2026-12-01T00:00:00Z'));
    expect(parseBound("'2026-12-01 00:00:00.000'")).toEqual(utc('2026-12-01T00:00:00Z'));
    expect(parseBound('739000')).toBeNull();
  });
});

describe('planPartitionChanges', () => {
  it('bootstraps from pmax only: current month plus 3 ahead', () => {
    const actions = planPartitionChanges(
      spec('email_messages'),
      [pmax],
      utc('2026-11-15T10:00:00Z'),
      opts,
    );
    expect(actions).toEqual([
      {
        kind: 'split-pmax',
        partitions: [
          { name: 'p202611', lessThan: '2026-12-01 00:00:00' },
          { name: 'p202612', lessThan: '2027-01-01 00:00:00' },
          { name: 'p202701', lessThan: '2027-02-01 00:00:00' },
          { name: 'p202702', lessThan: '2027-03-01 00:00:00' },
        ],
      },
    ]);
  });

  it('bootstraps from --bootstrap-from and never drops on the bootstrap run', () => {
    const actions = planPartitionChanges(
      spec('email_events'),
      [pmax],
      utc('2026-11-15T00:00:00Z'),
      {
        ...opts,
        bootstrapFrom: utc('2026-07-20T00:00:00Z'),
      },
    );
    expect(actions).toHaveLength(1);
    const split = actions[0]!;
    expect(split.kind).toBe('split-pmax');
    if (split.kind === 'split-pmax') {
      expect(split.partitions.map((p) => p.name)).toEqual([
        'p202607',
        'p202608',
        'p202609',
        'p202610',
        'p202611',
        'p202612',
        'p202701',
        'p202702',
      ]);
    }
  });

  it('rejects a bootstrap date in the future', () => {
    expect(() =>
      planPartitionChanges(spec('email_messages'), [pmax], utc('2026-11-15T00:00:00Z'), {
        ...opts,
        bootstrapFrom: utc('2027-01-01T00:00:00Z'),
      }),
    ).toThrow(PartitionPlanError);
  });

  it('is a no-op when enough partitions exist', () => {
    const existing = monthly('p202611', 'p202612', 'p202701', 'p202702');
    expect(
      planPartitionChanges(spec('email_messages'), existing, utc('2026-11-30T23:59:59.999Z'), opts),
    ).toEqual([]);
  });

  it('extends across the December → January rollover', () => {
    const existing = monthly('p202610', 'p202611', 'p202612', 'p202701');
    const actions = planPartitionChanges(
      spec('email_messages'),
      existing,
      utc('2026-12-01T00:00:00Z'),
      opts,
    );
    expect(actions).toEqual([
      {
        kind: 'split-pmax',
        partitions: [
          { name: 'p202702', lessThan: '2027-03-01 00:00:00' },
          { name: 'p202703', lessThan: '2027-04-01 00:00:00' },
        ],
      },
    ]);
    const yearEnd = planPartitionChanges(
      spec('email_messages'),
      monthly('p202609', 'p202610', 'p202611', 'p202612'),
      utc('2026-10-01T00:00:00Z'),
      opts,
    );
    expect(yearEnd).toEqual([
      { kind: 'split-pmax', partitions: [{ name: 'p202701', lessThan: '2027-02-01 00:00:00' }] },
    ]);
  });

  it('plans daily partitions across a leap day (UTC boundaries)', () => {
    const actions = planPartitionChanges(
      spec('message_outbox'),
      [pmax],
      utc('2028-02-27T23:30:00Z'),
      opts,
    );
    expect(actions).toEqual([
      {
        kind: 'split-pmax',
        partitions: [
          { name: 'p20280227', lessThan: '2028-02-28 00:00:00' },
          { name: 'p20280228', lessThan: '2028-02-29 00:00:00' },
          { name: 'p20280229', lessThan: '2028-03-01 00:00:00' },
          { name: 'p20280301', lessThan: '2028-03-02 00:00:00' },
          { name: 'p20280302', lessThan: '2028-03-03 00:00:00' },
          { name: 'p20280303', lessThan: '2028-03-04 00:00:00' },
          { name: 'p20280304', lessThan: '2028-03-05 00:00:00' },
          { name: 'p20280305', lessThan: '2028-03-06 00:00:00' },
        ],
      },
    ]);
  });

  it('drops a monthly partition exactly when its upper bound reaches the cutoff', () => {
    // 6 months at 2027-06-xx: cutoff 2026-12-01, so p202611 (< 2026-12-01) goes, p202612 stays.
    const existing = monthly(
      'p202611',
      'p202612',
      'p202701',
      'p202702',
      'p202703',
      'p202704',
      'p202705',
      'p202706',
      'p202707',
      'p202708',
      'p202709',
    );
    expect(retentionCutoff(spec('email_messages'), utc('2027-06-30T23:59:59Z'))).toEqual(
      utc('2026-12-01T00:00:00Z'),
    );
    expect(
      planPartitionChanges(spec('email_messages'), existing, utc('2027-06-01T00:00:00Z'), opts),
    ).toEqual([{ kind: 'drop', partitions: ['p202611'] }]);
    // One millisecond earlier it is still May: cutoff 2026-11-01, nothing expires.
    expect(
      planPartitionChanges(spec('email_messages'), existing, utc('2027-05-31T23:59:59.999Z'), opts),
    ).toEqual([]);
  });

  it('drops a daily partition exactly at today − N days', () => {
    const existing = daily(
      'p20261101',
      'p20261102',
      'p20261103',
      'p20261104',
      'p20261105',
      'p20261106',
      'p20261107',
      'p20261108',
      'p20261109',
      'p20261110',
      'p20261111',
      'p20261112',
      'p20261113',
      'p20261114',
      'p20261115',
      'p20261116',
    );
    // today 2026-11-09: cutoff 2026-11-02; p20261101 (< 11-02) is expired.
    expect(
      planPartitionChanges(spec('message_outbox'), existing, utc('2026-11-09T00:00:00Z'), opts),
    ).toEqual([{ kind: 'drop', partitions: ['p20261101'] }]);
    expect(
      planPartitionChanges(spec('message_outbox'), existing, utc('2026-11-08T23:59:59Z'), opts),
    ).toEqual([]);
  });

  it('never drops tables marked drop: false', () => {
    const existing = monthly('p202001', 'p202002', 'p202611', 'p202612', 'p202701', 'p202702');
    for (const table of ['audit_logs', 'email_archives']) {
      const actions = planPartitionChanges(
        spec(table),
        existing,
        utc('2026-11-15T00:00:00Z'),
        opts,
      );
      expect(
        actions.filter((a) => a.kind === 'drop'),
        table,
      ).toEqual([]);
    }
    const custom: PartitionSpec = { ...spec('email_messages'), drop: false };
    expect(planPartitionChanges(custom, existing, utc('2026-11-15T00:00:00Z'), opts)).toEqual([]);
  });

  it('refuses tables that break the naming convention', () => {
    const now = utc('2026-11-15T00:00:00Z');
    expect(() =>
      planPartitionChanges(
        spec('email_messages'),
        [{ name: 'p0', description: "'2026-12-01 00:00:00'" }, pmax],
        now,
        opts,
      ),
    ).toThrow(/unexpected partition name/);
    expect(() =>
      planPartitionChanges(
        spec('email_messages'),
        [{ name: 'p202611', description: "'2026-11-15 00:00:00'" }, pmax],
        now,
        opts,
      ),
    ).toThrow(/expected '2026-12-01 00:00:00'/);
    expect(() =>
      planPartitionChanges(spec('email_messages'), monthly('p202611').slice(0, 1), now, opts),
    ).toThrow(/no pmax/);
    expect(() =>
      planPartitionChanges(spec('message_outbox'), monthly('p202611'), now, opts),
    ).toThrow(PartitionPlanError);
  });
});
