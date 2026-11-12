import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  cronInstants,
  InvalidDigestScheduleError,
  isValidCronExpression,
  isValidTimeZoneName,
  nextDigestWindows,
  parseCron,
} from './cron';

const iso = (dates: Date[]) => dates.map((d) => d.toISOString());
const at = (s: string) => new Date(s);
const instants = (expr: string, tz: string, from: string, to: string) =>
  iso(cronInstants(parseCron(expr)!, tz, at(from), at(to)));

const VALID = [
  '0 8 * * *',
  '*/15 * * * *',
  '0-30/5 9-17 * * MON-FRI',
  '0 0 1,15 * *',
  '30 7 * JAN-MAR,DEC sun',
  '59 23 31 12 7',
  '0 0 * * 0',
  '  5   4  *  *  *  ',
  '0 */2 * * *',
  '1-59/58 0 1-31 1-12 0-7',
];
const INVALID = [
  '',
  '0 8 * *',
  '0 8 * * * *',
  '60 * * * *',
  '* 24 * * *',
  '* * 0 * *',
  '* * 32 * *',
  '* * * 13 *',
  '* * * * 8',
  '5/10 * * * *',
  '*/0 * * * *',
  '*/60 * * * *',
  '10-5 * * * *',
  '1-2-3 * * * *',
  '@daily',
  '0 8 ? * *',
  '0 8 L * *',
  '0 8 * * 1#2',
  '0 8 * * MON/2',
  'a b c d e',
  '0 8 * * MONDAY',
  '001 * * * *',
  ',0 * * * *',
  `${'0,'.repeat(40)}0 * * * *`,
];

describe('cron grammar (same as the api organization settings validator)', () => {
  it.each(VALID)('accepts %j', (e) => expect(isValidCronExpression(e)).toBe(true));
  it.each(INVALID)('refuses %j', (e) => expect(isValidCronExpression(e)).toBe(false));

  it('agrees with apps/api isValidCron on the corpus and 20 000 random expressions', async () => {
    const path = resolve(
      __dirname,
      '../../../apps/api/src/modules/organizations/domain/settings-validation.ts',
    );
    expect(existsSync(path)).toBe(true);
    const api = (await import(path)) as { isValidCron: (e: string) => boolean };
    for (const e of [...VALID, ...INVALID])
      expect(isValidCronExpression(e), e).toBe(api.isValidCron(e));
    let a = 42;
    const rand = (n: number) => {
      // mulberry32
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * n);
    };
    const atoms = [
      ['*', '0', '5', '59', '60', '00', 'JAN'],
      ['*', '0', '8', '23', '24', '07'],
      ['*', '1', '15', '31', '32', '0'],
      ['*', '1', '12', 'JAN', 'dec', '13', 'MON'],
      ['*', '0', '7', 'MON', 'sun', '8', 'JAN'],
      ['*', '1'],
    ];
    const field = (i: number) => {
      const pool = atoms[Math.min(i, atoms.length - 1)]!;
      const parts = Array.from({ length: 1 + rand(2) }, () => {
        let p = pool[rand(pool.length)]!;
        if (rand(4) === 0) p += `-${pool[rand(pool.length)]}`;
        if (rand(4) === 0) p += `/${['1', '2', '15', '0', '61'][rand(5)]}`;
        return p;
      });
      return parts.join(',');
    };
    let agreeValid = 0;
    for (let i = 0; i < 20_000; i += 1) {
      const e = Array.from({ length: rand(8) === 0 ? 4 + 2 * rand(2) : 5 }, (_, i) =>
        field(i),
      ).join(' ');
      const mine = isValidCronExpression(e);
      expect(mine, e).toBe(api.isValidCron(e));
      if (mine) agreeValid += 1;
    }
    expect(agreeValid).toBeGreaterThan(50);
  });

  it('parses names, 7 = Sunday and the day-of-month/day-of-week star rule', () => {
    const c = parseCron('0 9 * * 7')!;
    expect([...c.daysOfWeek]).toEqual([0]);
    expect(c.domStar).toBe(true);
    expect(parseCron('0 9 1 * MON')).toMatchObject({ domStar: false, dowStar: false });
  });
});

describe('time zones', () => {
  it('accepts IANA names and UTC; refuses offsets and unknown zones', () => {
    for (const tz of ['UTC', 'Asia/Kolkata', 'America/Argentina/Buenos_Aires', 'Etc/GMT+5']) {
      expect(isValidTimeZoneName(tz), tz).toBe(true);
    }
    for (const tz of ['', '+05:30', 'Mars/Olympus', 'EST5EDT/x/y/z', 'a'.repeat(65)]) {
      expect(isValidTimeZoneName(tz), tz).toBe(false);
    }
  });
});

describe('cron instants across time zones and DST', () => {
  it('daily 08:00 in Asia/Kolkata (+05:30, no DST)', () => {
    expect(
      instants('0 8 * * *', 'Asia/Kolkata', '2026-11-10T00:00:00Z', '2026-11-12T23:59:00Z'),
    ).toEqual(['2026-11-10T02:30:00.000Z', '2026-11-11T02:30:00.000Z', '2026-11-12T02:30:00.000Z']);
  });
  it('America/New_York spring forward: 02:30 does not exist → 03:30 EDT', () => {
    expect(
      instants('30 2 * * *', 'America/New_York', '2026-03-07T00:00:00Z', '2026-03-10T00:00:00Z'),
    ).toEqual([
      '2026-03-07T07:30:00.000Z', // 02:30 EST
      '2026-03-08T07:30:00.000Z', // gap: 03:30 EDT
      '2026-03-09T06:30:00.000Z', // 02:30 EDT
    ]);
  });
  it('America/New_York fall back: 01:30 occurs twice → fires once (first)', () => {
    expect(
      instants('30 1 * * *', 'America/New_York', '2026-10-31T00:00:00Z', '2026-11-02T12:00:00Z'),
    ).toEqual([
      '2026-10-31T05:30:00.000Z',
      '2026-11-01T05:30:00.000Z', // 01:30 EDT only
      '2026-11-02T06:30:00.000Z',
    ]);
  });
  it('an hourly schedule over the fall-back hour yields each wall-clock hour once', () => {
    const list = instants(
      '0 * * * *',
      'America/New_York',
      '2026-11-01T03:30:00Z',
      '2026-11-01T08:30:00Z',
    );
    expect(list).toEqual([
      '2026-11-01T04:00:00.000Z', // 00:00 EDT
      '2026-11-01T05:00:00.000Z', // 01:00 EDT (01:00 EST is the same wall time: skipped)
      '2026-11-01T07:00:00.000Z', // 02:00 EST
      '2026-11-01T08:00:00.000Z', // 03:00 EST
    ]);
  });
  it('Europe/London spring forward at 01:00 and Australia/Lord_Howe 30-minute shift', () => {
    expect(
      instants('30 1 29 3 *', 'Europe/London', '2026-03-28T00:00:00Z', '2026-03-30T00:00:00Z'),
    ).toEqual([
      '2026-03-29T01:30:00.000Z', // 01:30 GMT does not exist → 02:30 BST
    ]);
    expect(
      instants(
        '15 2 4 10 *',
        'Australia/Lord_Howe',
        '2026-10-03T00:00:00Z',
        '2026-10-05T00:00:00Z',
      ),
    ).toEqual([
      '2026-10-03T15:45:00.000Z', // 02:15 in the 02:00→02:30 gap → 02:45 (+11:00)
    ]);
  });
  it('day-of-month OR day-of-week when both are restricted; AND when one is a star', () => {
    // Nov 2026: the 13th is a Friday; Mondays are 2, 9, 16, 23, 30.
    const or = instants('0 12 13 * MON', 'UTC', '2026-11-01T00:00:00Z', '2026-11-17T00:00:00Z');
    expect(or).toEqual([
      '2026-11-02T12:00:00.000Z',
      '2026-11-09T12:00:00.000Z',
      '2026-11-13T12:00:00.000Z',
      '2026-11-16T12:00:00.000Z',
    ]);
    const and = instants('0 12 */2 * MON', 'UTC', '2026-11-01T00:00:00Z', '2026-11-17T00:00:00Z');
    expect(and).toEqual(['2026-11-09T12:00:00.000Z']);
  });
  it('(from, to] bounds; empty for an empty range', () => {
    expect(instants('0 8 * * *', 'UTC', '2026-11-12T08:00:00Z', '2026-11-13T08:00:00Z')).toEqual([
      '2026-11-13T08:00:00.000Z',
    ]);
    expect(instants('0 8 * * *', 'UTC', '2026-11-12T09:00:00Z', '2026-11-12T09:00:00Z')).toEqual(
      [],
    );
  });
});

describe('nextDigestWindows (Q20)', () => {
  it('daily: one due run with the window from the previous run', () => {
    expect(
      nextDigestWindows(
        '0 8 * * *',
        'Asia/Kolkata',
        at('2026-11-11T02:30:00Z'),
        at('2026-11-12T03:00:00Z'),
        24,
      ),
    ).toEqual([
      { scheduledFor: at('2026-11-12T02:30:00Z'), windowFrom: at('2026-11-11T02:30:00Z') },
    ]);
  });
  it('nothing due before the next instant; idempotent for the same last run', () => {
    expect(
      nextDigestWindows(
        '0 8 * * *',
        'UTC',
        at('2026-11-12T08:00:00Z'),
        at('2026-11-12T20:00:00Z'),
        24,
      ),
    ).toEqual([]);
  });
  it('coalesces to at most one run per hour', () => {
    const w = nextDigestWindows(
      '*/15 * * * *',
      'UTC',
      at('2026-11-12T08:00:00Z'),
      at('2026-11-12T10:20:00Z'),
      24,
    );
    expect(w).toEqual([
      { scheduledFor: at('2026-11-12T09:00:00Z'), windowFrom: at('2026-11-12T08:00:00Z') },
      { scheduledFor: at('2026-11-12T10:00:00Z'), windowFrom: at('2026-11-12T09:00:00Z') },
    ]);
  });
  it('caps at maxPerDay (latest kept; the first window starts at the last run)', () => {
    const w = nextDigestWindows(
      '0 * * * *',
      'UTC',
      at('2026-11-12T00:00:00Z'),
      at('2026-11-12T10:30:00Z'),
      3,
    );
    expect(w).toEqual([
      { scheduledFor: at('2026-11-12T08:00:00Z'), windowFrom: at('2026-11-12T00:00:00Z') },
      { scheduledFor: at('2026-11-12T09:00:00Z'), windowFrom: at('2026-11-12T08:00:00Z') },
      { scheduledFor: at('2026-11-12T10:00:00Z'), windowFrom: at('2026-11-12T09:00:00Z') },
    ]);
  });
  it('first run (no previous run): the latest due instant(s) within 24 h, window from now − 24 h', () => {
    expect(nextDigestWindows('0 8 * * *', 'UTC', null, at('2026-11-12T09:00:00Z'), 24)).toEqual([
      { scheduledFor: at('2026-11-12T08:00:00Z'), windowFrom: at('2026-11-11T09:00:00Z') },
    ]);
  });
  it('a long outage: instants older than 48 h are merged into the first window', () => {
    const w = nextDigestWindows(
      '0 8 * * *',
      'UTC',
      at('2026-11-01T08:00:00Z'),
      at('2026-11-12T09:00:00Z'),
      24,
    );
    expect(w).toEqual([
      { scheduledFor: at('2026-11-11T08:00:00Z'), windowFrom: at('2026-11-01T08:00:00Z') },
      { scheduledFor: at('2026-11-12T08:00:00Z'), windowFrom: at('2026-11-11T08:00:00Z') },
    ]);
  });
  it('DST: a daily 02:30 New York digest still runs on the spring-forward day', () => {
    const w = nextDigestWindows(
      '30 2 * * *',
      'America/New_York',
      at('2026-03-07T07:30:00Z'),
      at('2026-03-08T12:00:00Z'),
      24,
    );
    expect(w).toEqual([
      { scheduledFor: at('2026-03-08T07:30:00Z'), windowFrom: at('2026-03-07T07:30:00Z') },
    ]);
  });
  it('refuses invalid schedules, time zones and maxPerDay', () => {
    const call =
      (s: string, tz: string, max = 24) =>
      () =>
        nextDigestWindows(s, tz, null, at('2026-11-12T09:00:00Z'), max);
    expect(call('@daily', 'UTC')).toThrow(InvalidDigestScheduleError);
    expect(call('0 8 * * *', 'Nowhere/City')).toThrow(/time_zone/);
    expect(call('0 8 * * *', 'UTC', 0)).toThrow(/max_per_day/);
  });
});
