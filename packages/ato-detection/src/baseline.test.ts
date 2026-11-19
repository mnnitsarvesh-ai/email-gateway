import { describe, expect, it } from 'vitest';
import {
  ACTIVITY_LIMITS,
  applyActivityDelta,
  baselineView,
  buildBaseline,
  emptyActivityDay,
  isMature,
  localHour,
  median,
  medianMad,
  parseBaseline,
  robustThreshold,
  utcDayStart,
  type ActivityDayRow,
} from './baseline';
import { mergeAtoSettings } from './settings';

const settings = mergeAtoSettings({});
const NOW = new Date('2026-11-18T10:00:00.000Z');
const day = (offset: number) => new Date(utcDayStart(NOW).getTime() - offset * 86_400_000);

describe('statistics (integer)', () => {
  it('median and MAD (scaled 1483/1000)', () => {
    expect(median([])).toBe(0);
    expect(median([3, 1, 2])).toBe(2);
    expect(median([1, 2, 3, 4])).toBe(2);
    expect(medianMad([10, 10, 10, 10])).toEqual({ median: 10, mad: 0 });
    expect(medianMad([1, 2, 3, 4, 100])).toEqual({ median: 3, mad: 1 });
    expect(medianMad([10, 12, 14, 16, 18])).toEqual({ median: 14, mad: 2 });
  });

  it('robust threshold = max(absMin, median + k × max(MAD, max(1, median/10)))', () => {
    expect(robustThreshold([20, 20, 20, 20], 6, 100)).toBe(100);
    expect(robustThreshold([200, 200, 200, 200], 6, 100)).toBe(200 + 6 * 20);
    expect(robustThreshold([10, 12, 14, 16, 18], 6, 0)).toBe(14 + 6 * 2);
    expect(robustThreshold([0, 0, 0], 6, 0)).toBe(6);
  });

  it('maturity needs active days and events', () => {
    expect(isMature(7, 30, settings.baselines)).toBe(true);
    expect(isMature(6, 300, settings.baselines)).toBe(false);
    expect(isMature(20, 29, settings.baselines)).toBe(false);
  });
});

describe('daily activity rows', () => {
  it('merges deltas with bounded lists and hourly maxima', () => {
    let row = emptyActivityDay(day(0));
    row = applyActivityDelta(row, {
      at: NOW,
      messages: 1,
      recipients: 3,
      externalRecipients: 2,
      recipientDomains: ['a.example', 'b.example'],
      attachmentTypes: ['application/pdf'],
      becCategories: ['bank_change'],
      clientPrefix: '198.51.100.0/24',
      hourExternalDomains: 2,
    });
    row = applyActivityDelta(row, {
      at: NOW,
      messages: 1,
      recipientDomains: ['a.example'],
      authSuccess: 1,
      ipPrefix: { p: '192.0.2.0/24', cc: 'IN', asn: 64500 },
    });
    expect(row.messages).toBe(2);
    expect(row.hourCounts[10]).toEqual({ m: 2, a: 1 });
    expect(row.maxHourMessages).toBe(2);
    expect(row.recipientDomains).toEqual([
      { d: 'a.example', n: 2 },
      { d: 'b.example', n: 1 },
    ]);
    expect(row.ipPrefixes).toEqual([{ p: '192.0.2.0/24', n: 1, cc: 'IN', asn: 64500 }]);
    expect(row.content.bec).toEqual({ bank_change: 1 });
    expect(row.content.clientPrefixes).toEqual(['198.51.100.0/24']);
    expect(row.content.maxHourExternalDomains).toBe(2);
    let big = emptyActivityDay(day(0));
    for (let i = 0; i < 150; i++)
      big = applyActivityDelta(big, { at: NOW, recipientDomains: [`d${i}.example`] });
    expect(big.recipientDomains).toHaveLength(ACTIVITY_LIMITS.recipientDomains);
  });
});

describe('buildBaseline', () => {
  function days(): ActivityDayRow[] {
    return Array.from({ length: 10 }, (_, i) => ({
      ...applyActivityDelta(emptyActivityDay(day(i + 1)), {
        at: new Date(day(i + 1).getTime() + 9 * 3_600_000),
        messages: 5,
        externalRecipients: 3,
        recipientDomains: ['partner.example'],
        attachmentTypes: ['application/pdf'],
        clientPrefix: '198.51.100.0/24',
      }),
    }));
  }
  const auth = Array.from({ length: 30 }, (_, i) => ({
    occurredAt: new Date(day((i % 10) + 1).getTime() + 9 * 3_600_000),
    outcome: 'success',
    channel: 'portal',
    ipPrefix: '192.0.2.0/24',
    countryCode: 'IN',
    asn: 64500,
    deviceHash: '0123456789abcdef',
  }));

  it('builds a mature baseline in the organization time zone', () => {
    const b = buildBaseline(days(), auth, settings, NOW, 'Asia/Kolkata');
    expect(b.version).toBe('ato-baseline/1');
    expect(b.activeDays).toBe(10);
    expect(b.eventCount).toBe(50);
    expect(b.mature).toBe(true);
    expect(b.prefixes).toEqual([{ p: '192.0.2.0/24', n: 30 }]);
    expect(b.countries).toEqual([{ c: 'IN', n: 30 }]);
    expect(b.channels).toEqual(['portal']);
    // 09:00 UTC is 14:30 in Asia/Kolkata.
    expect(b.hourHistogram[14]).toBe(30);
    expect(b.messageHourHistogram[14]).toBe(50);
    expect(b.dailyMessages).toHaveLength(28);
    expect(b.dailyMessages.filter((n) => n === 5)).toHaveLength(10);
    expect(b.externalDomains).toEqual([{ d: 'partner.example', n: 10 }]);
    expect(Buffer.byteLength(JSON.stringify(b))).toBeLessThanOrEqual(32 * 1024);
  });

  it('is immature with few active days and ignores days outside the window', () => {
    const old = applyActivityDelta(emptyActivityDay(day(40)), { at: day(40), messages: 100 });
    const b = buildBaseline([...days().slice(0, 3), old], [], settings, NOW);
    expect(b.mature).toBe(false);
    expect(b.eventCount).toBe(15);
  });

  it('view and parse round-trip', () => {
    const b = buildBaseline(days(), auth, settings, NOW);
    const v = baselineView(parseBaseline(JSON.parse(JSON.stringify(b))));
    expect(v.mature).toBe(true);
    expect(v.prefixes.has('192.0.2.0/24')).toBe(true);
    expect(v.clientPrefixes.has('198.51.100.0/24')).toBe(true);
    expect(v.attachmentTypes.has('application/pdf')).toBe(true);
    expect(parseBaseline({ version: 'other' })).toBeNull();
    expect(baselineView(null).mature).toBe(false);
  });

  it('localHour falls back to UTC for an unknown zone', () => {
    expect(localHour(NOW, 'Not/AZone')).toBe(10);
    expect(localHour(NOW, 'Asia/Kolkata')).toBe(15);
  });
});
