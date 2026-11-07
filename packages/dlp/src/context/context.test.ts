import { DLP_CATEGORIES, type DlpCategory } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { detect } from '../detect';
import type { Candidate } from '../detectors/types';
import { DlpDictionarySet } from '../dictionaries';
import { NOW, platformSettings } from '../test-support/pipeline.test-support';
import { luhnCheckDigit } from '../validators';
import {
  SpanIndex,
  codeLikeAt,
  columnAt,
  scoreCandidates,
  type SegmentContextIndex,
} from './scoring';

const dictionaries = DlpDictionarySet.create();
const thresholds = (value: number) =>
  Object.fromEntries(DLP_CATEGORIES.map((c) => [c, value])) as Record<DlpCategory, number>;

const cardWith = (seed: number) => {
  const body = `4532${String(seed).padStart(11, '7')}`;
  return body + String(luhnCheckDigit(body));
};

async function scored(
  text: string,
  kind: 'text' | 'table' = 'text',
  settings = platformSettings(),
) {
  return (
    await detect({
      segments: [
        {
          source: { kind: 'attachment', partIndex: 0 },
          format: kind === 'table' ? 'csv' : 'text',
          kind,
          text,
        },
      ],
      settings,
      aadhaarEnabled: true,
      dictionaries,
      now: NOW,
    })
  ).candidates;
}

describe('SpanIndex', () => {
  it('finds overlaps at the window edges only', () => {
    const index = new SpanIndex([
      { start: 10, end: 14 },
      { start: 100, end: 120 },
    ]);
    expect(index.near(14, 20)).toBe(false); // ends exactly at lo
    expect(index.near(13, 20)).toBe(true);
    expect(index.near(0, 10)).toBe(false); // starts exactly at hi
    expect(index.near(0, 11)).toBe(true);
    expect(index.near(110, 111)).toBe(true);
    expect(SpanIndex.EMPTY.near(0, 1e9)).toBe(false);
  });
});

describe('context window (D7)', () => {
  it('counts a positive term within 64 code units and not beyond', async () => {
    const card = cardWith(1);
    const near = await scored(`card ${'x'.repeat(58)} ${card}`);
    expect(near[0]!.confidence).toBe(0.75);
    const far = await scored(`card ${'x'.repeat(64)} ${card}`);
    expect(far[0]!.confidence).toBe(0.45);
    const after = await scored(`${card} ${'y'.repeat(58)} cvv`);
    expect(after[0]!.confidence).toBe(0.75);
  });

  it('applies positive context once and negative context once, clamped to [0, 1]', async () => {
    const card = cardWith(2);
    expect((await scored(`card credit debit visa ${card}`))[0]!.confidence).toBe(0.75);
    expect((await scored(`test sample demo ${card}`))[0]!.confidence).toBe(0.15);
    expect((await scored(`test card ${card}`))[0]!.confidence).toBe(0.45);
  });

  it('matches context through case, NFKC, zero-width characters and Latin confusables', async () => {
    const card = cardWith(3);
    for (const word of ['CARD', 'ｃａｒｄ', 'ca​rd', 'cаrd' /* Cyrillic а */]) {
      expect((await scored(`${word} ${card}`))[0]!.confidence, word).toBe(0.75);
    }
  });

  it('uses Hindi context terms', async () => {
    expect((await scored(`कार्ड ${cardWith(4)}`))[0]!.confidence).toBe(0.75);
    expect((await scored('पैन ABCPD1234E'))[0]!.confidence).toBe(0.85);
  });
});

describe('table column context and bulk aggregation', () => {
  it('a header cell with a context term applies to its column only', async () => {
    const cards = Array.from({ length: 3 }, (_, i) => cardWith(10 + i));
    const table = ['name\tcard_number\tnote', ...cards.map((c, i) => `P${i}\t${c}\tx`)].join('\n');
    expect((await scored(table, 'table')).map((c) => c.confidence)).toEqual([0.75, 0.75, 0.75]);
    // The context header is on another column: the values get no column context.
    const other = [
      `card_number\tremarks_${'r'.repeat(70)}`,
      ...cards.map((c, i) => `P${i}\t${c}`),
    ].join('\n');
    expect((await scored(other, 'table')).map((c) => c.confidence)).toEqual([0.45, 0.45, 0.45]);
    expect(columnAt('a\tb\tc', 4)).toBe(2);
  });

  it('adds +0.15 with at least 5 distinct values in a segment', async () => {
    const four = Array.from({ length: 4 }, (_, i) => cardWith(20 + i)).join('\n');
    expect((await scored(four)).map((c) => c.confidence)).toEqual([0.45, 0.45, 0.45, 0.45]);
    const five = Array.from({ length: 5 }, (_, i) => cardWith(30 + i)).join('\n');
    expect((await scored(five)).every((c) => c.confidence === 0.6 && c.reportable)).toBe(true);
    // Repeating one value is not bulk.
    const same = Array.from({ length: 6 }, () => cardWith(40)).join('\n');
    expect((await scored(same)).every((c) => c.confidence === 0.45)).toBe(true);
  });
});

describe('code penalty', () => {
  it('detects code-like lines', () => {
    expect(codeLikeAt('const PAN = "ABCPD1234E";', 13, 23)).toBe(true);
    expect(codeLikeAt('x = 0xABCPD1234E;', 6, 16)).toBe(true);
    expect(codeLikeAt('my_ABCPD1234E', 3, 13)).toBe(true);
    expect(codeLikeAt('PAN: ABCPD1234E', 5, 15)).toBe(false);
    expect(codeLikeAt('{"pan": "ABCPD1234E"}', 9, 19)).toBe(false);
  });
  it('applies to PAN, passport, mobile and cards, ignores their positive context', async () => {
    expect((await scored('let card = "4532015112830366";'))[0]!.confidence).toBe(0.15);
    expect((await scored('var passport = "K1234567";'))[0]!.reportable).toBe(false);
    // Not to IBAN.
    expect((await scored('const iban = "GB82WEST12345698765432";'))[0]!.confidence).toBe(0.9);
  });
});

describe('thresholds per category', () => {
  it('reportable iff confidence ≥ the category threshold', () => {
    const candidate: Candidate = {
      detector: 'NI1',
      segment: 0,
      start: 0,
      end: 10,
      value: 'ABCPD1234E',
      compact: 'ABCPD1234E',
      base: 0.5,
      context: ['pan'],
      contextBonus: 0.35,
      requiresContext: false,
      negative: null,
      codePenalty: false,
      extra: {},
    };
    const index: SegmentContextIndex = {
      positive: new Map(),
      negative: SpanIndex.EMPTY,
      negativePhone: SpanIndex.EMPTY,
      disclaimer: SpanIndex.EMPTY,
      columns: null,
      codeSegment: false,
      awsKeyIds: SpanIndex.EMPTY,
    };
    const run = (threshold: number, overrides: Partial<Record<DlpCategory, number>> = {}) =>
      scoreCandidates([candidate], 'ABCPD1234E', index, {
        window: 64,
        bulkMinDistinct: 5,
        thresholds: { ...thresholds(threshold), ...overrides },
      })[0]!;
    expect(run(0.5).reportable).toBe(true);
    expect(run(0.51).reportable).toBe(false);
    expect(run(0.5, { national_id: 0.95 }).reportable).toBe(false);
    expect(run(0.95, { national_id: 0.5 }).reportable).toBe(true);
    // Requires-context detectors need the term even above the threshold.
    expect(
      scoreCandidates([{ ...candidate, requiresContext: true }], 'ABCPD1234E', index, {
        window: 64,
        bulkMinDistinct: 5,
        thresholds: thresholds(0.5),
      })[0]!.reportable,
    ).toBe(false);
  });
});
