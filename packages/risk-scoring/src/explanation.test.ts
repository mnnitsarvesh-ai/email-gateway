import { describe, expect, it } from 'vitest';
import { Prng } from '../scripts/prng';
import {
  canonicalJson,
  EXPLANATION_LINE_CODES,
  type ExplanationLine,
  platformProfile,
  renderExplanation,
  resolveProfile,
  riskResultToRowJson,
  riskScoreViewSchema,
  rowJsonToRiskView,
  scoreRisk,
  scoringErrorResult,
  sha256Hex,
} from './index';
import { build, cleanRows, final, setFinal, withBec, withCodes } from './rows.test-support';

const PLATFORM = platformProfile('rsk-default/1');
const PUBLIC_ID = '0190a6f2-7b3c-7def-8abc-0123456789ab';

/** Host-like token: a dot between two letter/digit runs (e.g. `example.com`). */
const HOST_LIKE = /[A-Za-z0-9-]+\.[A-Za-z][A-Za-z0-9-]*/;

function busyResult() {
  let rows = withCodes(cleanRows(), 'rspamd', 'spam', [
    'spam.score',
    'auth.dmarc_fail_arc_trusted',
    'reputation.ip_listed',
  ]);
  rows = withCodes(rows, 'url', 'malicious', [
    'url.feed_malicious',
    'url.lookalike_homoglyph',
    'url.too_long',
    'url.future_rule',
  ]);
  rows = withBec(rows, 'suspicious', [
    'bec.content.urgency',
    'bec.impersonation.executive_name',
    'bec.trusted_sender',
  ]);
  rows = setFinal(rows, final('attachment', 'unknown', ['archive.unsupported_format']));
  rows = setFinal(rows, final('sandbox', 'error', ['sandbox.error.internal']));
  return scoreRisk(build({ ...rows, dlp: null }, 1), PLATFORM);
}

describe('explanation (R11)', () => {
  it('is rendered from templates: summary first, profile last', () => {
    const r = busyResult();
    const codes = r.explanation.lines.map((l) => l.code);
    expect(codes[0]).toBe('summary');
    expect(codes[codes.length - 1]).toBe('profile');
    expect(codes).toEqual(
      expect.arrayContaining([
        'hard_block',
        'engine_unknown',
        'input_missing',
        'top_signal',
        'unmapped_codes',
        'arc_trusted',
        'floor',
        'sandbox',
      ]),
    );
    expect(
      r.explanation.text.startsWith(
        `Risk ${r.score}/1000 (${r.level}): recommended ${r.recommendedAction}.`,
      ),
    ).toBe(true);
    expect(r.explanation.text).toBe(renderExplanation(r.explanation.lines));
    expect(r.explanation.lines.filter((l) => l.code === 'top_signal').length).toBeLessThanOrEqual(
      5,
    );
  });

  it('never contains @, :// or host-like tokens; digits only from integers and versions', () => {
    const results = [
      busyResult(),
      scoreRisk(build(cleanRows()), PLATFORM),
      scoringErrorResult(null, PLATFORM, 'input_invalid'),
    ];
    const tenant = resolveProfile('rsk-default/1', {
      publicId: PUBLIC_ID,
      versionNo: 7,
      baseProfile: 'rsk-default/1',
      overrides: {},
    });
    results.push(scoreRisk(build(cleanRows()), tenant));
    for (const r of results) {
      const text = r.explanation.text;
      expect(text).not.toMatch(/@|:\/\//);
      expect(text.replace(/\.(\s|$)/g, ' ')).not.toMatch(HOST_LIKE);
      expect(text.length).toBeLessThanOrEqual(2048);
      expect(r.explanation.lines.length).toBeLessThanOrEqual(20);
      // every number in the text is a param value or a version number
      const numbers = new Set(
        r.explanation.lines.flatMap((l) =>
          Object.values(l.params)
            .filter((v) => typeof v === 'number')
            .map(String),
        ),
      );
      for (const n of text.match(/\d+/g) ?? []) expect(['1000', '1', ...numbers]).toContain(n);
    }
    expect(results[3]!.explanation.text).toContain(
      'Profile: tenant version 7 (rsk-default/1 base).',
    );
  });

  it('is bounded to 2048 characters with whole lines', () => {
    const line: ExplanationLine = {
      code: 'top_signal',
      params: {
        signal: 'credential_form_cross_origin',
        group: 'credential',
        points: 450,
        engines: 'url+bec',
      },
    };
    const text = renderExplanation(Array.from({ length: 100 }, () => line));
    expect(text.length).toBeLessThanOrEqual(2048);
    expect(text.endsWith('(more omitted)')).toBe(true);
  });

  it('has a template for every line code', () => {
    for (const code of EXPLANATION_LINE_CODES) {
      expect(renderExplanation([{ code, params: {} }]).length).toBeGreaterThan(0);
    }
  });
});

describe('row mapping (R11)', () => {
  it('riskResultToRowJson / rowJsonToRiskView round trip', () => {
    const rng = new Prng(7);
    const tenant = resolveProfile('rsk-default/1', {
      publicId: PUBLIC_ID,
      versionNo: 12,
      baseProfile: 'rsk-default/1',
      overrides: { thresholds: { high: 600 } },
    });
    for (const [result, revision] of [
      [busyResult(), 1],
      [scoreRisk(build(cleanRows()), tenant), 0],
      [scoringErrorResult(build(cleanRows()), PLATFORM, 'scorer_exception'), 0],
    ] as const) {
      const row = riskResultToRowJson(result);
      expect(row.explanation).toEqual(result.explanation.lines);
      expect(row.explanationText).toBe(result.explanation.text);
      expect(row.profileIdText).toBe(result.versions.profile.id);
      // JSON columns come back as parsed JSON
      const stored = JSON.parse(JSON.stringify(row)) as typeof row;
      const createdAt = new Date(Date.UTC(2026, 10, 10, 10, rng.int(0, 59)));
      const view = rowJsonToRiskView({ ...stored, revision, createdAt });
      expect(riskScoreViewSchema.parse(view)).toEqual(view);
      expect(view).toEqual({ ...result, revision, createdAt: createdAt.toISOString() });
    }
  });

  it('refuses a malformed row', () => {
    const row = riskResultToRowJson(scoreRisk(build(cleanRows()), PLATFORM));
    expect(() =>
      rowJsonToRiskView({ ...row, level: 'extreme', revision: 0, createdAt: new Date() }),
    ).toThrow();
  });
});

describe('canonicalJson and sha256Hex', () => {
  it('sorts keys, has no whitespace and refuses non-JSON values', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 0, y: -1.5 } })).toBe(
      '{"a":[true,null,"x"],"b":1,"c":{"y":-1.5,"z":0}}',
    );
    expect(() => canonicalJson({ a: Number.NaN })).toThrow();
    expect(() => canonicalJson({ a: Infinity })).toThrow();
    expect(() => canonicalJson({ a: 1n })).toThrow();
    expect(() => canonicalJson({ a: undefined })).toThrow();
    expect(() => canonicalJson([undefined])).toThrow();
    expect(() => canonicalJson(new Date())).toThrow();
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
