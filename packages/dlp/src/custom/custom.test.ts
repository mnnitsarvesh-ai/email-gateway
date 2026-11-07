import { describe, expect, it } from 'vitest';
import { Deadline } from '@email-gateway/bec';
import {
  CompiledPatternCache,
  DLP_CUSTOM_PATTERN_CODES,
  compileCustomPattern,
  findPatternMatches,
  hasUnsupportedConstruct,
  loadTenantPatterns,
  probeCorpus,
  repetitionComplexity,
  testCustomPattern,
  type CustomPatternInput,
  type TenantPatternInput,
} from './index';

const input = (pattern: string, extra: Partial<CustomPatternInput> = {}): CustomPatternInput => ({
  pattern,
  caseInsensitive: false,
  ...extra,
});

const code = (pattern: string, extra: Partial<CustomPatternInput> = {}) => {
  const result = compileCustomPattern(input(pattern, extra));
  return result.ok ? 'ok' : result.code;
};

describe('compileCustomPattern (D9 validation)', () => {
  it('accepts an ordinary tenant pattern', () => {
    const result = compileCustomPattern(input('EMP-[0-9]{6}', { contextKeywords: ['employee'] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.compiled.complexity).toEqual({ repetitionProduct: 6, length: 12 });
  });

  it('step 1: length bounds', () => {
    expect(code('')).toBe('pattern_syntax');
    expect(code(`X${'[0-9]'.repeat(51)}Y`)).toBe('pattern_syntax'); // 257 characters
    expect(compileCustomPattern(input('ABC-[0-9]{4}'), { maxLength: 8 })).toMatchObject({
      ok: false,
      code: 'pattern_syntax',
    });
  });

  it('step 2: syntax errors and unsupported constructs', () => {
    expect(code('[0-9')).toBe('pattern_syntax');
    expect(code('(ABC')).toBe('pattern_syntax');
    for (const p of [
      '(a)\\1',
      '(?=EMP)EMP',
      '(?!x)EMP',
      '(?<=x)EMP',
      '(?<!x)EMP',
      'EMP++',
      'EMP*+',
      '(?>EMP)',
      '(?P<n>a)(?P=n)',
      '\\k<name>',
    ]) {
      expect(code(p), p).toBe('pattern_unsupported');
    }
    expect(hasUnsupportedConstruct('\\+\\+')).toBe(false);
    expect(hasUnsupportedConstruct('a\\+')).toBe(false);
  });

  it('step 3: counted repetition bounds and nested products', () => {
    expect(repetitionComplexity('(a{100}){100}')).toEqual({ maxRepeat: 100, product: 10_000 });
    expect(repetitionComplexity('((a{10})){200}').product).toBe(2000);
    expect(repetitionComplexity('[{]{3}').product).toBe(3);
    expect(code('(ZQ{100}){100}')).toBe('pattern_too_complex');
    expect(code('ZQ{101}')).toBe('pattern_too_complex');
    expect(code('(ZQ[0-9]{10}){20}X')).toBe('ok');
    expect(code('(ZQ[0-9]{10}){101}X')).toBe('pattern_too_complex');
  });

  it('step 4: a pattern matching the empty string', () => {
    expect(code('a*')).toBe('pattern_matches_empty');
    expect(code('(EMP)?')).toBe('pattern_matches_empty');
    expect(code('\\b')).toBe('pattern_matches_empty'); // empty match on the probe corpus
  });

  it('step 5: more than 50 matches on the probe corpus is too broad', () => {
    expect(code('[a-z]+')).toBe('pattern_too_broad');
    expect(code('[0-9]{2}')).toBe('pattern_too_broad');
    expect(code('the', { caseInsensitive: true })).toBe('pattern_too_broad');
    expect(code('Pune')).toBe('ok');
  });

  it('step 6: the cost probe', () => {
    let t = 0;
    const slowClock = () => (t += 60);
    expect(compileCustomPattern(input('EMP-[0-9]{6}'), { now: slowClock })).toMatchObject({
      ok: false,
      code: 'pattern_too_slow',
    });
    expect(compileCustomPattern(input('EMP-[0-9]{6}'), { now: () => 0 }).ok).toBe(true);
  });

  it('step 7: validator and context keywords', () => {
    expect(code('EMP-[0-9]{6}', { validator: 'luhn' })).toBe('ok');
    expect(code('EMP-[0-9]{6}', { validator: 'rot13' as never })).toBe('pattern_invalid_options');
    expect(
      code('EMP-[0-9]{6}', { contextKeywords: Array.from({ length: 21 }, (_, i) => `k${i}`) }),
    ).toBe('pattern_invalid_options');
    expect(code('EMP-[0-9]{6}', { contextKeywords: ['x'.repeat(65)] })).toBe(
      'pattern_invalid_options',
    );
    expect(code('EMP-[0-9]{6}', { requireContext: true })).toBe('pattern_invalid_options');
    expect(DLP_CUSTOM_PATTERN_CODES).toContain('pattern_too_slow');
  });

  it('never echoes the pattern in its result codes', () => {
    const result = compileCustomPattern(input('SECRET-MARKER-(?=x)'));
    expect(JSON.stringify(result)).not.toContain('SECRET-MARKER');
  });

  it('the probe corpus is about 64 KiB of ordinary text', () => {
    const bytes = Buffer.byteLength(probeCorpus(), 'utf8');
    expect(bytes).toBeGreaterThan(60 * 1024);
    expect(bytes).toBeLessThan(70 * 1024);
  });
});

describe('catastrophic patterns are rejected or run in linear time', () => {
  const adversarial = `${'a'.repeat(1 << 20)}!`;
  for (const pattern of ['(a+)+$', '(a|a)*b', '(.*)*x', '(a|aa)+c', '(x+x+)+y']) {
    it(`${pattern}: linear on 1 MiB`, () => {
      const result = compileCustomPattern(input(pattern), { probeCorpus: 'zzz' });
      if (!result.ok) {
        expect([
          'pattern_too_broad',
          'pattern_matches_empty',
          'pattern_unsupported',
          'pattern_too_complex',
        ]).toContain(result.code);
        return;
      }
      const started = performance.now();
      findPatternMatches(result.compiled, adversarial, { maxMatches: 10 });
      // re2js is linear: well under a second on 1 MiB on any CI machine (measured ≈ 0.1 s).
      expect(performance.now() - started).toBeLessThan(3000);
    });
  }
  it('nested counted repetition is refused before it can expand', () => {
    expect(code('(a{100}){100}')).toBe('pattern_too_complex');
  });
});

describe('run-time scanning', () => {
  const compiled = (pattern: string, extra: Partial<CustomPatternInput> = {}) => {
    const result = compileCustomPattern(input(pattern, extra));
    if (!result.ok) throw new Error(result.code);
    return result.compiled;
  };

  it('finds matches with UTF-16 offsets, validates them and caps the count', () => {
    const p = compiled('CARD-[0-9]{16}', { validator: 'luhn' });
    const text = 'ééé CARD-4532015112830366 and CARD-4532015112830367';
    const { matches } = findPatternMatches(p, text);
    expect(matches.map((m) => [m.start, m.end, m.validated])).toEqual([
      [4, 25, true],
      [30, 51, false],
    ]);
    const many = findPatternMatches(compiled('ZK[0-9]'), 'ZK1 '.repeat(50), { maxMatches: 10 });
    expect(many.matches).toHaveLength(10);
    expect(many.capped).toBe(true);
  });

  it('owns a match by the chunk where it starts (no duplicates across the overlap)', () => {
    const p = compiled('ZK[0-9]{4}');
    const text = `${'x'.repeat(98)}ZK1234${'y'.repeat(100)}ZK5678`;
    const { matches } = findPatternMatches(p, text, { chunkChars: 100, overlap: 20 });
    expect(matches.map((m) => m.start)).toEqual([98, 204]);
  });

  it('checks the deadline between chunks', () => {
    let calls = 0;
    const deadline = new Deadline(0, () => (calls += 1));
    expect(() =>
      findPatternMatches(compiled('ZK[0-9]'), 'x'.repeat(1000), { chunkChars: 100, deadline }),
    ).toThrow(/time budget/);
  });

  it('loads stored patterns: invalid ones are skipped by id, never thrown', () => {
    const base: TenantPatternInput = {
      id: 'b',
      version: 1,
      pattern: 'EMP-[0-9]{6}',
      caseInsensitive: false,
      validator: 'none',
      contextKeywords: [],
      requireContext: false,
      severity: 'medium',
      baseConfidence: 0.6,
      maskStyle: 'last4',
    };
    const { loaded, invalid } = loadTenantPatterns([
      base,
      { ...base, id: 'a', pattern: '(?=x)' },
      { ...base, id: 'c', baseConfidence: 0.2 },
    ]);
    expect(loaded.map((p) => p.id)).toEqual(['b']);
    expect(invalid).toEqual(['a', 'c']);
  });

  it('costProbe false skips only the wall-clock probe (worker load, closer review)', () => {
    let t = 0;
    const slow = () => (t += 1_000);
    const pattern = input('EMP-[0-9]{6}');
    expect(compileCustomPattern(pattern, { now: slow })).toMatchObject({
      ok: false,
      code: 'pattern_too_slow',
    });
    expect(compileCustomPattern(pattern, { now: slow, costProbe: false }).ok).toBe(true);
    // The deterministic steps still run without the cost probe.
    expect(compileCustomPattern(input('[a-z]'), { costProbe: false })).toMatchObject({
      ok: false,
      code: 'pattern_too_broad',
    });
    expect(compileCustomPattern(input('(a)\\1'), { costProbe: false })).toMatchObject({
      ok: false,
      code: 'pattern_unsupported',
    });
  });

  it('a cache compiles each row version once and is bounded', () => {
    const row: TenantPatternInput = {
      id: 'p1',
      version: 1,
      pattern: 'EMP-[0-9]{6}',
      caseInsensitive: false,
      severity: 'medium',
      baseConfidence: 0.6,
      maskStyle: 'last4',
    };
    const cache = new CompiledPatternCache(2);
    const first = loadTenantPatterns([row], { costProbe: false }, cache).loaded[0]!.compiled;
    expect(loadTenantPatterns([row], { costProbe: false }, cache).loaded[0]!.compiled).toBe(first);
    const v2 = loadTenantPatterns([{ ...row, version: 2 }], { costProbe: false }, cache);
    expect(v2.loaded[0]!.compiled).not.toBe(first);
    // A changed pattern text under the same version is a different entry, never a stale one.
    const changed = loadTenantPatterns([{ ...row, pattern: 'EMP-[0-9]{7}' }], {}, cache);
    expect(changed.loaded[0]!.compiled.input.pattern).toBe('EMP-[0-9]{7}');
    expect(cache.size).toBe(2);
    // Invalid results are cached too (deterministic) and still reported.
    const bad = loadTenantPatterns([{ ...row, id: 'p2', pattern: '(?=x)' }], {}, cache);
    expect(bad.invalid).toEqual(['p2']);
    expect(cache.size).toBe(2);
  });
});

describe('testCustomPattern (api test endpoint)', () => {
  it('returns masked matches with validation and context flags, never the values', () => {
    const result = testCustomPattern(
      {
        pattern: 'CARD-[0-9]{16}',
        caseInsensitive: false,
        validator: 'luhn',
        contextKeywords: ['card'],
      },
      'card CARD-4532015112830366 and CARD-4532015112830367',
    );
    expect(result.valid).toBe(true);
    expect(result.matches).toEqual([
      { start: 5, end: 26, masked: `${'*'.repeat(16)}0366`, validated: true, contextMatched: true },
      {
        start: 31,
        end: 52,
        masked: `${'*'.repeat(16)}0367`,
        validated: false,
        contextMatched: true,
      },
    ]);
    expect(JSON.stringify(result)).not.toContain('4532015112830366');
  });
  it('refuses invalid patterns and long samples with a code', () => {
    expect(testCustomPattern({ pattern: '(?=x)', caseInsensitive: false }, 'x')).toMatchObject({
      valid: false,
      code: 'pattern_unsupported',
    });
    expect(
      testCustomPattern({ pattern: 'EMP', caseInsensitive: false }, 'x'.repeat(4097)),
    ).toMatchObject({ valid: false, code: 'sample_too_long' });
  });
});
