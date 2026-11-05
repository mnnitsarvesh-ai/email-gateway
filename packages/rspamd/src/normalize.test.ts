import { describe, expect, it } from 'vitest';
import {
  ARC_SYMBOLS,
  DKIM_SYMBOLS,
  DMARC_SYMBOLS,
  MAX_OPTION_LENGTH,
  MAX_SYMBOLS,
  normalizeDomain,
  normalizeReply,
  SPF_SYMBOLS,
} from './normalize';
import { rspamdCheckReplySchema, type RspamdCheckReply } from './reply';

type SymbolInput = { score?: number; options?: string[] };

function reply(
  symbols: Record<string, SymbolInput>,
  extra: Partial<RspamdCheckReply> = {},
): RspamdCheckReply {
  return rspamdCheckReplySchema.parse({
    is_skipped: false,
    score: 1,
    required_score: 15,
    action: 'no action',
    symbols: Object.fromEntries(
      Object.entries(symbols).map(([name, s]) => [
        name,
        { name, score: s.score ?? 0, ...(s.options ? { options: s.options } : {}) },
      ]),
    ),
    ...extra,
  });
}

describe('normalizeReply: authentication extraction (S9 table)', () => {
  it.each(Object.entries(SPF_SYMBOLS))('SPF %s -> %s', (symbol, outcome) => {
    const n = normalizeReply(reply({ [symbol]: { options: ['-all'] } }), {
      envelopeFrom: 'a@Spoof.Scan.Test',
    });
    expect(n.auth.spf).toEqual({ result: outcome, domain: 'spoof.scan.test' });
  });

  it('takes the SPF domain from the HELO name for the null sender', () => {
    const n = normalizeReply(reply({ R_SPF_ALLOW: {} }), {
      envelopeFrom: '',
      helo: 'mx.clean.scan.test',
    });
    expect(n.auth.spf).toEqual({ result: 'pass', domain: 'mx.clean.scan.test' });
    expect(normalizeReply(reply({ R_SPF_ALLOW: {} })).auth.spf).toEqual({
      result: 'pass',
      domain: null,
    });
  });

  it.each(Object.entries(DKIM_SYMBOLS))('DKIM %s -> %s', (symbol, outcome) => {
    expect(normalizeReply(reply({ [symbol]: {} })).auth.dkim.result).toBe(outcome);
  });

  it('prefers a valid DKIM signature over a failed one', () => {
    expect(normalizeReply(reply({ R_DKIM_REJECT: {}, R_DKIM_ALLOW: {} })).auth.dkim.result).toBe(
      'pass',
    );
  });

  it('builds per-signature results from DKIM_TRACE with selectors from the R_DKIM_* options', () => {
    const n = normalizeReply(
      reply({
        R_DKIM_ALLOW: { options: ['clean.scan.test:s=eg2026'] },
        R_DKIM_REJECT: { options: ['other.scan.test:s=sel1'] },
        R_DKIM_TEMPFAIL: { options: ['temp.scan.test:s=t1'] },
        DKIM_TRACE: {
          options: [
            'clean.scan.test:+',
            'other.scan.test:-',
            'temp.scan.test:?',
            'perm.scan.test:~',
            'garbage',
            'x.scan.test:!',
          ],
        },
      }),
    );
    expect(n.auth.dkim).toEqual({
      result: 'pass',
      signatures: [
        { domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' },
        { domain: 'other.scan.test', result: 'fail', selector: 'sel1' },
        { domain: 'temp.scan.test', result: 'temperror', selector: 't1' },
        { domain: 'perm.scan.test', result: 'permerror', selector: null },
      ],
    });
  });

  it('bounds DKIM signatures to 10', () => {
    const options = Array.from({ length: 12 }, (_, i) => `d${i}.scan.test:+`);
    // DKIM_TRACE options are capped at 5 by the symbol bounds; the signature cap applies after.
    const n = normalizeReply(reply({ R_DKIM_ALLOW: {}, DKIM_TRACE: { options } }));
    expect(n.auth.dkim.signatures.length).toBeLessThanOrEqual(10);
  });

  it.each(Object.entries(DMARC_SYMBOLS))('DMARC %s -> %o', (symbol, expected) => {
    const n = normalizeReply(
      reply({ [symbol]: { options: ['spoof.scan.test : No valid SPF, No valid DKIM', 'reject'] } }),
    );
    expect(n.auth.dmarc.result).toBe(expected.result);
    expect(n.auth.dmarc.domain).toBe('spoof.scan.test');
    if (expected.policy !== null) expect(n.auth.dmarc.policy).toBe(expected.policy);
  });

  it('reads the published policy of a DMARC pass from the options', () => {
    const n = normalizeReply(
      reply({ DMARC_POLICY_ALLOW: { options: ['clean.scan.test', 'reject'] } }),
    );
    expect(n.auth.dmarc).toEqual({ result: 'pass', policy: 'reject', domain: 'clean.scan.test' });
  });

  it('uses DMARC_POLICY_ALLOW options for the ALLOW_WITH_FAILURES composite (real 3.12 reply)', () => {
    const n = normalizeReply(
      reply({
        DMARC_POLICY_ALLOW_WITH_FAILURES: { score: -0.5 },
        DMARC_POLICY_ALLOW: { options: ['clean.scan.test', 'reject'] },
        R_DKIM_REJECT: { options: ['clean.scan.test:s=eg2026'] },
        R_SPF_ALLOW: { options: ['+ip4:192.0.2.10:c'] },
        DKIM_TRACE: { options: ['clean.scan.test:-'] },
      }),
      { envelopeFrom: 'alice@clean.scan.test' },
    );
    expect(n.auth).toEqual({
      spf: { result: 'pass', domain: 'clean.scan.test' },
      dkim: {
        result: 'fail',
        signatures: [{ domain: 'clean.scan.test', result: 'fail', selector: 'eg2026' }],
      },
      dmarc: { result: 'pass', policy: 'reject', domain: 'clean.scan.test' },
      arc: { result: null },
    });
  });

  it('keeps a DMARC_NA domain only when the option is a domain', () => {
    expect(
      normalizeReply(reply({ DMARC_NA: { options: ['listed-spam.scan.test'] } })).auth.dmarc,
    ).toEqual({
      result: 'none',
      policy: null,
      domain: 'listed-spam.scan.test',
    });
    expect(
      normalizeReply(reply({ DMARC_NA: { options: ['Duplicate From header'] } })).auth.dmarc.domain,
    ).toBeNull();
  });

  it.each(Object.entries(ARC_SYMBOLS))('ARC %s -> %s', (symbol, outcome) => {
    expect(normalizeReply(reply({ [symbol]: {} })).auth.arc.result).toBe(outcome);
  });

  it('returns nulls when no authentication symbol is present and ignores unknown symbols', () => {
    const n = normalizeReply(reply({ SOME_FUTURE_SYMBOL: { score: 2, options: ['x'] } }));
    expect(n.auth).toEqual({
      spf: { result: null, domain: null },
      dkim: { result: null, signatures: [] },
      dmarc: { result: null, policy: null, domain: null },
      arc: { result: null },
    });
    expect(n.symbols).toEqual([{ name: 'SOME_FUTURE_SYMBOL', score: 2, options: ['x'] }]);
  });
});

describe('normalizeReply: symbols, skip and pre-filter results', () => {
  it('sorts symbols by |score| descending, then name', () => {
    const n = normalizeReply(
      reply({ B: { score: 1 }, A: { score: -1 }, C: { score: 6.5 }, D: { score: 0 } }),
    );
    expect(n.symbols.map((s) => s.name)).toEqual(['C', 'A', 'B', 'D']);
  });

  it('bounds symbols, options per symbol and option length, and strips control characters', () => {
    const many = Object.fromEntries(
      Array.from({ length: MAX_SYMBOLS + 5 }, (_, i) => [
        `S${String(i).padStart(3, '0')}`,
        { score: 1 },
      ]),
    );
    const n = normalizeReply(
      reply({
        ...many,
        ZZ_OPTS: {
          score: 100,
          options: ['a\u0000b\r\nc\u007f', 'x'.repeat(500), '3', '4', '5', '6', '7'],
        },
      }),
    );
    expect(n.symbols).toHaveLength(MAX_SYMBOLS);
    expect(n.symbolsTruncated).toBe(true);
    const opts = n.symbols[0]!;
    expect(opts.name).toBe('ZZ_OPTS');
    expect(opts.options).toHaveLength(5);
    expect(opts.options[0]).toBe('abc');
    expect(opts.options[1]).toHaveLength(MAX_OPTION_LENGTH);
  });

  it('drops symbols whose name is not printable ASCII', () => {
    const n = normalizeReply(reply({ 'BAD NAME': { score: 1 }, GOOD: { score: 1 } }));
    expect(n.symbols.map((s) => s.name)).toEqual(['GOOD']);
  });

  it('treats GTUBE (is_skipped with passthrough_module) as a definite result, not a skip', () => {
    const gtube = rspamdCheckReplySchema.parse({
      passthrough_module: 'GTUBE',
      is_skipped: true,
      score: 15,
      required_score: 15,
      action: 'reject',
      thresholds: { reject: 15, 'add header': 6 },
      symbols: { GTUBE: { name: 'GTUBE', score: 0, metric_score: 0 } },
      messages: { smtp_message: 'Gtube pattern' },
      'message-id': 'x@b.test',
      time_real: 0.01,
    });
    const n = normalizeReply(gtube);
    expect(n).toMatchObject({
      skipped: false,
      passthroughModule: 'GTUBE',
      action: 'reject',
      score: 15,
      requiredScore: 15,
    });
    expect(n.symbols.map((s) => s.name)).toEqual(['GTUBE']);
  });

  it('reports a real skip', () => {
    const n = normalizeReply(reply({}, { is_skipped: true }));
    expect(n.skipped).toBe(true);
    expect(n.passthroughModule).toBeNull();
    expect(n.symbols).toEqual([]);
  });
});

describe('normalizeDomain', () => {
  it('lower-cases, strips the root dot and converts IDNs to A-labels', () => {
    expect(normalizeDomain('Clean.Scan.Test.')).toBe('clean.scan.test');
    expect(normalizeDomain('bücher.scan.test')).toBe('xn--bcher-kva.scan.test');
  });

  it('refuses non-domains', () => {
    for (const v of [
      null,
      undefined,
      '',
      'localhost',
      'a b.test',
      'x'.repeat(254) + '.test',
      '-a.test.',
    ]) {
      expect(normalizeDomain(v)).toBeNull();
    }
  });
});
