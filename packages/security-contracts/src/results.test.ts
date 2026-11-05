import { describe, expect, it } from 'vitest';
import {
  AUTH_OUTCOMES,
  type AuthResults,
  authResultsSchema,
  DMARC_POLICIES,
  type NormalizedEngineResult,
  normalizedEngineResultSchema,
} from './index';

const auth: AuthResults = {
  spf: { result: 'pass', domain: 'clean.scan.test' },
  dkim: {
    result: 'pass',
    signatures: [{ domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' }],
  },
  dmarc: { result: 'pass', policy: 'reject', domain: 'clean.scan.test' },
  arc: { result: null },
};

const result: NormalizedEngineResult = {
  engine: 'rspamd',
  engineVersion: '3.12.1',
  outcome: 'clean',
  score: -0.5,
  requiredScore: 15,
  action: 'no action',
  reasonCodes: ['clean.below_threshold'],
  signals: [
    { name: 'R_SPF_ALLOW', score: -0.2, options: ['+ip4:192.0.2.10'] },
    { name: 'DKIM_TRACE', score: 0, options: ['clean.scan.test:+'] },
  ],
  auth,
  durationMs: 41,
  settingsVersion: 'rspamd-map/1;p=0123456789ab;t=none',
  mappingVersion: 'rspamd-map/1',
};

describe('authResultsSchema (S9)', () => {
  it('has the RFC 8601 outcomes and the three DMARC policies', () => {
    expect([...AUTH_OUTCOMES]).toEqual([
      'pass',
      'fail',
      'softfail',
      'neutral',
      'none',
      'temperror',
      'permerror',
    ]);
    expect([...DMARC_POLICIES]).toEqual(['none', 'quarantine', 'reject']);
  });

  it('accepts a full and an all-unknown result', () => {
    expect(authResultsSchema.parse(auth)).toEqual(auth);
    const empty = {
      spf: { result: null, domain: null },
      dkim: { result: null, signatures: [] },
      dmarc: { result: null, policy: null, domain: null },
      arc: { result: null },
    };
    expect(authResultsSchema.safeParse(empty).success).toBe(true);
  });

  it('refuses unknown outcomes, upper-case or overlong domains, more than 10 signatures and extra keys', () => {
    const bad = (patch: (a: AuthResults) => unknown) =>
      authResultsSchema.safeParse(patch(structuredClone(auth))).success;
    expect(bad((a) => ({ ...a, spf: { result: 'ok', domain: null } }))).toBe(false);
    expect(bad((a) => ({ ...a, spf: { result: 'pass', domain: 'Clean.Scan.Test' } }))).toBe(false);
    expect(bad((a) => ({ ...a, spf: { result: 'pass', domain: `${'a'.repeat(250)}.test` } }))).toBe(
      false,
    );
    expect(
      bad((a) => ({
        ...a,
        dkim: {
          result: 'pass',
          signatures: Array.from({ length: 11 }, () => a.dkim.signatures[0]),
        },
      })),
    ).toBe(false);
    expect(bad((a) => ({ ...a, bimi: { result: 'pass' } }))).toBe(false);
    expect(bad((a) => ({ ...a, dmarc: { ...a.dmarc, policy: 'block' } }))).toBe(false);
  });
});

describe('normalizedEngineResultSchema (S9)', () => {
  it('accepts a complete result with and without auth', () => {
    expect(normalizedEngineResultSchema.parse(result)).toEqual(result);
    const { auth: _auth, ...withoutAuth } = result;
    expect(normalizedEngineResultSchema.safeParse(withoutAuth).success).toBe(true);
  });

  it('never carries a failure or skipped as a result outcome (invariant 1)', () => {
    for (const outcome of ['timeout', 'error', 'skipped']) {
      expect(normalizedEngineResultSchema.safeParse({ ...result, outcome }).success, outcome).toBe(
        false,
      );
    }
    for (const outcome of ['clean', 'spam', 'suspicious', 'malicious', 'unknown']) {
      expect(normalizedEngineResultSchema.safeParse({ ...result, outcome }).success, outcome).toBe(
        true,
      );
    }
  });

  it('bounds signals, options and reason codes and refuses control characters', () => {
    const signal = { name: 'X', score: 1, options: [] };
    expect(
      normalizedEngineResultSchema.safeParse({
        ...result,
        signals: Array.from({ length: 201 }, () => signal),
      }).success,
    ).toBe(false);
    expect(
      normalizedEngineResultSchema.safeParse({
        ...result,
        signals: [{ ...signal, options: ['a', 'b', 'c', 'd', 'e', 'f'] }],
      }).success,
    ).toBe(false);
    expect(
      normalizedEngineResultSchema.safeParse({
        ...result,
        signals: [{ ...signal, options: ['x'.repeat(201)] }],
      }).success,
    ).toBe(false);
    expect(
      normalizedEngineResultSchema.safeParse({
        ...result,
        signals: [{ ...signal, options: ['line\r\nInjected: 1'] }],
      }).success,
    ).toBe(false);
    expect(
      normalizedEngineResultSchema.safeParse({ ...result, signals: [{ ...signal, name: 'A B' }] })
        .success,
    ).toBe(false);
    expect(
      normalizedEngineResultSchema.safeParse({ ...result, reasonCodes: ['NotACode'] }).success,
    ).toBe(false);
    expect(
      normalizedEngineResultSchema.safeParse({ ...result, engine: 'spamassassin' }).success,
    ).toBe(false);
    expect(normalizedEngineResultSchema.safeParse({ ...result, durationMs: -1 }).success).toBe(
      false,
    );
    expect(normalizedEngineResultSchema.safeParse({ ...result, score: Number.NaN }).success).toBe(
      false,
    );
    expect(normalizedEngineResultSchema.safeParse({ ...result, extra: 1 }).success).toBe(false);
  });
});
