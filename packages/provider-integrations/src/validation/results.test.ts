import { describe, expect, it } from 'vitest';
import { HEALTH_CHECKS } from '../health';
import {
  boundEvidence,
  checksForRun,
  summarizeResults,
  validationOutcome,
  validationResultSchema,
  validationResultsSchema,
  VALIDATION_CHECK_CODES,
  type ValidationResult,
} from './results';

const result = (
  code: string,
  status: ValidationResult['status'],
  severity: ValidationResult['severity'] = 'critical',
): ValidationResult => ({
  code,
  subject: '',
  status,
  severity,
  evidence: {},
  remediation: '#x',
});

describe('provider-validation/1', () => {
  it('every validation code has a health-check definition (title, anchor)', () => {
    const codes = new Set(HEALTH_CHECKS.map((c) => c.code));
    for (const code of VALIDATION_CHECK_CODES) expect(codes.has(code), code).toBe(true);
  });

  it('selects the checks per kind and provider', () => {
    expect(checksForRun('credentials', 'google_workspace').map((c) => c.code)).toEqual([
      'credentials.token',
      'permissions.granted',
      'tenant.identity',
    ]);
    expect(checksForRun('inbound', 'google_workspace').map((c) => c.code)).not.toContain(
      'inbound.destination_matches_provider',
    );
    expect(checksForRun('inbound', 'microsoft_365').map((c) => c.code)).toContain(
      'inbound.destination_matches_provider',
    );
    expect(checksForRun('outbound', 'microsoft_365').map((c) => c.code)).toEqual([
      'credentials.token',
      'dns.spf_gateway',
      'dns.dkim_provider',
      'outbound.probe',
    ]);
    expect(checksForRun('full', 'microsoft_365')).toHaveLength(15);
  });

  it('computes the run outcome from required checks', () => {
    const pass = (kind: 'full' | 'outbound', provider: 'microsoft_365' | 'google_workspace') =>
      checksForRun(kind, provider).map((c) => result(c.code, 'pass'));
    const base = {
      kind: 'full' as const,
      provider: 'microsoft_365' as const,
      outboundMode: 'probe_only' as const,
    };
    expect(validationOutcome({ ...base, results: pass('full', 'microsoft_365') })).toBe('passed');
    const withWarn = pass('full', 'microsoft_365').map((r) =>
      r.code === 'dns.dkim_provider' ? { ...r, status: 'fail' as const } : r,
    );
    expect(validationOutcome({ ...base, results: withWarn })).toBe('warning');
    const lockdownWarn = pass('full', 'microsoft_365').map((r) =>
      r.code === 'lockdown.attested' ? { ...r, status: 'warn' as const } : r,
    );
    expect(validationOutcome({ ...base, results: lockdownWarn })).toBe('warning');
    const failed = pass('full', 'microsoft_365').map((r) =>
      r.code === 'inbound.smtp' ? { ...r, status: 'error' as const } : r,
    );
    expect(validationOutcome({ ...base, results: failed })).toBe('failed');
    // Outbound probe is required only when outbound is not off.
    const noProbe = pass('full', 'microsoft_365').filter((r) => r.code !== 'outbound.probe');
    expect(validationOutcome({ ...base, results: noProbe })).toBe('failed');
    expect(validationOutcome({ ...base, outboundMode: 'off', results: noProbe })).toBe('passed');
    const probeFail = pass('full', 'microsoft_365').map((r) =>
      r.code === 'outbound.probe' ? { ...r, status: 'fail' as const } : r,
    );
    expect(validationOutcome({ ...base, outboundMode: 'off', results: probeFail })).toBe('warning');
    // A missing always-required result fails the run.
    expect(validationOutcome({ ...base, results: [] })).toBe('failed');
  });

  it('summarizes and bounds results', () => {
    expect(
      summarizeResults([
        result('a', 'pass'),
        result('b', 'pass'),
        result('c', 'warn'),
        result('d', 'error'),
      ]),
    ).toEqual({
      pass: 2,
      warn: 1,
      fail: 0,
      skipped: 0,
      error: 1,
    });
    expect(validationResultSchema.safeParse(result('credentials.token', 'pass')).success).toBe(
      true,
    );
    expect(
      validationResultSchema.safeParse({ ...result('credentials.token', 'pass'), extra: 1 })
        .success,
    ).toBe(false);
    expect(validationResultSchema.safeParse({ ...result('Bad Code', 'pass') }).success).toBe(false);
    expect(
      validationResultSchema.safeParse({
        ...result('a.b', 'pass'),
        evidence: {
          big: 'x'.repeat(500).repeat(1),
          more: 'y'.repeat(500),
          again: 'z'.repeat(500),
          last: 'w'.repeat(500),
          over: 'v'.repeat(100),
        },
      }).success,
    ).toBe(false);
    expect(
      validationResultsSchema.safeParse(Array.from({ length: 65 }, () => result('a.b', 'pass')))
        .success,
    ).toBe(false);
  });

  it('boundEvidence clips strings, arrays and size', () => {
    const bounded = boundEvidence({
      banner: 'x'.repeat(1000),
      list: Array.from({ length: 50 }, (_, i) => i),
      when: new Date('2026-11-18T00:00:00Z'),
      id: 12n,
      nested: { a: { b: { c: { d: 1 } } } },
      skip: undefined,
    });
    expect((bounded.banner as string).length).toBe(256);
    expect(bounded.list).toHaveLength(10);
    expect(bounded.when).toBe('2026-11-18T00:00:00.000Z');
    expect(bounded.id).toBe('12');
    expect('skip' in bounded).toBe(false);
    const huge = boundEvidence(
      Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`k${i}`, 'y'.repeat(250)])),
    );
    expect(Buffer.byteLength(JSON.stringify(huge))).toBeLessThanOrEqual(2048);
    expect(huge.truncated).toBe(true);
    expect(
      validationResultSchema.safeParse({ ...result('a.b', 'pass'), evidence: huge }).success,
    ).toBe(true);
  });
});
