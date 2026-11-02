import { describe, expect, it } from 'vitest';
import { indeterminate, negative, txtAnswer } from '../../../../test/support/dns/dns-results';
import {
  evaluateVerification,
  generateVerificationToken,
  normalizeTxtValue,
  verificationRecord,
} from './verification';

const host = '_emailgateway-verify.acme.test';
const token = 'a'.repeat(40);
const expected = `emailgateway-verification=${token}`;

describe('verification', () => {
  it('generates 40 lower-case hex characters, different each time', () => {
    const a = generateVerificationToken();
    expect(a).toMatch(/^[0-9a-f]{40}$/);
    expect(generateVerificationToken()).not.toBe(a);
  });

  it('builds the record at <label>.<domain>', () => {
    expect(verificationRecord('acme.test', token, '_emailgateway-verify')).toEqual({
      host,
      value: expected,
    });
  });

  it('is valid when any TXT string equals the expected value (other tenants may publish too)', () => {
    const result = evaluateVerification(
      txtAnswer(host, [`emailgateway-verification=${'b'.repeat(40)}`, expected]),
      expected,
    );
    expect(result.outcome).toBe('valid');
    expect(result.observedValue).toContain(expected);
  });

  it('ignores surrounding whitespace and quotes but nothing else', () => {
    expect(evaluateVerification(txtAnswer(host, [` "${expected}" `]), expected).outcome).toBe(
      'valid',
    );
    expect(evaluateVerification(txtAnswer(host, [`${expected}x`]), expected).outcome).toBe(
      'invalid',
    );
    expect(evaluateVerification(txtAnswer(host, [expected.toUpperCase()]), expected).outcome).toBe(
      'invalid',
    );
    expect(normalizeTxtValue('"x"')).toBe('x');
    expect(normalizeTxtValue('"')).toBe('"');
  });

  it('maps NXDOMAIN and NODATA to missing', () => {
    expect(evaluateVerification(negative(host, 'nxdomain'), expected)).toEqual({
      outcome: 'missing',
      observedValue: null,
    });
    expect(evaluateVerification(negative(host, 'nodata'), expected).outcome).toBe('missing');
  });

  it.each(['timeout', 'servfail', 'refused', 'network', 'malformed', 'other'] as const)(
    'never turns an indeterminate (%s) lookup into a definitive outcome',
    (reason) => {
      expect(evaluateVerification(indeterminate(host, reason), expected).outcome).toBe(
        'indeterminate',
      );
    },
  );
});
