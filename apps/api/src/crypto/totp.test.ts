import { describe, expect, it } from 'vitest';
import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  hotp,
  otpauthUri,
  totpCode,
  totpStep,
  verifyTotp,
} from './totp';

/** RFC 6238 Appendix B, SHA-1: ASCII "12345678901234567890". */
const RFC_KEY = Buffer.from('12345678901234567890', 'ascii');
const RFC_SECRET = base32Encode(RFC_KEY);
const RFC_VECTORS: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

describe('RFC 6238 Appendix B (SHA-1)', () => {
  it.each(RFC_VECTORS)('T=%i → %s (8 digits)', (seconds, expected) => {
    expect(hotp(RFC_KEY, Math.floor(seconds / 30), 8)).toBe(expected);
  });

  it.each(RFC_VECTORS)(
    'T=%i → last 6 digits with the production code length',
    (seconds, expected) => {
      const step = totpStep(seconds * 1000);
      expect(totpCode(RFC_SECRET, step)).toBe(expected.slice(-6));
      expect(verifyTotp(RFC_SECRET, expected.slice(-6), { now: seconds * 1000 })).toEqual({
        ok: true,
        step,
      });
    },
  );
});

describe('base32', () => {
  it('matches RFC 4648 vectors (without padding)', () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'MY'],
      ['fo', 'MZXQ'],
      ['foo', 'MZXW6'],
      ['foob', 'MZXW6YQ'],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI'],
    ];
    for (const [plain, encoded] of vectors) {
      expect(base32Encode(Buffer.from(plain))).toBe(encoded);
      expect(base32Decode(encoded).toString()).toBe(plain);
    }
  });

  it('decodes lower-case, spaced and padded input', () => {
    expect(base32Decode('mzxw 6ytb oi======').toString()).toBe('foobar');
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base32Decode('MZXW1')).toThrow();
  });

  it('generates 160-bit secrets', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Decode(secret)).toHaveLength(20);
    expect(generateTotpSecret()).not.toBe(secret);
  });
});

describe('verifyTotp', () => {
  const secret = generateTotpSecret();
  const now = 1_800_000_000_000;
  const step = totpStep(now);

  it('accepts the current code and ±1 step of drift', () => {
    for (const s of [step - 1, step, step + 1]) {
      expect(verifyTotp(secret, totpCode(secret, s), { now })).toEqual({ ok: true, step: s });
    }
  });

  it('rejects codes outside the window', () => {
    expect(verifyTotp(secret, totpCode(secret, step - 2), { now }).ok).toBe(false);
    expect(verifyTotp(secret, totpCode(secret, step + 2), { now }).ok).toBe(false);
    expect(verifyTotp(secret, totpCode(secret, step - 2), { now, window: 2 }).ok).toBe(true);
  });

  it('rejects a replayed code (step not after the last used one)', () => {
    const code = totpCode(secret, step);
    const first = verifyTotp(secret, code, { now });
    expect(first).toEqual({ ok: true, step });
    expect(verifyTotp(secret, code, { now, afterStep: step }).ok).toBe(false);
    expect(verifyTotp(secret, code, { now: now + 30_000, afterStep: BigInt(step) }).ok).toBe(false);
    // An older code inside the window is also refused once a newer step was used.
    expect(verifyTotp(secret, totpCode(secret, step - 1), { now, afterStep: step }).ok).toBe(false);
    expect(verifyTotp(secret, totpCode(secret, step + 1), { now, afterStep: step })).toEqual({
      ok: true,
      step: step + 1,
    });
  });

  it.each(['', '12345', '1234567', 'abcdef', '12 345'])('rejects malformed code %j', (code) => {
    expect(verifyTotp(secret, code, { now }).ok).toBe(false);
  });

  it('rejects a code of another secret', () => {
    expect(verifyTotp(generateTotpSecret(), totpCode(secret, step), { now }).ok).toBe(false);
  });
});

describe('otpauthUri', () => {
  it('follows the Key Uri Format', () => {
    const uri = otpauthUri({
      issuer: 'Email Gateway',
      account: 'alice@example.com',
      secret: 'JBSWY3DPEHPK3PXP',
    });
    expect(uri).toBe(
      'otpauth://totp/Email%20Gateway:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Email%20Gateway&algorithm=SHA1&digits=6&period=30',
    );
  });
});
