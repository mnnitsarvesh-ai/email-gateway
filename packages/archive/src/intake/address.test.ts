import { describe, expect, it } from 'vitest';
import {
  base32Lower,
  deriveIntakeAddressToken,
  deriveIntakeHeaderToken,
  intakeAddress,
  intakeAddressHash,
  intakeHeaderTokenHash,
  IntakeAddressError,
  intakeLocalPart,
  maskIntakeAddress,
  maskIntakeHeaderToken,
  parseIntakeAddressSecret,
  parseIntakeLocalPart,
  sha256HexEqual,
} from './address';

// A synthetic key (32 bytes of 0x07); never a real secret.
const KEY = Buffer.alloc(32, 7);
const SOURCE = '11111111-2222-3333-4444-555555555555';

describe('base32 (RFC 4648 §10 vectors, lower-case, no padding)', () => {
  it.each([
    ['', ''],
    ['f', 'my'],
    ['fo', 'mzxq'],
    ['foo', 'mzxw6'],
    ['foob', 'mzxw6yq'],
    ['fooba', 'mzxw6ytb'],
    ['foobar', 'mzxw6ytboi'],
  ])('%j → %s', (input, expected) => {
    expect(base32Lower(Buffer.from(input))).toBe(expected);
  });
});

describe('intake address and header tokens (D1)', () => {
  it('derives the documented vectors (computed independently)', () => {
    expect(deriveIntakeAddressToken(KEY, SOURCE, 1)).toBe('o24pprcjhsfn6ligyvusv5yz7r');
    expect(deriveIntakeAddressToken(KEY, SOURCE, 2)).toBe('oiqlhgkv4gxevxbq2jxfluox3u');
    expect(deriveIntakeHeaderToken(KEY, SOURCE, 1)).toBe('y4tzc2c2n43uhmrtmf6mvu7tsh');
    expect(intakeAddressHash('journal-o24pprcjhsfn6ligyvusv5yz7r')).toBe(
      'de6fd0e1a5591e30afd03b549a0a32691ff9bb288b59b9d424bb69fd0fa2a4cd',
    );
    // The hash is of the lower-cased local part.
    expect(intakeAddressHash('JOURNAL-O24PPRCJHSFN6LIGYVUSV5YZ7R')).toBe(
      intakeAddressHash('journal-o24pprcjhsfn6ligyvusv5yz7r'),
    );
  });

  it('separates address and header tokens, versions and sources', () => {
    const a = deriveIntakeAddressToken(KEY, SOURCE, 1);
    expect(a).toMatch(/^[a-z2-7]{26}$/);
    expect(deriveIntakeHeaderToken(KEY, SOURCE, 1)).not.toBe(a);
    expect(deriveIntakeAddressToken(KEY, SOURCE, 2)).not.toBe(a);
    expect(deriveIntakeAddressToken(KEY, '11111111-2222-3333-4444-555555555556', 1)).not.toBe(a);
    expect(deriveIntakeAddressToken(Buffer.alloc(32, 8), SOURCE, 1)).not.toBe(a);
  });

  it('refuses short keys, malformed ids and versions without echoing them', () => {
    expect(() => deriveIntakeAddressToken(Buffer.alloc(16, 1), SOURCE, 1)).toThrow(
      IntakeAddressError,
    );
    expect(() => deriveIntakeAddressToken(KEY, 'not-a-uuid', 1)).toThrow('source id');
    expect(() => deriveIntakeAddressToken(KEY, SOURCE, 0)).toThrow('address version');
    expect(() => deriveIntakeAddressToken(KEY, SOURCE, 65_536)).toThrow('address version');
  });

  it('parses the configuration key as hex of at least 32 bytes', () => {
    expect(parseIntakeAddressSecret('07'.repeat(32))).toEqual(KEY);
    for (const bad of ['', '07'.repeat(31), 'zz'.repeat(32), '7'.repeat(65)]) {
      expect(() => parseIntakeAddressSecret(bad)).toThrow('JOURNAL_INTAKE_ADDRESS_SECRET');
    }
  });

  it('builds, parses and masks addresses', () => {
    const token = deriveIntakeAddressToken(KEY, SOURCE, 1);
    const address = intakeAddress(token, 'Journal.Gateway.Test.');
    expect(address).toBe(`journal-${token}@journal.gateway.test`);
    expect(intakeLocalPart(token)).toBe(`journal-${token}`);
    expect(parseIntakeLocalPart(`JOURNAL-${token.toUpperCase()}`)).toBe(token);
    for (const bad of [
      'journal-',
      `journal-${token}x`,
      `journal-${token.slice(1)}`,
      'postmaster',
      `journal-${token.slice(0, 25)}1`,
    ]) {
      expect(parseIntakeLocalPart(bad)).toBeNull();
    }
    expect(maskIntakeAddress(address)).toBe(`journal-••••${token.slice(-4)}@journal.gateway.test`);
    expect(maskIntakeAddress(address)).not.toContain(token);
    expect(maskIntakeAddress('someone@example.com')).toBe('••••');
    expect(maskIntakeHeaderToken(token)).toBe(`••••${token.slice(-4)}`);
    expect(maskIntakeHeaderToken('short')).toBe('••••');
    expect(() => intakeAddress('UPPER', 'journal.gateway.test')).toThrow(IntakeAddressError);
    expect(() => intakeAddress(token, 'bad domain')).toThrow('domain');
  });

  it('hashes header tokens and compares digests in constant time', () => {
    const token = deriveIntakeHeaderToken(KEY, SOURCE, 1);
    expect(intakeHeaderTokenHash(token)).toBe(
      'ff571d50b6505042f3730a8b9b2d66faaf03e1ff00617516462290f703ec0ca3',
    );
    expect(intakeHeaderTokenHash(` ${token.toUpperCase()} `)).toBe(intakeHeaderTokenHash(token));
    const h = intakeHeaderTokenHash(token);
    expect(sha256HexEqual(h, h)).toBe(true);
    expect(sha256HexEqual(h, intakeHeaderTokenHash('x'))).toBe(false);
    expect(sha256HexEqual(h, 'not-hex')).toBe(false);
  });
});
