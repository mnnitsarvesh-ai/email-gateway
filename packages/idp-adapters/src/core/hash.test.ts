import { describe, expect, it } from 'vitest';
import {
  appIdHash,
  deviceIdHash,
  directoryRefHash,
  domainOf,
  identityHash,
  mailboxItemHash,
  sha256Hex,
} from './hash';

describe('hashes (D4, D8, §3)', () => {
  it('are deterministic lower-case hex SHA-256 values over |-joined parts', () => {
    expect(sha256Hex('a')).toMatch(/^[0-9a-f]{64}$/);
    expect(identityHash('microsoft_entra', 'x')).toBe(sha256Hex('microsoft_entra|x'));
    expect(mailboxItemHash('microsoft_entra', 'u', 'inbox_rule', 'r1')).toBe(
      sha256Hex('microsoft_entra|u|inbox_rule|r1'),
    );
    expect(mailboxItemHash('microsoft_entra', 'u', 'inbox_rule', 'r1')).not.toBe(
      mailboxItemHash('microsoft_entra', 'u', 'delegate', 'r1'),
    );
  });

  it('normalizes directory and application ids', () => {
    expect(directoryRefHash('microsoft_entra', ' ABC ')).toBe(
      directoryRefHash('microsoft_entra', 'abc'),
    );
    expect(directoryRefHash('microsoft_entra', 'abc')).not.toBe(
      directoryRefHash('google_workspace', 'abc'),
    );
    expect(appIdHash('ABC-1')).toBe(sha256Hex('abc-1'));
  });

  it('shortens device ids to 16 hex', () => {
    expect(deviceIdHash('EXAMPLE-device-0001')).toMatch(/^[0-9a-f]{16}$/);
  });

  it('extracts lower-cased domains of addresses only', () => {
    expect(domainOf('Alex@Contoso-IT.example')).toBe('contoso-it.example');
    expect(domainOf('smtp:a@b.example')).toBe('b.example');
    expect(domainOf('<a@b.example>')).toBe('b.example');
    expect(domainOf('no-address')).toBeNull();
    expect(domainOf('a@localhost')).toBeNull();
    expect(domainOf(null)).toBeNull();
  });
});
