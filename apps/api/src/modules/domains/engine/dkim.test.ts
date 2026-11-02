import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { indeterminate, negative, txtAnswer } from '../../../../test/support/dns/dns-results';
import {
  dkimTxtValue,
  evaluateDkim,
  generateDkimKeyPair,
  generateDkimSelector,
  parseDkimRecord,
} from './dkim';

const host = 'egr20261102abcd._domainkey.acme.test';

/** Rebuilds a verification key from the DNS `p=` value only, as a DKIM verifier does. */
function publicKeyFromDns(algorithm: 'rsa_2048' | 'ed25519', publicKeyDns: string) {
  const der = Buffer.from(publicKeyDns, 'base64');
  const spki =
    algorithm === 'rsa_2048'
      ? der
      : Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), der]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

describe('generateDkimKeyPair', () => {
  it('generates RSA 2048 / e=65537 with an SPKI DER public key, and signs verifiably', async () => {
    const pair = await generateDkimKeyPair('rsa_2048');
    expect(pair.algorithm).toBe('rsa_2048');
    expect(pair.privateKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/);
    const publicKey = publicKeyFromDns('rsa_2048', pair.publicKeyDns);
    const details = publicKey.asymmetricKeyDetails!;
    expect(publicKey.asymmetricKeyType).toBe('rsa');
    expect(details.modulusLength).toBe(2048);
    expect(details.publicExponent).toBe(65537n);

    const data = Buffer.from('dkim-signature header hash input');
    const signature = sign('sha256', data, createPrivateKey(pair.privateKeyPem));
    expect(verify('sha256', data, publicKey, signature)).toBe(true);
    expect(verify('sha256', Buffer.from('tampered'), publicKey, signature)).toBe(false);
  });

  it('generates Ed25519 with the raw 32-byte public key (RFC 8463), and signs verifiably', async () => {
    const pair = await generateDkimKeyPair('ed25519');
    expect(Buffer.from(pair.publicKeyDns, 'base64')).toHaveLength(32);
    expect(createPrivateKey(pair.privateKeyPem).asymmetricKeyType).toBe('ed25519');
    const publicKey = publicKeyFromDns('ed25519', pair.publicKeyDns);
    const data = Buffer.from('dkim-signature header hash input');
    const signature = sign(null, data, createPrivateKey(pair.privateKeyPem));
    expect(verify(null, data, publicKey, signature)).toBe(true);
  });

  it('generates a new key every time', async () => {
    const [a, b] = await Promise.all([
      generateDkimKeyPair('ed25519'),
      generateDkimKeyPair('ed25519'),
    ]);
    expect(a.publicKeyDns).not.toBe(b.publicKeyDns);
  });
});

describe('dkimTxtValue / generateDkimSelector', () => {
  it('formats the record per algorithm', () => {
    expect(dkimTxtValue('rsa_2048', 'MIIB')).toBe('v=DKIM1; k=rsa; p=MIIB');
    expect(dkimTxtValue('ed25519', 'abc=')).toBe('v=DKIM1; k=ed25519; p=abc=');
  });

  it('builds eg<r|e><yyyymmdd><4 [a-z0-9]> from the UTC date', () => {
    const now = new Date('2026-11-02T23:30:00Z');
    expect(generateDkimSelector('rsa_2048', now)).toMatch(/^egr20261102[a-z0-9]{4}$/);
    expect(generateDkimSelector('ed25519', now)).toMatch(/^ege20261102[a-z0-9]{4}$/);
    const many = new Set(Array.from({ length: 50 }, () => generateDkimSelector('rsa_2048', now)));
    expect(many.size).toBeGreaterThan(40);
  });
});

describe('parseDkimRecord', () => {
  it('parses tags, removes whitespace from p and defaults k to rsa', () => {
    const parsed = parseDkimRecord('v=DKIM1; t=y:s; p=MIIB AAAA\tBBBB==');
    expect(parsed).toMatchObject({
      keyType: 'rsa',
      publicKey: 'MIIBAAAABBBB==',
      testing: true,
      errors: [],
    });
  });

  it('flags missing p, misplaced v and bad base64', () => {
    expect(parseDkimRecord('v=DKIM1; k=rsa').errors).toContain('p');
    expect(parseDkimRecord('k=rsa; v=DKIM1; p=AAAA').errors).toContain('v');
    expect(parseDkimRecord('v=DKIM1; p=not*base64').errors).toContain('p');
    expect(parseDkimRecord('p=').publicKey).toBe('');
  });
});

describe('evaluateDkim', () => {
  const expected = { algorithm: 'rsa_2048' as const, publicKeyDns: 'MIIBexpectedKey' };

  it('is valid when p and k match (whitespace in p ignored)', () => {
    const result = evaluateDkim(txtAnswer(host, ['v=DKIM1; k=rsa; p=MIIB expected Key']), expected);
    expect(result).toEqual({
      outcome: 'valid',
      observedValue: 'v=DKIM1; k=rsa; p=MIIB expected Key',
      warnings: [],
    });
    expect(evaluateDkim(txtAnswer(host, ['p=MIIBexpectedKey']), expected).outcome).toBe('valid');
  });

  it('warns in testing mode', () => {
    expect(
      evaluateDkim(txtAnswer(host, ['v=DKIM1; t=y; p=MIIBexpectedKey']), expected),
    ).toMatchObject({
      outcome: 'valid',
      warnings: ['dkim_testing_mode'],
    });
  });

  it('is invalid for another key, another algorithm or an unparsable record', () => {
    for (const record of [
      'v=DKIM1; k=rsa; p=MIIBother',
      'v=DKIM1; k=ed25519; p=MIIBexpectedKey',
      'garbage',
    ]) {
      expect(evaluateDkim(txtAnswer(host, [record]), expected)).toMatchObject({
        outcome: 'invalid',
        warnings: ['dkim_public_key_mismatch'],
      });
    }
  });

  it('is invalid when the key is revoked in DNS (empty p)', () => {
    expect(evaluateDkim(txtAnswer(host, ['v=DKIM1; p=']), expected)).toMatchObject({
      outcome: 'invalid',
      warnings: ['dkim_key_revoked_in_dns'],
    });
  });

  it('is missing for NXDOMAIN/NODATA and indeterminate stays indeterminate', () => {
    expect(evaluateDkim(negative(host), expected).outcome).toBe('missing');
    expect(evaluateDkim(negative(host, 'nodata'), expected).outcome).toBe('missing');
    expect(evaluateDkim(indeterminate(host, 'timeout'), expected).outcome).toBe('indeterminate');
  });
});
