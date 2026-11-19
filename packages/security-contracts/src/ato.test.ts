import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  ATO_ACCOUNT_KINDS,
  ATO_ACCOUNT_SUBJECT_KIND,
  ATO_POLICY_FACTS_VERSION,
  ATO_RISK_LEVELS,
  ATO_SUBJECT_KINDS,
  atoMailboxSha256,
  atoRiskLevelRank,
  atoRiskLevelSchema,
  atoSubjectHash,
  normalizeAtoMailboxAddress,
} from './index';

const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

describe('ATO vocabulary (step 8.4 D1, D23, §3.3)', () => {
  it('orders the four risk levels of the brief', () => {
    expect([...ATO_RISK_LEVELS]).toEqual(['low', 'medium', 'high', 'critical']);
    expect(ATO_RISK_LEVELS.map(atoRiskLevelRank)).toEqual([0, 1, 2, 3]);
    expect(atoRiskLevelSchema.safeParse('high').success).toBe(true);
    expect(atoRiskLevelSchema.safeParse('none').success).toBe(false);
  });

  it('names the three account kinds and their subject-key prefixes', () => {
    expect([...ATO_ACCOUNT_KINDS]).toEqual(['mailbox', 'gateway_user', 'smtp_connector']);
    expect([...ATO_SUBJECT_KINDS]).toEqual(['mailbox', 'user', 'connector']);
    expect(ATO_ACCOUNT_SUBJECT_KIND).toEqual({
      mailbox: 'mailbox',
      gateway_user: 'user',
      smtp_connector: 'connector',
    });
    expect(Object.isFrozen(ATO_ACCOUNT_SUBJECT_KIND)).toBe(true);
  });

  it('versions the policy facts block', () => {
    expect(ATO_POLICY_FACTS_VERSION).toBe('ato-policy-facts/1');
  });
});

describe('atoSubjectHash (D1)', () => {
  it('is the hex SHA-256 of <kind>:<subject>', () => {
    expect(atoSubjectHash('mailbox', 'finance@acme.example')).toBe(
      sha256('mailbox:finance@acme.example'),
    );
    expect(atoSubjectHash('user', '42')).toBe(sha256('user:42'));
    expect(atoSubjectHash('connector', 7n)).toBe(sha256('connector:7'));
    expect(atoSubjectHash('connector', '7')).toBe(atoSubjectHash('connector', 7n));
    expect(atoSubjectHash('user', '18446744073709551615')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('lower-cases the full mailbox address and keeps sub-addresses distinct', () => {
    expect(atoSubjectHash('mailbox', 'Finance@ACME.Example')).toBe(
      atoSubjectHash('mailbox', 'finance@acme.example'),
    );
    expect(atoSubjectHash('mailbox', 'a+x@acme.example')).not.toBe(
      atoSubjectHash('mailbox', 'a@acme.example'),
    );
  });

  it('keeps kinds apart for the same subject string', () => {
    expect(atoSubjectHash('user', '7')).not.toBe(atoSubjectHash('connector', '7'));
  });

  it('refuses malformed subjects and unknown kinds', () => {
    for (const bad of ['', 'no-at', '@acme.example', 'a@', 'a@@b', 'a b@acme.example', 'a\n@b']) {
      expect(() => atoSubjectHash('mailbox', bad), JSON.stringify(bad)).toThrow(
        'Invalid mailbox address',
      );
    }
    expect(() => atoSubjectHash('mailbox', `${'a'.repeat(310)}@acme.example`)).toThrow(
      'Invalid mailbox address',
    );
    expect(() => atoSubjectHash('mailbox', 5n)).toThrow('A mailbox subject is an address');
    for (const bad of ['0', '07', '-1', '1.5', 'x', '', '123456789012345678901']) {
      expect(() => atoSubjectHash('user', bad), bad).toThrow('decimal id');
    }
    expect(() => atoSubjectHash('connector', 0n)).toThrow('decimal id');
    expect(() => atoSubjectHash('tenant' as never, '1')).toThrow('Unknown ATO subject kind');
  });
});

describe('atoMailboxSha256 (D14)', () => {
  it('is the hex SHA-256 of the lower-cased address, distinct from the subject hash', () => {
    expect(atoMailboxSha256('Finance@Acme.Example')).toBe(sha256('finance@acme.example'));
    expect(atoMailboxSha256('finance@acme.example')).not.toBe(
      atoSubjectHash('mailbox', 'finance@acme.example'),
    );
    expect(() => atoMailboxSha256('not an address')).toThrow('Invalid mailbox address');
  });

  it('normalizes without stripping anything but case', () => {
    expect(normalizeAtoMailboxAddress('A.B+Tag@Sub.Example')).toBe('a.b+tag@sub.example');
  });
});
