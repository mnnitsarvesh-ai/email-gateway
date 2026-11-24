import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  classifyRecipient,
  normalizeRecipient,
  recipientDomainOf,
  recipientKindText,
  recipientSha256,
  type RecipientDirectory,
} from './recipients';

const MEMBERS = new Set(['bob.member@alpha.example.test', 'carol@other-org.example.test']);
const directory = (patch: Partial<RecipientDirectory> = {}): RecipientDirectory => ({
  selfEmail: 'Ada.Admin@Alpha.Example.Test',
  isActiveMember: (address) => MEMBERS.has(address.toLowerCase()),
  verifiedDomains: new Set(['alpha.example.test', 'Beta.Example.Test']),
  ...patch,
});

describe('normalizeRecipient (design D5 step 2)', () => {
  it.each([
    ['ada@example.test', 'ada@example.test'],
    ['  Ada.Admin@EXAMPLE.Test  ', 'Ada.Admin@example.test'],
    ["o'brien+reports@sub.example.test", "o'brien+reports@sub.example.test"],
    ['a@xn--bcher-kva.example', 'a@xn--bcher-kva.example'],
  ])('%s → %s', (input, expected) => {
    expect(normalizeRecipient(input)).toBe(expected);
  });

  it.each([
    [''],
    ['   '],
    ['ada'],
    ['@example.test'],
    ['ada@'],
    ['ada@@example.test'],
    ['a@b@example.test'],
    ['Ada <ada@example.test>'],
    ['<ada@example.test>'],
    ['"ada"@example.test'],
    ['ada@example.test, bob@example.test'],
    ['ada@example.test;bob@example.test'],
    ['ada@example.test\r\nBcc: x@example.test'],
    ['ada@exam\nple.test'],
    ['ada @example.test'],
    ['ada@localhost'],
    ['ada@[127.0.0.1]'],
    ['ada@127.0.0.1'],
    ['ada@-example.test'],
    ['ada@example..test'],
    ['.ada@example.test'],
    ['ada.@example.test'],
    ['ädä@example.test'],
    ['ada@bücher.example'],
    [`${'a'.repeat(65)}@example.test`],
    [`a@${'b'.repeat(250)}.test`],
  ])('refuses %j', (input) => {
    expect(normalizeRecipient(input)).toBeNull();
  });

  it('refuses non-strings and > 254 characters', () => {
    expect(normalizeRecipient(undefined)).toBeNull();
    expect(normalizeRecipient(42)).toBeNull();
    expect(normalizeRecipient(['a@example.test'])).toBeNull();
    const long = `${'a'.repeat(64)}@${'b'.repeat(62)}.${'c'.repeat(62)}.${'d'.repeat(62)}.test`;
    expect(long.length).toBeGreaterThan(254);
    expect(normalizeRecipient(long)).toBeNull();
  });
});

describe('classifyRecipient (design D5 step 2, I17)', () => {
  it.each([
    ['ada.admin@alpha.example.test', 'self'],
    ['ADA.ADMIN@ALPHA.EXAMPLE.TEST', 'self'],
    ['bob.member@alpha.example.test', 'member'],
    ['Bob.Member@Alpha.Example.Test', 'member'],
    // A member of the organization whose address is outside its domains is still a member.
    ['carol@other-org.example.test', 'member'],
    ['someone@alpha.example.test', 'domain'],
    ['someone@BETA.example.test', 'domain'],
  ])('%s → %s', (address, kind) => {
    expect(classifyRecipient(address, directory())).toBe(kind);
  });

  it.each([
    ['someone@sub.alpha.example.test'], // no subdomain match
    ['someone@example.test'], // no parent-domain match
    ['someone@alpha.example.test.evil.test'],
    ['someone@outside.test'],
    ['Ada <ada.admin@alpha.example.test>'],
    ['ada.admin@alpha.example.test, x@outside.test'],
    ['ädä@alpha.example.test'],
  ])('refuses %s', (address) => {
    expect(classifyRecipient(address, directory())).toBeNull();
  });

  it('checks in the order self, member, domain', () => {
    const calls: string[] = [];
    const dir = directory({
      isActiveMember: (a) => {
        calls.push(a);
        return true;
      },
    });
    expect(classifyRecipient('ada.admin@alpha.example.test', dir)).toBe('self');
    expect(calls).toEqual([]);
    expect(classifyRecipient('someone@alpha.example.test', dir)).toBe('member');
    expect(calls).toEqual(['someone@alpha.example.test']);
  });

  it('works without an own address and with no verified domains', () => {
    const dir = directory({ selfEmail: null, verifiedDomains: new Set() });
    expect(classifyRecipient('ada.admin@alpha.example.test', dir)).toBeNull();
    expect(classifyRecipient('bob.member@alpha.example.test', dir)).toBe('member');
  });

  it('hashes and splits addresses; card wording per class', () => {
    expect(recipientDomainOf('Ada@Alpha.Example.Test')).toBe('alpha.example.test');
    expect(recipientSha256(' Ada@Example.Test ')).toBe(
      createHash('sha256').update('ada@example.test').digest('hex'),
    );
    expect(recipientKindText('self', 'x.test')).toBe('your own address');
    expect(recipientKindText('member', 'x.test')).toBe('user of your organization');
    expect(recipientKindText('domain', 'alpha.example.test')).toBe(
      'address in verified domain alpha.example.test',
    );
  });
});
