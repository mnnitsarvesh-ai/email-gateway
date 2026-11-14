import { describe, expect, it } from 'vitest';
import {
  SEARCH_FIELDS,
  isMessageUuid,
  normalizeSubject,
  validateAddress,
  validateDomain,
  validateMessageId,
  validateSubject,
  validateSubjectPrefix,
} from './search-fields';

const value = (result: ReturnType<typeof validateAddress>) => (result.ok ? result.value : null);

describe('explorer search validators (mirror the api rules)', () => {
  it('addresses: complete, lower-cased, 3–320 characters', () => {
    expect(value(validateAddress(' Jane.Doe@Example.COM '))).toBe('jane.doe@example.com');
    expect(validateAddress('jane').ok).toBe(false);
    expect(validateAddress('jane@').ok).toBe(false);
    expect(validateAddress('a b@example.com').ok).toBe(false);
    expect(validateAddress(`${'a'.repeat(320)}@x`).ok).toBe(false);
  });

  it('domains: lower-cased, one leading @ removed, LDH labels, IDNs only in A-label form', () => {
    expect(value(validateDomain('@Example.COM'))).toBe('example.com');
    expect(value(validateDomain('xn--mnchen-3ya.example.test'))).toBe(
      'xn--mnchen-3ya.example.test',
    );
    expect(validateDomain('münchen.example').ok).toBe(false);
    expect(validateDomain('localhost').ok).toBe(false);
    expect(validateDomain('-bad.example').ok).toBe(false);
    expect(validateDomain('exa mple.com').ok).toBe(false);
  });

  it('subject: not empty after removing reply markers', () => {
    expect(value(validateSubject('Re: Invoice 4471'))).toBe('Re: Invoice 4471');
    expect(validateSubject('Re: Fwd:').ok).toBe(false);
    expect(validateSubject('RE[2]:  ').ok).toBe(false);
    expect(validateSubject('x'.repeat(999)).ok).toBe(false);
  });

  it('subject prefix: 3–128 characters after normalization', () => {
    expect(validateSubjectPrefix('Inv').ok).toBe(true);
    expect(validateSubjectPrefix('Re:  In').ok).toBe(false);
    expect(validateSubjectPrefix('Fwd: Invoice').ok).toBe(true);
    expect(validateSubjectPrefix('x'.repeat(129)).ok).toBe(false);
    expect(validateSubjectPrefix('请查收').ok).toBe(true);
  });

  it('normalizes subjects like the api (markers, Unicode white space runs, edges)', () => {
    expect(normalizeSubject('Re: AW: Fwd[3]:  Quarterly\t\treport ')).toBe('Quarterly report');
    expect(normalizeSubject('Report: Re: x')).toBe('Report: Re: x');
  });

  it('Message-ID: brackets optional, not brackets only', () => {
    expect(value(validateMessageId('<abc@mail.example.test>'))).toBe('<abc@mail.example.test>');
    expect(value(validateMessageId('abc@mail.example.test'))).toBe('abc@mail.example.test');
    expect(validateMessageId('<>').ok).toBe(false);
    expect(validateMessageId('  ').ok).toBe(false);
  });

  it('recognizes a gateway message id (UUID) for "Open message"', () => {
    expect(isMessageUuid('01933c3a-1b2c-7d4e-8f00-00000000a001')).toBe(true);
    expect(isMessageUuid('<01933c3a@x>')).toBe(false);
  });

  it('offers the eight search fields of §2 E10', () => {
    expect(SEARCH_FIELDS.map((field) => field.label)).toEqual([
      'Sender (envelope)',
      'Sender (From header)',
      'Recipient',
      'Subject',
      'Subject starts with',
      'Message ID',
      'Sender domain',
      'Recipient domain',
    ]);
  });
});
