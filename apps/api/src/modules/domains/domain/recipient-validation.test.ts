import { describe, expect, it } from 'vitest';
import {
  LocalPartError,
  normalizeLocalPart,
  toRecipientValidationSettings,
  toRecipientValidationState,
} from './recipient-validation';

describe('recipient validation mapping (D3)', () => {
  it.each([
    [null, { mode: 'accept_all', enforcement: 'monitor', implemented: true }],
    [
      { recipientValidation: 'none', rejectUnknownRecipients: true },
      { mode: 'accept_all', enforcement: 'reject', implemented: true },
    ],
    [
      { recipientValidation: 'list', rejectUnknownRecipients: true },
      { mode: 'allow_list', enforcement: 'reject', implemented: true },
    ],
    [
      { recipientValidation: 'list', rejectUnknownRecipients: false },
      { mode: 'allow_list', enforcement: 'monitor', implemented: true },
    ],
    [
      { recipientValidation: 'smtp_callout', rejectUnknownRecipients: true },
      { mode: 'smtp_callout', enforcement: 'reject', implemented: false },
    ],
    [
      { recipientValidation: 'ldap', rejectUnknownRecipients: false },
      { mode: 'ldap', enforcement: 'monitor', implemented: false },
    ],
  ] as const)('columns %j → %j', (settings, state) => {
    expect(toRecipientValidationState(settings)).toEqual(state);
  });

  it.each([
    [
      { mode: 'accept_all', enforcement: 'monitor' },
      { recipientValidation: 'none', rejectUnknownRecipients: false },
    ],
    [
      { mode: 'allow_list', enforcement: 'reject' },
      { recipientValidation: 'list', rejectUnknownRecipients: true },
    ],
    [
      { mode: 'allow_list', enforcement: 'monitor' },
      { recipientValidation: 'list', rejectUnknownRecipients: false },
    ],
  ] as const)('API %j → columns %j (and back)', (input, columns) => {
    expect(toRecipientValidationSettings(input)).toEqual(columns);
    expect(toRecipientValidationState(columns)).toMatchObject(
      input.mode === 'accept_all' ? { mode: 'accept_all' } : input,
    );
  });
});

describe('normalizeLocalPart (D3)', () => {
  it.each([
    ['John.Doe', 'john.doe'],
    ['SALES+EU', 'sales+eu'],
    ['José', 'josé'], // NFC
    ['ÉLODIE', 'élodie'],
    ['a'.repeat(64), 'a'.repeat(64)],
    ['"quoted"', '"quoted"'],
  ])('%j → %j', (input, expected) => {
    expect(normalizeLocalPart(input)).toBe(expected);
  });

  it.each([
    ['', 'must not be empty'],
    ['user@example.com', 'must be a local part without "@" or domain'],
    ['john doe', 'must not contain whitespace or control characters'],
    [' john', 'must not contain whitespace or control characters'],
    ['john\t', 'must not contain whitespace or control characters'],
    ['jo\u0000hn', 'must not contain whitespace or control characters'],
    ['jo​hn', 'must not contain whitespace or control characters'],
    ['jo hn', 'must not contain whitespace or control characters'],
    ['jo\ud800hn', 'must not contain whitespace or control characters'],
    ['a'.repeat(65), 'must be at most 64 bytes (UTF-8)'],
    ['é'.repeat(33), 'must be at most 64 bytes (UTF-8)'],
  ])('refuses %j (%s)', (input, message) => {
    expect(() => normalizeLocalPart(input)).toThrow(new LocalPartError(message));
  });

  it('counts octets, not characters', () => {
    expect(normalizeLocalPart('é'.repeat(32))).toHaveLength(32);
  });
});
