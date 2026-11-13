import { describe, expect, it } from 'vitest';
import { WEBHOOK_ENVELOPE_TYPES, WEBHOOK_EXAMPLE_DATA } from './catalogue';
import { buildEnvelope } from './envelope';
import {
  assertWebhookPayloadSafe,
  WEBHOOK_DENIED_KEYS,
  WEBHOOK_MAX_PAYLOAD_BYTES,
  type WebhookPayloadErrorCode,
  WebhookPayloadError,
} from './payload-guard';

const SOURCE = '01936b2e-7c4f-7a3b-9c1d-2e3f4a5b6c7d';
const ORG = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10';

const envelopeOf = (data: unknown) => ({
  id: '0193a1b2-7c3d-8e4f-9a0b-1c2d3e4f5a6b',
  type: 'email.received',
  version: 1,
  occurredAt: '2026-11-13T09:14:03.120Z',
  organizationId: ORG,
  data,
});
const example = WEBHOOK_EXAMPLE_DATA['email.received'];
const withMessage = (fields: Record<string, unknown>) =>
  envelopeOf({ message: { ...example.message, ...fields } });

function refusal(value: unknown): { code: WebhookPayloadErrorCode; path: string } {
  try {
    assertWebhookPayloadSafe(value);
  } catch (error) {
    if (error instanceof WebhookPayloadError) return { code: error.code, path: error.path };
    throw error;
  }
  throw new Error('expected a refusal');
}

describe('assertWebhookPayloadSafe (W2, W4)', () => {
  it('passes a realistic envelope of every type (the catalogue examples, built)', () => {
    for (const type of WEBHOOK_ENVELOPE_TYPES) {
      const built = buildEnvelope({
        type,
        occurredAt: '2026-11-13T09:14:03.120Z',
        organizationPublicId: ORG,
        sourceEventId: SOURCE,
        data: WEBHOOK_EXAMPLE_DATA[type],
      });
      expect(() => assertWebhookPayloadSafe(built.envelope), type).not.toThrow();
    }
  });

  it('refuses an envelope with a subject, an address, an S3 key or a base64 blob', () => {
    expect(refusal(withMessage({ subject: 'Q4 invoice' }))).toEqual({
      code: 'forbidden_key',
      path: '$.data.message.subject',
    });
    expect(refusal(withMessage({ envelopeFrom: 'alice@partner.example' }))).toEqual({
      code: 'forbidden_key',
      path: '$.data.message.envelopeFrom',
    });
    // An address under an innocent key is caught by value.
    expect(refusal(withMessage({ senderDomain: 'alice@partner.example' }))).toEqual({
      code: 'address_value',
      path: '$.data.message.senderDomain',
    });
    expect(refusal(withMessage({ emlS3Key: 'org/42/eml/2026/11/13/9.eml' }))).toMatchObject({
      code: 'forbidden_key',
    });
    expect(refusal(withMessage({ ref: 'org/42/eml/2026/11/13/9.eml' }))).toEqual({
      code: 's3_key_value',
      path: '$.data.message.ref',
    });
    expect(refusal(withMessage({ blob: 'QUJD'.repeat(160) }))).toEqual({
      code: 'base64_blob',
      path: '$.data.message.blob',
    });
    expect(refusal(withMessage({ link: 'https://phish.example/login' }))).toEqual({
      code: 'url_value',
      path: '$.data.message.link',
    });
  });

  it('refuses every denied key, case-insensitively and at any depth', () => {
    for (const key of WEBHOOK_DENIED_KEYS) {
      const value = key === 'recipients' ? ['a.example'] : { nested: 1 };
      expect(refusal(envelopeOf({ deep: [{ [key]: value }] })), key).toMatchObject({
        code: 'forbidden_key',
      });
      expect(
        refusal(envelopeOf({ [key.toUpperCase()]: key === 'recipients' ? 'a' : 1 })),
        key,
      ).toMatchObject({ code: 'forbidden_key' });
    }
    // `recipients` as an object of counts is the delivered event's shape and is allowed.
    expect(() =>
      assertWebhookPayloadSafe(envelopeOf({ recipients: { delivered: 1, failed: 0 } })),
    ).not.toThrow();
    expect(refusal(envelopeOf({ recipients: 'a@b.example' }))).toMatchObject({
      code: 'forbidden_key',
    });
  });

  it('exempts only internetMessageId from the address rule', () => {
    expect(() =>
      assertWebhookPayloadSafe(withMessage({ internetMessageId: '<abc@mail.partner.example>' })),
    ).not.toThrow();
    expect(refusal(withMessage({ headerFromDomain: '<abc@mail.partner.example>' }))).toMatchObject({
      code: 'address_value',
    });
  });

  it('maps the content guard codes (assertMetadataOnly with 1024-character strings)', () => {
    expect(refusal(withMessage({ note: 'x '.repeat(513) })).code).toBe('oversized_string');
    expect(() => assertWebhookPayloadSafe(withMessage({ note: 'x '.repeat(512) }))).not.toThrow();
    expect(refusal(withMessage({ note: 'Content-Type: text/plain' })).code).toBe('mime_content');
    expect(refusal(withMessage({ part: Buffer.from('x') })).code).toBe('binary_value');
    expect(refusal(envelopeOf({ data: 'inline' })).code).toBe('forbidden_field');
    let deep: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 20; i += 1) deep = { d: deep };
    expect(refusal(envelopeOf(deep)).code).toBe('too_deep');
  });

  it('refuses an envelope over 16 KiB and one that cannot be serialized', () => {
    const many = Object.fromEntries(
      Array.from({ length: 40 }, (_, i) => [`k${i}`, 'v'.repeat(500)]),
    );
    expect(Buffer.byteLength(JSON.stringify(envelopeOf(many)))).toBeGreaterThan(
      WEBHOOK_MAX_PAYLOAD_BYTES,
    );
    expect(refusal(envelopeOf(many))).toEqual({ code: 'too_large', path: '$' });
    expect(refusal(envelopeOf({ n: 10n })).code).toBe('not_serializable');
  });

  it('names a path, never a value', () => {
    try {
      assertWebhookPayloadSafe(withMessage({ subject: 'very-secret-subject' }));
    } catch (error) {
      expect(String(error)).not.toContain('very-secret-subject');
      expect(String(error)).toContain('$.data.message.subject');
    }
  });
});
