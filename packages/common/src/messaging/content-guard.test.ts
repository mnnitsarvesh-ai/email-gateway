import {
  EVENT_REGISTRY,
  EXAMPLE_EVENT_PAYLOADS,
  type RegisteredEventType,
} from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { assertMetadataOnly, ContentGuardError, type ContentGuardCode } from './content-guard';

const envelope = (eventType: string, payload: unknown) => ({
  eventId: '01936b2e-7c4f-7a3b-9c1d-2e3f4a5b6c7d',
  eventType,
  occurredAt: '2026-11-01T10:15:30.123Z',
  correlationId: 'corr-0123456789',
  organizationId: '42',
  payload,
});

function refusal(value: unknown): { code: ContentGuardCode; path: string } {
  try {
    assertMetadataOnly(value);
  } catch (error) {
    if (error instanceof ContentGuardError) return { code: error.code, path: error.path };
    throw error;
  }
  throw new Error('expected a refusal');
}

describe('assertMetadataOnly: valid envelopes pass', () => {
  const types = Object.keys(EVENT_REGISTRY) as RegisteredEventType[];

  it('covers all sixteen registered event types (two added by step 3.3, one by step 4.2, three by step 4.3, one by step 4.4)', () => {
    expect(types).toHaveLength(16);
  });

  it.each(types)('%s example passes the registry schema and the guard', (type) => {
    const payload = EXAMPLE_EVENT_PAYLOADS[type];
    expect(EVENT_REGISTRY[type].schema.safeParse(payload).success).toBe(true);
    expect(() => assertMetadataOnly(envelope(type, payload))).not.toThrow();
  });

  it('passes a 1000-recipient mail.delivery.approved.v1', () => {
    const base = EXAMPLE_EVENT_PAYLOADS['mail.delivery.approved.v1'] as Record<string, unknown>;
    const payload = {
      ...base,
      recipients: Array.from({ length: 1000 }, (_, i) => ({
        recipientId: String(1_000_000 + i),
        rcptSeq: i,
      })),
    };
    expect(EVENT_REGISTRY['mail.delivery.approved.v1'].schema.safeParse(payload).success).toBe(
      true,
    );
    expect(() => assertMetadataOnly(envelope('mail.delivery.approved.v1', payload))).not.toThrow();
  });

  it('allows forbidden key names when they hold references (objects), not content', () => {
    expect(() =>
      assertMetadataOnly({ body: { s3Key: 'org/42/part/x.text', sha256: 'a'.repeat(64) } }),
    ).not.toThrow();
    expect(() => assertMetadataOnly({ data: { count: 3 }, text: null, content: 7 })).not.toThrow();
  });

  it('allows a 2048-character string and short base64-like ids', () => {
    expect(() => assertMetadataOnly({ note: 'ab. '.repeat(512) })).not.toThrow();
    expect(() =>
      assertMetadataOnly({ sha256: 'f'.repeat(64), key: 'A'.repeat(511) }),
    ).not.toThrow();
  });
});

describe('assertMetadataOnly: refusals with their JSON path', () => {
  it('binary_value: Buffer, typed arrays, ArrayBuffer, DataView, Blob-like, serialized Buffer', () => {
    expect(refusal({ payload: { attachment: Buffer.from('MZ') } })).toEqual({
      code: 'binary_value',
      path: '$.payload.attachment',
    });
    expect(refusal({ a: [1, new Uint8Array(4)] })).toEqual({
      code: 'binary_value',
      path: '$.a[1]',
    });
    expect(refusal({ a: new ArrayBuffer(8) })).toEqual({ code: 'binary_value', path: '$.a' });
    expect(refusal({ a: new DataView(new ArrayBuffer(2)) })).toEqual({
      code: 'binary_value',
      path: '$.a',
    });
    expect(refusal({ a: new Blob(['x']) })).toEqual({ code: 'binary_value', path: '$.a' });
    const serialized = JSON.parse(JSON.stringify({ file: Buffer.from('%PDF-1.7') })) as unknown;
    expect(refusal({ payload: serialized })).toEqual({
      code: 'binary_value',
      path: '$.payload.file',
    });
  });

  it('oversized_string: 2049 characters', () => {
    expect(refusal({ payload: { notes: ['ok', 'y'.repeat(2049)] } })).toEqual({
      code: 'oversized_string',
      path: '$.payload.notes[1]',
    });
  });

  it('mime_content: a MIME part, a header at the start, any case', () => {
    const part = 'preamble\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello';
    expect(refusal({ payload: { part } })).toEqual({
      code: 'mime_content',
      path: '$.payload.part',
    });
    expect(refusal({ x: 'MIME-Version: 1.0' })).toEqual({ code: 'mime_content', path: '$.x' });
    expect(refusal({ x: 'a\ncontent-transfer-encoding : base64' })).toEqual({
      code: 'mime_content',
      path: '$.x',
    });
    expect(refusal({ x: 'content-disposition: attachment' })).toEqual({
      code: 'mime_content',
      path: '$.x',
    });
  });

  it('base64_blob: a base64 PDF (with line breaks) and base64url runs', () => {
    const pdf = Buffer.from(`%PDF-1.7\n${'stream data '.repeat(60)}`).toString('base64');
    const wrapped = pdf.replace(/(.{76})/g, '$1\r\n');
    expect(refusal({ payload: { attachments: [{ file: wrapped }] } })).toEqual({
      code: 'base64_blob',
      path: '$.payload.attachments[0].file',
    });
    expect(refusal({ token: 'ab-_'.repeat(128) })).toEqual({
      code: 'base64_blob',
      path: '$.token',
    });
  });

  it('forbidden_field: content keys with a string, number array or binary (case-insensitive)', () => {
    expect(refusal({ payload: { body: 'Hello' } })).toEqual({
      code: 'forbidden_field',
      path: '$.payload.body',
    });
    expect(refusal({ payload: { HTML: '<p>x</p>' } })).toEqual({
      code: 'forbidden_field',
      path: '$.payload.HTML',
    });
    expect(refusal({ data: [1, 2, 3] })).toEqual({ code: 'forbidden_field', path: '$.data' });
    expect(refusal({ x: { rawBody: Buffer.from('a') } })).toEqual({
      code: 'forbidden_field',
      path: '$.x.rawBody',
    });
    for (const key of [
      'raw',
      'text',
      'content',
      'contentBase64',
      'bytes',
      'eml',
      'mime',
      'attachmentData',
      'attachmentContent',
    ]) {
      expect(refusal({ [key]: 'v' })).toEqual({ code: 'forbidden_field', path: `$.${key}` });
    }
  });

  it('too_deep: 17 levels or more than 10 000 nodes', () => {
    let deep: unknown = { leaf: 1 };
    for (let i = 0; i < 15; i += 1) deep = { n: deep };
    expect(() => assertMetadataOnly(deep)).not.toThrow(); // 16 levels
    expect(refusal({ n: deep }).code).toBe('too_deep');
    const wide = { items: Array.from({ length: 10_001 }, (_, i) => i) };
    expect(refusal(wide).code).toBe('too_deep');
  });

  it('quotes non-identifier keys in the path and never includes values', () => {
    const secret = 'Content-Type: text/html';
    const { path } = refusal({ 'x-header': { 'a b': secret } });
    expect(path).toBe('$["x-header"]["a b"]');
    try {
      assertMetadataOnly({ a: secret });
    } catch (error) {
      expect((error as Error).message).not.toContain('text/html');
    }
  });

  it('honours maxStringLength', () => {
    expect(() => assertMetadataOnly({ a: 'x'.repeat(20) }, { maxStringLength: 10 })).toThrow(
      ContentGuardError,
    );
  });
});
