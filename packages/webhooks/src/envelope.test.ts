import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  WEBHOOK_ENVELOPE_TYPES,
  WEBHOOK_EXAMPLE_DATA,
  type WebhookEnvelopeType,
} from './catalogue';
import {
  buildEnvelope,
  parseStoredEnvelope,
  WEBHOOK_ENVELOPE_VERSION,
  WebhookEnvelopeError,
  webhookEnvelopeSchema,
  webhookEventId,
} from './envelope';
import { WEBHOOK_MAX_PAYLOAD_BYTES, WebhookPayloadError } from './payload-guard';

const SOURCE = '01936b2e-7c4f-7a3b-9c1d-2e3f4a5b6c7d';
const ORG = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10';
const OCCURRED = '2026-11-13T09:14:03.120Z';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const build = <T extends WebhookEnvelopeType>(
  type: T,
  extra: Partial<{ subKey: string; data: unknown }> = {},
) =>
  buildEnvelope({
    type,
    occurredAt: OCCURRED,
    organizationPublicId: ORG,
    sourceEventId: SOURCE,
    subKey: extra.subKey,
    data: (extra.data ?? WEBHOOK_EXAMPLE_DATA[type]) as never,
  });

describe('webhookEventId (W2)', () => {
  it('is the SHA-256 of the namespaced triple, version 8, RFC 9562 variant', () => {
    const id = webhookEventId(SOURCE, 'email.quarantined', 'policy');
    expect(id).toMatch(UUID);
    const digest = createHash('sha256')
      .update(`eg-webhook-event/v1\0${SOURCE}\0email.quarantined\0policy`)
      .digest();
    const hex = id.replaceAll('-', '');
    // Unchanged bytes are the digest's; byte 6 high nibble = 8; byte 8 top bits = 10.
    expect(hex.slice(0, 12)).toBe(digest.subarray(0, 6).toString('hex'));
    expect(hex[12]).toBe('8');
    expect(hex.slice(13, 16)).toBe(digest.subarray(6, 8).toString('hex').slice(1));
    expect(parseInt(hex.slice(16, 18), 16) & 0xc0).toBe(0x80);
    expect(parseInt(hex.slice(16, 18), 16) & 0x3f).toBe(digest[8]! & 0x3f);
    expect(hex.slice(18)).toBe(digest.subarray(9, 16).toString('hex'));
  });

  it('is deterministic and distinct per source, type and subKey (default subKey empty)', () => {
    const a = webhookEventId(SOURCE, 'email.received');
    expect(webhookEventId(SOURCE, 'email.received')).toBe(a);
    expect(webhookEventId(SOURCE, 'email.received', '')).toBe(a);
    const ids = new Set([
      a,
      webhookEventId(SOURCE, 'email.scanned'),
      webhookEventId(SOURCE, 'email.quarantined', 'policy'),
      webhookEventId(SOURCE, 'email.quarantined', 'manual'),
      webhookEventId(SOURCE, 'email.threat.detected', 'scan'),
      webhookEventId(SOURCE, 'email.threat.detected', 'sandbox:3'),
      webhookEventId(SOURCE, 'alert:threat_detected'),
      webhookEventId('01936b2e-7c4f-7a3b-9c1d-2e3f4a5b6c7e', 'email.received'),
    ]);
    expect(ids.size).toBe(8);
    // The separator keeps (a, bc) and (ab, c) apart.
    expect(webhookEventId('x', 'ab', 'c')).not.toBe(webhookEventId('x', 'a', 'bc'));
    for (const id of ids) expect(id).toMatch(UUID);
  });
});

describe('buildEnvelope (W4)', () => {
  it('builds a valid envelope of every type with a deterministic id, bytes and hash', () => {
    for (const type of WEBHOOK_ENVELOPE_TYPES) {
      const built = build(type);
      expect(built.envelope).toEqual({
        id: webhookEventId(SOURCE, type),
        type,
        version: WEBHOOK_ENVELOPE_VERSION,
        occurredAt: OCCURRED,
        organizationId: ORG,
        data: WEBHOOK_EXAMPLE_DATA[type],
      });
      expect(built.json).toBe(JSON.stringify(built.envelope));
      expect(built.sha256).toBe(createHash('sha256').update(built.json).digest('hex'));
      expect(webhookEnvelopeSchema.safeParse(JSON.parse(built.json)).success, type).toBe(true);
      expect(parseStoredEnvelope(built.json)).toEqual(built.envelope);
      // A redelivery produces the same bytes.
      expect(build(type).json).toBe(built.json);
      expect(Object.keys(JSON.parse(built.json))).toEqual([
        'id',
        'type',
        'version',
        'occurredAt',
        'organizationId',
        'data',
      ]);
    }
  });

  it('serializes data in schema key order whatever the input key order', () => {
    const data = WEBHOOK_EXAMPLE_DATA['webhook.ping'];
    const reordered = { requestedAt: data.requestedAt, subscriptionId: data.subscriptionId };
    expect(build('webhook.ping', { data: reordered }).json).toBe(build('webhook.ping').json);
  });

  it('accepts a Date occurredAt and uses the subKey in the id', () => {
    const built = buildEnvelope({
      type: 'email.quarantined',
      occurredAt: new Date(OCCURRED),
      organizationPublicId: ORG,
      sourceEventId: SOURCE,
      subKey: 'manual',
      data: WEBHOOK_EXAMPLE_DATA['email.quarantined'],
    });
    expect(built.envelope.occurredAt).toBe(OCCURRED);
    expect(built.envelope.id).toBe(webhookEventId(SOURCE, 'email.quarantined', 'manual'));
  });

  it('validates data with the type schema and the envelope fields', () => {
    expect(() => build('email.received', { data: { message: { id: 'x' } } })).toThrow(
      WebhookEnvelopeError,
    );
    expect(() =>
      build('email.received', { data: { ...WEBHOOK_EXAMPLE_DATA['email.received'], extra: 1 } }),
    ).toThrow(WebhookEnvelopeError);
    expect(() =>
      buildEnvelope({
        type: 'email.received',
        occurredAt: 'yesterday',
        organizationPublicId: ORG,
        sourceEventId: SOURCE,
        data: WEBHOOK_EXAMPLE_DATA['email.received'],
      }),
    ).toThrow(WebhookEnvelopeError);
    expect(() =>
      buildEnvelope({
        type: 'email.received',
        occurredAt: OCCURRED,
        organizationPublicId: '42',
        sourceEventId: SOURCE,
        data: WEBHOOK_EXAMPLE_DATA['email.received'],
      }),
    ).toThrow(WebhookEnvelopeError);
    expect(() => build('email.unknown' as never)).toThrow();
    try {
      build('email.received', { data: { message: { id: 'secret-value' } } });
    } catch (error) {
      expect(String(error)).not.toContain('secret-value');
    }
  });

  it('runs the payload guard (16 KiB cap) on the built envelope', () => {
    // A schema-valid message cannot reach 16 KiB, so the cap is shown on the guard directly; a
    // schema-valid envelope near the bound stays below it.
    const big = {
      ...WEBHOOK_EXAMPLE_DATA['email.received'],
      message: {
        ...WEBHOOK_EXAMPLE_DATA['email.received'].message,
        recipientDomains: Array.from(
          { length: 20 },
          (_, i) => `${'d'.repeat(60)}.${'e'.repeat(60)}.${'f'.repeat(60)}${i}.example`,
        ),
        internetMessageId: `<${'m'.repeat(240)}@x.example>`,
      },
    };
    const built = build('email.received', { data: big });
    expect(Buffer.byteLength(built.json)).toBeLessThan(WEBHOOK_MAX_PAYLOAD_BYTES);
    // An unsafe value that the schema allows is refused by the guard (a URL in the Message-ID).
    expect(() =>
      build('email.received', {
        data: {
          ...WEBHOOK_EXAMPLE_DATA['email.received'],
          message: {
            ...WEBHOOK_EXAMPLE_DATA['email.received'].message,
            internetMessageId: '<https://evil.example/x>',
          },
        },
      }),
    ).toThrow(WebhookPayloadError);
  });
});
