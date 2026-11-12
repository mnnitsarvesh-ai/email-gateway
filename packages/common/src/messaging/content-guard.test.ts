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

  it('covers all twenty-four registered event types (two added by step 3.3, one by step 4.2, three by step 4.3, one by step 4.4, one by step 4.5, three by step 4.6, two by step 5.2, two by step 5.3)', () => {
    expect(types).toHaveLength(24);
    expect(types).toContain('mail.message.dlp_incident.v1');
    expect(types).toEqual(
      expect.arrayContaining([
        'mail.sandbox.task_requested.v1',
        'mail.sandbox.task_completed.v1',
        'mail.attachment.sandbox_completed.v1',
        // Step 5.2 P15 (mail.policy.decided.v1 existed as a placeholder and was redefined).
        'mail.policy.decided.v1',
        'mail.message.archive_requested.v1',
        'mail.policy.notification_requested.v1',
        // Step 5.3 Q27.
        'mail.quarantine.release_requested.v1',
        'mail.quarantine.notification_requested.v1',
      ]),
    );
  });

  /** Step 4.6 §4: every maximal sandbox payload is metadata only and well below 128 KiB. */
  const MAX_MESSAGE_BYTES = 131_072;
  const sandboxTaskId = '01890a5d-ac96-774b-bcce-b302099a8070';
  const hex = (c: string) => c.repeat(64);
  const host = (i: number) => `${'a'.repeat(50)}-${i}.${'b'.repeat(60)}.${'c'.repeat(60)}.test`;
  const maximalSandbox: Record<string, unknown> = {
    'mail.sandbox.task_requested.v1': {
      ...(EXAMPLE_EVENT_PAYLOADS['mail.sandbox.task_requested.v1'] as object),
      sample: {
        key: `samples/2026/11/${sandboxTaskId}.bin`,
        sha256: hex('c'),
        sizeBytes: 67_108_864,
        detectedType: 'ooxml_powerpoint',
      },
      limits: {
        wallTimeoutMs: 600_000,
        memoryMb: 4_096,
        cpuMillis: 4_000,
        pids: 1_024,
        scratchMb: 1_024,
        maxArtifacts: 16,
        maxArtifactBytes: 8_388_608,
        maxTotalArtifactBytes: 33_554_432,
      },
    },
    'mail.sandbox.task_completed.v1': {
      ...(EXAMPLE_EVENT_PAYLOADS['mail.sandbox.task_completed.v1'] as object),
      backend: 'hardened-container',
      backendVersion: `hardened-container/1+runner:${'d'.repeat(36)}`,
      isolation: 'container',
      executed: true,
      controllerVersion: 'v'.repeat(64),
      analyzerVersion: 'w'.repeat(64),
      observations: {
        processes: Array.from({ length: 32 }, (_, i) => ({
          seq: i,
          parentSeq: i === 0 ? null : i - 1,
          image: 'i'.repeat(64),
          argvSha256: hex('a'),
          exitCode: -2_147_483_648,
          killedBy: 'pids',
        })),
        processCount: 1_000_000,
        network: {
          dns: Array.from({ length: 50 }, (_, i) => ({
            name: host(i),
            type: 'AAAA',
            source: 'sinkhole',
          })),
          http: Array.from({ length: 50 }, (_, i) => ({
            host: host(i),
            port: 65_535,
            method: 'OTHER',
            pathSha256: hex('b'),
            userAgentSha256: hex('c'),
          })),
          tls: Array.from({ length: 50 }, (_, i) => ({ sni: host(i), port: 443 })),
          connections: Array.from({ length: 50 }, (_, i) => ({
            ip: `2001:db8:ffff:ffff:ffff:ffff:ffff:${(0xff00 + i).toString(16)}`,
            port: 65_535,
            protocol: 'udp',
            outcome: 'sinkhole',
          })),
          totals: { dns: 1_000_000, http: 1_000_000, tls: 1_000_000, connections: 1_000_000 },
        },
        files: {
          dropped: Array.from({ length: 32 }, (_, i) => ({
            seq: i,
            sha256: hex('e'),
            sizeBytes: 2 ** 40,
            typeHint: 'pe_executable',
          })),
          deniedWrites: 1_000_000,
        },
        findings: Array.from({ length: 32 }, (_, i) => ({
          code: `behaviour.${'x'.repeat(50)}_${String(i).padStart(2, '0')}`,
          severity: 'critical',
          count: 1_000_000,
        })),
        limitsHit: [
          'memory',
          'pids',
          'cpu',
          'scratch_full',
          'wall_timeout',
          'analyzer_resources',
          'output_truncated',
          'artifact_cap',
        ],
        browser: {
          navigations: 1_000_000,
          requests: 1_000_000,
          downloadsAttempted: 1_000_000,
          dialogs: 1_000_000,
          passwordFields: 1_000_000,
          forms: 1_000_000,
        },
      },
      artifacts: Array.from({ length: 16 }, (_, i) => ({
        seq: i,
        kind: 'dropped_file',
        contentType: 'application/octet-stream',
        key: `artifacts/2026/11/${sandboxTaskId}/0f1e2d3c4b5a6978/${i}-dropped_file.bin`,
        objectSha256: hex('a'),
        plainSha256: hex('b'),
        sizeBytes: 8_388_608,
        wrappedKey: `x1.k1234567.${'A'.repeat(43)}.${'B'.repeat(16)}.${'C'.repeat(22)}.${'D'.repeat(43)}`,
        keyId: 'k1234567',
        algorithm: 'sandbox-artifact/1',
      })),
      cleanup: { runnerRemoved: true, scratchRemoved: true },
    },
    'mail.attachment.sandbox_completed.v1': {
      ...(EXAMPLE_EVENT_PAYLOADS['mail.attachment.sandbox_completed.v1'] as object),
      submissionId: '18446744073709551615',
      messageId: '18446744073709551615',
      scanId: '18446744073709551615',
      lifecycleRound: 65_535,
      partIndex: 65_535,
      reasonCodes: Array.from(
        { length: 16 },
        (_, i) => `sandbox.behaviour.${'y'.repeat(40)}_${String(i).padStart(2, '0')}`,
      ),
    },
  };

  it.each(Object.keys(maximalSandbox))(
    'passes a maximal %s (step 4.6 §4: metadata only, < 128 KiB)',
    (type) => {
      const payload = maximalSandbox[type];
      const schema = EVENT_REGISTRY[type as RegisteredEventType].schema;
      expect(schema.safeParse(payload).error).toBeUndefined();
      const value = envelope(type, payload);
      expect(() => assertMetadataOnly(value)).not.toThrow();
      expect(Buffer.byteLength(JSON.stringify(value), 'utf8')).toBeLessThan(MAX_MESSAGE_BYTES);
    },
  );

  it('passes a maximal mail.message.dlp_incident.v1 (ids, codes and counts only, step 4.5 D14)', () => {
    const base = EXAMPLE_EVENT_PAYLOADS['mail.message.dlp_incident.v1'] as Record<string, unknown>;
    const payload = {
      ...base,
      categories: [
        'payment_card',
        'bank_account',
        'national_id',
        'passport',
        'personal_info',
        'confidential',
        'source_code',
        'credential',
        'financial',
        'custom',
      ].map((category) => ({ category, count: 1_000_000, maxSeverity: 'critical' })),
      detectorCodes: Array.from({ length: 24 }, (_, i) => `dlp.detector_${i}.code`),
    };
    expect(EVENT_REGISTRY['mail.message.dlp_incident.v1'].schema.safeParse(payload).success).toBe(
      true,
    );
    expect(() =>
      assertMetadataOnly(envelope('mail.message.dlp_incident.v1', payload)),
    ).not.toThrow();
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
