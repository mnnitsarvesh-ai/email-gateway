import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  getContext,
  getRequestId,
  normalizeCorrelationId,
  runWithContext,
  setContextRequestId,
  setContextTenant,
} from './context';
import { createLogger, REDACT_PATHS } from './logger';

function capture(): { stream: Writable; lines: () => Record<string, unknown>[] } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return {
    stream,
    lines: () =>
      chunks
        .join('')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as Record<string, unknown>),
  };
}

describe('createLogger', () => {
  it('emits JSON with service and correlation id from async context', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    runWithContext({ correlationId: 'corr-12345678', tenantId: 't-1' }, () => logger.info('hello'));
    const [line] = out.lines();
    expect(line).toMatchObject({
      level: 'info',
      service: 'test-svc',
      message: 'hello',
      correlationId: 'corr-12345678',
      tenantId: 't-1',
    });
  });

  it('redacts secrets', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    logger.info({ password: 'hunter2', headers: { authorization: 'Bearer x' } }, 'login');
    const serialized = JSON.stringify(out.lines()[0]);
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('Bearer x');
  });
});

describe('redaction of credentials (design §6)', () => {
  const fields = [
    'accessToken',
    'refreshToken',
    'mfaToken',
    'recoveryCode',
    'recoveryCodes',
    'code',
    'newPassword',
    'currentPassword',
    'key',
    'apiKey',
    'otpauthUri',
  ];

  it.each(fields)('censors %s at the top level and one level down', (field) => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    const top = `top-${field}-value-1234`;
    const nested = `nested-${field}-value-5678`;
    logger.info({ [field]: top, body: { [field]: nested } }, 'event');
    const line = out.lines()[0]!;
    const serialized = JSON.stringify(line);
    expect(serialized).not.toContain(top);
    expect(serialized).not.toContain(nested);
    expect(line[field]).toBe('[REDACTED]');
    expect((line.body as Record<string, unknown>)[field]).toBe('[REDACTED]');
  });

  it('censors arrays of recovery codes as a whole', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    logger.info({ recoveryCodes: ['abcde-fghij', 'klmno-pqrst'] }, 'mfa');
    expect(JSON.stringify(out.lines()[0])).not.toContain('abcde-fghij');
  });

  it('censors the X-API-Key header on requests and bare header objects', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    logger.info(
      {
        req: { headers: { 'x-api-key': 'egk_reqheader0001_secret' } },
        headers: { 'x-api-key': 'egk_bareheader001_secret' },
      },
      'request',
    );
    const serialized = JSON.stringify(out.lines()[0]);
    expect(serialized).not.toContain('egk_reqheader0001_secret');
    expect(serialized).not.toContain('egk_bareheader001_secret');
  });

  it('keeps the original paths', () => {
    expect(REDACT_PATHS).toEqual(
      expect.arrayContaining([
        'password',
        '*.password',
        'secret',
        'token',
        'req.headers.authorization',
        'headers.cookie',
      ]),
    );
  });
});

describe('redaction of DKIM key material (step 2.1 §6)', () => {
  it.each(['privateKey', 'privateKeyPem', 'privateKeyCiphertext'])(
    'censors %s at the top level and one level down',
    (field) => {
      const out = capture();
      const logger = createLogger({ service: 'test-svc', destination: out.stream });
      const pem = `-----BEGIN PRIVATE KEY-----${field}TopSecret-----END PRIVATE KEY-----`;
      const nested = `${field}-nested-ciphertext-value`;
      logger.info(
        { [field]: pem, dkimKey: { selector: 'egr20261102abcd', [field]: nested } },
        'dkim',
      );
      const line = out.lines()[0]!;
      const serialized = JSON.stringify(line);
      expect(serialized).not.toContain('TopSecret');
      expect(serialized).not.toContain(nested);
      expect(line[field]).toBe('[REDACTED]');
      expect((line.dkimKey as Record<string, unknown>).selector).toBe('egr20261102abcd');
    },
  );

  it('lists the paths and their *. variants', () => {
    expect(REDACT_PATHS).toEqual(
      expect.arrayContaining([
        'privateKey',
        '*.privateKey',
        'privateKeyPem',
        '*.privateKeyPem',
        'privateKeyCiphertext',
        '*.privateKeyCiphertext',
      ]),
    );
  });
});

describe('redaction of webhook secret ciphertexts (step 6.2 W7)', () => {
  it.each(['secretCiphertext', 'previousSecretCiphertext'])(
    'censors %s at the top level and one level down',
    (field) => {
      const out = capture();
      const logger = createLogger({ service: 'test-svc', destination: out.stream });
      const top = `v1.k1.${field}-top-ciphertext`;
      const nested = `v1.k1.${field}-nested-ciphertext`;
      logger.info({ [field]: top, subscription: { publicId: 'sub-1', [field]: nested } }, 'wh');
      const line = out.lines()[0]!;
      const serialized = JSON.stringify(line);
      expect(serialized).not.toContain(top);
      expect(serialized).not.toContain(nested);
      expect(line[field]).toBe('[REDACTED]');
      expect((line.subscription as Record<string, unknown>)[field]).toBe('[REDACTED]');
      expect((line.subscription as Record<string, unknown>).publicId).toBe('sub-1');
    },
  );

  it('lists the paths and their *. variants', () => {
    expect(REDACT_PATHS).toEqual(
      expect.arrayContaining([
        'secretCiphertext',
        '*.secretCiphertext',
        'previousSecretCiphertext',
        '*.previousSecretCiphertext',
      ]),
    );
  });
});

describe('redaction of mail content (step 3.1 M15)', () => {
  const fields = [
    'subject',
    'filename',
    'originalFilename',
    'envelopeFrom',
    'headerFrom',
    'headerValue',
    'textBody',
    'htmlBody',
    'rawHeaders',
  ];

  it.each(fields)('censors %s at the top level and one level down', (field) => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    const top = `top-${field}-marker-1234`;
    const nested = `nested-${field}-marker-5678`;
    logger.info(
      {
        messageId: '9007199254740993',
        [field]: top,
        attachment: { partIndex: 3, [field]: nested },
      },
      'parsed',
    );
    const line = out.lines()[0]!;
    const serialized = JSON.stringify(line);
    expect(serialized).not.toContain(top);
    expect(serialized).not.toContain(nested);
    expect(line[field]).toBe('[REDACTED]');
    expect(line.attachment).toEqual({ partIndex: 3, [field]: '[REDACTED]' });
    expect(line.messageId).toBe('9007199254740993');
  });

  it('censors structured values (header arrays, body objects) as a whole', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    logger.info(
      {
        rawHeaders: [{ name: 'Subject', value: 'raw-header-marker' }],
        textBody: { s3Key: 'org/1/part/x.text', preview: 'body-marker' },
      },
      'parse',
    );
    const serialized = JSON.stringify(out.lines()[0]);
    expect(serialized).not.toContain('raw-header-marker');
    expect(serialized).not.toContain('body-marker');
  });

  it('censors the envelope sender of a logged event envelope, keeping its ids', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    const payload = { messageId: '77', envelopeFrom: 'sender-marker@example.test', sizeBytes: 10 };
    logger.info({ eventId: 'e-1', payload }, 'envelope');
    logger.warn({ event: { eventId: 'e-2', payload } }, 'nested envelope');
    const [top, nested] = out.lines();
    expect(JSON.stringify([top, nested])).not.toContain('sender-marker');
    expect(top!.payload).toEqual({ messageId: '77', envelopeFrom: '[REDACTED]', sizeBytes: 10 });
    expect((nested!.event as { payload: unknown }).payload).toEqual({
      messageId: '77',
      envelopeFrom: '[REDACTED]',
      sizeBytes: 10,
    });
  });

  it('keeps recipients, from and to, and the existing ids, counts and codes', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    logger.info(
      {
        eventId: 'e-3',
        messageId: '9',
        organizationId: '42',
        status: 'parsed_with_defects',
        limitsExceeded: ['attachment_size'],
        defects: ['invalid_base64'],
        attachmentCount: 2,
        recipients: 3,
        from: 'queued',
        to: 'delivered',
        errName: 'TimeoutError',
        errCode: 'ETIMEDOUT',
      },
      'parsed',
    );
    expect(out.lines()[0]).toMatchObject({
      eventId: 'e-3',
      messageId: '9',
      organizationId: '42',
      status: 'parsed_with_defects',
      limitsExceeded: ['attachment_size'],
      defects: ['invalid_base64'],
      attachmentCount: 2,
      recipients: 3,
      from: 'queued',
      to: 'delivered',
      errName: 'TimeoutError',
      errCode: 'ETIMEDOUT',
    });
  });

  it('lists the paths, their *. variants and the envelope paths, and keeps every earlier path', () => {
    expect(REDACT_PATHS).toEqual(
      expect.arrayContaining([
        ...fields.flatMap((f) => [f, `*.${f}`]),
        'payload.envelopeFrom',
        '*.payload.envelopeFrom',
        'password',
        '*.password',
        'privateKey',
        'req.headers.authorization',
        'headers["x-api-key"]',
      ]),
    );
    for (const absent of ['recipients', 'from', 'to', '*.recipients', '*.from', '*.to']) {
      expect(REDACT_PATHS).not.toContain(absent);
    }
  });
});

describe('setContextTenant', () => {
  it('adds the tenant to the current context and to later log lines', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    runWithContext({ correlationId: 'corr-tenant-0001' }, () => {
      logger.info('before');
      setContextTenant('42');
      expect(getContext()?.tenantId).toBe('42');
      logger.info('after');
    });
    const [before, after] = out.lines();
    expect(before).not.toHaveProperty('tenantId');
    expect(after).toMatchObject({ correlationId: 'corr-tenant-0001', tenantId: '42' });
  });

  it('is a no-op outside a request context', () => {
    expect(() => setContextTenant('7')).not.toThrow();
    expect(getContext()).toBeUndefined();
  });

  it('does not leak the tenant into a sibling context', async () => {
    const seen: (string | undefined)[] = [];
    await Promise.all([
      runWithContext({ correlationId: 'corr-a-000001' }, async () => {
        setContextTenant('1');
        await new Promise((r) => setTimeout(r, 5));
        seen.push(getContext()?.tenantId);
      }),
      runWithContext({ correlationId: 'corr-b-000001' }, async () => {
        await new Promise((r) => setTimeout(r, 10));
        seen.push(getContext()?.tenantId);
      }),
    ]);
    expect(seen).toEqual(['1', undefined]);
  });
});

describe('normalizeCorrelationId', () => {
  it('keeps a well-formed id', () => {
    expect(normalizeCorrelationId('abc-12345678')).toBe('abc-12345678');
  });

  it('replaces malformed or hostile ids', () => {
    const injected = 'x\n{"level":"fatal"}';
    expect(normalizeCorrelationId(injected)).not.toBe(injected);
    expect(normalizeCorrelationId(undefined)).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('setContextRequestId / getRequestId (step 6.1 D1)', () => {
  it('adds the request id to the current context and to later log lines', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    runWithContext({ correlationId: 'corr-request-0001' }, () => {
      logger.info('before');
      expect(getRequestId()).toBeUndefined();
      setContextRequestId('0b9c6a2e-1111-4222-8333-444455556666');
      expect(getRequestId()).toBe('0b9c6a2e-1111-4222-8333-444455556666');
      logger.info('after');
    });
    const [before, after] = out.lines();
    expect(before).not.toHaveProperty('requestId');
    expect(after).toMatchObject({
      correlationId: 'corr-request-0001',
      requestId: '0b9c6a2e-1111-4222-8333-444455556666',
    });
  });

  it('is a no-op outside a request context', () => {
    expect(() => setContextRequestId('r-1')).not.toThrow();
    expect(getRequestId()).toBeUndefined();
  });

  it('keeps sibling contexts apart', async () => {
    const seen: (string | undefined)[] = [];
    await Promise.all([
      runWithContext({ correlationId: 'corr-a-000001' }, async () => {
        setContextRequestId('a');
        await new Promise((r) => setTimeout(r, 5));
        seen.push(getRequestId());
      }),
      runWithContext({ correlationId: 'corr-b-000001' }, async () => {
        await new Promise((r) => setTimeout(r, 1));
        seen.push(getRequestId());
      }),
    ]);
    expect(seen.sort()).toEqual(['a', undefined].sort());
  });
});
