import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { getContext, normalizeCorrelationId, runWithContext, setContextTenant } from './context';
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
