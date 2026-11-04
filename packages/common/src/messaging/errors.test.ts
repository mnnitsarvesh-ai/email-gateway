import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import {
  amqpReplyName,
  BrokerUnavailableError,
  defaultClassify,
  errorFields,
  isTransientInfrastructureError,
  NonRetryableError,
} from './errors';

const known = (code: string, meta?: Record<string, unknown>) =>
  new Prisma.PrismaClientKnownRequestError('query failed: secret value', {
    code,
    clientVersion: '6.0.0',
    ...(meta ? { meta } : {}),
  });

describe('isTransientInfrastructureError', () => {
  it.each(['P1001', 'P1002', 'P1008', 'P1017', 'P2024', 'P2028', 'P2034'])(
    'Prisma %s is transient',
    (code) => {
      expect(isTransientInfrastructureError(known(code))).toBe(true);
    },
  );

  it('Prisma data errors are not transient', () => {
    for (const code of ['P2002', 'P2003', 'P2000', 'P2025']) {
      expect(isTransientInfrastructureError(known(code))).toBe(false);
    }
  });

  it('MySQL lock wait (1205) and deadlock (1213) of a raw query are transient', () => {
    expect(isTransientInfrastructureError(known('P2010', { code: '1205' }))).toBe(true);
    expect(isTransientInfrastructureError(known('P2010', { code: 1213 }))).toBe(true);
    expect(isTransientInfrastructureError(known('P2010', { code: '1062' }))).toBe(false);
    expect(isTransientInfrastructureError({ errno: 1213, code: 'ER_LOCK_DEADLOCK' })).toBe(true);
  });

  it('Prisma initialization and unknown-request errors are transient', () => {
    expect(
      isTransientInfrastructureError(new Prisma.PrismaClientInitializationError('down', '6.0.0')),
    ).toBe(true);
    expect(
      isTransientInfrastructureError(
        new Prisma.PrismaClientUnknownRequestError('x', { clientVersion: '6.0.0' }),
      ),
    ).toBe(true);
  });

  it('AWS SDK 5xx, 429 and throttling are transient; other 4xx are not', () => {
    const aws = (name: string, httpStatusCode: number, extra: object = {}) =>
      Object.assign(new Error('aws'), { name, $metadata: { httpStatusCode }, ...extra });
    expect(isTransientInfrastructureError(aws('InternalError', 500))).toBe(true);
    expect(isTransientInfrastructureError(aws('ServiceUnavailable', 503))).toBe(true);
    expect(isTransientInfrastructureError(aws('TooManyRequestsException', 429))).toBe(true);
    expect(isTransientInfrastructureError(aws('SlowDown', 400))).toBe(true);
    expect(
      isTransientInfrastructureError(aws('X', 400, { $retryable: { throttling: true } })),
    ).toBe(true);
    expect(isTransientInfrastructureError(aws('NoSuchKey', 404))).toBe(false);
    expect(isTransientInfrastructureError(aws('AccessDenied', 403))).toBe(false);
  });

  it.each(['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN', 'UND_ERR_SOCKET'])(
    'socket code %s is transient',
    (code) => {
      expect(isTransientInfrastructureError(Object.assign(new Error('x'), { code }))).toBe(true);
    },
  );

  it('AbortError, TimeoutError and BrokerUnavailableError are transient', () => {
    expect(isTransientInfrastructureError(new DOMException('aborted', 'AbortError'))).toBe(true);
    expect(
      isTransientInfrastructureError(Object.assign(new Error('t'), { name: 'TimeoutError' })),
    ).toBe(true);
    expect(isTransientInfrastructureError(new BrokerUnavailableError())).toBe(true);
  });

  it('follows cause (bounded) and rejects non-objects', () => {
    const wrapped = new Error('outer', {
      cause: new Error('inner', { cause: { code: 'ECONNRESET' } }),
    });
    expect(isTransientInfrastructureError(wrapped)).toBe(true);
    const loop: { cause?: unknown } = {};
    loop.cause = loop;
    expect(isTransientInfrastructureError(loop)).toBe(false);
    expect(isTransientInfrastructureError('ECONNRESET')).toBe(false);
    expect(isTransientInfrastructureError(null)).toBe(false);
    expect(isTransientInfrastructureError(new TypeError('bug'))).toBe(false);
  });
});

describe('defaultClassify', () => {
  it('fatal for NonRetryableError, transient for outages, retryable otherwise', () => {
    expect(defaultClassify(new NonRetryableError('message_missing'))).toBe('fatal');
    expect(defaultClassify(known('P1001'))).toBe('transient');
    expect(defaultClassify(new Error('bug'))).toBe('retryable');
    expect(defaultClassify(known('P2002'))).toBe('retryable');
  });
});

describe('errorFields', () => {
  it('returns token name and code only, never the message', () => {
    expect(errorFields(known('P1001'))).toEqual({
      errName: 'PrismaClientKnownRequestError',
      errCode: 'P1001',
    });
    expect(errorFields(Object.assign(new Error('x'), { code: 'has spaces and text' }))).toEqual({
      errName: 'Error',
    });
    expect(errorFields({ name: 'Bad Name With Spaces', code: 404 })).toEqual({ errCode: '404' });
    expect(errorFields('a string')).toEqual({ errName: 'string' });
    expect(JSON.stringify(errorFields(known('P1001')))).not.toContain('secret');
  });
});

describe('NonRetryableError / BrokerUnavailableError / amqpReplyName', () => {
  it('keeps codes as tokens', () => {
    expect(new NonRetryableError('bad_code').code).toBe('bad_code');
    expect(new NonRetryableError('Bad Code!').message).toContain('handler_rejected');
    expect(new BrokerUnavailableError('ACCESS_REFUSED').code).toBe('ACCESS_REFUSED');
    expect(new BrokerUnavailableError('free text here').code).toBe('disconnected');
  });

  it('maps reply codes to names, never broker text', () => {
    expect(amqpReplyName({ code: 403, message: 'ACCESS_REFUSED - user eg-x ...' })).toBe(
      'ACCESS_REFUSED',
    );
    expect(amqpReplyName(404)).toBe('NOT_FOUND');
    expect(amqpReplyName(312)).toBe('NO_ROUTE');
    expect(amqpReplyName({ code: 999 })).toBe('amqp_999');
    expect(amqpReplyName({}, 'x')).toBe('x');
  });
});
