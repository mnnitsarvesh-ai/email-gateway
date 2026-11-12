import type { ArgumentsHost } from '@nestjs/common';
import { HttpStatus } from '@nestjs/common';
import { runWithContext } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { CodedExceptionFilter, CodedHttpException, codedErrorSchema } from './coded-exception';

function hostFor(res: { status: (n: number) => unknown; json: (b: unknown) => unknown }) {
  const headers: Record<string, string> = {};
  Object.assign(res, {
    headersSent: false,
    getHeader: (name: string) => headers[name],
    setHeader: (name: string, value: string) => (headers[name] = value),
  });
  return { switchToHttp: () => ({ getResponse: () => res }) } as unknown as ArgumentsHost;
}

describe('CodedHttpException and CodedExceptionFilter', () => {
  it('renders the standard body plus code and details', () => {
    const json = vi.fn();
    const res = { status: vi.fn(() => res), json };
    const error = new CodedHttpException(HttpStatus.CONFLICT, 'message_state_conflict', 'No', {
      currentState: 'delivered',
      currentVersion: 4,
    });
    runWithContext({ correlationId: 'corr-12345678', requestId: 'req-1' }, () =>
      new CodedExceptionFilter().catch(error, hostFor(res)),
    );
    expect(res.status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith({
      statusCode: 409,
      error: 'CONFLICT',
      code: 'message_state_conflict',
      message: 'No',
      currentState: 'delivered',
      currentVersion: 4,
      correlationId: 'corr-12345678',
      requestId: 'req-1',
    });
  });

  it('mints a request id (and sets X-Request-Id) when none is bound to the context', () => {
    const json = vi.fn();
    const res = { status: vi.fn(() => res), json };
    const host = hostFor(res);
    new CodedExceptionFilter().catch(
      new CodedHttpException(HttpStatus.NOT_FOUND, 'message_not_found', 'Message not found'),
      host,
    );
    const body = json.mock.calls[0]![0] as { requestId: string };
    expect(body.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect((res as unknown as { getHeader: (n: string) => string }).getHeader('X-Request-Id')).toBe(
      body.requestId,
    );
  });

  it('details never override the standard fields', () => {
    const json = vi.fn();
    const res = { status: vi.fn(() => res), json };
    new CodedExceptionFilter().catch(
      new CodedHttpException(HttpStatus.NOT_FOUND, 'message_not_found', 'Message not found', {
        code: 'forged',
        statusCode: 200,
      }),
      hostFor(res),
    );
    expect(json.mock.calls[0]![0]).toMatchObject({ statusCode: 404, code: 'message_not_found' });
  });

  it('documents the codes and detail properties', () => {
    const schema = codedErrorSchema(409, ['a', 'b'], { currentVersion: { type: 'integer' } });
    expect(schema.required).toEqual(['statusCode', 'error', 'code', 'message']);
    expect(schema.properties).toMatchObject({
      requestId: { type: 'string', format: 'uuid' },
      statusCode: { enum: [409] },
      code: { enum: ['a', 'b'] },
      currentVersion: { type: 'integer' },
    });
  });
});
