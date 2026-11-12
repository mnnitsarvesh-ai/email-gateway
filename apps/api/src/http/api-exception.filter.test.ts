import {
  type ArgumentsHost,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Logger,
  NotFoundException,
  PayloadTooLargeException,
  ServiceUnavailableException,
  UnauthorizedException,
  UnprocessableEntityException,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { runWithContext } from '@email-gateway/logger';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiExceptionFilter, defaultErrorCode } from './api-exception.filter';
import {
  CodedExceptionFilter,
  CodedForbiddenException,
  CodedHttpException,
} from './coded-exception';
import { IdempotencyInProgressException } from './idempotency/idempotency-key';

interface FakeResponse {
  statusCode?: number;
  body?: Record<string, unknown>;
  headers: Record<string, string>;
  headersSent: boolean;
}

function render(
  exception: unknown,
  options: { route?: boolean; filter?: 'api' | 'coded' } = {},
): FakeResponse {
  const out: FakeResponse = { headers: {}, headersSent: false };
  const res = {
    get headersSent() {
      return out.headersSent;
    },
    getHeader: (name: string) => out.headers[name],
    setHeader: (name: string, value: string) => (out.headers[name] = value),
    status(code: number) {
      out.statusCode = code;
      return res;
    },
    json(body: Record<string, unknown>) {
      out.body = body;
      out.headersSent = true;
      return res;
    },
  };
  const req = options.route === false ? {} : { route: { path: '/api/v1/x' } };
  const host = {
    switchToHttp: () => ({ getResponse: () => res, getRequest: () => req }),
  } as unknown as ArgumentsHost;
  runWithContext({ correlationId: 'corr-0000001', requestId: 'req-0000001' }, () => {
    if (options.filter === 'coded') {
      new CodedExceptionFilter().catch(exception as CodedHttpException, host);
    } else {
      new ApiExceptionFilter().catch(exception, host);
    }
  });
  return out;
}

describe('ApiExceptionFilter (step 6.1 D1, D2, §3.2)', () => {
  let error: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    error = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it.each([
    [new BadRequestException(['name: Required']), 400, 'validation_failed', ['name: Required']],
    [new UnauthorizedException(), 401, 'unauthorized', 'Unauthorized'],
    [new ForbiddenException(), 403, 'forbidden', 'Forbidden'],
    [new NotFoundException('Organization not found'), 404, 'not_found', 'Organization not found'],
    [
      new ConflictException('Organization limit reached: max_users'),
      409,
      'conflict',
      'Organization limit reached: max_users',
    ],
    [new PayloadTooLargeException(), 413, 'payload_too_large', 'Payload Too Large'],
    [new UnsupportedMediaTypeException(), 415, 'unsupported_media_type', 'Unsupported Media Type'],
    [new UnprocessableEntityException('No'), 422, 'unprocessable', 'No'],
    [new HttpException('Too many requests', 429), 429, 'rate_limited', 'Too many requests'],
    [
      new ServiceUnavailableException('Service temporarily unavailable'),
      503,
      'service_unavailable',
      'Service temporarily unavailable',
    ],
    [new HttpException('Gone', HttpStatus.GONE), 410, 'gone', 'Gone'],
  ])('renders %s with its default code', (exception, status, code, message) => {
    const out = render(exception);
    expect(out.statusCode).toBe(status);
    expect(out.body).toEqual({
      statusCode: status,
      error: HttpStatus[status],
      code,
      message,
      correlationId: 'corr-0000001',
      requestId: 'req-0000001',
    });
  });

  it('codes a 404 of a path no route serves as route_not_found', () => {
    const out = render(new NotFoundException('Cannot GET /api/v1/nope'), { route: false });
    expect(out.body).toMatchObject({ statusCode: 404, code: 'route_not_found' });
    expect(render(new NotFoundException('x')).body).toMatchObject({ code: 'not_found' });
  });

  it('renders coded exceptions exactly like the controller-scoped CodedExceptionFilter', () => {
    const coded = new CodedHttpException(HttpStatus.CONFLICT, 'message_version_conflict', 'No', {
      currentVersion: 4,
      code: 'forged',
    });
    const global = render(coded);
    const scoped = render(coded, { filter: 'coded' });
    expect(global.body).toEqual(scoped.body);
    expect(JSON.stringify(global.body)).toBe(JSON.stringify(scoped.body));
    expect(global.body).toEqual({
      currentVersion: 4,
      statusCode: 409,
      error: 'CONFLICT',
      code: 'message_version_conflict',
      message: 'No',
      correlationId: 'corr-0000001',
      requestId: 'req-0000001',
    });
  });

  it('renders the coded 403s of the permissions guard with their codes', () => {
    expect(render(new CodedForbiddenException('mfa_required', 'MFA required')).body).toMatchObject({
      statusCode: 403,
      code: 'mfa_required',
      message: 'MFA required',
    });
  });

  it('sets Retry-After of an in-progress idempotency conflict', () => {
    const out = render(new IdempotencyInProgressException(42));
    expect(out.statusCode).toBe(409);
    expect(out.headers['Retry-After']).toBe('42');
    expect(out.body).toMatchObject({ code: 'idempotency_request_in_progress' });
    expect(
      render(new IdempotencyInProgressException(7), { filter: 'coded' }).headers,
    ).toMatchObject({ 'Retry-After': '7' });
  });

  it('renders anything else as a generic 500 internal_error and logs it, never leaking internals', () => {
    const out = render(new Error('SELECT secret FROM table failed at db.internal:3306'));
    expect(out.statusCode).toBe(500);
    expect(out.body).toEqual({
      statusCode: 500,
      error: 'INTERNAL_SERVER_ERROR',
      code: 'internal_error',
      message: 'Internal server error',
      correlationId: 'corr-0000001',
      requestId: 'req-0000001',
    });
    expect(JSON.stringify(out.body)).not.toContain('secret');
    expect(error).toHaveBeenCalledWith(expect.objectContaining({ err: expect.any(Error) }));
  });

  it('logs 5xx HttpExceptions and leaves an already sent response alone', () => {
    render(new ServiceUnavailableException());
    expect(error).toHaveBeenCalled();
    error.mockClear();
    const out: FakeResponse = { headers: {}, headersSent: true };
    const res = { headersSent: true, status: vi.fn(), json: vi.fn() };
    new ApiExceptionFilter().catch(new Error('late'), {
      switchToHttp: () => ({ getResponse: () => res, getRequest: () => ({}) }),
    } as unknown as ArgumentsHost);
    expect(res.status).not.toHaveBeenCalled();
    expect(out.body).toBeUndefined();
    expect(error).toHaveBeenCalledTimes(1);
  });

  it('uses the lower-cased status name for unlisted 4xx and internal_error for unlisted 5xx', () => {
    expect(defaultErrorCode(405)).toBe('method_not_allowed');
    expect(defaultErrorCode(502)).toBe('internal_error');
    expect(defaultErrorCode(499)).toBe('error');
  });
});
