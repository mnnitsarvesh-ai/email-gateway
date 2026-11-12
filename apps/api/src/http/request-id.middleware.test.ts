import { EventEmitter } from 'node:events';
import { getContext, getRequestId, runWithContext } from '@email-gateway/logger';
import type { Request, Response } from 'express';
import { describe, expect, it, vi } from 'vitest';
import {
  HttpMetricsMiddleware,
  routeLabel,
  statusClass,
  UNMATCHED_ROUTE,
} from './http-metrics.middleware';
import { ensureRequestId, REQUEST_ID_HEADER, RequestIdMiddleware } from './request-id.middleware';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function response() {
  const headers: Record<string, string> = {};
  return {
    headers,
    res: {
      headersSent: false,
      getHeader: (n: string) => headers[n],
      setHeader: (n: string, v: string) => (headers[n] = v),
    } as unknown as Response,
  };
}

describe('RequestIdMiddleware (step 6.1 D1)', () => {
  it('mints a UUID, ignores an inbound X-Request-Id and binds it to the context', () => {
    const { res, headers } = response();
    const req = { originalUrl: '/api/v1/meta', headers: { 'x-request-id': 'client-chosen' } };
    let seen: string | undefined;
    runWithContext({ correlationId: 'corr-0000001' }, () =>
      new RequestIdMiddleware().use(req as unknown as Request, res, () => {
        seen = getRequestId();
      }),
    );
    expect(headers[REQUEST_ID_HEADER]).toMatch(UUID);
    expect(headers[REQUEST_ID_HEADER]).not.toBe('client-chosen');
    expect(seen).toBe(headers[REQUEST_ID_HEADER]);
    expect(headers['Cache-Control']).toBe('no-store');
  });

  it('sets Cache-Control only on /api paths and mints a new id per request', () => {
    const a = response();
    const b = response();
    runWithContext({ correlationId: 'corr-0000002' }, () => {
      new RequestIdMiddleware().use(
        { originalUrl: '/health/live' } as Request,
        a.res,
        () => undefined,
      );
    });
    runWithContext({ correlationId: 'corr-0000003' }, () => {
      new RequestIdMiddleware().use({ originalUrl: '/metrics' } as Request, b.res, () => undefined);
    });
    expect(a.headers['Cache-Control']).toBeUndefined();
    expect(a.headers[REQUEST_ID_HEADER]).not.toBe(b.headers[REQUEST_ID_HEADER]);
  });

  it('opens its own context when the correlation middleware did not run', () => {
    const { res, headers } = response();
    headers['x-correlation-id'] = 'corr-fallback-1';
    let context: ReturnType<typeof getContext>;
    new RequestIdMiddleware().use({ originalUrl: '/api/v1/x' } as Request, res, () => {
      context = getContext();
    });
    expect(context!).toEqual({
      correlationId: 'corr-fallback-1',
      requestId: headers[REQUEST_ID_HEADER],
    });
  });

  it('ensureRequestId prefers the context, then the header, then mints and sets one', () => {
    const { res, headers } = response();
    runWithContext({ correlationId: 'c-00000001', requestId: 'ctx-id' }, () =>
      expect(ensureRequestId(res)).toBe('ctx-id'),
    );
    headers[REQUEST_ID_HEADER] = 'header-id';
    expect(ensureRequestId(res)).toBe('header-id');
    delete headers[REQUEST_ID_HEADER];
    const minted = ensureRequestId(res);
    expect(minted).toMatch(UUID);
    expect(headers[REQUEST_ID_HEADER]).toBe(minted);
  });
});

describe('HttpMetricsMiddleware (step 6.1 D16)', () => {
  it('labels by method, route template and status class, never by path', () => {
    const inc = vi.fn();
    const observe = vi.fn();
    const middleware = new HttpMetricsMiddleware({
      httpRequests: { inc },
      httpDuration: { observe },
    } as never);
    const res = Object.assign(new EventEmitter(), { statusCode: 404 }) as unknown as Response;
    const req = { method: 'get', baseUrl: '', route: undefined } as unknown as Request;
    const next = vi.fn();
    middleware.use(req, res, next);
    expect(next).toHaveBeenCalled();
    (req as { route?: unknown }).route = { path: '/api/v1/messages/:messageId' };
    (res as unknown as { statusCode: number }).statusCode = 200;
    res.emit('finish');
    res.emit('close');
    expect(inc).toHaveBeenCalledTimes(1);
    expect(inc).toHaveBeenCalledWith({
      method: 'GET',
      route: '/api/v1/messages/:messageId',
      status_class: '2xx',
    });
    expect(observe).toHaveBeenCalledWith(
      { method: 'GET', route: '/api/v1/messages/:messageId' },
      expect.any(Number),
    );
  });

  it('labels requests no route served as unmatched', () => {
    expect(routeLabel({ route: undefined, baseUrl: '' } as Request)).toBe(UNMATCHED_ROUTE);
    expect(statusClass(503)).toBe('5xx');
    expect(statusClass(42)).toBe('other');
  });
});
