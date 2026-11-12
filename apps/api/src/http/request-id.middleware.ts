import { randomUUID } from 'node:crypto';
import { Injectable, type NestMiddleware } from '@nestjs/common';
import {
  CORRELATION_ID_HEADER,
  getContext,
  getRequestId,
  normalizeCorrelationId,
  runWithContext,
  setContextRequestId,
} from '@email-gateway/logger';
import type { NextFunction, Request, Response } from 'express';

/** Response header carrying the server-minted request id (step 6.1 D1). */
export const REQUEST_ID_HEADER = 'X-Request-Id';

/** `Cache-Control` of every `/api/` response unless the route sets its own (D1, §3.4). */
export const API_CACHE_CONTROL = 'no-store';

type HeaderTarget = Pick<Response, 'getHeader' | 'setHeader' | 'headersSent'>;

/**
 * The request id of the current request: the one the middleware bound to the async context,
 * else the one already on the response, else a new one set on the response (a request that
 * failed before the middleware ran, e.g. a body-parser error). Never read from the request.
 */
export function ensureRequestId(res: HeaderTarget): string {
  const bound = getRequestId();
  if (bound !== undefined) return bound;
  const existing = res.getHeader(REQUEST_ID_HEADER);
  if (typeof existing === 'string' && existing !== '') return existing;
  const minted = randomUUID();
  if (!res.headersSent) res.setHeader(REQUEST_ID_HEADER, minted);
  return minted;
}

/**
 * Mints the request id of every HTTP request (step 6.1 D1): a UUID, never taken from the client
 * (an inbound `X-Request-Id` is ignored; clients use `x-correlation-id` for their own ids). Sets
 * `X-Request-Id` on the response, binds the id to the async log context (every log line and
 * `audit_logs.metadata.requestId`) and sets `Cache-Control: no-store` up front on `/api/`
 * responses (a route may override it). Applied after the correlation-id middleware, whose
 * context it extends; without one (wiring error) it opens its own context.
 */
@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction): void {
    const requestId = randomUUID();
    res.setHeader(REQUEST_ID_HEADER, requestId);
    const path = req.originalUrl ?? req.url;
    if (path.startsWith('/api/') || path === '/api') {
      res.setHeader('Cache-Control', API_CACHE_CONTROL);
    }
    if (getContext()) {
      setContextRequestId(requestId);
      next();
      return;
    }
    const correlation = res.getHeader(CORRELATION_ID_HEADER);
    runWithContext(
      {
        correlationId:
          typeof correlation === 'string' ? correlation : normalizeCorrelationId(undefined),
        requestId,
      },
      next,
    );
  }
}
