import { Injectable, type NestMiddleware } from '@nestjs/common';
import {
  CORRELATION_ID_HEADER,
  normalizeCorrelationId,
  runWithContext,
} from '@email-gateway/logger';
import type { NextFunction, Request, Response } from 'express';

/**
 * Accepts a well-formed inbound `x-correlation-id` or mints one, echoes it on the response and
 * binds it to async context so every log line and outgoing event for this request carries it.
 */
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction): void {
    const correlationId = normalizeCorrelationId(req.header(CORRELATION_ID_HEADER));
    res.setHeader(CORRELATION_ID_HEADER, correlationId);
    runWithContext({ correlationId }, next);
  }
}
