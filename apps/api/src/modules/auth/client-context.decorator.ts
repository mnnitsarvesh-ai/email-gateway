import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import { clientIp } from '../../http/client-ip';
import type { ClientContext } from './services/session.service';

const MAX_USER_AGENT = 512;

export function clientContextOf(req: Request): ClientContext {
  const ua = req.headers['user-agent'];
  return {
    ip: clientIp(req),
    userAgent: typeof ua === 'string' && ua !== '' ? ua.slice(0, MAX_USER_AGENT) : null,
  };
}

/** The caller's IP (trust-proxy aware) and user agent. */
export const Client = createParamDecorator((_data: unknown, context: ExecutionContext) =>
  clientContextOf(context.switchToHttp().getRequest<Request>()),
);
