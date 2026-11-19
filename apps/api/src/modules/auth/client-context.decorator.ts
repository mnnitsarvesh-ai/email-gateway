import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import { clientIp } from '../../http/client-ip';
import { viaTrustedForwarder } from '../../http/trusted-forwarder.middleware';
import type { ClientContext } from './services/session.service';

const MAX_USER_AGENT = 512;

export function clientContextOf(req: Request): ClientContext {
  const ua = req.headers['user-agent'];
  return {
    ip: clientIp(req),
    userAgent: typeof ua === 'string' && ua !== '' ? ua.slice(0, MAX_USER_AGENT) : null,
    channel: viaTrustedForwarder(req) ? 'portal' : 'api',
  };
}

/** The caller's IP (trust-proxy aware), user agent and channel (portal BFF or direct api). */
export const Client = createParamDecorator((_data: unknown, context: ExecutionContext) =>
  clientContextOf(context.switchToHttp().getRequest<Request>()),
);
