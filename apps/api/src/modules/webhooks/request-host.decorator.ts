import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';

/**
 * The host name the request reached (Express `req.hostname`: the `Host` header, or
 * `X-Forwarded-Host` behind a trusted proxy hop). Used only to REFUSE webhook endpoints that
 * point back at the api itself (W6); it never grants anything.
 */
export const RequestHost = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string | null => {
    const host = context.switchToHttp().getRequest<Request>().hostname;
    return typeof host === 'string' && host !== '' ? host.toLowerCase() : null;
  },
);
