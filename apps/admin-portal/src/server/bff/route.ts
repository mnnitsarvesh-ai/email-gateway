import 'server-only';
import { portalError } from '@/server/http';
import { logger } from '@/server/log';
import type { BffDeps } from '@/server/upstream';
import { getBffDeps } from './deps';

/** Wraps a BFF handler: resolves its dependencies and turns unexpected failures into a 500. */
export function bffRoute(
  handler: (request: Request, deps: BffDeps) => Promise<Response>,
): (request: Request) => Promise<Response> {
  return async (request: Request) => {
    try {
      return await handler(request, await getBffDeps());
    } catch (error) {
      logger.error('bff route failed', {
        path: new URL(request.url).pathname,
        errorName: error instanceof Error ? error.name : 'unknown',
        errorMessage:
          error instanceof Error && error.name === 'PortalConfigError' ? error.message : undefined,
      });
      return portalError(500, 'internal_error', 'Internal error');
    }
  };
}
