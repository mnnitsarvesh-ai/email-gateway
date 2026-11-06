import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Logger } from '@email-gateway/logger';
import { PublicExceptionFilter } from './public-exception.filter';
import { securityHeaders } from './security-headers';

/**
 * Public listener setup (U14): the security headers on every response (before routing, so 404s
 * and errors carry them too), the client address from CLICK_TRUST_PROXY hops, no
 * `X-Powered-By`, HTML error pages, graceful shutdown. No URI versioning: the public paths are
 * fixed (`/c/:token`).
 */
export function configurePublicApp(
  app: NestExpressApplication,
  options: { trustProxyHops: number; hsts: boolean; logger: Logger },
): void {
  app.disable('x-powered-by');
  app.set('trust proxy', options.trustProxyHops > 0 ? options.trustProxyHops : false);
  app.set('etag', false);
  for (const middleware of securityHeaders({ hsts: options.hsts })) app.use(middleware);
  app.useGlobalFilters(new PublicExceptionFilter(options.logger));
  app.enableShutdownHooks();
}
