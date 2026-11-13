import 'server-only';
import { getServerConfig } from '@/server/config';
import { logger } from '@/server/log';
import type { BffDeps, UpstreamFetch } from '@/server/upstream';

let pending: Promise<BffDeps> | undefined;

/**
 * Dependencies of every BFF route. The dev fixture layer (design P9) replaces the upstream
 * `fetch` only when `NODE_ENV === 'development'` (inlined by Next at build time, so production
 * builds drop the branch and emit no mock chunk) and `PORTAL_DEV_MOCKS=enabled`.
 */
export function getBffDeps(): Promise<BffDeps> {
  pending ??= (async () => {
    const config = getServerConfig();
    let upstream: UpstreamFetch = (url, init) => fetch(url, init);
    let devMocks = false;
    if (process.env.NODE_ENV === 'development' && config.PORTAL_DEV_MOCKS === 'enabled') {
      const mocks = await import('@/server/dev-mocks');
      upstream = mocks.createMockFetch();
      devMocks = true;
      logger.warn('dev fixture mode: the BFF answers from synthetic fixtures, not the api');
    }
    return { config, fetch: upstream, logger, now: () => Date.now(), devMocks };
  })();
  pending.catch(() => {
    pending = undefined;
  });
  return pending;
}
