'use client';

import { useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';

/**
 * `GET /quarantine/catalog` (enums, limits, self-service switches, `downloadEnabled`). Static per
 * deployment and tenant settings, so it is cached for five minutes.
 */
export function useQuarantineCatalog() {
  const allowed = useCan('QuarantineToolsController_catalog_v1');
  return useApiQuery('QuarantineToolsController_catalog_v1', undefined, {
    staleTime: 300_000,
    enabled: allowed,
  });
}
