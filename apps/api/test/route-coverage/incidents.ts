/**
 * Route coverage of step 8.4 (docs/plan/steps/24-account-takeover-core.md §5.2, §10.4): the 8
 * generic security incident operations with their `@covers` files, the cross-tenant assertion
 * (another organization's incidents, and incidents of a category the caller may not read,
 * answer like unknown ids) and the cursor encoding. Consumed by the route inventory.
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/incidents.e2e.test.ts';
const INT = 'apps/api/integration/incidents.test.ts';
const ISOLATION = 'apps/api/integration/tenant-isolation-incidents.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: ISOLATION,
  ...(cursor && { cursor }),
});

/** The routes of `NEW_IN_8_4` of the `incidents` tag, in §5.2 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/incidents', 'v1'),
  entry('post /api/v1/incidents'),
  entry('get /api/v1/incidents/:incidentId'),
  entry('patch /api/v1/incidents/:incidentId'),
  entry('post /api/v1/incidents/:incidentId/notes'),
  entry('get /api/v1/incidents/:incidentId/timeline', 'v1'),
  entry('get /api/v1/incidents/:incidentId/messages', 'v1'),
  entry('get /api/v1/incidents/:incidentId/report'),
]);
