/**
 * Route coverage of step 8.6 (docs/plan/steps/27-journal-intake-and-archive-split.md D11, §9.4):
 * the 12 journaling operations with the test files that carry their `@covers` marker, their
 * cross-tenant assertion (another organization's intake sources answer like unknown ids; the
 * tenant always comes from the authenticated scope) and their cursor encoding (the intake source
 * list is a signed v1 list). Consumed by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/journaling.e2e.test.ts';
const INT = 'apps/api/integration/journaling.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: INT,
  ...(cursor && { cursor }),
});

/** The routes of `NEW_IN_8_6` (route inventory), in D11 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/journaling/settings'),
  entry('put /api/v1/journaling/settings'),
  entry('get /api/v1/journaling/intake-sources', 'v1'),
  entry('post /api/v1/journaling/intake-sources'),
  entry('get /api/v1/journaling/intake-sources/:sourceId'),
  entry('patch /api/v1/journaling/intake-sources/:sourceId'),
  entry('delete /api/v1/journaling/intake-sources/:sourceId'),
  entry('post /api/v1/journaling/intake-sources/:sourceId/rotate-address'),
  entry('get /api/v1/journaling/intake-sources/:sourceId/wizard'),
  entry('get /api/v1/journaling/intake-sources/:sourceId/setup-guide'),
  entry('post /api/v1/journaling/intake-sources/:sourceId/attestations'),
  entry('get /api/v1/journaling/status'),
]);
