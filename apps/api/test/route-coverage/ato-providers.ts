/**
 * Route coverage of step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6, §11.4): the 13
 * identity-provider operations with the test files that carry their `@covers` marker and their
 * cross-tenant assertion (another organization's integrations, connections and accounts answer
 * like unknown ids; lists never include foreign rows; the directory key is checked without
 * disclosing the other organization). No list of this step is paged (a handful of integrations
 * per organization). Consumed by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/ato-providers.e2e.test.ts';
const INT = 'apps/api/integration/ato-providers.test.ts';
const ISOLATION = 'apps/api/integration/tenant-isolation-ato-providers.test.ts';

const entry = (route: string): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: ISOLATION,
});

/** The routes of `NEW_IN_8_5` of the `ato` tag, in §6 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/ato/providers'),
  entry('get /api/v1/ato/providers/requirements'),
  entry('get /api/v1/ato/providers/connections'),
  entry('post /api/v1/ato/providers'),
  entry('get /api/v1/ato/providers/:integrationId'),
  entry('patch /api/v1/ato/providers/:integrationId'),
  entry('post /api/v1/ato/providers/:integrationId/pause'),
  entry('post /api/v1/ato/providers/:integrationId/resume'),
  entry('post /api/v1/ato/providers/:integrationId/health-check'),
  entry('post /api/v1/ato/providers/:integrationId/backfill'),
  entry('delete /api/v1/ato/providers/:integrationId'),
  entry('get /api/v1/ato/accounts/:accountId/mailbox-state'),
  entry('post /api/v1/ato/accounts/:accountId/mailbox-state/refresh'),
]);
