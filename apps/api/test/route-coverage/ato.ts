/**
 * Route coverage of step 8.4 (docs/plan/steps/24-account-takeover-core.md §5.1, §10.4): the 26
 * account takeover operations with the test files that carry their `@covers` marker, their
 * cross-tenant assertion (another organization's accounts, contexts, incidents and responses
 * answer like unknown ids; lists never include foreign rows) and their cursor encoding (every
 * list is a signed v1 list). Consumed by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/ato.e2e.test.ts';
const INT = 'apps/api/integration/ato.test.ts';
const ISOLATION = 'apps/api/integration/tenant-isolation-ato.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: ISOLATION,
  ...(cursor && { cursor }),
});

/** The routes of `NEW_IN_8_4` of the `ato` tag, in §5.1 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/ato/overview'),
  entry('get /api/v1/ato/attention'),
  entry('get /api/v1/ato/accounts', 'v1'),
  entry('get /api/v1/ato/accounts/:accountId'),
  entry('patch /api/v1/ato/accounts/:accountId'),
  entry('get /api/v1/ato/accounts/:accountId/signals', 'v1'),
  entry('get /api/v1/ato/accounts/:accountId/auth-events', 'v1'),
  entry('get /api/v1/ato/accounts/:accountId/activity'),
  entry('get /api/v1/ato/accounts/:accountId/score-history', 'v1'),
  entry('put /api/v1/ato/accounts/:accountId/override'),
  entry('post /api/v1/ato/accounts/:accountId/override/clear'),
  entry('post /api/v1/ato/accounts/:accountId/trusted-contexts'),
  entry('delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId'),
  entry('get /api/v1/ato/incidents/:incidentId/signals', 'v1'),
  entry('get /api/v1/ato/incidents/:incidentId/auth-events', 'v1'),
  entry('post /api/v1/ato/incidents/:incidentId/responses'),
  entry('get /api/v1/ato/responses', 'v1'),
  entry('get /api/v1/ato/responses/:responseId'),
  entry('post /api/v1/ato/responses/:responseId/approve'),
  entry('post /api/v1/ato/responses/:responseId/reject'),
  entry('post /api/v1/ato/responses/:responseId/cancel'),
  entry('post /api/v1/ato/responses/:responseId/rollback'),
  entry('get /api/v1/ato/restrictions', 'v1'),
  entry('get /api/v1/ato/settings'),
  entry('put /api/v1/ato/settings'),
  entry('get /api/v1/ato/rules'),
]);
