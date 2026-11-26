/**
 * Route coverage of step API-1 (docs/plan/steps/35-api-mode-protection.md D12, §9.4): the 16
 * API-mode operations (14 under the `api-mode` tag, the two public Graph callbacks of
 * `provider-notifications`) with the test files that carry their `@covers` marker, their
 * cross-tenant assertion (another organization's connections, mailboxes, detections, domains and
 * organization answer like unknown ids; the tenant always comes from the authenticated scope) and
 * their cursor encoding (the mailbox and detection lists are signed v1 lists). The callbacks are
 * public (no tenant input: a stored subscription id selects the mailbox). Consumed by the route
 * inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/api-mode.e2e.test.ts';
const INT = 'apps/api/integration/api-mode.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: INT,
  ...(cursor && { cursor }),
});

const callback = (route: string): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: {
    na: 'public',
    why: 'Graph callback without a principal: only a stored subscription id plus the client-state hash select a mailbox',
  },
});

/** The routes of `NEW_IN_API_1` (route inventory), in D12 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/organizations/:id/protection-mode'),
  entry('put /api/v1/organizations/:id/protection-mode'),
  entry('put /api/v1/domains/:domainId/protection-mode'),
  entry('get /api/v1/api-mode/overview'),
  entry('get /api/v1/api-mode/connections'),
  entry('get /api/v1/api-mode/connections/:connectionId'),
  entry('get /api/v1/api-mode/connections/:connectionId/setup-guide'),
  entry('put /api/v1/api-mode/connections/:connectionId/settings'),
  entry('post /api/v1/api-mode/connections/:connectionId/inventory-sync'),
  entry('get /api/v1/api-mode/mailboxes', 'v1'),
  entry('get /api/v1/api-mode/mailboxes/:mailboxId'),
  entry('post /api/v1/api-mode/mailboxes/:mailboxId/resync'),
  entry('get /api/v1/api-mode/detections', 'v1'),
  entry('get /api/v1/api-mode/detections/:detectionId'),
  callback('post /api/v1/provider-notifications/graph'),
  callback('post /api/v1/provider-notifications/graph/lifecycle'),
]);
