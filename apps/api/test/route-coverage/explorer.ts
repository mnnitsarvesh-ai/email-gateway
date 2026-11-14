/**
 * Route coverage of step 7.2 (docs/plan/steps/21-email-explorer-details.md §3.3): the routes the
 * Email Explorer and Email Details add — WP1: the five saved views routes; WP2 adds the headers
 * and reveal routes — with the test files that carry their `@covers` marker, their cross-tenant
 * assertion and their cursor encoding. The changed `GET /messages` and `GET /audit/logs` keep
 * their entries in messages.ts and insights.ts. Consumed by the route inventory
 * (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test';
const INT = 'apps/api/integration';
const ISOLATION = `${INT}/tenant-isolation-messages-data.test.ts`;
const SAVED_VIEWS_E2E = `${E2E}/saved-views.e2e.test.ts`;
const SAVED_VIEWS_INT = `${INT}/saved-views.test.ts`;
const SENSITIVE_E2E = `${E2E}/messages-sensitive.e2e.test.ts`;
const SENSITIVE_INT = `${INT}/messages-sensitive.test.ts`;

export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  {
    route: 'get /api/v1/saved-views',
    e2e: SAVED_VIEWS_E2E,
    integration: SAVED_VIEWS_INT,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'post /api/v1/saved-views',
    e2e: SAVED_VIEWS_E2E,
    integration: SAVED_VIEWS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/saved-views/:viewId',
    e2e: SAVED_VIEWS_E2E,
    integration: SAVED_VIEWS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'put /api/v1/saved-views/:viewId',
    e2e: SAVED_VIEWS_E2E,
    integration: SAVED_VIEWS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'delete /api/v1/saved-views/:viewId',
    e2e: SAVED_VIEWS_E2E,
    integration: SAVED_VIEWS_INT,
    crossTenant: ISOLATION,
  },
  // WP2: the stored headers and the audited reveal operations (§2 E6, E7).
  {
    route: 'get /api/v1/messages/:messageId/headers',
    e2e: SENSITIVE_E2E,
    integration: SENSITIVE_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/messages/reveal',
    e2e: SENSITIVE_E2E,
    integration: SENSITIVE_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/messages/:messageId/reveal',
    e2e: SENSITIVE_E2E,
    integration: SENSITIVE_INT,
    crossTenant: ISOLATION,
  },
]);
