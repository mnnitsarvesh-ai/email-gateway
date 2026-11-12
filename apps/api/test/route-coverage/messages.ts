/**
 * Route coverage of step 6.1 WP2 (docs/plan/steps/18-rest-api.md §3.8): every messages data route
 * (list, detail, recipients, attachments and the hash search, URLs, URL clicks, recipient
 * suppressions) and the pre-6.1 messages-module routes (lifecycle 4, scans 1) with the test
 * files that carry their `@covers` marker, their cross-tenant assertion and their cursor
 * encoding. Consumed by the WP5 route inventory (`route-coverage/index.ts`).
 */

/** The §3.8 manifest entry (structurally identical to the one WP5's index exports). */
export interface RouteCoverage {
  /** `get /api/v1/messages/:messageId` — Nest path syntax, lower-case method. */
  route: string;
  /** Repo-relative test files that contain the marker comment `@covers <route>`. */
  e2e: string;
  integration: string;
  /** File with the cross-tenant assertion, or why none applies. */
  crossTenant:
    string | { na: 'public' | 'self-only' | 'platform-only' | 'no-tenant-data'; why: string };
  cursor?: 'v0' | 'v1';
}

const E2E = 'apps/api/test';
const INT = 'apps/api/integration';
const ISOLATION = `${INT}/tenant-isolation-messages-data.test.ts`;
const LIFECYCLE_ISOLATION = `${INT}/tenant-isolation-messages.test.ts`;

export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  {
    route: 'get /api/v1/messages',
    e2e: `${E2E}/messages-list.e2e.test.ts`,
    integration: `${INT}/messages-list.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/messages/:messageId',
    e2e: `${E2E}/messages-data.e2e.test.ts`,
    integration: `${INT}/messages-data.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/messages/:messageId/recipients',
    e2e: `${E2E}/messages-data.e2e.test.ts`,
    integration: `${INT}/messages-data.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/messages/:messageId/attachments',
    e2e: `${E2E}/messages-data.e2e.test.ts`,
    integration: `${INT}/messages-data.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/attachments',
    e2e: `${E2E}/messages-data.e2e.test.ts`,
    integration: `${INT}/messages-data.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/messages/:messageId/urls',
    e2e: `${E2E}/messages-data.e2e.test.ts`,
    integration: `${INT}/messages-data.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/url-protection/clicks',
    e2e: `${E2E}/messages-data.e2e.test.ts`,
    integration: `${INT}/messages-data.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/recipients/suppressions',
    e2e: `${E2E}/recipients.e2e.test.ts`,
    integration: `${INT}/recipient-suppressions.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/recipients/suppressions/:suppressionId',
    e2e: `${E2E}/recipients.e2e.test.ts`,
    integration: `${INT}/recipient-suppressions.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/recipients/suppressions',
    e2e: `${E2E}/recipients.e2e.test.ts`,
    integration: `${INT}/recipient-suppressions.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'delete /api/v1/recipients/suppressions/:suppressionId',
    e2e: `${E2E}/recipients.e2e.test.ts`,
    integration: `${INT}/recipient-suppressions.test.ts`,
    crossTenant: ISOLATION,
  },
  // Pre-6.1 messages module (step 3.3 lifecycle, step 4.1 scans).
  {
    route: 'get /api/v1/messages/:messageId/lifecycle',
    e2e: `${E2E}/messages.e2e.test.ts`,
    integration: `${INT}/messages-lifecycle.test.ts`,
    crossTenant: LIFECYCLE_ISOLATION,
  },
  {
    route: 'get /api/v1/messages/:messageId/lifecycle/history',
    e2e: `${E2E}/messages.e2e.test.ts`,
    integration: `${INT}/messages-lifecycle.test.ts`,
    crossTenant: LIFECYCLE_ISOLATION,
    cursor: 'v0',
  },
  {
    route: 'post /api/v1/messages/:messageId/rescan',
    e2e: `${E2E}/messages.e2e.test.ts`,
    integration: `${INT}/messages-lifecycle.test.ts`,
    crossTenant: LIFECYCLE_ISOLATION,
  },
  {
    route: 'post /api/v1/messages/:messageId/release',
    e2e: `${E2E}/messages.e2e.test.ts`,
    integration: `${INT}/messages-lifecycle.test.ts`,
    crossTenant: LIFECYCLE_ISOLATION,
  },
  {
    route: 'get /api/v1/messages/:messageId/scans',
    e2e: `${E2E}/messages.e2e.test.ts`,
    // The scans' own results suite is integration/scans.test.ts (step 4.1, another package's
    // file); the own-message 200 and B's 404 are asserted in the lifecycle isolation suite.
    integration: LIFECYCLE_ISOLATION,
    crossTenant: LIFECYCLE_ISOLATION,
    cursor: 'v0',
  },
]);
