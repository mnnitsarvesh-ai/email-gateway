/**
 * Route coverage of step 6.1 WP3 (docs/plan/steps/18-rest-api.md §3.8): every insight route with
 * the test files that carry its `@covers` marker, its cross-tenant assertion and its cursor
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
const ISOLATION = `${INT}/tenant-isolation-insights.test.ts`;

export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  {
    route: 'get /api/v1/audit/logs',
    e2e: `${E2E}/insights-audit.e2e.test.ts`,
    integration: `${INT}/insights-audit.test.ts`,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/platform/audit/logs',
    e2e: `${E2E}/insights-audit.e2e.test.ts`,
    integration: `${INT}/insights-audit.test.ts`,
    // Platform-only, but its refusal of tenant principals (admins, API keys, overrides) is
    // asserted with real sessions in the isolation suite.
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/reports/traffic',
    e2e: `${E2E}/insights-reports.e2e.test.ts`,
    integration: `${INT}/insights-reports.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/reports/threats',
    e2e: `${E2E}/insights-reports.e2e.test.ts`,
    integration: `${INT}/insights-reports.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/reports/url-clicks',
    e2e: `${E2E}/insights-reports.e2e.test.ts`,
    integration: `${INT}/insights-reports.test.ts`,
    crossTenant: ISOLATION,
  },
  // Step 7.1 §3.3.2 (docs/plan/steps/20-admin-portal.md).
  {
    route: 'get /api/v1/reports/delivery',
    e2e: `${E2E}/insights-reports.e2e.test.ts`,
    integration: `${INT}/insights-reports.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/reports/processing',
    e2e: `${E2E}/insights-reports.e2e.test.ts`,
    integration: `${INT}/insights-reports.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/reports/top-domains',
    e2e: `${E2E}/insights-reports.e2e.test.ts`,
    integration: `${INT}/insights-reports.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/usage',
    e2e: `${E2E}/insights-billing.e2e.test.ts`,
    integration: `${INT}/insights-billing.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/billing/plan',
    e2e: `${E2E}/insights-billing.e2e.test.ts`,
    integration: `${INT}/insights-billing.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/billing/usage',
    e2e: `${E2E}/insights-billing.e2e.test.ts`,
    integration: `${INT}/insights-billing.test.ts`,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/threat-intelligence/lookup',
    e2e: `${E2E}/insights-threat-intel.e2e.test.ts`,
    integration: `${INT}/insights-threat-intel.test.ts`,
    crossTenant: {
      na: 'no-tenant-data',
      why:
        'Reads only platform threat_indicators (org_scope = 0) and malware_signatures; no ' +
        'tenant-owned row is read, so every tenant gets the same answer. The audit row is ' +
        'written for the caller’s scope (asserted in the integration suite).',
    },
  },
]);
