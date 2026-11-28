/**
 * Route coverage of step API-1 (docs/plan/steps/35-api-mode-protection.md D12, §9.4): the 16
 * API-mode operations (14 under the `api-mode` tag, the two public Graph callbacks of
 * `provider-notifications`) with the test files that carry their `@covers` marker, their
 * cross-tenant assertion (another organization's connections, mailboxes, detections, domains and
 * organization answer like unknown ids; the tenant always comes from the authenticated scope) and
 * their cursor encoding (the mailbox and detection lists are signed v1 lists). The callbacks are
 * public (no tenant input: a stored subscription id selects the mailbox). Step API-2 adds the 9
 * remediation operations (docs/plan/steps/36-api-mode-remediation.md R13) with their own e2e and
 * integration files. Step API-3 adds the 19 clawback, report and settings operations
 * (docs/plan/steps/37-api-mode-clawback-reporting.md C14) with their e2e files and one integration
 * file. Step API-4 adds the 5 onboarding operations (docs/plan/steps/38-api-mode-parity-onboarding.md
 * A10, B3, B6, B8): protection by mode, the domain onboarding state, the mailbox scope and the
 * provider ownership check of a domain. Consumed by the route inventory
 * (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/api-mode.e2e.test.ts';
const INT = 'apps/api/integration/api-mode.test.ts';
/** Step API-2 (docs/plan/steps/36-api-mode-remediation.md R13, §9.4). */
const E2E_API_2 = 'apps/api/test/api-mode-remediation.e2e.test.ts';
const INT_API_2 = 'apps/api/integration/api-mode-remediation.test.ts';
/** Step API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md C14, §9.4). */
const E2E_API_3_CLAWBACK = 'apps/api/test/api-mode-clawback.e2e.test.ts';
const E2E_API_3_REPORTS = 'apps/api/test/api-mode-reports.e2e.test.ts';
const INT_API_3 = 'apps/api/integration/api-mode-clawback.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: INT,
  ...(cursor && { cursor }),
});

const remediation = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E_API_2,
  integration: INT_API_2,
  crossTenant: INT_API_2,
  ...(cursor && { cursor }),
});

const api3 =
  (e2e: string) =>
  (route: string, cursor?: 'v1'): RouteCoverage => ({
    route,
    e2e,
    integration: INT_API_3,
    crossTenant: INT_API_3,
    ...(cursor && { cursor }),
  });
const clawback = api3(E2E_API_3_CLAWBACK);
const report = api3(E2E_API_3_REPORTS);

/** Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md §10.4). */
const E2E_API_4 = 'apps/api/test/api-mode-onboarding.e2e.test.ts';
const E2E_API_4_PROVIDER = 'apps/api/test/domains-provider-ownership.e2e.test.ts';
const INT_API_4 = 'apps/api/integration/api-mode-onboarding.test.ts';
const api4 =
  (e2e: string) =>
  (route: string, cursor?: 'v1'): RouteCoverage => ({
    route,
    e2e,
    integration: INT_API_4,
    crossTenant: INT_API_4,
    ...(cursor && { cursor }),
  });
const onboarding = api4(E2E_API_4);
const providerCheck = api4(E2E_API_4_PROVIDER);

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
  // Step API-2 R13: the remediation policy, history and manual requests.
  remediation('get /api/v1/api-mode/remediation-policy'),
  remediation('put /api/v1/api-mode/remediation-policy'),
  remediation('put /api/v1/api-mode/remediation-policy/domains/:domainId'),
  remediation('delete /api/v1/api-mode/remediation-policy/domains/:domainId'),
  remediation('get /api/v1/api-mode/remediations', 'v1'),
  remediation('get /api/v1/api-mode/remediations/:remediationId'),
  remediation('post /api/v1/api-mode/remediations/:remediationId/retry'),
  remediation('post /api/v1/api-mode/detections/:detectionId/remediate'),
  remediation('post /api/v1/api-mode/detections/:detectionId/restore'),
  // Step API-3 C14: clawbacks, user reports, report mailboxes and settings.
  clawback('post /api/v1/api-mode/clawbacks'),
  clawback('get /api/v1/api-mode/clawbacks', 'v1'),
  clawback('get /api/v1/api-mode/clawbacks/:clawbackId'),
  clawback('get /api/v1/api-mode/clawbacks/:clawbackId/targets', 'v1'),
  clawback('post /api/v1/api-mode/clawbacks/:clawbackId/submit'),
  clawback('post /api/v1/api-mode/clawbacks/:clawbackId/submit-hard-delete'),
  clawback('post /api/v1/api-mode/clawbacks/:clawbackId/approve'),
  clawback('post /api/v1/api-mode/clawbacks/:clawbackId/deny'),
  clawback('post /api/v1/api-mode/clawbacks/:clawbackId/cancel'),
  clawback('post /api/v1/api-mode/clawbacks/:clawbackId/restore'),
  report('get /api/v1/api-mode/reports', 'v1'),
  report('get /api/v1/api-mode/reports/:reportId'),
  report('post /api/v1/api-mode/reports/:reportId/triage'),
  report('post /api/v1/api-mode/reports/:reportId/clawback'),
  report('get /api/v1/api-mode/report-mailboxes'),
  report('post /api/v1/api-mode/report-mailboxes'),
  report('put /api/v1/api-mode/mailboxes/:mailboxId/report-mailbox'),
  clawback('get /api/v1/api-mode/settings'),
  clawback('put /api/v1/api-mode/settings'),
  // Step API-4 A10, B3, B6, B8: protection by mode, onboarding, scope, provider ownership.
  onboarding('get /api/v1/api-mode/protection-coverage', 'v1'),
  onboarding('get /api/v1/api-mode/domains/:domainId/onboarding'),
  onboarding('get /api/v1/api-mode/domains/:domainId/scope'),
  onboarding('put /api/v1/api-mode/domains/:domainId/scope'),
  providerCheck('post /api/v1/domains/:domainId/ownership/provider-check'),
]);
