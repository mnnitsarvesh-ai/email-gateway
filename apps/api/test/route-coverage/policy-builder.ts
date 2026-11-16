/**
 * Route coverage of step 7.3 (docs/plan/steps/22-policy-builder.md §4.4): the two routes the
 * visual policy builder adds — validation without saving and the sample dry-run over recent
 * stored evaluations — with the test files that carry their `@covers` marker and their
 * cross-tenant assertion (another organization's departments, versions and rounds are never
 * seen). Consumed by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/policy-builder.e2e.test.ts';
const INT = 'apps/api/integration/policy-builder.test.ts';

export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  {
    route: 'post /api/v1/policies/validate',
    e2e: E2E,
    integration: INT,
    crossTenant: INT,
  },
  {
    route: 'post /api/v1/policies/dry-run',
    e2e: E2E,
    integration: INT,
    crossTenant: INT,
  },
]);
