/**
 * Route coverage of step 8.2 (docs/plan/steps/25-m365-google-connectors.md §5.2, §10.4): the 24
 * Microsoft 365 and Google Workspace connection operations with the test files that carry their
 * `@covers` marker, their cross-tenant assertion (another organization's connections, grants,
 * consent states, domains and validation runs answer like unknown ids; the tenant always comes
 * from the authenticated scope) and their cursor encoding (both lists are signed v1 lists).
 * Consumed by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/provider-connections.e2e.test.ts';
const INT = 'apps/api/integration/provider-connections.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: INT,
  ...(cursor && { cursor }),
});

/** The routes of `NEW_IN_8_2` (route inventory), in §5.2 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  {
    route: 'get /api/v1/provider-integrations/catalog',
    e2e: E2E,
    integration: INT,
    crossTenant: {
      na: 'no-tenant-data',
      why:
        'The catalogue lists the platform’s permission profiles, attestation codes, gateway ' +
        'values and the active provider egress range sets (platform rows); it reads no ' +
        'organization data.',
    },
  },
  entry('get /api/v1/provider-connections', 'v1'),
  entry('post /api/v1/provider-connections'),
  entry('get /api/v1/provider-connections/:id'),
  entry('patch /api/v1/provider-connections/:id'),
  entry('delete /api/v1/provider-connections/:id'),
  entry('get /api/v1/provider-connections/:id/wizard'),
  entry('post /api/v1/provider-connections/:id/grants'),
  entry('post /api/v1/provider-connections/consent/complete'),
  entry('put /api/v1/provider-connections/:id/grants/:profile/credentials'),
  entry('post /api/v1/provider-connections/:id/grants/:profile/verify'),
  entry('delete /api/v1/provider-connections/:id/grants/:profile'),
  entry('get /api/v1/provider-connections/:id/domains'),
  entry('put /api/v1/provider-connections/:id/domains'),
  entry('post /api/v1/provider-connections/:id/mail-flow/preview'),
  entry('post /api/v1/provider-connections/:id/mail-flow/apply'),
  entry('get /api/v1/provider-connections/:id/mail-flow'),
  entry('post /api/v1/provider-connections/:id/attestations'),
  entry('post /api/v1/provider-connections/:id/validations'),
  entry('get /api/v1/provider-connections/:id/validations', 'v1'),
  entry('get /api/v1/provider-connections/:id/validations/:runId'),
  entry('get /api/v1/provider-connections/:id/health'),
  entry('post /api/v1/provider-connections/:id/health/check'),
  entry('get /api/v1/provider-connections/:id/setup-guide'),
]);
