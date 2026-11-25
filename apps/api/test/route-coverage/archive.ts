/**
 * Route coverage of step 8.1 (docs/plan/steps/23-journaling-archiving.md §4.4, §9.3): the 41
 * archive, legal hold and eDiscovery operations (plus the capture-issue read of step AI-5 D8,
 * docs/plan/steps/33-ai-chat-compliance-integrations.md) with the test files that carry their `@covers`
 * marker, their cross-tenant assertion (another organization's messages, policies, holds,
 * cases, searches, exports and download tokens answer like unknown ids; searches only ever run
 * through the caller's tenant alias) and their cursor encoding (every list is a signed v1 list).
 * Consumed by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test';
const INT = 'apps/api/integration';
const ARCHIVE_E2E = `${E2E}/archive.e2e.test.ts`;
const EDISCOVERY_E2E = `${E2E}/ediscovery.e2e.test.ts`;
const ADMIN_INT = `${INT}/archive.test.ts`;
const CONTENT_INT = `${INT}/archive-content.test.ts`;
const EDISCOVERY_INT = `${INT}/archive-ediscovery.test.ts`;
const ISOLATION = `${INT}/tenant-isolation-archive.test.ts`;

const entry = (route: string, e2e: string, integration: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e,
  integration,
  crossTenant: ISOLATION,
  ...(cursor && { cursor }),
});

/** The routes of `NEW_IN_8_1` and `NEW_IN_AI_5` (route inventory), in §4.4 order. */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/archive/settings', ARCHIVE_E2E, ADMIN_INT),
  entry('put /api/v1/archive/settings', ARCHIVE_E2E, ADMIN_INT),
  entry('get /api/v1/archive/retention-policies', ARCHIVE_E2E, ADMIN_INT, 'v1'),
  entry('post /api/v1/archive/retention-policies', ARCHIVE_E2E, ADMIN_INT),
  entry('get /api/v1/archive/retention-policies/:policyId', ARCHIVE_E2E, ADMIN_INT),
  entry('put /api/v1/archive/retention-policies/:policyId', ARCHIVE_E2E, ADMIN_INT),
  entry('delete /api/v1/archive/retention-policies/:policyId', ARCHIVE_E2E, ADMIN_INT),
  entry('get /api/v1/archive/keys', ARCHIVE_E2E, ADMIN_INT, 'v1'),
  entry('post /api/v1/archive/keys/rotate', ARCHIVE_E2E, ADMIN_INT),
  entry('get /api/v1/archive/status', ARCHIVE_E2E, ADMIN_INT),
  entry('get /api/v1/archive/capture-issues', ARCHIVE_E2E, ADMIN_INT, 'v1'),
  // Step AI-5 D8: the capture intent of one message (any status).
  entry('get /api/v1/archive/capture-issues/:messageId', ARCHIVE_E2E, ADMIN_INT),
  entry('post /api/v1/archive/capture-issues/:messageId/retry', ARCHIVE_E2E, ADMIN_INT),
  entry('get /api/v1/archive/disposals', ARCHIVE_E2E, ADMIN_INT, 'v1'),
  {
    route: 'get /api/v1/archive/export-signing-keys',
    e2e: ARCHIVE_E2E,
    integration: ADMIN_INT,
    crossTenant: {
      na: 'no-tenant-data',
      why:
        'The platform’s export signing public keys (ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY and the ' +
        'previous keys): the same for every organization, never tenant data.',
    },
  },
  entry('get /api/v1/archive/messages', ARCHIVE_E2E, CONTENT_INT, 'v1'),
  entry('get /api/v1/archive/messages/:messageId', ARCHIVE_E2E, CONTENT_INT),
  entry('get /api/v1/archive/messages/:messageId/journal', ARCHIVE_E2E, CONTENT_INT),
  entry('get /api/v1/archive/messages/:messageId/security', ARCHIVE_E2E, CONTENT_INT),
  entry('post /api/v1/archive/messages/:messageId/reveal', ARCHIVE_E2E, CONTENT_INT),
  entry('get /api/v1/archive/messages/:messageId/preview', ARCHIVE_E2E, CONTENT_INT),
  entry('post /api/v1/archive/messages/:messageId/download-grants', ARCHIVE_E2E, CONTENT_INT),
  entry('get /api/v1/archive/downloads/:token', ARCHIVE_E2E, CONTENT_INT),
  entry('post /api/v1/archive/messages/:messageId/dispose', ARCHIVE_E2E, CONTENT_INT),
  entry('get /api/v1/legal-holds', EDISCOVERY_E2E, EDISCOVERY_INT, 'v1'),
  entry('get /api/v1/legal-holds/:holdId', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('post /api/v1/legal-holds/:holdId/release', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('post /api/v1/ediscovery/cases/:caseId/holds', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('get /api/v1/ediscovery/cases', EDISCOVERY_E2E, EDISCOVERY_INT, 'v1'),
  entry('post /api/v1/ediscovery/cases', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('get /api/v1/ediscovery/cases/:caseId', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('patch /api/v1/ediscovery/cases/:caseId', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('post /api/v1/ediscovery/cases/:caseId/close', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('post /api/v1/ediscovery/cases/:caseId/searches', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('get /api/v1/ediscovery/cases/:caseId/searches', EDISCOVERY_E2E, EDISCOVERY_INT, 'v1'),
  entry('get /api/v1/ediscovery/cases/:caseId/searches/:searchId', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry(
    'get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits',
    EDISCOVERY_E2E,
    EDISCOVERY_INT,
    'v1',
  ),
  entry(
    'post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review',
    EDISCOVERY_E2E,
    EDISCOVERY_INT,
  ),
  entry('post /api/v1/ediscovery/cases/:caseId/exports', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry('get /api/v1/ediscovery/cases/:caseId/exports', EDISCOVERY_E2E, EDISCOVERY_INT, 'v1'),
  entry('get /api/v1/ediscovery/cases/:caseId/exports/:exportId', EDISCOVERY_E2E, EDISCOVERY_INT),
  entry(
    'post /api/v1/ediscovery/cases/:caseId/exports/:exportId/download-grants',
    EDISCOVERY_E2E,
    EDISCOVERY_INT,
  ),
]);
