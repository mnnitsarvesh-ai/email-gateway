/**
 * Route coverage of step AI-1 (docs/plan/steps/28-ai-chat-management.md §4.1, §9 items 3-4): the
 * 15 assistant operations with the test files that carry their `@covers` marker — the stubbed e2e
 * suite (WP3), the integration suite over real MySQL/Redis with the api listening so the loopback
 * is real, and the tenant-isolation suite (WP4: another user's or organization's conversations,
 * messages, executions, refs and "more" pages answer like unknown ids) — and their cursor
 * encoding (both lists are signed v1 lists). Step AI-2 (docs/plan/steps/
 * 29-ai-chat-confirmations-mail-writes.md §4.1, §9 items 3-4) adds the 3 confirmation routes,
 * covered end to end by the confirmations integration suite (WP4) and the assistant
 * tenant-isolation suite (another user's or organization's confirmations answer 404). Step AI-R
 * (docs/plan/steps/31-ai-chat-reports.md §4.1, §9 items 3 and 5) adds the report read, covered end
 * to end by the reports integration suite (WP6: owner view with the HTML from MinIO, another user
 * or organization 404, purged state) and the assistant tenant-isolation suite. Step AI-6
 * (docs/plan/steps/34-ai-chat-hardening-operations.md §4.1, §9 items 4-5) adds the 11 hardening
 * operations: the stubbed refusal/validation/view suite `assistant-hardening.e2e.test.ts`, the
 * admin/feedback/search/audit integration suite (`assistant-admin.test.ts`), the tenant-key routes
 * in the provider-fallback suite, and the assistant tenant-isolation suite (another
 * organization's feedback, search, admin and audit rows and provider key: 404 or empty). Consumed
 * by the route inventory (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/assistant.e2e.test.ts';
const INT = 'apps/api/integration/assistant.test.ts';
const ISOLATION = 'apps/api/integration/tenant-isolation-assistant.test.ts';
const CONFIRMATIONS_INT = 'apps/api/integration/assistant-confirmations.test.ts';
const REPORTS_INT = 'apps/api/integration/assistant-reports.test.ts';
const HARDENING_E2E = 'apps/api/test/assistant-hardening.e2e.test.ts';
const ADMIN_INT = 'apps/api/integration/assistant-admin.test.ts';
const FALLBACK_INT = 'apps/api/integration/assistant-provider-fallback.test.ts';

const hardening = (route: string, integration: string, cursor?: 'v1'): RouteCoverage => ({
  ...entry(route, cursor),
  e2e: HARDENING_E2E,
  integration,
});

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: ISOLATION,
  ...(cursor && { cursor }),
});

/**
 * The routes of `NEW_IN_AI_1`, `NEW_IN_AI_2`, `NEW_IN_AI_R` and `NEW_IN_AI_6` (route inventory),
 * in §4.1 order.
 */
export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  entry('get /api/v1/assistant/status'),
  entry('get /api/v1/assistant/settings'),
  entry('put /api/v1/assistant/settings'),
  entry('get /api/v1/assistant/usage'),
  entry('get /api/v1/assistant/tools'),
  entry('get /api/v1/assistant/conversations', 'v1'),
  entry('post /api/v1/assistant/conversations'),
  entry('get /api/v1/assistant/conversations/:conversationId'),
  entry('patch /api/v1/assistant/conversations/:conversationId'),
  entry('delete /api/v1/assistant/conversations/:conversationId'),
  entry('get /api/v1/assistant/conversations/:conversationId/messages', 'v1'),
  entry('post /api/v1/assistant/conversations/:conversationId/turns'),
  entry('post /api/v1/assistant/turns/:turnId/cancel'),
  entry('get /api/v1/assistant/executions/:executionId'),
  entry('post /api/v1/assistant/executions/:executionId/more'),
  // Step AI-2 §4.1 (`NEW_IN_AI_2`).
  {
    ...entry('get /api/v1/assistant/confirmations/:confirmationId'),
    integration: CONFIRMATIONS_INT,
  },
  {
    ...entry('post /api/v1/assistant/confirmations/:confirmationId/confirm'),
    integration: CONFIRMATIONS_INT,
  },
  {
    ...entry('post /api/v1/assistant/confirmations/:confirmationId/cancel'),
    integration: CONFIRMATIONS_INT,
  },
  // Step AI-R §4.1 (`NEW_IN_AI_R`).
  { ...entry('get /api/v1/assistant/reports/:reportId'), integration: REPORTS_INT },
  // Step AI-6 §4.1 (`NEW_IN_AI_6`, contracts §35.6).
  hardening('put /api/v1/assistant/settings/provider-key', FALLBACK_INT),
  hardening('delete /api/v1/assistant/settings/provider-key', FALLBACK_INT),
  hardening('post /api/v1/assistant/settings/provider-key/validate', FALLBACK_INT),
  hardening('get /api/v1/assistant/search', ADMIN_INT, 'v1'),
  hardening('put /api/v1/assistant/messages/:messageId/feedback', ADMIN_INT),
  hardening('delete /api/v1/assistant/messages/:messageId/feedback', ADMIN_INT),
  hardening('get /api/v1/assistant/admin/usage/users', ADMIN_INT, 'v1'),
  hardening('get /api/v1/assistant/admin/feedback', ADMIN_INT, 'v1'),
  hardening('get /api/v1/assistant/admin/conversations', ADMIN_INT, 'v1'),
  hardening('get /api/v1/assistant/admin/conversations/:conversationId', ADMIN_INT),
  hardening('get /api/v1/assistant/admin/executions', ADMIN_INT, 'v1'),
]);
