/**
 * Route coverage of step AI-1 (docs/plan/steps/28-ai-chat-management.md §4.1, §9 items 3-4): the
 * 15 assistant operations with the test files that carry their `@covers` marker — the stubbed e2e
 * suite (WP3), the integration suite over real MySQL/Redis with the api listening so the loopback
 * is real, and the tenant-isolation suite (WP4: another user's or organization's conversations,
 * messages, executions, refs and "more" pages answer like unknown ids) — and their cursor
 * encoding (both lists are signed v1 lists). Consumed by the route inventory
 * (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test/assistant.e2e.test.ts';
const INT = 'apps/api/integration/assistant.test.ts';
const ISOLATION = 'apps/api/integration/tenant-isolation-assistant.test.ts';

const entry = (route: string, cursor?: 'v1'): RouteCoverage => ({
  route,
  e2e: E2E,
  integration: INT,
  crossTenant: ISOLATION,
  ...(cursor && { cursor }),
});

/** The routes of `NEW_IN_AI_1` (route inventory), in §4.1 order. */
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
]);
