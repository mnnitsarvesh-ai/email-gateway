/**
 * Route coverage of step 6.2 (docs/plan/steps/19-webhooks-notifications.md §6.2): the 13
 * webhook and 4 notification routes with the test files that carry their `@covers` marker,
 * their cross-tenant assertion and their cursor encoding. Consumed by the route inventory
 * (`route-coverage/index.ts`).
 */
import type { RouteCoverage } from './insights';

const E2E = 'apps/api/test';
const INT = 'apps/api/integration';
const ISOLATION = `${INT}/tenant-isolation-webhooks.test.ts`;
const WEBHOOKS_E2E = `${E2E}/webhooks.e2e.test.ts`;
const NOTIFICATIONS_E2E = `${E2E}/notifications.e2e.test.ts`;
const SUBSCRIPTIONS_INT = `${INT}/webhooks.test.ts`;
const DELIVERIES_INT = `${INT}/webhook-deliveries.test.ts`;
const NOTIFICATIONS_INT = `${INT}/notifications.test.ts`;

const SELF_ONLY = {
  na: 'self-only',
  why:
    'The caller’s own preferences: the user comes from the authenticated session (API keys ' +
    'and platform overrides are refused), no id is taken from the request.',
} as const;

export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  {
    route: 'get /api/v1/webhooks',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'post /api/v1/webhooks',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/webhooks/event-types',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: {
      na: 'no-tenant-data',
      why: 'The static event catalogue of the platform (the same for every organization).',
    },
  },
  {
    route: 'get /api/v1/webhooks/:webhookId',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'patch /api/v1/webhooks/:webhookId',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'delete /api/v1/webhooks/:webhookId',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/webhooks/:webhookId/rotate-secret',
    e2e: WEBHOOKS_E2E,
    integration: SUBSCRIPTIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/webhooks/:webhookId/test',
    e2e: WEBHOOKS_E2E,
    integration: DELIVERIES_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/webhooks/:webhookId/deliveries',
    e2e: WEBHOOKS_E2E,
    integration: DELIVERIES_INT,
    crossTenant: ISOLATION,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/webhooks/:webhookId/deliveries/:deliveryId',
    e2e: WEBHOOKS_E2E,
    integration: DELIVERIES_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay',
    e2e: WEBHOOKS_E2E,
    integration: DELIVERIES_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'post /api/v1/webhooks/:webhookId/replays',
    e2e: WEBHOOKS_E2E,
    integration: DELIVERIES_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/webhooks/:webhookId/replays/:replayId',
    e2e: WEBHOOKS_E2E,
    integration: DELIVERIES_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/notifications/settings',
    e2e: NOTIFICATIONS_E2E,
    integration: NOTIFICATIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'put /api/v1/notifications/settings',
    e2e: NOTIFICATIONS_E2E,
    integration: NOTIFICATIONS_INT,
    crossTenant: ISOLATION,
  },
  {
    route: 'get /api/v1/notifications/preferences',
    e2e: NOTIFICATIONS_E2E,
    integration: NOTIFICATIONS_INT,
    crossTenant: SELF_ONLY,
  },
  {
    route: 'put /api/v1/notifications/preferences',
    e2e: NOTIFICATIONS_E2E,
    integration: NOTIFICATIONS_INT,
    crossTenant: SELF_ONLY,
  },
]);
