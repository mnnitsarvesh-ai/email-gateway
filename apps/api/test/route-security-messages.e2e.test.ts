/**
 * Route metadata of every step 6.1 WP2 route and of the messages module (lifecycle, scans),
 * discovered from the running app (test/support/route-discovery.ts): the exact permission
 * requirement, user-only/MFA flags, rate class, idempotency mechanism and operation, and cursor
 * encoding. A route added to these modules without an entry here fails the suite.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AttachmentsController } from '../src/modules/attachments/attachments.controller';
import { TRANSACTIONAL_IDEMPOTENCY_KEY } from '../src/modules/messages/api-docs';
import { MessageLifecycleController } from '../src/modules/messages/controllers/message-lifecycle.controller';
import { MessageScansController } from '../src/modules/messages/controllers/message-scans.controller';
import { MessagesController } from '../src/modules/messages/controllers/messages.controller';
import { RecipientSuppressionsController } from '../src/modules/recipients/recipient-suppressions.controller';
import { UrlProtectionController } from '../src/modules/url-protection/url-protection.controller';
import { COVERAGE } from './route-coverage/messages';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { type DiscoveredRoute, discoverRoutes } from './support/route-discovery';

interface Expected {
  route: string;
  permissions: string[];
  rateClass: 'sensitive' | 'expensive' | null;
  /** Transactional Idempotency-Key operation (IdempotencyService.execute), or null. */
  idempotency: string | null;
  cursor: 'v0' | 'v1' | null;
}

const EXPECTED: Expected[] = [
  {
    route: 'get /api/v1/messages',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/messages/:messageId',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: null,
  },
  {
    route: 'get /api/v1/messages/:messageId/recipients',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/messages/:messageId/attachments',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/attachments',
    permissions: ['message:read'],
    rateClass: 'expensive',
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/messages/:messageId/urls',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/url-protection/clicks',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/recipients/suppressions',
    permissions: ['delivery:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v1',
  },
  {
    route: 'get /api/v1/recipients/suppressions/:suppressionId',
    permissions: ['delivery:read'],
    rateClass: null,
    idempotency: null,
    cursor: null,
  },
  {
    route: 'post /api/v1/recipients/suppressions',
    permissions: ['delivery:suppression_manage'],
    rateClass: 'sensitive',
    idempotency: 'recipient_suppression.create',
    cursor: null,
  },
  {
    route: 'delete /api/v1/recipients/suppressions/:suppressionId',
    permissions: ['delivery:suppression_manage'],
    rateClass: 'sensitive',
    idempotency: 'recipient_suppression.delete',
    cursor: null,
  },
  // Pre-6.1 messages module routes (convergence).
  {
    route: 'get /api/v1/messages/:messageId/lifecycle',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: null,
  },
  {
    route: 'get /api/v1/messages/:messageId/lifecycle/history',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v0',
  },
  {
    route: 'post /api/v1/messages/:messageId/rescan',
    permissions: ['message:rescan'],
    rateClass: 'sensitive',
    idempotency: 'message.rescan',
    cursor: null,
  },
  {
    route: 'post /api/v1/messages/:messageId/release',
    permissions: ['quarantine:release'],
    rateClass: 'sensitive',
    idempotency: 'message.release',
    cursor: null,
  },
  {
    route: 'get /api/v1/messages/:messageId/scans',
    permissions: ['message:read'],
    rateClass: null,
    idempotency: null,
    cursor: 'v0',
  },
];

const CONTROLLERS = [
  MessagesController,
  MessageLifecycleController,
  MessageScansController,
  AttachmentsController,
  UrlProtectionController,
  RecipientSuppressionsController,
];

function transactionalOperation(route: DiscoveredRoute): string | null {
  const [controllerName, method] = route.name.split('.') as [string, string];
  const controller = CONTROLLERS.find((c) => c.name === controllerName)!;
  const handler = (controller.prototype as unknown as Record<string, object>)[method]!;
  const meta = Reflect.getMetadata(TRANSACTIONAL_IDEMPOTENCY_KEY, handler) as
    { operation: string } | undefined;
  return meta?.operation ?? null;
}

describe('route security of the messages data routes (step 6.1 WP2)', () => {
  let api: StubbedApiApp;
  let routes: DiscoveredRoute[];

  beforeAll(async () => {
    api = await createStubbedApiApp({}, { discovery: true });
    const names = new Set(CONTROLLERS.map((c) => c.name));
    routes = discoverRoutes(api.app).filter((r) => names.has(r.name.split('.')[0]!));
  });

  afterAll(async () => {
    await api?.close();
  });

  it('discovers exactly the expected routes of these controllers', () => {
    expect(routes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      EXPECTED.map((e) => e.route).sort(),
    );
  });

  it.each(EXPECTED)('$route', (expected) => {
    const route = routes.find((r) => `${r.method} ${r.path}` === expected.route)!;
    expect(route).toBeDefined();
    expect(route.isPublic).toBe(false);
    expect(route.requirement).toEqual({ mode: 'all', permissions: expected.permissions });
    // API keys are accepted (no user-only flag) and no MFA step-up on these tenant routes.
    expect(route.userOnly).toBe(false);
    expect(route.requireMfa).toBe(false);
    expect(route.rateClass).toBe(expected.rateClass);
    expect(route.cursor).toBe(expected.cursor);
    expect(transactionalOperation(route)).toBe(expected.idempotency);
    // Transactional routes never also use the reservation interceptor (double handling).
    expect(route.idempotency).toBeNull();
    expect(route.returnsSecret).toBe(false);
    if (expected.idempotency) expect(route.rateClass).toBe('sensitive');
  });
});

describe('route coverage manifest of WP2 (route-coverage/messages.ts, §3.8)', () => {
  const repoRoot = resolve(__dirname, '../../..');
  const read = (file: string) => readFileSync(resolve(repoRoot, file), 'utf8');

  it('lists exactly the routes above with their cursor encoding', () => {
    expect(COVERAGE.map((c) => c.route).sort()).toEqual(EXPECTED.map((e) => e.route).sort());
    for (const entry of COVERAGE) {
      expect(entry.cursor ?? null, entry.route).toBe(
        EXPECTED.find((e) => e.route === entry.route)!.cursor,
      );
    }
  });

  it.each(COVERAGE.map((c) => [c.route, c] as const))(
    '%s: every named file exists and carries the @covers marker',
    (_route, entry) => {
      const files = [entry.e2e, entry.integration];
      if (typeof entry.crossTenant === 'string') files.push(entry.crossTenant);
      for (const file of files) {
        expect(read(file), `${file} → ${entry.route}`).toContain(`@covers ${entry.route}`);
      }
    },
  );
});
