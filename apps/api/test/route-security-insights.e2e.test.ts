/**
 * Step 6.1 WP3 route security (docs/plan/steps/18-rest-api.md §3.3, §3.5, §3.6): the exact
 * authorization requirement, MFA, user-only, rate class, idempotency and cursor metadata of every
 * insight route, discovered from the running app, and that every one of them answers 401 without
 * credentials.
 */
// @covers get /api/v1/audit/logs
// @covers get /api/v1/platform/audit/logs
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/reports/threats
// @covers get /api/v1/reports/url-clicks
// @covers get /api/v1/usage
// @covers get /api/v1/billing/plan
// @covers get /api/v1/billing/usage
// @covers get /api/v1/threat-intelligence/lookup
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { type DiscoveredRoute, discoverRoutes } from './support/route-discovery';

interface Expected {
  permissions: string[];
  mfa: boolean;
  userOnly: boolean;
  rateClass: 'expensive' | null;
  cursor: 'v1' | null;
}

const EXPECTED: Record<string, Expected> = {
  'get /api/v1/audit/logs': {
    permissions: ['audit:read'],
    mfa: false,
    userOnly: false,
    rateClass: null,
    cursor: 'v1',
  },
  'get /api/v1/platform/audit/logs': {
    permissions: ['platform:operations', 'audit:read'],
    mfa: true,
    userOnly: true,
    rateClass: null,
    cursor: 'v1',
  },
  'get /api/v1/reports/traffic': {
    permissions: ['report:read'],
    mfa: false,
    userOnly: false,
    rateClass: 'expensive',
    cursor: null,
  },
  'get /api/v1/reports/threats': {
    permissions: ['report:read'],
    mfa: false,
    userOnly: false,
    rateClass: 'expensive',
    cursor: null,
  },
  'get /api/v1/reports/url-clicks': {
    permissions: ['report:read'],
    mfa: false,
    userOnly: false,
    rateClass: 'expensive',
    cursor: null,
  },
  'get /api/v1/usage': {
    permissions: ['organization:read'],
    mfa: false,
    userOnly: false,
    rateClass: null,
    cursor: null,
  },
  'get /api/v1/billing/plan': {
    permissions: ['billing:read'],
    mfa: false,
    userOnly: false,
    rateClass: null,
    cursor: null,
  },
  'get /api/v1/billing/usage': {
    permissions: ['billing:read'],
    mfa: false,
    userOnly: false,
    rateClass: 'expensive',
    cursor: null,
  },
  'get /api/v1/threat-intelligence/lookup': {
    permissions: ['threat_intel:read'],
    mfa: false,
    userOnly: false,
    rateClass: 'expensive',
    cursor: null,
  },
};

const WP3_CONTROLLERS = new Set([
  'AuditLogsController',
  'PlatformAuditLogsController',
  'ReportsController',
  'UsageController',
  'BillingController',
  'ThreatIntelligenceController',
]);

let t: StubbedApiApp;
let routes: DiscoveredRoute[];

beforeAll(async () => {
  t = await createStubbedApiApp({}, { discovery: true });
  routes = discoverRoutes(t.app);
});
afterAll(async () => {
  await t?.close();
});

describe('WP3 route security metadata', () => {
  it('has exactly the documented routes in the WP3 controllers', () => {
    const wp3 = routes
      .filter((r) => WP3_CONTROLLERS.has(r.name.split('.')[0]!))
      .map((r) => `${r.method} ${r.path}`)
      .sort();
    expect(wp3).toEqual(Object.keys(EXPECTED).sort());
  });

  it.each(Object.entries(EXPECTED))('%s', (key, expected) => {
    const route = routes.find((r) => `${r.method} ${r.path}` === key);
    expect(route, key).toBeDefined();
    expect(route!.isPublic).toBe(false);
    expect(route!.requirement).toEqual({ mode: 'all', permissions: expected.permissions });
    expect(route!.requireMfa).toBe(expected.mfa);
    expect(route!.userOnly).toBe(expected.userOnly);
    expect(route!.rateClass).toBe(expected.rateClass);
    expect(route!.cursor).toBe(expected.cursor);
    expect(route!.idempotency).toBeNull();
    expect(route!.returnsSecret).toBe(false);
    expect(route!.rateLimits).toEqual([]);
  });

  it('answers 401 unauthorized without credentials on every WP3 route', async () => {
    for (const key of Object.keys(EXPECTED)) {
      const path = key.split(' ')[1]!;
      const res = await t.http().get(path);
      expect(res.status, key).toBe(401);
      expect(res.body.code).toBe('unauthorized');
    }
  });
});
