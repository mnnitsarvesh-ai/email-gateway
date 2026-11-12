/**
 * Step 6.1 WP4 (§3.8 route coverage): e2e coverage of the pre-6.1 routes no module e2e suite
 * exercised over HTTP until now (they had integration coverage only): self-service auth routes,
 * password change, the platform override start and end, organization features, BEC profile /
 * trusted sender / feedback sub-routes, DLP rule / exception / pattern / dictionary sub-routes,
 * quarantine release / approval reads, approval cancel and end-user preferences, and the
 * Prometheus scrape. MySQL, Redis and S3 are stubbed and each route's service is stubbed with a
 * canned result: per route, the exact permission (403 without it, the service not called), the
 * success status, the body passed through, the validated input reaching the service, and the
 * tenant scope taken from the principal (never from a client header).
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/bec/executives/:id
// @covers delete /api/v1/bec/suppressions/:id
// @covers delete /api/v1/bec/trusted-senders/:id
// @covers delete /api/v1/bec/vendors/:id
// @covers delete /api/v1/dlp/dictionaries/:id
// @covers delete /api/v1/dlp/exceptions/:id
// @covers delete /api/v1/dlp/policies/:id/rules/:ruleId
// @covers delete /api/v1/platform/overrides/:overrideId
// @covers get /api/v1/auth/sessions
// @covers get /api/v1/bec/feedback
// @covers get /api/v1/bec/suppressions
// @covers get /api/v1/bec/trusted-senders
// @covers get /api/v1/bec/vendors
// @covers get /api/v1/bec/vendors/:id
// @covers get /api/v1/dlp/dictionaries/:id
// @covers get /api/v1/dlp/patterns/:id
// @covers get /api/v1/organizations/:id/features
// @covers get /api/v1/permissions
// @covers get /api/v1/quarantine/approvals/:approvalId
// @covers get /api/v1/quarantine/me/preferences
// @covers get /api/v1/quarantine/releases/:releaseId
// @covers get /metrics
// @covers patch /api/v1/bec/executives/:id
// @covers patch /api/v1/bec/trusted-senders/:id
// @covers patch /api/v1/bec/vendors/:id
// @covers patch /api/v1/dlp/dictionaries/:id
// @covers patch /api/v1/dlp/exceptions/:id
// @covers patch /api/v1/dlp/patterns/:id
// @covers patch /api/v1/dlp/policies/:id/rules/:ruleId
// @covers post /api/v1/auth/email/verification
// @covers post /api/v1/auth/email/verify
// @covers post /api/v1/auth/invitations/accept
// @covers post /api/v1/auth/invitations/inspect
// @covers post /api/v1/auth/logout
// @covers post /api/v1/auth/logout-all
// @covers post /api/v1/auth/mfa/recovery-codes
// @covers post /api/v1/auth/mfa/totp/disable
// @covers post /api/v1/auth/mfa/totp/enable
// @covers post /api/v1/auth/mfa/totp/setup
// @covers post /api/v1/auth/password/change
// @covers post /api/v1/dlp/exceptions
// @covers post /api/v1/platform/overrides
// @covers post /api/v1/quarantine/approvals/:approvalId/cancel
// @covers put /api/v1/quarantine/me/preferences
// ---- end of route coverage ----
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthenticationService } from '../src/modules/auth/services/authentication.service';
import { EmailVerificationService } from '../src/modules/auth/services/email-verification.service';
import { InvitationService } from '../src/modules/auth/services/invitation.service';
import { MfaService } from '../src/modules/auth/services/mfa.service';
import { PasswordService } from '../src/modules/auth/services/password.service';
import { PlatformOverrideService } from '../src/modules/auth/services/platform-override.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { BecFeedbackService } from '../src/modules/bec/services/bec-feedback.service';
import { BecProfilesService } from '../src/modules/bec/services/bec-profiles.service';
import { BecTrustedSendersService } from '../src/modules/bec/services/bec-trusted-senders.service';
import { DlpDictionariesService } from '../src/modules/dlp/services/dlp-dictionaries.service';
import { DlpExceptionsService } from '../src/modules/dlp/services/dlp-exceptions.service';
import { DlpPatternsService } from '../src/modules/dlp/services/dlp-patterns.service';
import { DlpPoliciesService } from '../src/modules/dlp/services/dlp-policies.service';
import { RolesService } from '../src/modules/roles/roles.service';
import { OrganizationEntitlementsService } from '../src/modules/organizations/services/organization-entitlements.service';
import { QuarantineApprovalsService } from '../src/modules/quarantine/services/quarantine-approvals.service';
import { QuarantineQueryService } from '../src/modules/quarantine/services/quarantine-query.service';
import { QuarantineSettingsService } from '../src/modules/quarantine/services/quarantine-settings.service';
import { idem } from './legacy-idempotency-support';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { type DiscoveredRoute, discoverRoutes } from './support/route-discovery';

const ID = randomUUID();
const OTHER = randomUUID();
const FUTURE = new Date(Date.now() + 10 * 86_400_000).toISOString();
const page = { data: [], nextCursor: null };

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';
interface Case {
  route: string;
  method: Method;
  url: string;
  body?: object;
  headers?: Record<string, string>;
  status: number;
  service: abstract new (...args: never[]) => unknown;
  call: string;
  result: unknown;
  /** The response body (default: `result`; `null` for an empty 2xx body). */
  response?: unknown;
  /** The argument of the service call that carries the validated input, and its value. */
  input?: [number, unknown];
  platform?: boolean;
}

const CASES: Case[] = [
  // ---- auth (self-service) -------------------------------------------------------------------
  {
    route: 'post /api/v1/auth/logout',
    method: 'post',
    url: '/api/v1/auth/logout',
    status: 204,
    service: AuthenticationService,
    call: 'logout',
    result: undefined,
    response: null,
  },
  {
    route: 'post /api/v1/auth/logout-all',
    method: 'post',
    url: '/api/v1/auth/logout-all',
    status: 204,
    service: SessionService,
    call: 'revokeAllForUserAudited',
    result: undefined,
    response: null,
  },
  {
    route: 'post /api/v1/auth/password/change',
    method: 'post',
    url: '/api/v1/auth/password/change',
    body: { currentPassword: 'current-password', newPassword: 'Correct-Horse-Battery-9!' },
    status: 204,
    service: PasswordService,
    call: 'change',
    result: undefined,
    response: null,
    input: [1, { currentPassword: 'current-password', newPassword: 'Correct-Horse-Battery-9!' }],
  },
  {
    route: 'post /api/v1/auth/email/verification',
    method: 'post',
    url: '/api/v1/auth/email/verification',
    status: 202,
    service: EmailVerificationService,
    call: 'resend',
    result: undefined,
    response: null,
  },
  {
    route: 'post /api/v1/auth/email/verify',
    method: 'post',
    url: '/api/v1/auth/email/verify',
    body: { token: 'verify-token' },
    status: 204,
    service: EmailVerificationService,
    call: 'verify',
    result: undefined,
    response: null,
    input: [0, 'verify-token'],
  },
  {
    route: 'post /api/v1/auth/invitations/inspect',
    method: 'post',
    url: '/api/v1/auth/invitations/inspect',
    body: { token: 'invite-token' },
    status: 200,
    service: InvitationService,
    call: 'inspect',
    result: { email: 'new@example.test', organization: { name: 'Acme' } },
    input: [0, 'invite-token'],
  },
  {
    route: 'post /api/v1/auth/invitations/accept',
    method: 'post',
    url: '/api/v1/auth/invitations/accept',
    body: { token: 'invite-token', password: 'Correct-Horse-Battery-9!' },
    status: 204,
    service: InvitationService,
    call: 'accept',
    result: undefined,
    response: null,
    input: [0, { token: 'invite-token', password: 'Correct-Horse-Battery-9!' }],
  },
  {
    route: 'post /api/v1/auth/mfa/totp/setup',
    method: 'post',
    url: '/api/v1/auth/mfa/totp/setup',
    status: 200,
    service: MfaService,
    call: 'setup',
    result: { otpauthUrl: 'otpauth://totp/x' },
  },
  {
    route: 'post /api/v1/auth/mfa/totp/enable',
    method: 'post',
    url: '/api/v1/auth/mfa/totp/enable',
    body: { code: '123456' },
    status: 200,
    service: MfaService,
    call: 'enable',
    result: { enabled: true },
    input: [1, '123456'],
  },
  {
    route: 'post /api/v1/auth/mfa/totp/disable',
    method: 'post',
    url: '/api/v1/auth/mfa/totp/disable',
    body: { password: 'current-password', code: '123456' },
    status: 204,
    service: MfaService,
    call: 'disable',
    result: undefined,
    response: null,
    input: [1, { password: 'current-password', code: '123456' }],
  },
  {
    route: 'post /api/v1/auth/mfa/recovery-codes',
    method: 'post',
    url: '/api/v1/auth/mfa/recovery-codes',
    body: { code: '123456' },
    status: 200,
    service: MfaService,
    call: 'regenerateRecoveryCodes',
    result: { generatedAt: '2026-11-12T10:00:00.000Z' },
    input: [1, '123456'],
  },
  {
    route: 'get /api/v1/auth/sessions',
    method: 'get',
    url: '/api/v1/auth/sessions',
    status: 200,
    service: SessionService,
    call: 'listLiveForUser',
    result: [],
    response: { data: [] },
  },
  {
    route: 'post /api/v1/platform/overrides',
    method: 'post',
    url: '/api/v1/platform/overrides',
    body: { organizationId: OTHER, reason: 'investigate ticket 4711' },
    status: 201,
    service: PlatformOverrideService,
    call: 'start',
    result: { overrideId: ID, organizationId: OTHER, expiresAt: FUTURE },
    // durationMinutes defaults to 30.
    input: [1, { organizationId: OTHER, reason: 'investigate ticket 4711', durationMinutes: 30 }],
    platform: true,
  },
  {
    route: 'delete /api/v1/platform/overrides/:overrideId',
    method: 'delete',
    url: `/api/v1/platform/overrides/${ID}`,
    status: 204,
    service: PlatformOverrideService,
    call: 'end',
    result: undefined,
    response: null,
    input: [1, ID],
  },
  // ---- roles --------------------------------------------------------------------------------
  {
    route: 'get /api/v1/permissions',
    method: 'get',
    url: '/api/v1/permissions',
    status: 200,
    service: RolesService,
    call: 'listPermissions',
    result: [{ key: 'user:read', description: 'Read users', category: 'users' }],
    response: { data: [{ key: 'user:read', description: 'Read users', category: 'users' }] },
  },
  // ---- organizations -------------------------------------------------------------------------
  {
    route: 'get /api/v1/organizations/:id/features',
    method: 'get',
    url: `/api/v1/organizations/${ID}/features`,
    status: 200,
    service: OrganizationEntitlementsService,
    call: 'listFeatures',
    result: { organizationId: ID, data: [] },
    input: [1, ID],
  },
  // ---- BEC -----------------------------------------------------------------------------------
  {
    route: 'patch /api/v1/bec/executives/:id',
    method: 'patch',
    url: `/api/v1/bec/executives/${ID}`,
    body: { version: 1, title: 'CFO' },
    status: 200,
    service: BecProfilesService,
    call: 'updateExecutive',
    result: { id: ID, version: 2 },
    input: [3, { version: 1, title: 'CFO' }],
  },
  {
    route: 'delete /api/v1/bec/executives/:id',
    method: 'delete',
    url: `/api/v1/bec/executives/${ID}?version=3`,
    status: 204,
    service: BecProfilesService,
    call: 'deleteExecutive',
    result: undefined,
    response: null,
    input: [3, 3],
  },
  {
    route: 'get /api/v1/bec/vendors',
    method: 'get',
    url: '/api/v1/bec/vendors?limit=5',
    status: 200,
    service: BecProfilesService,
    call: 'listVendors',
    result: page,
  },
  {
    route: 'get /api/v1/bec/vendors/:id',
    method: 'get',
    url: `/api/v1/bec/vendors/${ID}`,
    status: 200,
    service: BecProfilesService,
    call: 'getVendor',
    result: { id: ID, name: 'Globex' },
    input: [1, ID],
  },
  {
    route: 'patch /api/v1/bec/vendors/:id',
    method: 'patch',
    url: `/api/v1/bec/vendors/${ID}`,
    body: { version: 1, name: 'Globex Supplies' },
    status: 200,
    service: BecProfilesService,
    call: 'updateVendor',
    result: { id: ID, version: 2 },
    input: [3, { version: 1, name: 'Globex Supplies' }],
  },
  {
    route: 'delete /api/v1/bec/vendors/:id',
    method: 'delete',
    url: `/api/v1/bec/vendors/${ID}?version=2`,
    status: 204,
    service: BecProfilesService,
    call: 'deleteVendor',
    result: undefined,
    response: null,
    input: [3, 2],
  },
  {
    route: 'get /api/v1/bec/trusted-senders',
    method: 'get',
    url: '/api/v1/bec/trusted-senders',
    status: 200,
    service: BecTrustedSendersService,
    call: 'list',
    result: page,
  },
  {
    route: 'patch /api/v1/bec/trusted-senders/:id',
    method: 'patch',
    url: `/api/v1/bec/trusted-senders/${ID}`,
    body: { version: 1, reason: 'Payroll partner' },
    status: 200,
    service: BecTrustedSendersService,
    call: 'update',
    result: { id: ID, version: 2 },
    input: [3, { version: 1, reason: 'Payroll partner' }],
  },
  {
    route: 'delete /api/v1/bec/trusted-senders/:id',
    method: 'delete',
    url: `/api/v1/bec/trusted-senders/${ID}?version=1`,
    status: 204,
    service: BecTrustedSendersService,
    call: 'remove',
    result: undefined,
    response: null,
    input: [3, 1],
  },
  {
    route: 'get /api/v1/bec/feedback',
    method: 'get',
    url: '/api/v1/bec/feedback',
    status: 200,
    service: BecFeedbackService,
    call: 'list',
    result: page,
  },
  {
    route: 'get /api/v1/bec/suppressions',
    method: 'get',
    url: '/api/v1/bec/suppressions',
    status: 200,
    service: BecFeedbackService,
    call: 'listSuppressions',
    result: page,
  },
  {
    route: 'delete /api/v1/bec/suppressions/:id',
    method: 'delete',
    url: `/api/v1/bec/suppressions/${ID}`,
    status: 204,
    service: BecFeedbackService,
    call: 'deleteSuppression',
    result: undefined,
    response: null,
    input: [2, ID],
  },
  // ---- DLP -----------------------------------------------------------------------------------
  {
    route: 'patch /api/v1/dlp/policies/:id/rules/:ruleId',
    method: 'patch',
    url: `/api/v1/dlp/policies/${ID}/rules/${OTHER}`,
    body: { version: 1, enabled: false },
    status: 200,
    service: DlpPoliciesService,
    call: 'updateRule',
    result: { id: OTHER, version: 2 },
    input: [3, OTHER],
  },
  {
    route: 'delete /api/v1/dlp/policies/:id/rules/:ruleId',
    method: 'delete',
    url: `/api/v1/dlp/policies/${ID}/rules/${OTHER}?version=2`,
    status: 204,
    service: DlpPoliciesService,
    call: 'removeRule',
    result: undefined,
    response: null,
    input: [4, 2],
  },
  {
    route: 'post /api/v1/dlp/exceptions',
    method: 'post',
    url: '/api/v1/dlp/exceptions',
    body: {
      scope: 'recipient_domain',
      value: 'auditor.example',
      reason: 'Statutory auditor',
      expiresAt: FUTURE,
    },
    status: 201,
    service: DlpExceptionsService,
    call: 'create',
    result: { id: ID, version: 1 },
  },
  {
    route: 'patch /api/v1/dlp/exceptions/:id',
    method: 'patch',
    url: `/api/v1/dlp/exceptions/${ID}`,
    body: { version: 1, enabled: false },
    status: 200,
    service: DlpExceptionsService,
    call: 'update',
    result: { id: ID, version: 2 },
    input: [3, { version: 1, enabled: false }],
  },
  {
    route: 'delete /api/v1/dlp/exceptions/:id',
    method: 'delete',
    url: `/api/v1/dlp/exceptions/${ID}?version=2`,
    status: 204,
    service: DlpExceptionsService,
    call: 'remove',
    result: undefined,
    response: null,
    input: [3, 2],
  },
  {
    route: 'get /api/v1/dlp/patterns/:id',
    method: 'get',
    url: `/api/v1/dlp/patterns/${ID}`,
    status: 200,
    service: DlpPatternsService,
    call: 'get',
    result: { id: ID, name: 'Employee id' },
    input: [1, ID],
  },
  {
    route: 'patch /api/v1/dlp/patterns/:id',
    method: 'patch',
    url: `/api/v1/dlp/patterns/${ID}`,
    body: { version: 1, name: 'Employee number' },
    status: 200,
    service: DlpPatternsService,
    call: 'update',
    result: { id: ID, version: 2 },
    input: [3, { version: 1, name: 'Employee number' }],
  },
  {
    route: 'get /api/v1/dlp/dictionaries/:id',
    method: 'get',
    url: `/api/v1/dlp/dictionaries/${ID}`,
    status: 200,
    service: DlpDictionariesService,
    call: 'get',
    result: { id: ID, name: 'Projects' },
    input: [1, ID],
  },
  {
    route: 'patch /api/v1/dlp/dictionaries/:id',
    method: 'patch',
    url: `/api/v1/dlp/dictionaries/${ID}`,
    body: { version: 1, name: 'Code names' },
    status: 200,
    service: DlpDictionariesService,
    call: 'update',
    result: { id: ID, version: 2 },
    input: [3, { version: 1, name: 'Code names' }],
  },
  {
    route: 'delete /api/v1/dlp/dictionaries/:id',
    method: 'delete',
    url: `/api/v1/dlp/dictionaries/${ID}?version=2`,
    status: 204,
    service: DlpDictionariesService,
    call: 'remove',
    result: undefined,
    response: null,
    input: [3, 2],
  },
  // ---- quarantine ----------------------------------------------------------------------------
  {
    route: 'get /api/v1/quarantine/releases/:releaseId',
    method: 'get',
    url: `/api/v1/quarantine/releases/${ID}`,
    status: 200,
    service: QuarantineQueryService,
    call: 'release',
    result: { id: ID, status: 'pending' },
    input: [1, ID],
  },
  {
    route: 'get /api/v1/quarantine/approvals/:approvalId',
    method: 'get',
    url: `/api/v1/quarantine/approvals/${ID}`,
    status: 200,
    service: QuarantineQueryService,
    call: 'approval',
    result: { id: ID, status: 'pending' },
    input: [1, ID],
  },
  {
    route: 'post /api/v1/quarantine/approvals/:approvalId/cancel',
    method: 'post',
    url: `/api/v1/quarantine/approvals/${ID}/cancel`,
    body: { reason: 'raised by mistake' },
    headers: idem('cancel-key-1'),
    status: 200,
    service: QuarantineApprovalsService,
    call: 'cancel',
    result: { statusCode: 200, body: { id: ID, status: 'cancelled' }, replayed: false },
    response: { id: ID, status: 'cancelled' },
  },
  {
    route: 'put /api/v1/quarantine/me/preferences',
    method: 'put',
    url: '/api/v1/quarantine/me/preferences',
    body: { digestOptOut: true },
    status: 200,
    service: QuarantineSettingsService,
    call: 'putPreferences',
    result: { digestOptOut: true },
    input: [2, { digestOptOut: true }],
  },
  {
    route: 'get /api/v1/quarantine/me/preferences',
    method: 'get',
    url: '/api/v1/quarantine/me/preferences',
    status: 200,
    service: QuarantineSettingsService,
    call: 'preferences',
    result: { digestOptOut: false },
  },
];

const spies = new Map<string, ReturnType<typeof vi.fn>>();
const spyOf = (c: Case) => {
  const key = `${c.service.name}.${c.call}`;
  if (!spies.has(key)) spies.set(key, vi.fn());
  return spies.get(key)!;
};
for (const c of CASES) spyOf(c);

describe('legacy routes without a module e2e suite (e2e, services stubbed)', () => {
  let t: StubbedApiApp;
  let routes: DiscoveredRoute[];

  beforeAll(async () => {
    const services = new Map<Case['service'], Record<string, unknown>>();
    for (const c of CASES) {
      const stub = services.get(c.service) ?? {};
      stub[c.call] = spyOf(c);
      services.set(c.service, stub);
    }
    // The stubbed app's own SessionService answers the AuthGuard's checks.
    services.set(SessionService, {
      ...services.get(SessionService),
      isRevoked: () => Promise.resolve(false),
      isLive: () => Promise.resolve(true),
    });
    t = await createStubbedApiApp(
      {},
      {
        discovery: true,
        override: (builder) => {
          let next = builder;
          for (const [service, stub] of services) {
            next = next.overrideProvider(service).useValue(stub);
          }
          return next;
        },
      },
    );
    routes = discoverRoutes(t.app);
  });

  afterAll(async () => {
    await t?.close();
  });

  beforeEach(() => {
    for (const spy of spies.values()) spy.mockReset();
  });

  const permissionsOf = (c: Case): string[] => {
    const route = routes.find((r) => `${r.method} ${r.path}` === c.route);
    expect(route, c.route).toBeDefined();
    const requirement = route!.requirement as
      { mode: 'all' | 'any'; permissions: string[] } | undefined;
    const permissions = requirement?.permissions ?? [];
    return requirement?.mode === 'any' ? permissions.slice(0, 1) : permissions;
  };
  const send = async (c: Case, permissions: string[]) => {
    t.principals.user(permissions, {
      mfaAuthenticated: true,
      orgKind: c.platform ? 'platform' : 'customer',
    });
    const req = request(t.app.getHttpServer())
      [c.method](c.url)
      .set(await t.principals.bearer())
      // A client-supplied tenant header never changes the scope.
      .set('X-Organization-Id', '999')
      .set(c.headers ?? {});
    return c.body === undefined ? req : req.send(c.body);
  };

  it.each(CASES.map((c) => [c.route, c] as const))('%s', async (_name, c) => {
    const permissions = permissionsOf(c);
    if (permissions.length > 0) {
      const denied = await send(c, []);
      expect(denied.status, c.route).toBe(403);
      expect(spyOf(c)).not.toHaveBeenCalled();
    }
    spyOf(c).mockResolvedValue(c.result);
    const res = await send(c, permissions);
    expect(res.status, JSON.stringify(res.body)).toBe(c.status);
    if (c.response === null) expect(res.text).toBe('');
    else expect(res.body).toEqual(c.response ?? c.result);
    expect(spyOf(c)).toHaveBeenCalledTimes(1);
    const args = spyOf(c).mock.calls[0] as unknown[];
    if (c.input) expect(args[c.input[0]]).toEqual(c.input[1]);
    // The tenant scope (or the principal it derives from) is the principal's organization.
    const scoped = args.find(
      (a): a is { organizationId: unknown } =>
        typeof a === 'object' && a !== null && 'organizationId' in a,
    );
    if (scoped) expect(scoped.organizationId).toBe(t.principals.organizationId);
  });

  it('GET /metrics serves the Prometheus text format (internal port only, never under /api)', async () => {
    const res = await request(t.app.getHttpServer()).get('/metrics').expect(200);
    expect(res.headers['content-type']).toMatch(/^text\/plain/);
    expect(res.text).toMatch(/# TYPE \w+/);
    await request(t.app.getHttpServer()).get('/api/v1/metrics').expect(404);
  });
});
