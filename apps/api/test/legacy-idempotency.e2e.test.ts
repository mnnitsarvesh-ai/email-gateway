/**
 * Step 6.1 WP4 (docs/plan/steps/18-rest-api.md D1, D8, D9, §3.5, §9): the legacy sensitive
 * mutations newly placed on the Idempotency-Key list, over HTTP with MySQL, Redis and S3 stubbed,
 * the `api_idempotency_keys` store in memory and each route's service stubbed with a canned
 * result (the services' own behaviour is covered by the module suites). For EVERY §3.5 legacy
 * route:
 *
 * - no key under `API_IDEMPOTENCY_LEGACY_MODE=enforce` → `400 idempotency_key_required`, the
 *   service is not called;
 * - no key under `warn` → processed as before, with `Deprecation: true` and the deprecation Link;
 * - the same key and request again → the stored status and body with `Idempotency-Replayed`, the
 *   service called once;
 * - the same key with another body → `422 idempotency_key_reused`.
 *
 * Plus: the `sensitive` class answers 429 with the RateLimit headers on one route, and every
 * converged module rejects an unknown body field and an unknown query parameter with
 * `400 validation_failed` (strict schemas, D1).
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/dlp/compliance/aadhaar
// ---- end of route coverage ----
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { IDEMPOTENCY_DEPRECATION_DOC } from '../src/http/idempotency/idempotency.interceptor';
import { BecFeedbackService } from '../src/modules/bec/services/bec-feedback.service';
import { DeadLetterReplayService } from '../src/modules/dead-letters/services/dead-letter-replay.service';
import { DlpComplianceService } from '../src/modules/dlp/services/dlp-compliance.service';
import { DlpEvidenceService } from '../src/modules/dlp/services/dlp-evidence.service';
import { DkimRotationService } from '../src/modules/domains/services/dkim-rotation.service';
import { OrganizationDeletionService } from '../src/modules/organizations/services/organization-deletion.service';
import { OrganizationsService } from '../src/modules/organizations/services/organizations.service';
import { PoliciesService } from '../src/modules/policies/services/policies.service';
import { RiskProfilesService } from '../src/modules/risk-scoring/services/risk-profiles.service';
import { AttachmentRescansService } from '../src/modules/scans/services/attachment-rescans.service';
import { ScanTrainingService } from '../src/modules/scans/services/scan-training.service';
import { ThreatHashesService } from '../src/modules/scans/services/threat-hashes.service';
import { ThreatIndicatorsService } from '../src/modules/scans/services/threat-indicators.service';
import { UsersService } from '../src/modules/users/users.service';
import { idem } from './legacy-idempotency-support';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { type DiscoveredRoute, discoverRoutes } from './support/route-discovery';

const ID = randomUUID();
const OTHER = randomUUID();
const SCAN = '900';
const REVIEW_DUE = new Date(Date.now() + 30 * 86_400_000).toISOString();

type Method = 'post' | 'put' | 'patch' | 'delete';

interface LegacyRoute {
  /** Nest route key (`<method> <path>` as discovered). */
  route: string;
  operation: string;
  method: Method;
  url: string;
  body?: object;
  /** Another body for the reuse check (a bodiless route gets an unexpected JSON body). */
  other: object;
  status: number;
  /** Service class and method the handler calls, and its canned result. */
  service: abstract new (...args: never[]) => unknown;
  call: string;
  result: unknown;
  /** The response body (defaults to `result`). */
  response?: unknown;
  platform?: boolean;
}

const user = (email: string) => ({
  id: ID,
  email,
  displayName: 'New',
  status: 'invited',
  statusReason: null,
  // `key` matches the credential pattern by name (a role key, not a credential): the route uses
  // @LegacyIdempotent({ publicFields: ['key'] }).
  roles: [{ key: 'read_only_user', name: 'Read only' }],
  mfaEnabled: false,
  emailVerified: false,
  lockedUntil: null,
  lastLoginAt: null,
  createdAt: '2026-11-12T10:00:00.000Z',
  updatedAt: '2026-11-12T10:00:00.000Z',
});
const policyChange = {
  version: {
    versionNo: 1,
    status: 'published',
    validation: { valid: true, violations: [{ path: 'rules[1]', code: 'shadowed', message: 'x' }] },
  },
  policy: { id: ID, activeVersionNo: 1, rowVersion: 2 },
};
const riskChange = { version: { id: ID, status: 'published' }, profile: { profileVersion: 3 } };
const compliance = { aadhaar: { enabled: true, version: 1 } };
const dkim = {
  domainId: ID,
  key: { selector: 'eg202611a', algorithm: 'rsa_2048', status: 'pending' },
  previous: null,
  dnsRecord: { key: 'dkim:eg202611a', purpose: 'dkim', value: 'v=DKIM1; k=rsa; p=MIIB' },
  overlapDays: 7,
};
const replay = {
  replayId: ID,
  dryRun: false,
  scanned: 1,
  matched: 1,
  replayed: 1,
  skipped: { invalid: 0, notMatching: 0 },
  items: [],
};

/** Every legacy route of §3.5 (22), in the order of the table. */
const LEGACY: LegacyRoute[] = [
  {
    route: 'post /api/v1/domains/:id/dkim/rotate',
    operation: 'domain.dkim_rotate',
    method: 'post',
    url: `/api/v1/domains/${ID}/dkim/rotate`,
    body: {},
    other: { algorithm: 'ed25519' },
    status: 201,
    service: DkimRotationService,
    call: 'rotate',
    result: dkim,
  },
  {
    route: 'patch /api/v1/organizations/:id/status',
    operation: 'organization.status_change',
    method: 'patch',
    url: `/api/v1/organizations/${ID}/status`,
    body: { status: 'active' },
    other: { status: 'suspended', reason: 'abuse report' },
    status: 200,
    service: OrganizationsService,
    call: 'changeStatus',
    // `plan.code` (a plan code): @LegacyIdempotent({ publicFields: ['code'] }).
    result: { id: ID, status: 'active', plan: { code: 'standard', name: 'Standard' } },
    platform: true,
  },
  {
    route: 'post /api/v1/organizations/:id/deletion',
    operation: 'organization.deletion_request',
    method: 'post',
    url: `/api/v1/organizations/${ID}/deletion`,
    body: { reason: 'Customer offboarded per contract', confirmSlug: 'acme' },
    other: { reason: 'Customer offboarded per contract', confirmSlug: 'acme-two' },
    status: 200,
    service: OrganizationDeletionService,
    call: 'request',
    result: { organizationId: ID, state: 'pending_deletion' },
    platform: true,
  },
  {
    route: 'post /api/v1/organizations/:id/deletion/confirm',
    operation: 'organization.deletion_confirm',
    method: 'post',
    url: `/api/v1/organizations/${ID}/deletion/confirm`,
    body: { confirmSlug: 'acme' },
    other: { confirmSlug: 'acme-two' },
    status: 200,
    service: OrganizationDeletionService,
    call: 'confirm',
    result: { organizationId: ID, state: 'deleted' },
    platform: true,
  },
  {
    route: 'post /api/v1/users/invitations',
    operation: 'user.invite',
    method: 'post',
    url: '/api/v1/users/invitations',
    body: { email: 'new.user@example.test', displayName: 'New', roleKeys: ['read_only_user'] },
    other: { email: 'other.user@example.test', displayName: 'New', roleKeys: ['read_only_user'] },
    status: 201,
    service: UsersService,
    call: 'invite',
    result: user('new.user@example.test'),
  },
  {
    route: 'post /api/v1/users/:id/invitation',
    operation: 'user.invitation_resend',
    method: 'post',
    url: `/api/v1/users/${ID}/invitation`,
    other: { unexpected: true },
    status: 202,
    service: UsersService,
    call: 'resendInvitation',
    result: { expiresAt: '2026-11-19T10:00:00.000Z' },
  },
  {
    route: 'post /api/v1/users/:id/mfa/reset',
    operation: 'user.mfa_reset',
    method: 'post',
    url: `/api/v1/users/${ID}/mfa/reset`,
    other: { unexpected: true },
    status: 204,
    service: UsersService,
    call: 'resetMfa',
    result: undefined,
    response: {},
  },
  {
    route: 'post /api/v1/policies/:policyId/versions/:versionNo/publish',
    operation: 'policy.version_publish',
    method: 'post',
    url: `/api/v1/policies/${ID}/versions/1/publish`,
    body: { expectedRowVersion: 1 },
    other: { expectedRowVersion: 2 },
    status: 200,
    service: PoliciesService,
    call: 'publish',
    result: policyChange,
  },
  {
    route: 'post /api/v1/policies/:policyId/versions/:versionNo/activate',
    operation: 'policy.version_activate',
    method: 'post',
    url: `/api/v1/policies/${ID}/versions/1/activate`,
    body: {},
    other: { expectedRowVersion: 3 },
    status: 200,
    service: PoliciesService,
    call: 'activate',
    result: policyChange,
  },
  {
    route: 'post /api/v1/risk-scoring/profile/versions/:versionId/publish',
    operation: 'risk_profile.publish',
    method: 'post',
    url: `/api/v1/risk-scoring/profile/versions/${ID}/publish`,
    body: { expectedRowVersion: 1 },
    other: { expectedRowVersion: 1, activate: false },
    status: 200,
    service: RiskProfilesService,
    call: 'publish',
    result: riskChange,
  },
  {
    route: 'post /api/v1/risk-scoring/profile/versions/:versionId/activate',
    operation: 'risk_profile.activate',
    method: 'post',
    url: `/api/v1/risk-scoring/profile/versions/${ID}/activate`,
    body: {},
    other: { expectedProfileVersion: 2 },
    status: 200,
    service: RiskProfilesService,
    call: 'activate',
    result: riskChange,
  },
  {
    route: 'post /api/v1/risk-scoring/profile/reset',
    operation: 'risk_profile.reset',
    method: 'post',
    url: '/api/v1/risk-scoring/profile/reset',
    body: {},
    other: { expectedProfileVersion: 2 },
    status: 200,
    service: RiskProfilesService,
    call: 'reset',
    result: { profileVersion: 4, active: null },
  },
  {
    route: 'delete /api/v1/bec/history',
    operation: 'bec.history_purge',
    method: 'delete',
    url: '/api/v1/bec/history',
    other: { unexpected: true },
    status: 202,
    service: BecFeedbackService,
    call: 'purgeHistory',
    result: { deleted: 3 },
  },
  {
    route: 'delete /api/v1/dlp/evidence',
    operation: 'dlp.evidence_purge_all',
    method: 'delete',
    url: '/api/v1/dlp/evidence',
    other: { unexpected: true },
    status: 202,
    service: DlpEvidenceService,
    call: 'purgeAll',
    result: { purged: 5 },
  },
  {
    route: 'delete /api/v1/messages/:messageId/scans/:scanId/dlp-evidence',
    operation: 'dlp.evidence_purge',
    method: 'delete',
    url: `/api/v1/messages/${ID}/scans/${SCAN}/dlp-evidence`,
    other: { unexpected: true },
    status: 204,
    service: DlpEvidenceService,
    call: 'purgeOne',
    result: undefined,
    response: {},
  },
  {
    route: 'put /api/v1/dlp/compliance/aadhaar',
    operation: 'dlp.aadhaar_enable',
    method: 'put',
    url: '/api/v1/dlp/compliance/aadhaar',
    body: {
      expectedVersion: 0,
      basis: 'regulatory_obligation',
      reference: 'RBI KYC direction 2026/14',
      attested: true,
      reviewDueAt: REVIEW_DUE,
    },
    other: {
      expectedVersion: 0,
      basis: 'regulatory_obligation',
      reference: 'Another reference',
      attested: true,
      reviewDueAt: REVIEW_DUE,
    },
    status: 200,
    service: DlpComplianceService,
    call: 'enableAadhaar',
    result: compliance,
  },
  {
    route: 'delete /api/v1/dlp/compliance/aadhaar',
    operation: 'dlp.aadhaar_disable',
    method: 'delete',
    url: '/api/v1/dlp/compliance/aadhaar',
    other: { unexpected: true },
    status: 200,
    service: DlpComplianceService,
    call: 'disableAadhaar',
    result: { aadhaar: { enabled: false, version: 2 } },
  },
  {
    route: 'post /api/v1/platform/dead-letters/replay',
    operation: 'platform.dead_letter_replay',
    method: 'post',
    url: '/api/v1/platform/dead-letters/replay',
    body: { sourceQueue: 'email.received', limit: 10, reason: 'replay after the parser fix' },
    other: { sourceQueue: 'email.received', limit: 20, reason: 'replay after the parser fix' },
    status: 200,
    service: DeadLetterReplayService,
    call: 'replay',
    result: replay,
    platform: true,
  },
  {
    route: 'post /api/v1/platform/attachment-rescans',
    operation: 'platform.attachment_rescan',
    method: 'post',
    url: '/api/v1/platform/attachment-rescans',
    body: { windowHours: 24, reason: 'new signatures' },
    other: { windowHours: 48, reason: 'new signatures' },
    status: 202,
    service: AttachmentRescansService,
    call: 'request',
    result: { kind: 'job', body: { id: ID, status: 'pending', estimatedMessages: 7 } },
    response: { id: ID, status: 'pending', estimatedMessages: 7 },
    platform: true,
  },
  {
    route: 'post /api/v1/platform/organizations/:organizationId/messages/:messageId/scan-training',
    operation: 'platform.scan_training',
    method: 'post',
    url: `/api/v1/platform/organizations/${ID}/messages/${OTHER}/scan-training`,
    body: { operation: 'learn_spam', reason: 'confirmed spam campaign' },
    other: { operation: 'learn_ham', reason: 'confirmed false positive' },
    status: 200,
    service: ScanTrainingService,
    call: 'train',
    result: { operation: 'learn_spam', messageId: OTHER, trained: true },
    platform: true,
  },
  {
    route: 'post /api/v1/platform/threat-hashes',
    operation: 'platform.threat_hash_add',
    method: 'post',
    url: '/api/v1/platform/threat-hashes',
    body: { sha256: 'e'.repeat(64), severity: 'high', reason: 'campaign' },
    other: { sha256: 'f'.repeat(64), severity: 'high', reason: 'campaign' },
    status: 201,
    service: ThreatHashesService,
    call: 'add',
    result: { sha256: 'e'.repeat(64), severity: 'high' },
    platform: true,
  },
  {
    route: 'post /api/v1/platform/threat-indicators',
    operation: 'platform.threat_indicator_add',
    method: 'post',
    url: '/api/v1/platform/threat-indicators',
    body: {
      type: 'domain',
      value: 'evil-new.example',
      severity: 'high',
      category: 'phishing',
      reason: 'campaign',
    },
    other: {
      type: 'domain',
      value: 'evil-other.example',
      severity: 'high',
      category: 'phishing',
      reason: 'campaign',
    },
    status: 201,
    service: ThreatIndicatorsService,
    call: 'add',
    result: { id: '7', type: 'domain', value: 'evil-new.example' },
    platform: true,
  },
];

/** One spy per service method, shared by the apps (reset per test). */
const spies = new Map<string, ReturnType<typeof vi.fn>>();
const spyOf = (r: LegacyRoute) => {
  const key = `${r.service.name}.${r.call}`;
  if (!spies.has(key)) spies.set(key, vi.fn());
  return spies.get(key)!;
};
for (const r of LEGACY) spyOf(r);

async function legacyApp(env: Record<string, string> = {}): Promise<StubbedApiApp> {
  const store = new InMemoryIdempotencyStore();
  const services = new Map<LegacyRoute['service'], Record<string, unknown>>();
  for (const r of LEGACY) {
    const stub = services.get(r.service) ?? {};
    stub[r.call] = spyOf(r);
    services.set(r.service, stub);
  }
  return createStubbedApiApp(env, {
    discovery: true,
    override: (builder) => {
      let next = store.override(builder);
      for (const [service, stub] of services) next = next.overrideProvider(service).useValue(stub);
      return next;
    },
  });
}

/** Every permission any legacy route requires (the test user holds them all). */
const permissionsOf = (routes: DiscoveredRoute[]): string[] => [
  ...new Set(
    routes.flatMap(
      (r) => (r.requirement as { permissions?: string[] } | undefined)?.permissions ?? [],
    ),
  ),
];

describe('legacy sensitive mutations: Idempotency-Key (e2e, step 6.1 §3.5)', () => {
  let enforce: StubbedApiApp;
  let warn: StubbedApiApp;
  let permissions: string[];

  const as = async (t: StubbedApiApp, r: LegacyRoute) => {
    t.principals.user(permissions, {
      mfaAuthenticated: true,
      orgKind: r.platform ? 'platform' : 'customer',
    });
    return t.principals.bearer();
  };
  const send = async (
    t: StubbedApiApp,
    r: LegacyRoute,
    headers: Record<string, string>,
    body?: object,
  ) => {
    const req = request(t.app.getHttpServer())
      [r.method](r.url)
      .set(await as(t, r))
      .set(headers);
    return body === undefined ? req : req.send(body);
  };

  beforeAll(async () => {
    enforce = await legacyApp();
    warn = await legacyApp({ API_IDEMPOTENCY_LEGACY_MODE: 'warn' });
    const routes = discoverRoutes(enforce.app);
    permissions = permissionsOf(
      routes.filter((r) => LEGACY.some((l) => l.route === `${r.method} ${r.path}`)),
    );
  });

  afterAll(async () => {
    await enforce?.close();
    await warn?.close();
  });

  const reset = (r: LegacyRoute) => {
    for (const spy of spies.values()) spy.mockReset();
    spyOf(r).mockResolvedValue(r.result);
  };

  it('covers the 22 legacy routes of §3.5 with their operation names', () => {
    const routes = discoverRoutes(enforce.app);
    expect(LEGACY).toHaveLength(22);
    for (const r of LEGACY) {
      const found = routes.find((d) => `${d.method} ${d.path}` === r.route);
      expect(found?.idempotency, r.route).toEqual({ operation: r.operation, legacy: true });
    }
  });

  describe.each(LEGACY.map((r) => [r.route, r] as const))('%s', (_name, r) => {
    it('enforce: no Idempotency-Key → 400 idempotency_key_required, nothing runs', async () => {
      reset(r);
      const res = await send(enforce, r, {}, r.body);
      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({
        code: 'idempotency_key_required',
        message: 'The Idempotency-Key header is required',
      });
      expect(spyOf(r)).not.toHaveBeenCalled();
    });

    it('warn: no Idempotency-Key → processed as before, with Deprecation and Link', async () => {
      reset(r);
      const res = await send(warn, r, {}, r.body);
      expect(res.status).toBe(r.status);
      expect(res.body).toEqual(r.response ?? r.result);
      expect(res.headers.deprecation).toBe('true');
      expect(res.headers.link).toBe(`<${IDEMPOTENCY_DEPRECATION_DOC}>; rel="deprecation"`);
      expect(res.headers['idempotency-replayed']).toBeUndefined();
      expect(spyOf(r)).toHaveBeenCalledTimes(1);
    });

    it('replay: the same key and request → the stored status and body, one effect', async () => {
      reset(r);
      const key = idem();
      const first = await send(enforce, r, key, r.body);
      expect(first.status).toBe(r.status);
      expect(first.body).toEqual(r.response ?? r.result);
      expect(first.headers['idempotency-replayed']).toBeUndefined();
      expect(first.headers.deprecation).toBeUndefined();
      const again = await send(enforce, r, key, r.body);
      expect(again.status).toBe(first.status);
      expect(again.body).toEqual(first.body);
      expect(again.headers['idempotency-replayed']).toBe('true');
      expect(spyOf(r)).toHaveBeenCalledTimes(1);
    });

    it('reuse: the same key with another body → 422 idempotency_key_reused', async () => {
      reset(r);
      const key = idem();
      await send(enforce, r, key, r.body).then((res) => expect(res.status).toBe(r.status));
      const reused = await send(enforce, r, key, r.other);
      expect(reused.status).toBe(422);
      expect(reused.body).toMatchObject({ code: 'idempotency_key_reused' });
      expect(spyOf(r)).toHaveBeenCalledTimes(1);
    });
  });

  it('an invalid Idempotency-Key → 400 idempotency_key_invalid', async () => {
    const r = LEGACY[0]!;
    reset(r);
    const res = await send(enforce, r, { 'Idempotency-Key': 'not valid!' }, r.body);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('idempotency_key_invalid');
    expect(spyOf(r)).not.toHaveBeenCalled();
  });

  it('a failed request releases the key: a retry with the same key runs again', async () => {
    const r = LEGACY.find((l) => l.operation === 'user.invite')!;
    reset(r);
    spyOf(r).mockRejectedValueOnce(new Error('transient'));
    const key = idem();
    expect((await send(enforce, r, key, r.body)).status).toBe(500);
    const retry = await send(enforce, r, key, r.body);
    expect(retry.status).toBe(201);
    expect(retry.headers['idempotency-replayed']).toBeUndefined();
    expect(spyOf(r)).toHaveBeenCalledTimes(2);
  });
});

describe('legacy sensitive mutations: the sensitive class (e2e, D8)', () => {
  let t: StubbedApiApp;
  beforeAll(async () => {
    t = await legacyApp({ API_RATE_SENSITIVE_PER_MINUTE: '2' });
  });
  afterAll(async () => {
    await t?.close();
  });

  it('answers 429 rate_limited (scope sensitive) with RateLimit headers and Retry-After', async () => {
    const r = LEGACY.find((l) => l.operation === 'user.invite')!;
    spyOf(r).mockReset();
    spyOf(r).mockResolvedValue(r.result);
    t.principals.user(['user:manage'], { mfaAuthenticated: true });
    const auth = await t.principals.bearer();
    const post = () =>
      request(t.app.getHttpServer()).post(r.url).set(auth).set(idem()).send(r.body);
    const ok = await post();
    expect(ok.status).toBe(201);
    expect(ok.headers['ratelimit-limit']).toBe('2');
    expect(ok.headers['ratelimit-remaining']).toBe('1');
    expect((await post()).status).toBe(201);
    const limited = await post();
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ code: 'rate_limited', scope: 'sensitive' });
    expect(limited.headers['ratelimit-limit']).toBe('2');
    expect(limited.headers['ratelimit-remaining']).toBe('0');
    expect(Number(limited.headers['ratelimit-reset'])).toBeGreaterThan(0);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    expect(spyOf(r)).toHaveBeenCalledTimes(2);
  });
});

/**
 * Strict request schemas (D1): one body route and one query route per converged module (a
 * module without a query schema has none). Validation runs before any service, so nothing is
 * stubbed beyond the principal.
 */
const STRICT: Array<{
  module: string;
  method: 'get' | Method;
  url: string;
  body?: object;
  platform?: boolean;
}> = [
  {
    module: 'auth',
    method: 'post',
    url: '/api/v1/auth/password/change',
    body: { currentPassword: 'x', newPassword: 'Another-Passw0rd!', extra: 1 },
  },
  {
    module: 'auth (platform override)',
    method: 'post',
    url: '/api/v1/platform/overrides',
    body: { organizationId: ID, reason: 'investigate ticket 42', extra: 1 },
    platform: true,
  },
  {
    module: 'users',
    method: 'patch',
    url: `/api/v1/users/${ID}`,
    body: { displayName: 'A', extra: 1 },
  },
  { module: 'users', method: 'get', url: '/api/v1/users?extra=1' },
  {
    module: 'roles',
    method: 'post',
    url: '/api/v1/roles',
    body: { key: 'mail_ops', name: 'M', permissions: ['user:read'], extra: 1 },
  },
  {
    module: 'api-keys',
    method: 'post',
    url: '/api/v1/api-keys',
    body: { name: 'ci', scopes: ['user:read'], extra: 1 },
  },
  { module: 'api-keys', method: 'get', url: '/api/v1/api-keys?extra=1' },
  { module: 'login-audit', method: 'get', url: '/api/v1/audit/login-events?extra=1' },
  {
    module: 'organizations',
    method: 'put',
    url: `/api/v1/organizations/${ID}`,
    body: { name: 'Renamed', extra: 1 },
  },
  { module: 'organizations', method: 'get', url: '/api/v1/organizations?extra=1' },
  { module: 'organizations', method: 'get', url: `/api/v1/organizations/${ID}/usage?extra=1` },
  {
    module: 'domains',
    method: 'post',
    url: '/api/v1/domains',
    body: { name: 'acme.test', extra: 1 },
  },
  { module: 'domains', method: 'get', url: '/api/v1/domains?extra=1' },
  {
    module: 'domains (recipients)',
    method: 'get',
    url: `/api/v1/domains/${ID}/recipients?extra=1`,
  },
  {
    module: 'smtp-connectors',
    method: 'patch',
    url: `/api/v1/smtp-connectors/${ID}`,
    body: { name: 'relay', extra: 1 },
  },
  { module: 'smtp-connectors', method: 'get', url: '/api/v1/smtp-connectors?extra=1' },
  {
    module: 'domain-destinations',
    method: 'put',
    url: `/api/v1/domains/${ID}/destinations`,
    body: { provider: 'google_workspace', extra: 1 },
  },
  { module: 'deliveries', method: 'get', url: '/api/v1/deliveries?extra=1' },
  {
    module: 'dead-letters',
    method: 'post',
    url: '/api/v1/platform/dead-letters/replay',
    body: { sourceQueue: 'email.received', limit: 1, reason: 'replay after the fix', extra: 1 },
    platform: true,
  },
  {
    module: 'scans',
    method: 'put',
    url: '/api/v1/scan-settings/rspamd',
    body: { expectedVersion: 0, settings: {}, extra: 1 },
  },
  { module: 'scans', method: 'get', url: '/api/v1/platform/threat-hashes?extra=1', platform: true },
  {
    module: 'bec',
    method: 'post',
    url: '/api/v1/bec/executives',
    body: { displayName: 'CEO', addresses: ['ceo@acme.test'], extra: 1 },
  },
  { module: 'bec', method: 'get', url: '/api/v1/bec/executives?extra=1' },
  {
    module: 'dlp',
    method: 'post',
    url: '/api/v1/dlp/patterns/test',
    body: { regex: 'a+', samples: ['aaa'], extra: 1 },
  },
  { module: 'dlp', method: 'get', url: '/api/v1/dlp/policies?extra=1' },
  {
    module: 'risk-scoring',
    method: 'post',
    url: '/api/v1/risk-scoring/profile/versions',
    body: { overrides: {}, extra: 1 },
  },
  { module: 'risk-scoring', method: 'get', url: '/api/v1/risk-scoring/profile/versions?extra=1' },
  { module: 'policies', method: 'put', url: '/api/v1/policy-settings', body: { extra: 1 } },
  { module: 'policies', method: 'get', url: '/api/v1/policies?extra=1' },
  {
    module: 'directory',
    method: 'post',
    url: '/api/v1/departments',
    body: { name: 'Finance', extra: 1 },
  },
  { module: 'directory', method: 'get', url: '/api/v1/departments?extra=1' },
  {
    module: 'quarantine',
    method: 'put',
    url: '/api/v1/quarantine/me/preferences',
    body: { digest: 'daily', extra: 1 },
  },
  { module: 'quarantine', method: 'get', url: '/api/v1/quarantine/entries?extra=1' },
];

describe('strict request schemas of the converged modules (e2e, D1)', () => {
  let t: StubbedApiApp;
  let permissions: string[];
  beforeAll(async () => {
    t = await legacyApp();
    permissions = permissionsOf(discoverRoutes(t.app));
  });
  afterAll(async () => {
    await t?.close();
  });

  it.each(STRICT.map((s) => [s.module, s.method.toUpperCase(), s.url, s] as const))(
    '%s: %s %s → 400 validation_failed',
    async (_module, _verb, _url, s) => {
      t.principals.user(permissions, {
        mfaAuthenticated: true,
        orgKind: s.platform ? 'platform' : 'customer',
      });
      const req = request(t.app.getHttpServer())
        [s.method](s.url)
        .set(await t.principals.bearer())
        .set(idem());
      const res = await (s.body === undefined ? req : req.send(s.body));
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('validation_failed');
      expect(res.body.message).toEqual(
        expect.arrayContaining([expect.stringMatching(/Unrecognized key.*"extra"/)]),
      );
    },
  );
});
