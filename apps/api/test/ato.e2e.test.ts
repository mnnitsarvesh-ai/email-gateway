/**
 * The account takeover routes of step 8.4 (docs/plan/steps/24-account-takeover-core.md §5.1,
 * §10.4) over HTTP with MySQL, Redis and S3 stubbed: the ATO repositories and the transactional
 * stores replaced by the in-memory `AtoWorld` (the libraries' coded errors and state machines),
 * the Idempotency-Key store by `InMemoryIdempotencyStore`. For every operation: success with the
 * OpenAPI example and a response that parses with its schema, 401, 403 without the permission,
 * API keys on user-only routes, sessions without MFA on MFA routes, 404 for another
 * organization's ids, the feature gate (D17), Idempotency-Key replay and reuse, coded errors
 * (approval self, response active, settings conflict and invalid, account conflict), cursors
 * (paging, tampered) and the expensive class (429). The real writer, replica and stores run in
 * integration/ato.test.ts.
 */
// @covers get /api/v1/ato/overview
// @covers get /api/v1/ato/attention
// @covers get /api/v1/ato/accounts
// @covers get /api/v1/ato/accounts/:accountId
// @covers patch /api/v1/ato/accounts/:accountId
// @covers get /api/v1/ato/accounts/:accountId/signals
// @covers get /api/v1/ato/accounts/:accountId/auth-events
// @covers get /api/v1/ato/accounts/:accountId/activity
// @covers get /api/v1/ato/accounts/:accountId/score-history
// @covers put /api/v1/ato/accounts/:accountId/override
// @covers post /api/v1/ato/accounts/:accountId/override/clear
// @covers post /api/v1/ato/accounts/:accountId/trusted-contexts
// @covers delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId
// @covers get /api/v1/ato/incidents/:incidentId/signals
// @covers get /api/v1/ato/incidents/:incidentId/auth-events
// @covers post /api/v1/ato/incidents/:incidentId/responses
// @covers get /api/v1/ato/responses
// @covers get /api/v1/ato/responses/:responseId
// @covers post /api/v1/ato/responses/:responseId/approve
// @covers post /api/v1/ato/responses/:responseId/reject
// @covers post /api/v1/ato/responses/:responseId/cancel
// @covers post /api/v1/ato/responses/:responseId/rollback
// @covers get /api/v1/ato/restrictions
// @covers get /api/v1/ato/settings
// @covers put /api/v1/ato/settings
// @covers get /api/v1/ato/rules
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { ATO_EXAMPLES } from '../src/modules/ato/dto/ato.examples';
import {
  AccountDetailSchema,
  AccountPageSchema,
  ActivitySchema,
  AttentionSchema,
  AuthEventPageSchema,
  OverviewSchema,
  ResponseDetailSchema,
  ResponsePageSchema,
  RestrictionPageSchema,
  RulesViewSchema,
  ScorePageSchema,
  SettingsViewSchema,
  SignalPageSchema,
  TrustedContextSchema,
} from '../src/modules/ato/dto/ato.schemas';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { AtoWorld, overrideAto, RecordingAuditService } from './support/ato-fixtures';

const R = 'ato:read';
const M = 'ato:manage';
const P = 'ato:respond';
const C = 'ato:configure';
const ALL = [R, M, P, C];
const OTHER_ORG = 2n;
const BASE = '/api/v1/ato';

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

interface Ctx {
  account: string;
  incident: string;
  pending: string;
  succeeded: string;
  context: string;
  foreignAccount: string;
  foreignIncident: string;
  foreignResponse: string;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx) => string;
  perm: string;
  user?: boolean;
  mfa?: boolean;
  keyed?: boolean;
  body?: (c: Ctx) => object;
  ok: number;
  schema?: z.ZodType;
  /** Path with another organization's id (404) and its code. */
  foreign?: [(c: Ctx) => string, string];
  /** Read answer while the feature is off. */
  off?: 'empty' | 404 | 'zero';
}

describe('account takeover routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new AtoWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_RATE_SENSITIVE_PER_MINUTE: '600', API_RATE_EXPENSIVE_PER_MINUTE: '600' },
      { override: (b) => store.override(overrideAto(b, world, audit)) },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = seed();
  });

  function seed(): Ctx {
    const account = world.addAccount(org, { riskScore: 78, riskLevel: 'critical', rowVersion: 3 });
    const incident = world.addIncident(org, account, { severity: 'critical' });
    for (let i = 0; i < 3; i += 1) {
      world.addSignal(account, { detectedAt: new Date(Date.now() - i * 60_000) });
      const event = world.addAuthEvent(account, { occurredAt: new Date(Date.now() - i * 60_000) });
      world.links.push({
        organizationId: org,
        incidentId: incident.id,
        linkType: 'ato_auth_event',
        refId: event.id,
        refTime: event.occurredAt,
      });
    }
    world.scores.push({
      id: world.id(),
      computedAt: new Date(),
      organizationId: org,
      accountId: account.id,
      score: 78,
      level: 'critical',
      previousScore: 20,
      previousLevel: 'low',
      trigger: 'signal',
      explanation: {},
      scorerVersion: 'ato-score/1',
      rulesVersion: 'ato-rules/1',
      settingsVersion: 1,
      createdAt: new Date(),
    } as never);
    const pending = world.addResponse(account, incident);
    const succeeded = world.addResponse(account, incident, {
      actionType: 'block_smtp_auth',
      status: 'succeeded',
      activeMarker: null,
      target: { scope: 'connector', accountPublicId: account.publicId, connectorId: '5' },
    });
    const restriction = {
      id: world.id(),
      publicId: randomUUID(),
      organizationId: org,
      kind: 'auth_block',
      scope: 'connector',
      connectorId: 5n,
      mailboxSha256: null,
      mailboxAddress: null,
      ipCidr: null,
      ipVersion: null,
      rangeStart: null,
      rangeEnd: null,
      mode: 'reject',
      status: 'active',
      reasonCode: 'ato_response',
      responseActionId: succeeded.id,
      startsAt: new Date(),
      expiresAt: new Date(Date.now() + 3_600_000),
      liftedAt: null,
      liftedByType: null,
      liftedById: null,
      liftReason: null,
      subjectHash: 'f'.repeat(64),
      activeMarker: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    world.restrictions.push(restriction as never);
    succeeded.restrictionId = restriction.id;
    world.contexts.push({
      id: world.id(),
      publicId: randomUUID(),
      organizationId: org,
      accountId: account.id,
      kind: 'country',
      value: 'IN',
      ipVersion: null,
      rangeStart: null,
      rangeEnd: null,
      reason: 'Home country',
      source: 'analyst',
      incidentId: null,
      createdByUserId: null,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 86_400_000),
    } as never);
    world.settings.set(org, {
      settings: { mode: 'monitor' },
      version: 2,
      rowVersion: 2,
      learningStartedAt: new Date(Date.now() - 30 * 86_400_000),
      updatedAt: new Date(),
    });
    const foreign = world.addAccount(OTHER_ORG);
    const foreignIncident = world.addIncident(OTHER_ORG, foreign);
    const foreignResponse = world.addResponse(foreign, foreignIncident);
    return {
      account: account.publicId,
      incident: incident.publicId,
      pending: pending.publicId,
      succeeded: succeeded.publicId,
      context: world.contexts[0]!.publicId,
      foreignAccount: foreign.publicId,
      foreignIncident: foreignIncident.publicId,
      foreignResponse: foreignResponse.publicId,
    };
  }

  const NF_ACCOUNT = 'ato_account_not_found';
  const NF_RESPONSE = 'ato_response_not_found';
  const NF_INCIDENT = 'incident_not_found';

  const SPECS: Spec[] = [
    {
      id: '#1',
      method: 'get',
      path: () => `${BASE}/overview?range=24h`,
      perm: R,
      ok: 200,
      schema: OverviewSchema,
      off: 'zero',
    },
    {
      id: '#2',
      method: 'get',
      path: () => `${BASE}/attention`,
      perm: R,
      ok: 200,
      schema: AttentionSchema,
      off: 'zero',
    },
    {
      id: '#3',
      method: 'get',
      path: () => `${BASE}/accounts`,
      perm: R,
      ok: 200,
      schema: AccountPageSchema,
      off: 'empty',
    },
    {
      id: '#4',
      method: 'get',
      path: (c) => `${BASE}/accounts/${c.account}`,
      perm: R,
      ok: 200,
      schema: AccountDetailSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}`, NF_ACCOUNT],
      off: 404,
    },
    {
      id: '#5',
      method: 'patch',
      path: (c) => `${BASE}/accounts/${c.account}`,
      perm: M,
      user: true,
      keyed: true,
      body: () => ATO_EXAMPLES.updateAccount,
      ok: 200,
      schema: AccountDetailSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}`, NF_ACCOUNT],
    },
    {
      id: '#6',
      method: 'get',
      path: (c) => `${BASE}/accounts/${c.account}/signals`,
      perm: R,
      ok: 200,
      schema: SignalPageSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/signals`, NF_ACCOUNT],
      off: 404,
    },
    {
      id: '#7',
      method: 'get',
      path: (c) => `${BASE}/accounts/${c.account}/auth-events`,
      perm: R,
      ok: 200,
      schema: AuthEventPageSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/auth-events`, NF_ACCOUNT],
      off: 404,
    },
    {
      id: '#8',
      method: 'get',
      path: (c) => `${BASE}/accounts/${c.account}/activity`,
      perm: R,
      ok: 200,
      schema: ActivitySchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/activity`, NF_ACCOUNT],
      off: 404,
    },
    {
      id: '#9',
      method: 'get',
      path: (c) => `${BASE}/accounts/${c.account}/score-history`,
      perm: R,
      ok: 200,
      schema: ScorePageSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/score-history`, NF_ACCOUNT],
      off: 404,
    },
    {
      id: '#10',
      method: 'put',
      path: (c) => `${BASE}/accounts/${c.account}/override`,
      perm: M,
      user: true,
      keyed: true,
      body: () => ATO_EXAMPLES.setOverride,
      ok: 200,
      schema: AccountDetailSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/override`, NF_ACCOUNT],
    },
    {
      id: '#11',
      method: 'post',
      path: (c) => `${BASE}/accounts/${c.account}/override/clear`,
      perm: M,
      user: true,
      keyed: true,
      body: () => ATO_EXAMPLES.clearOverride,
      ok: 404,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/override/clear`, NF_ACCOUNT],
    },
    {
      id: '#12',
      method: 'post',
      path: (c) => `${BASE}/accounts/${c.account}/trusted-contexts`,
      perm: M,
      user: true,
      keyed: true,
      body: () => ATO_EXAMPLES.addTrustedContext,
      ok: 201,
      schema: TrustedContextSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/trusted-contexts`, NF_ACCOUNT],
    },
    {
      id: '#13',
      method: 'delete',
      path: (c) => `${BASE}/accounts/${c.account}/trusted-contexts/${c.context}`,
      perm: M,
      user: true,
      keyed: true,
      ok: 204,
      foreign: [
        (c) => `${BASE}/accounts/${c.foreignAccount}/trusted-contexts/${c.context}`,
        NF_ACCOUNT,
      ],
    },
    {
      id: '#14',
      method: 'get',
      path: (c) => `${BASE}/incidents/${c.incident}/signals`,
      perm: R,
      ok: 200,
      schema: SignalPageSchema,
      foreign: [(c) => `${BASE}/incidents/${c.foreignIncident}/signals`, NF_INCIDENT],
      off: 404,
    },
    {
      id: '#15',
      method: 'get',
      path: (c) => `${BASE}/incidents/${c.incident}/auth-events`,
      perm: R,
      ok: 200,
      schema: AuthEventPageSchema,
      foreign: [(c) => `${BASE}/incidents/${c.foreignIncident}/auth-events`, NF_INCIDENT],
      off: 404,
    },
    {
      id: '#16',
      method: 'post',
      path: (c) => `${BASE}/incidents/${c.incident}/responses`,
      perm: P,
      keyed: true,
      body: () => ({ actionType: 'notify_soc', reason: 'Critical incident: inform the SOC' }),
      ok: 201,
      schema: ResponseDetailSchema,
      foreign: [(c) => `${BASE}/incidents/${c.foreignIncident}/responses`, NF_INCIDENT],
    },
    {
      id: '#17',
      method: 'get',
      path: () => `${BASE}/responses`,
      perm: R,
      ok: 200,
      schema: ResponsePageSchema,
      off: 'empty',
    },
    {
      id: '#18',
      method: 'get',
      path: (c) => `${BASE}/responses/${c.pending}`,
      perm: R,
      ok: 200,
      schema: ResponseDetailSchema,
      foreign: [(c) => `${BASE}/responses/${c.foreignResponse}`, NF_RESPONSE],
      off: 404,
    },
    {
      id: '#19',
      method: 'post',
      path: (c) => `${BASE}/responses/${c.pending}/approve`,
      perm: P,
      user: true,
      mfa: true,
      keyed: true,
      body: () => ATO_EXAMPLES.approve,
      ok: 200,
      schema: ResponseDetailSchema,
      foreign: [(c) => `${BASE}/responses/${c.foreignResponse}/approve`, NF_RESPONSE],
    },
    {
      id: '#20',
      method: 'post',
      path: (c) => `${BASE}/responses/${c.pending}/reject`,
      perm: P,
      user: true,
      keyed: true,
      body: () => ATO_EXAMPLES.reject,
      ok: 200,
      schema: ResponseDetailSchema,
      foreign: [(c) => `${BASE}/responses/${c.foreignResponse}/reject`, NF_RESPONSE],
    },
    {
      id: '#21',
      method: 'post',
      path: (c) => `${BASE}/responses/${c.pending}/cancel`,
      perm: P,
      keyed: true,
      body: () => ATO_EXAMPLES.cancel,
      ok: 200,
      schema: ResponseDetailSchema,
      foreign: [(c) => `${BASE}/responses/${c.foreignResponse}/cancel`, NF_RESPONSE],
    },
    {
      id: '#22',
      method: 'post',
      path: (c) => `${BASE}/responses/${c.succeeded}/rollback`,
      perm: P,
      user: true,
      mfa: true,
      keyed: true,
      body: () => ATO_EXAMPLES.rollback,
      ok: 200,
      schema: ResponseDetailSchema,
      foreign: [(c) => `${BASE}/responses/${c.foreignResponse}/rollback`, NF_RESPONSE],
    },
    {
      id: '#23',
      method: 'get',
      path: () => `${BASE}/restrictions`,
      perm: R,
      ok: 200,
      schema: RestrictionPageSchema,
      off: 'empty',
    },
    {
      id: '#24',
      method: 'get',
      path: () => `${BASE}/settings`,
      perm: R,
      ok: 200,
      schema: SettingsViewSchema,
    },
    {
      id: '#25',
      method: 'put',
      path: () => `${BASE}/settings`,
      perm: C,
      user: true,
      keyed: true,
      body: () => ATO_EXAMPLES.updateSettings,
      ok: 200,
      schema: SettingsViewSchema,
    },
    {
      id: '#26',
      method: 'get',
      path: () => `${BASE}/rules`,
      perm: R,
      ok: 200,
      schema: RulesViewSchema,
    },
  ];

  const asUser = (permissions: string[], mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();

  async function send(
    spec: Spec,
    options: {
      auth?: Record<string, string>;
      key?: string | null;
      body?: object;
      path?: string;
    } = {},
  ) {
    const auth = options.auth ?? (await asUser(ALL));
    let req = api
      .http()
      [spec.method](options.path ?? spec.path(ctx))
      .set(auth);
    if (spec.keyed && options.key !== null)
      req = req.set('Idempotency-Key', options.key ?? randomUUID());
    const body = options.body ?? spec.body?.(ctx);
    return body ? req.send(body) : req;
  }

  it('has a spec for each of the 26 operations', () => {
    expect(SPECS).toHaveLength(26);
  });

  it.each(SPECS.map((s) => [s.id, s] as const))(
    '%s answers its success status with a valid body',
    async (_id, spec) => {
      const res = await send(spec);
      expect(res.status, JSON.stringify(res.body)).toBe(spec.ok);
      if (spec.schema) {
        const parsed = spec.schema.safeParse(res.body);
        expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
      }
      expect(res.headers['cache-control']).toBe('no-store');
    },
  );

  it.each(SPECS.map((s) => [s.id, s] as const))(
    '%s: 401 without credentials, 403 without the permission',
    async (_id, spec) => {
      const anonymous = await api.http()[spec.method](spec.path(ctx));
      expect(anonymous.status).toBe(401);
      const others = ALL.filter((p) => p !== spec.perm);
      const forbidden = await send(spec, { auth: await asUser(others) });
      expect(forbidden.status).toBe(403);
      expect(forbidden.body.code).toBe('forbidden');
    },
  );

  it.each(SPECS.filter((s) => s.user).map((s) => [s.id, s] as const))(
    '%s refuses API keys (users only)',
    async (_id, spec) => {
      api.principals.apiKeyWith(ALL);
      const res = await send(spec, { auth: api.principals.apiKeyHeaders });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('user_required');
    },
  );

  it.each(SPECS.filter((s) => !s.user && s.keyed).map((s) => [s.id, s] as const))(
    '%s accepts API keys',
    async (_id, spec) => {
      api.principals.apiKeyWith(ALL);
      const res = await send(spec, { auth: api.principals.apiKeyHeaders });
      expect(res.status, JSON.stringify(res.body)).toBe(spec.ok);
    },
  );

  it.each(SPECS.filter((s) => s.mfa).map((s) => [s.id, s] as const))(
    '%s needs an MFA session',
    async (_id, spec) => {
      const res = await send(spec, { auth: await asUser(ALL, false) });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('mfa_required');
    },
  );

  it.each(SPECS.filter((s) => s.foreign).map((s) => [s.id, s] as const))(
    '%s answers 404 for another organization’s id',
    async (_id, spec) => {
      const [path, code] = spec.foreign!;
      const res = await send(spec, { path: path(ctx) });
      expect(res.status).toBe(404);
      expect(res.body.code).toBe(code);
    },
  );

  it.each(SPECS.filter((s) => s.foreign).map((s) => [s.id, s] as const))(
    '%s refuses a malformed id with 400',
    async (_id, spec) => {
      const res = await send(spec, { path: spec.path(ctx).replace(/[0-9a-f-]{36}/, 'not-a-uuid') });
      expect(res.status).toBe(400);
    },
  );

  describe('feature gate (D17: ATO off for the organization)', () => {
    beforeEach(() => world.featureOff.add(org));

    it.each(SPECS.filter((s) => s.keyed).map((s) => [s.id, s] as const))(
      '%s answers 403 ato_not_enabled',
      async (_id, spec) => {
        const res = await send(spec);
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('ato_not_enabled');
      },
    );

    it.each(SPECS.filter((s) => s.off).map((s) => [s.id, s] as const))(
      '%s answers empty data',
      async (_id, spec) => {
        const res = await send(spec);
        if (spec.off === 404) {
          expect(res.status).toBe(404);
        } else if (spec.off === 'empty') {
          expect(res.status).toBe(200);
          expect(res.body).toEqual({ data: [], nextCursor: null });
        } else {
          expect(res.status).toBe(200);
          if (spec.id === '#1') {
            expect(res.body.monitoring.featureEnabled).toBe(false);
            expect(res.body.accounts.monitored).toBe(0);
          } else {
            expect(res.body).toEqual({ criticalIncidents: 0, pendingApprovals: 0 });
          }
        }
      },
    );

    it('settings show featureEnabled: false', async () => {
      const res = await api
        .http()
        .get(`${BASE}/settings`)
        .set(await asUser(ALL));
      expect(res.status).toBe(200);
      expect(res.body.featureEnabled).toBe(false);
    });
  });

  describe('Idempotency-Key', () => {
    it.each(SPECS.filter((s) => s.keyed && s.ok < 400).map((s) => [s.id, s] as const))(
      '%s replays the stored response and refuses a reused key',
      async (_id, spec) => {
        const key = `key-${spec.id.slice(1)}-${randomUUID()}`;
        const first = await send(spec, { key });
        expect(first.status, JSON.stringify(first.body)).toBe(spec.ok);
        const replay = await send(spec, { key });
        expect(replay.status).toBe(spec.ok);
        expect(replay.headers['idempotency-replayed']).toBe('true');
        expect(replay.body).toEqual(first.body);
        const other = await send(spec, {
          key,
          ...(spec.body
            ? {
                body:
                  spec.id === '#25'
                    ? { ...spec.body(ctx), settings: { mode: 'enforce' } }
                    : { ...spec.body(ctx), reason: 'A different reason for the same key' },
              }
            : { path: `${BASE}/accounts/${ctx.account}/trusted-contexts/${randomUUID()}` }),
        });
        expect(other.status, JSON.stringify(other.body)).toBe(422);
        expect(other.body.code).toBe('idempotency_key_reused');
      },
    );

    it.each(SPECS.filter((s) => s.keyed).map((s) => [s.id, s] as const))(
      '%s without the header is 400 idempotency_key_required',
      async (_id, spec) => {
        const res = await send(spec, { key: null });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('idempotency_key_required');
      },
    );
  });

  describe('responses (D13)', () => {
    it('the requester may not approve or reject their own request (403 ato_approval_self)', async () => {
      const own = world.responses.find((r) => r.publicId === ctx.pending)!;
      own.requestedById = api.principals.ids.user;
      for (const action of ['approve', 'reject']) {
        const res = await api
          .http()
          .post(`${BASE}/responses/${ctx.pending}/${action}`)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send({ reason: 'I am the requester of this' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('ato_approval_self');
      }
    });

    it('a request made with an API key may not be decided by the key creator (403 ato_approval_self)', async () => {
      const own = world.responses.find((r) => r.publicId === ctx.pending)!;
      const before = { type: own.requestedByType, id: own.requestedById };
      const keyId = randomUUID();
      own.requestedByType = 'api_key';
      own.requestedById = keyId;
      world.apiKeyCreators.set(keyId, api.principals.ids.user);
      try {
        const view = await api
          .http()
          .get(`${BASE}/responses/${ctx.pending}`)
          .set(await asUser(ALL));
        expect(view.status).toBe(200);
        expect(view.body.canDecide).toBe(false);
        const res = await api
          .http()
          .post(`${BASE}/responses/${ctx.pending}/approve`)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send({});
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('ato_approval_self');
        expect(own.status).toBe('pending_approval');
      } finally {
        own.requestedByType = before.type;
        own.requestedById = before.id;
        world.apiKeyCreators.delete(keyId);
      }
    });

    it('approval executes the restriction; rollback lifts it; a second rollback is a state conflict', async () => {
      const approved = await api
        .http()
        .post(`${BASE}/responses/${ctx.pending}/approve`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({});
      expect(approved.status).toBe(200);
      expect(approved.body).toMatchObject({
        status: 'succeeded',
        providerStatus: 'applied',
        canRollback: true,
      });
      expect(approved.body.restriction).toMatchObject({ status: 'active', kind: 'send_block' });
      const rollback = await api
        .http()
        .post(`${BASE}/responses/${ctx.pending}/rollback`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send(ATO_EXAMPLES.rollback);
      expect(rollback.status).toBe(200);
      expect(rollback.body.status).toBe('rolled_back');
      expect(rollback.body.restriction.status).toBe('lifted');
      const again = await api
        .http()
        .post(`${BASE}/responses/${ctx.pending}/rollback`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send(ATO_EXAMPLES.rollback);
      expect(again.status).toBe(409);
      expect(again.body.code).toBe('ato_response_state');
    });

    it('a second active response of the same type is 409 ato_response_active with its id', async () => {
      const res = await api
        .http()
        .post(`${BASE}/incidents/${ctx.incident}/responses`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send(ATO_EXAMPLES.requestResponse);
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({ code: 'ato_response_active', responseId: ctx.pending });
    });

    it('validates the request: manual actions need a description; restriction options only for restrictions', async () => {
      const auth = await asUser(ALL);
      const post = (body: object) =>
        api
          .http()
          .post(`${BASE}/incidents/${ctx.incident}/responses`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const manual = await post({
        actionType: 'record_manual_action',
        reason: 'Revoked sessions by hand',
      });
      expect(manual.status).toBe(422);
      expect(manual.body.code).toBe('ato_response_invalid');
      const attested = await post({
        actionType: 'record_manual_action',
        reason: 'Revoked sessions by hand',
        description: 'Revoked all portal sessions through the Users page',
      });
      expect(attested.status).toBe(201);
      expect(attested.body).toMatchObject({ status: 'attested', providerStatus: 'unconfirmed' });
      const options = await post({
        actionType: 'notify_soc',
        reason: 'Inform the SOC now',
        durationMinutes: 60,
      });
      expect(options.status).toBe(422);
      const provider = await post({
        actionType: 'revoke_sessions',
        reason: 'Revoke all IdP sessions',
      });
      expect(provider.status).toBe(201);
      expect(provider.body.status).toBe('pending_approval');
      const strict = await post({
        actionType: 'notify_soc',
        reason: 'Inform the SOC now',
        extra: 1,
      });
      expect(strict.status).toBe(400);
      expect(strict.body.code).toBe('validation_failed');
    });

    it('step 8.5 provider params: forwarding item of the account, all external by default, appIdHash for OAuth', async () => {
      const auth = await asUser(ALL);
      const post = (body: object) =>
        api
          .http()
          .post(`${BASE}/incidents/${ctx.incident}/responses`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const account = world.accounts.find((a) => a.publicId === ctx.account)!;
      const itemId = randomUUID();
      world.mailboxItems.push({
        organizationId: account.organizationId,
        accountId: account.id,
        publicId: itemId,
      });
      const reason = 'External forwarding rule after a risky sign-in';
      const unknown = await post({
        actionType: 'remove_forwarding_rule',
        reason,
        params: { itemId: randomUUID() },
      });
      expect(unknown.status).toBe(422);
      expect(unknown.body.code).toBe('ato_response_invalid');
      const both = await post({
        actionType: 'remove_forwarding_rule',
        reason,
        params: { itemId, scope: 'all_external' },
      });
      expect(both.status).toBe(422);
      const notForGateway = await post({
        actionType: 'notify_soc',
        reason: 'Inform the SOC now',
        params: { itemId },
      });
      expect(notForGateway.status).toBe(422);
      const oauthWithoutHash = await post({ actionType: 'revoke_oauth_grant', reason, params: {} });
      expect(oauthWithoutHash.status).toBe(422);
      const badHash = await post({
        actionType: 'revoke_oauth_grant',
        reason,
        params: { appIdHash: 'NOT-HEX' },
      });
      expect(badHash.status).toBe(400);
      const item = await post({ actionType: 'remove_forwarding_rule', reason, params: { itemId } });
      expect(item.status).toBe(201);
      expect(world.responses.find((r) => r.publicId === item.body.id)?.params).toEqual({ itemId });
      const oauth = await post({
        actionType: 'revoke_oauth_grant',
        reason,
        params: { appIdHash: 'a'.repeat(64) },
      });
      expect(oauth.status).toBe(201);
      expect(world.responses.find((r) => r.publicId === oauth.body.id)?.params).toEqual({
        appIdHash: 'a'.repeat(64),
      });
      world.responses
        .filter((r) => r.actionType === 'remove_forwarding_rule')
        .forEach((r) => (r.activeMarker = null));
      const all = await post({ actionType: 'remove_forwarding_rule', reason });
      expect(all.status).toBe(201);
      expect(world.responses.find((r) => r.publicId === all.body.id)?.params).toEqual({
        scope: 'all_external',
      });
    });

    it('cancel only pending actions; canDecide reflects the caller', async () => {
      const list = await api
        .http()
        .get(`${BASE}/responses?status=pending_approval`)
        .set(await asUser(ALL));
      expect(list.status).toBe(200);
      expect(list.body.data).toHaveLength(1);
      expect(list.body.data[0].canDecide).toBe(true);
      const noMfa = await api
        .http()
        .get(`${BASE}/responses/${ctx.pending}`)
        .set(await asUser(ALL, false));
      expect(noMfa.body.canDecide).toBe(false);
      const res = await api
        .http()
        .post(`${BASE}/responses/${ctx.succeeded}/cancel`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({});
      expect(res.status).toBe(409);
      expect(res.body.code).toBe('ato_response_state');
    });
  });

  describe('accounts and settings', () => {
    it('PATCH compares and sets the row version (409 ato_account_conflict with currentRowVersion)', async () => {
      const res = await api
        .http()
        .patch(`${BASE}/accounts/${ctx.account}`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ ...ATO_EXAMPLES.updateAccount, expectedRowVersion: 1 });
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({ code: 'ato_account_conflict', currentRowVersion: 3 });
      const ok = await api
        .http()
        .patch(`${BASE}/accounts/${ctx.account}`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send(ATO_EXAMPLES.updateAccount);
      expect(ok.body).toMatchObject({ protected: true, rowVersion: 4 });
    });

    it('override set and clear rescore the account', async () => {
      const auth = await asUser(ALL);
      const set = await api
        .http()
        .put(`${BASE}/accounts/${ctx.account}/override`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send(ATO_EXAMPLES.setOverride);
      expect(set.body).toMatchObject({ riskLevel: 'low', override: { verdict: 'benign' } });
      const cleared = await api
        .http()
        .post(`${BASE}/accounts/${ctx.account}/override/clear`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send(ATO_EXAMPLES.clearOverride);
      expect(cleared.status).toBe(200);
      expect(cleared.body.override).toBeNull();
    });

    it('trusted contexts: an invalid value is 422; a context of another account is 404', async () => {
      const auth = await asUser(ALL);
      const bad = await api
        .http()
        .post(`${BASE}/accounts/${ctx.account}/trusted-contexts`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ kind: 'country', value: 'Germany', reason: 'trip', expiresInDays: 5 });
      expect(bad.status).toBe(422);
      expect(bad.body.code).toBe('ato_trusted_context_invalid');
      const other = world.addAccount(org);
      const res = await api
        .http()
        .delete(`${BASE}/accounts/${other.publicId}/trusted-contexts/${ctx.context}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID());
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('ato_trusted_context_not_found');
    });

    it('settings: CAS conflict, invalid documents with paths, first save from version 0', async () => {
      const auth = await asUser(ALL);
      const put = (body: object) =>
        api
          .http()
          .put(`${BASE}/settings`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const conflict = await put({ expectedRowVersion: 1, settings: {} });
      expect(conflict.status).toBe(409);
      expect(conflict.body).toMatchObject({ code: 'ato_settings_conflict', currentRowVersion: 2 });
      const invalid = await put({
        expectedRowVersion: 2,
        settings: { mode: 'panic', learningDays: 999 },
      });
      expect(invalid.status).toBe(400);
      expect(invalid.body.code).toBe('ato_settings_invalid');
      expect(invalid.body.issues.map((i: { path: string }) => i.path).sort()).toEqual([
        'learningDays',
        'mode',
      ]);
      expect(JSON.stringify(invalid.body)).not.toContain('panic');
      const ok = await put({ expectedRowVersion: 2, settings: { mode: 'enforce' } });
      expect(ok.status).toBe(200);
      expect(ok.body).toMatchObject({ version: 3, rowVersion: 3, stored: { mode: 'enforce' } });
      world.settings.clear();
      const first = await put({ expectedRowVersion: 0, settings: { learningDays: 7 } });
      expect(first.status).toBe(200);
      expect(first.body.stored).toMatchObject({ learningDays: 7 });
    });

    it('capabilities: missing or stale reports are unknown; a fresh report is parsed', async () => {
      const auth = await asUser(ALL);
      expect((await api.http().get(`${BASE}/rules`).set(auth)).body.capabilities.status).toBe(
        'unknown',
      );
      world.capabilities = {
        value: {
          geoipCity: { loaded: true, stale: false },
          geoipAsn: { loaded: true },
          dnsblZones: 0,
          breachIndicators: 3,
          providers: [],
          updatedAt: new Date().toISOString(),
        },
        updatedAt: new Date(),
      };
      const rules = await api.http().get(`${BASE}/rules`).set(auth);
      expect(rules.body.capabilities).toMatchObject({
        status: 'known',
        geoipCity: 'available',
        dnsbl: 'unavailable',
        breachIntel: 'available',
      });
      const travel = rules.body.data.find(
        (r: { code: string }) => r.code === 'ato.geo.impossible_travel',
      );
      expect(travel.availability.available).toBe(true);
      world.capabilities.value = {
        ...(world.capabilities.value as object),
        updatedAt: new Date(Date.now() - 16 * 60_000).toISOString(),
      };
      expect((await api.http().get(`${BASE}/settings`).set(auth)).body.capabilities.status).toBe(
        'unknown',
      );
    });

    it('auth events: the first page is audited (no IP addresses), later pages are not', async () => {
      const auth = await asUser(ALL);
      const first = await api
        .http()
        .get(`${BASE}/accounts/${ctx.account}/auth-events?limit=2`)
        .set(auth);
      expect(first.body.data).toHaveLength(2);
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const viewed = audit.entries.filter((e) => e.action === 'ato.auth_events.viewed');
      expect(viewed).toHaveLength(1);
      expect(viewed[0]).toMatchObject({ resourceType: 'ato_account', resourceId: ctx.account });
      expect(JSON.stringify(viewed[0]!.metadata)).not.toContain('203.0.113');
      const second = await api
        .http()
        .get(
          `${BASE}/accounts/${ctx.account}/auth-events?limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
        )
        .set(auth);
      expect(second.status).toBe(200);
      expect(second.body.data).toHaveLength(1);
      expect(audit.entries.filter((e) => e.action === 'ato.auth_events.viewed')).toHaveLength(1);
    });
  });

  describe('lists and cursors', () => {
    it('pages with signed cursors bound to filters; a tampered or foreign cursor is 400', async () => {
      const auth = await asUser(ALL);
      for (let i = 0; i < 3; i += 1) world.addAccount(org, { riskScore: 10 + i });
      const first = await api.http().get(`${BASE}/accounts?limit=2`).set(auth);
      expect(first.body.data).toHaveLength(2);
      const cursor = first.body.nextCursor as string;
      const second = await api
        .http()
        .get(`${BASE}/accounts?limit=2&cursor=${encodeURIComponent(cursor)}`)
        .set(auth);
      expect(second.status).toBe(200);
      const seen = [...first.body.data, ...second.body.data].map((a: { id: string }) => a.id);
      expect(new Set(seen).size).toBe(seen.length);
      expect(seen).not.toContain(ctx.foreignAccount);
      const tampered = await api
        .http()
        .get(`${BASE}/accounts?limit=2&cursor=${encodeURIComponent(cursor.slice(0, -2) + 'xx')}`)
        .set(auth);
      expect(tampered.status).toBe(400);
      expect(tampered.body.code).toBe('cursor_invalid');
      const otherFilters = await api
        .http()
        .get(`${BASE}/accounts?limit=2&kind=mailbox&cursor=${encodeURIComponent(cursor)}`)
        .set(auth);
      expect(otherFilters.status).toBe(400);
      expect(otherFilters.body.code).toBe('cursor_invalid');
    });

    it('refuses unknown parameters, bad sorts and too-long ranges', async () => {
      const auth = await asUser(ALL);
      for (const path of [
        `${BASE}/accounts?unknown=1`,
        `${BASE}/accounts?sort=riskScore`,
        `${BASE}/accounts/${ctx.account}/signals?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z`,
        `${BASE}/accounts/${ctx.account}/auth-events?from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z`,
        `${BASE}/overview?range=1y`,
        `${BASE}/restrictions?status=gone`,
      ]) {
        const res = await api.http().get(path).set(auth);
        expect(res.status, path).toBe(400);
        expect(res.body.code, path).toBe('validation_failed');
      }
    });

    it('filters responses by incident and account; foreign filters yield empty pages', async () => {
      const auth = await asUser(ALL);
      const byIncident = await api
        .http()
        .get(`${BASE}/responses?incidentId=${ctx.incident}`)
        .set(auth);
      expect(byIncident.body.data).toHaveLength(2);
      const foreign = await api
        .http()
        .get(`${BASE}/responses?incidentId=${ctx.foreignIncident}`)
        .set(auth);
      expect(foreign.body).toEqual({ data: [], nextCursor: null });
      const byAccount = await api
        .http()
        .get(`${BASE}/responses?accountId=${ctx.foreignAccount}`)
        .set(auth);
      expect(byAccount.body).toEqual({ data: [], nextCursor: null });
    });

    it('the overview is cached per organization and range', async () => {
      const auth = await asUser(ALL);
      const first = await api.http().get(`${BASE}/overview?range=7d`).set(auth);
      expect(first.body.accounts.monitored).toBe(1);
      world.addAccount(org);
      const cached = await api.http().get(`${BASE}/overview?range=7d`).set(auth);
      expect(cached.body.accounts.monitored).toBe(1);
      expect(cached.body.generatedAt).toBe(first.body.generatedAt);
      const other = await api.http().get(`${BASE}/overview?range=30d`).set(auth);
      expect(other.body.accounts.monitored).toBe(2);
      expect(first.body.attention).toEqual({ criticalIncidents: 1, pendingApprovals: 1 });
    });
  });

  describe('expensive class (429 with RateLimit-* and Retry-After)', () => {
    let limited: StubbedApiApp;
    const lworld = new AtoWorld();

    beforeAll(async () => {
      limited = await createStubbedApiApp(
        { API_RATE_EXPENSIVE_PER_MINUTE: '1' },
        {
          override: (b) =>
            new InMemoryIdempotencyStore().override(
              overrideAto(b, lworld, new RecordingAuditService()),
            ),
        },
      );
    });

    afterAll(async () => {
      await limited?.close();
    });

    it('the overview is in the expensive class', async () => {
      const auth = await limited.principals.user([R]).bearer();
      const first = await limited.http().get(`${BASE}/overview`).set(auth);
      expect(first.status).toBe(200);
      const second = await limited.http().get(`${BASE}/overview`).set(auth);
      expect(second.status).toBe(429);
      expect(second.body).toMatchObject({ code: 'rate_limited', scope: 'expensive' });
      expect(second.headers['retry-after']).toMatch(/^\d+$/);
      expect(second.headers['ratelimit-limit']).toBe('1');
    });
  });
});
