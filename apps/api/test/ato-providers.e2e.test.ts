/**
 * The identity-provider routes of step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6,
 * §11.4) over HTTP with MySQL, Redis and the 8.2 tables stubbed: the providers and mailbox item
 * repositories and the connection directory replaced by the in-memory `AtoProviderWorld`, the
 * 8.4 stores by the `AtoWorld` doubles and the Idempotency-Key store by
 * `InMemoryIdempotencyStore`. For every operation: success with a body that parses with its
 * schema, 401, 403 without the permission, API keys on user-only routes, sessions without MFA on
 * MFA routes, 404 for another organization's ids, the feature gate (D17), Idempotency-Key replay
 * and reuse; then the coded errors and effects of D4 (eligibility, already bound, directory in
 * use without disclosure, limit), D10 (settings validation and CAS), pause/resume, backfill
 * bounds, removal of in-flight provider actions, mailbox state and refresh, and the 8.4 settings
 * and account responses fed by the new tables. The real writer, replica and 8.2 tables run in
 * integration/ato-providers.test.ts.
 */
// @covers get /api/v1/ato/providers
// @covers get /api/v1/ato/providers/requirements
// @covers get /api/v1/ato/providers/connections
// @covers post /api/v1/ato/providers
// @covers get /api/v1/ato/providers/:integrationId
// @covers patch /api/v1/ato/providers/:integrationId
// @covers post /api/v1/ato/providers/:integrationId/pause
// @covers post /api/v1/ato/providers/:integrationId/resume
// @covers post /api/v1/ato/providers/:integrationId/health-check
// @covers post /api/v1/ato/providers/:integrationId/backfill
// @covers delete /api/v1/ato/providers/:integrationId
// @covers get /api/v1/ato/accounts/:accountId/mailbox-state
// @covers post /api/v1/ato/accounts/:accountId/mailbox-state/refresh
import { randomUUID } from 'node:crypto';
import { PROVIDER_STREAMS } from '@email-gateway/ato-detection';
import {
  defaultBindingSettings,
  directoryRefHash,
  type ProbeReport,
  sha256Hex,
  STREAM_ROLES,
} from '@email-gateway/idp-adapters';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { ATO_PROVIDER_EXAMPLES } from '../src/modules/ato/ato-providers.api-docs';
import {
  MailboxRefreshSchema,
  MailboxStateSchema,
  ProviderConnectionsSchema,
  ProviderDetailSchema,
  ProviderHealthCheckSchema,
  ProviderListSchema,
  type ProviderDetailView,
  ProviderRequirementsSchema,
} from '../src/modules/ato/dto/ato-providers.schemas';

type StreamView = ProviderDetailView['streamDetails'][number];
import { AccountDetailSchema, SettingsViewSchema } from '../src/modules/ato/dto/ato.schemas';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { AtoWorld, overrideAto, RecordingAuditService } from './support/ato-fixtures';
import { AtoProviderWorld } from './support/ato-provider-fixtures';

const R = 'ato:read';
const M = 'ato:manage';
const P = 'ato:respond';
const C = 'ato:configure';
const ALL = [R, M, P, C];
const OTHER_ORG = 2n;
const BASE = '/api/v1/ato';
const DAY = 86_400_000;

type Method = 'get' | 'post' | 'patch' | 'delete';

interface Ctx {
  integration: string;
  connection: string;
  freeConnection: string;
  account: string;
  foreignIntegration: string;
  foreignAccount: string;
  foreignConnection: string;
  /** A fixed backfill start (the fingerprint of a replayed request must not change). */
  backfillFrom: string;
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
  foreign?: [(c: Ctx) => string, string];
  off?: 'empty' | 404;
}

/** A probe report with every stream and action available and an active telemetry grant. */
function report(provider: 'microsoft_entra' | 'google_workspace' = 'microsoft_entra'): ProbeReport {
  return {
    ok: true,
    checkedAt: new Date().toISOString(),
    directoryRefHash: null,
    streams: Object.fromEntries(
      PROVIDER_STREAMS.map((s) => [
        s,
        {
          availability:
            STREAM_ROLES[provider][s].role === 'unsupported' ? 'not_offered' : 'available',
        },
      ]),
    ) as ProbeReport['streams'],
    actions: {
      revoke_sessions: { availability: 'available', rollback: false, confirmation: 'synchronous' },
      require_mfa: { availability: 'not_configured', rollback: true, confirmation: 'polling' },
      require_password_reset: {
        availability: 'available',
        rollback: false,
        confirmation: 'synchronous',
      },
      suspend_account: { availability: 'available', rollback: true, confirmation: 'polling' },
      remove_forwarding_rule: {
        availability: 'available',
        rollback: true,
        confirmation: 'polling',
      },
      revoke_oauth_grant: {
        availability: 'missing_permission',
        rollback: false,
        confirmation: 'synchronous',
      },
    },
    grants: [
      {
        profile: provider === 'microsoft_entra' ? 'm365.ato_telemetry' : 'google.ato_telemetry',
        status: 'active',
        missingPermissions: [],
      },
    ],
  };
}

describe('identity-provider routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new AtoWorld();
  const providers = new AtoProviderWorld(world);
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_RATE_SENSITIVE_PER_MINUTE: '600', API_RATE_EXPENSIVE_PER_MINUTE: '600' },
      { override: (b) => store.override(overrideAto(b, world, audit, [], providers)) },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    providers.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = seed();
  });

  /** A bound integration with its seven stream rows, as `POST /ato/providers` leaves it. */
  function bound(organizationId: bigint) {
    const connection = providers.addConnection(organizationId);
    const integration = providers.addIntegration(organizationId, {
      connectorRef: connection.publicId,
      bindingKey: sha256Hex(`microsoft_entra|${connection.publicId}`),
      displayName: connection.displayName,
      directoryRefHash: directoryRefHash('microsoft_entra', connection.externalTenantId!),
      settings: defaultBindingSettings(),
      healthDetail: report() as never,
    });
    for (const stream of PROVIDER_STREAMS) {
      const role = STREAM_ROLES.microsoft_entra[stream].role;
      providers.addStream(integration, {
        stream,
        role,
        availability: 'available',
        watermarkAt: role === 'primary' ? new Date(Date.now() - 600_000) : null,
      });
    }
    return { connection, integration };
  }

  function seed(): Ctx {
    const { connection, integration } = bound(org);
    const free = providers.addConnection(org);
    const account = world.addAccount(org);
    providers.addIdentity(integration, org, account.id);
    providers.addItem(integration, account.id);
    providers.addItem(integration, account.id, {
      itemKind: 'forwarding',
      state: 'removed',
      lastChange: 'removed',
      removedAt: new Date(Date.now() - 2 * DAY),
    });
    providers.addItem(integration, account.id, {
      itemKind: 'delegate',
      state: 'removed',
      removedAt: new Date(Date.now() - 40 * DAY),
    });
    const foreign = bound(OTHER_ORG);
    const foreignAccount = world.addAccount(OTHER_ORG);
    return {
      integration: integration.publicId,
      connection: connection.publicId,
      freeConnection: free.publicId,
      account: account.publicId,
      foreignIntegration: foreign.integration.publicId,
      foreignAccount: foreignAccount.publicId,
      foreignConnection: foreign.connection.publicId,
      backfillFrom: new Date(Date.now() - 2 * DAY).toISOString(),
    };
  }

  const NF = 'ato_provider_not_found';
  const NF_ACCOUNT = 'ato_account_not_found';
  const settingsBody = () => ({ ...defaultBindingSettings(), pollIntervalSeconds: 600 });

  const SPECS: Spec[] = [
    {
      id: '#1',
      method: 'get',
      path: () => `${BASE}/providers`,
      perm: R,
      ok: 200,
      schema: ProviderListSchema,
      off: 'empty',
    },
    {
      id: '#2',
      method: 'get',
      path: () => `${BASE}/providers/requirements`,
      perm: R,
      ok: 200,
      schema: ProviderRequirementsSchema,
    },
    {
      id: '#3',
      method: 'get',
      path: () => `${BASE}/providers/connections`,
      perm: C,
      ok: 200,
      schema: ProviderConnectionsSchema,
      off: 'empty',
    },
    {
      id: '#4',
      method: 'post',
      path: () => `${BASE}/providers`,
      perm: C,
      user: true,
      mfa: true,
      keyed: true,
      body: (c) => ({ connectionId: c.freeConnection }),
      ok: 201,
      schema: ProviderDetailSchema,
    },
    {
      id: '#5',
      method: 'get',
      path: (c) => `${BASE}/providers/${c.integration}`,
      perm: R,
      ok: 200,
      schema: ProviderDetailSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}`, NF],
      off: 404,
    },
    {
      id: '#6',
      method: 'patch',
      path: (c) => `${BASE}/providers/${c.integration}`,
      perm: C,
      user: true,
      mfa: true,
      keyed: true,
      body: () => ({ rowVersion: 1, settings: settingsBody() }),
      ok: 200,
      schema: ProviderDetailSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}`, NF],
    },
    {
      id: '#7',
      method: 'post',
      path: (c) => `${BASE}/providers/${c.integration}/pause`,
      perm: C,
      user: true,
      keyed: true,
      body: () => ATO_PROVIDER_EXAMPLES.pauseBody,
      ok: 200,
      schema: ProviderDetailSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}/pause`, NF],
    },
    {
      id: '#8',
      method: 'post',
      path: (c) => `${BASE}/providers/${c.integration}/resume`,
      perm: C,
      user: true,
      keyed: true,
      ok: 200,
      schema: ProviderDetailSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}/resume`, NF],
    },
    {
      id: '#9',
      method: 'post',
      path: (c) => `${BASE}/providers/${c.integration}/health-check`,
      perm: C,
      keyed: true,
      ok: 202,
      schema: ProviderHealthCheckSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}/health-check`, NF],
    },
    {
      id: '#10',
      method: 'post',
      path: (c) => `${BASE}/providers/${c.integration}/backfill`,
      perm: C,
      user: true,
      keyed: true,
      body: (c) => ({ from: c.backfillFrom }),
      ok: 202,
      schema: ProviderDetailSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}/backfill`, NF],
    },
    {
      id: '#11',
      method: 'delete',
      path: (c) => `${BASE}/providers/${c.integration}`,
      perm: C,
      user: true,
      mfa: true,
      keyed: true,
      body: () => ATO_PROVIDER_EXAMPLES.removeBody,
      ok: 200,
      schema: ProviderDetailSchema,
      foreign: [(c) => `${BASE}/providers/${c.foreignIntegration}`, NF],
    },
    {
      id: '#12',
      method: 'get',
      path: (c) => `${BASE}/accounts/${c.account}/mailbox-state`,
      perm: R,
      ok: 200,
      schema: MailboxStateSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/mailbox-state`, NF_ACCOUNT],
      off: 404,
    },
    {
      id: '#13',
      method: 'post',
      path: (c) => `${BASE}/accounts/${c.account}/mailbox-state/refresh`,
      perm: M,
      keyed: true,
      ok: 202,
      schema: MailboxRefreshSchema,
      foreign: [(c) => `${BASE}/accounts/${c.foreignAccount}/mailbox-state/refresh`, NF_ACCOUNT],
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

  const call = async (
    method: Method,
    path: string,
    body?: object,
    auth?: Record<string, string>,
  ) => {
    let req = api
      .http()
      [method](path)
      .set(auth ?? (await asUser(ALL)));
    if (method !== 'get') req = req.set('Idempotency-Key', randomUUID());
    return body ? req.send(body) : req;
  };

  it('has a spec for each of the 13 operations', () => {
    expect(SPECS).toHaveLength(13);
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
      const forbidden = await send(spec, {
        auth: await asUser(ALL.filter((p) => p !== spec.perm)),
      });
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

  it.each(SPECS.filter((s) => !s.mfa && s.user).map((s) => [s.id, s] as const))(
    '%s does not need MFA',
    async (_id, spec) => {
      const res = await send(spec, { auth: await asUser(ALL, false) });
      expect(res.status, JSON.stringify(res.body)).toBe(spec.ok);
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

  describe('feature gate (8.4 D17: ATO off for the organization)', () => {
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
        } else {
          expect(res.status).toBe(200);
          expect(res.body).toMatchObject({ featureEnabled: false, data: [] });
        }
      },
    );

    it('the requirements catalogue stays readable', async () => {
      const res = await call('get', `${BASE}/providers/requirements`);
      expect(res.status).toBe(200);
      expect(res.body.providers).toHaveLength(2);
    });
  });

  describe('Idempotency-Key', () => {
    it.each(SPECS.filter((s) => s.keyed).map((s) => [s.id, s] as const))(
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
                body: {
                  ...spec.body(ctx),
                  ...(spec.id === '#4'
                    ? { connectionId: randomUUID() }
                    : spec.id === '#6'
                      ? { rowVersion: 2 }
                      : spec.id === '#10'
                        ? { from: new Date(Date.now() - DAY).toISOString() }
                        : { reason: 'A different reason for the same key' }),
                },
              }
            : { path: spec.path(ctx).replace(/[0-9a-f-]{36}/, randomUUID()) }),
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

  describe('bind (D4)', () => {
    const create = (body: object) => call('post', `${BASE}/providers`, body);

    it('creates the integration with seven stream rows, backfills where the provider keeps data, locks the organization and audits', async () => {
      const res = await create({ connectionId: ctx.freeConnection });
      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(res.body).toMatchObject({
        provider: 'microsoft_entra',
        status: 'active',
        rowVersion: 1,
        settingsVersion: 1,
        health: { status: 'unknown', stale: true },
        connection: { id: ctx.freeConnection, status: 'active' },
      });
      expect(res.body.streamDetails).toHaveLength(7);
      const byStream = Object.fromEntries(
        (res.body.streamDetails as StreamView[]).map((s) => [s.stream, s]),
      );
      expect(byStream.sign_ins).toMatchObject({ role: 'primary', status: 'backfilling' });
      expect(byStream.forwarding_changes).toMatchObject({
        role: 'companion',
        primary: 'mailbox_audit',
        status: 'active',
      });
      // sign-ins: 7 days (settings), mailbox audit: 7 days (provider retention).
      const from = Date.parse(byStream.sign_ins!.backfill.from!);
      expect(Date.now() - from).toBeGreaterThan(6.9 * DAY);
      expect(Date.now() - from).toBeLessThan(7.1 * DAY);
      expect(providers.locks).toEqual([org]);
      const row = providers.integrations.find((r) => r.publicId === res.body.id)!;
      expect(row.nextHealthAt).not.toBeNull();
      expect(row.directoryDomains).toEqual(['contoso-it.example']);
      expect(row.grantedPermissions).toContain('AuditLog.Read.All');
      const stream = providers.streams.find(
        (s) => s.integrationId === row.id && s.stream === 'sign_ins',
      )!;
      expect(stream.cursor).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(audit.entries.map((e) => e.action)).toEqual(['ato.provider.bound']);
      expect(audit.entries[0]!.metadata).toMatchObject({
        provider: 'microsoft_entra',
        connectionId: ctx.freeConnection,
      });
    });

    it('answers 404 for an unknown or foreign connection', async () => {
      for (const id of [randomUUID(), ctx.foreignConnection]) {
        const res = await create({ connectionId: id });
        expect(res.status).toBe(404);
        expect(res.body.code).toBe('ato_provider_connection_not_found');
      }
    });

    it('refuses an ineligible connection with its reasons', async () => {
      const pending = providers.addConnection(org, { telemetry: 'pending' });
      const missing = providers.addConnection(org, { telemetry: null, status: 'configuring' });
      const a = await create({ connectionId: pending.publicId });
      expect(a.status).toBe(409);
      expect(a.body).toMatchObject({
        code: 'ato_provider_connection_ineligible',
        reasons: [{ reason: 'telemetry_grant_inactive' }],
      });
      const b = await create({ connectionId: missing.publicId });
      expect(b.body.reasons).toEqual([
        { reason: 'connection_inactive' },
        { reason: 'telemetry_grant_missing' },
      ]);
    });

    it('refuses an already bound connection with the integration id', async () => {
      const res = await create({ connectionId: ctx.connection });
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({
        code: 'ato_provider_already_bound',
        integrationId: ctx.integration,
      });
    });

    it('refuses a directory monitored by another organization without naming it', async () => {
      const conn = providers.connections.find((c) => c.publicId === ctx.freeConnection)!;
      const other = providers.addIntegration(OTHER_ORG, {
        directoryRefHash: directoryRefHash('microsoft_entra', conn.externalTenantId!),
      });
      const res = await create({ connectionId: ctx.freeConnection });
      expect(res.status).toBe(409);
      expect(res.body.code).toBe('ato_provider_directory_in_use');
      const text = JSON.stringify(res.body);
      expect(text).not.toContain(other.publicId);
      // No detail field at all: neither an integration id nor an organization.
      expect(res.body).not.toHaveProperty('integrationId');
      expect(res.body).not.toHaveProperty('organizationId');
      // Once the other integration is disabled the directory is free.
      other.status = 'disabled';
      expect((await create({ connectionId: ctx.freeConnection })).status).toBe(201);
    });

    it('refuses the sixth integration (ATO_IDP_MAX_INTEGRATIONS_PER_ORG = 5)', async () => {
      for (let i = 0; i < 4; i += 1) providers.addIntegration(org);
      const res = await create({ connectionId: ctx.freeConnection });
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({ code: 'ato_provider_limit_reached', limit: 5 });
    });

    it('validates the settings as a whole (paths, never values)', async () => {
      const companion = defaultBindingSettings();
      companion.streams.mailbox_audit.enabled = false;
      const a = await create({ connectionId: ctx.freeConnection, settings: companion });
      expect(a.status).toBe(400);
      expect(a.body.code).toBe('ato_provider_settings_invalid');
      expect(a.body.issues).toEqual(
        expect.arrayContaining([
          { path: 'streams.forwarding_changes.enabled', message: 'companion_requires_primary' },
        ]),
      );
      const google = defaultBindingSettings();
      google.mfaEnforcement.orgUnitPath = '/Secure';
      const b = await create({ connectionId: ctx.freeConnection, settings: google });
      expect(b.body.issues).toEqual([
        { path: 'mfaEnforcement.orgUnitPath', message: 'not_for_provider' },
      ]);
      const extra = await create({
        connectionId: ctx.freeConnection,
        settings: { ...defaultBindingSettings(), secretKnob: 'EXAMPLE-value' },
      });
      expect(extra.status).toBe(400);
      expect(JSON.stringify(extra.body)).not.toContain('EXAMPLE-value');
      const strict = await create({ connectionId: ctx.freeConnection, extra: true });
      expect(strict.status).toBe(400);
    });

    it('binds a connection again under its previous id after removal', async () => {
      const removed = await call('delete', `${BASE}/providers/${ctx.integration}`, {
        reason: 'Rebinding test',
      });
      expect(removed.status).toBe(200);
      const again = await create({ connectionId: ctx.connection });
      expect(again.status, JSON.stringify(again.body)).toBe(201);
      expect(again.body).toMatchObject({
        id: ctx.integration,
        status: 'active',
        settingsVersion: 2,
      });
    });
  });

  describe('settings, pause, resume, probe (D10)', () => {
    it('PATCH: CAS conflict with the current version; stream flags follow; changed paths audited', async () => {
      const stale = await call('patch', `${BASE}/providers/${ctx.integration}`, {
        rowVersion: 7,
        settings: settingsBody(),
      });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({ code: 'ato_provider_conflict', currentRowVersion: 1 });
      const next = settingsBody();
      next.streams.oauth_consents.enabled = false;
      const ok = await call('patch', `${BASE}/providers/${ctx.integration}`, {
        rowVersion: 1,
        settings: next,
      });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body).toMatchObject({ rowVersion: 2, settingsVersion: 2 });
      const consents = (ok.body.streamDetails as Array<{ stream: string; enabled: boolean }>).find(
        (s) => s.stream === 'oauth_consents',
      );
      expect(consents?.enabled).toBe(false);
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'ato.provider.updated',
        metadata: {
          changedPaths: ['pollIntervalSeconds', 'streams.oauth_consents.enabled'],
        },
      });
      // The same document again changes nothing (no version, no audit).
      const same = await call('patch', `${BASE}/providers/${ctx.integration}`, {
        rowVersion: 2,
        settings: next,
      });
      expect(same.body.rowVersion).toBe(2);
      expect(audit.entries.filter((e) => e.action === 'ato.provider.updated')).toHaveLength(1);
      const invalid = await call('patch', `${BASE}/providers/${ctx.integration}`, {
        rowVersion: 2,
        settings: { ...next, pollIntervalSeconds: 5 },
      });
      expect(invalid.status).toBe(400);
      expect(invalid.body.issues).toEqual([{ path: 'pollIntervalSeconds', message: 'too_small' }]);
    });

    it('pause is idempotent with reason `user`; resume needs an active connection', async () => {
      const path = `${BASE}/providers/${ctx.integration}`;
      const paused = await call('post', `${path}/pause`, { reason: 'Maintenance window' });
      expect(paused.body).toMatchObject({ status: 'paused', pausedReason: 'user', rowVersion: 2 });
      const again = await call('post', `${path}/pause`, { reason: 'Again' });
      expect(again.body).toMatchObject({ status: 'paused', rowVersion: 2 });
      expect(audit.entries.filter((e) => e.action === 'ato.provider.paused')).toHaveLength(1);
      const conn = providers.connections.find((c) => c.publicId === ctx.connection)!;
      conn.grants[0]!.status = 'error';
      const inactive = await call('post', `${path}/resume`);
      expect(inactive.status).toBe(409);
      expect(inactive.body.code).toBe('ato_provider_connection_inactive');
      conn.grants[0]!.status = 'active';
      const resumed = await call('post', `${path}/resume`);
      expect(resumed.body).toMatchObject({ status: 'active', pausedReason: null, rowVersion: 3 });
      expect(audit.entries.at(-1)?.action).toBe('ato.provider.resumed');
    });

    it('health check schedules a probe without a version change', async () => {
      const row = providers.integrations.find((r) => r.publicId === ctx.integration)!;
      row.nextHealthAt = new Date(Date.now() + 3_600_000);
      const res = await call('post', `${BASE}/providers/${ctx.integration}/health-check`);
      expect(res.status).toBe(202);
      expect(row.nextHealthAt.getTime()).toBeLessThanOrEqual(Date.now());
      expect(row.rowVersion).toBe(1);
      expect(audit.entries.at(-1)?.action).toBe('ato.provider.health_check_requested');
    });

    it('a removed integration refuses changes with 409 ato_provider_disabled', async () => {
      await call('delete', `${BASE}/providers/${ctx.integration}`, { reason: 'Removed' });
      for (const [method, suffix, body] of [
        ['patch', '', { rowVersion: 2, settings: settingsBody() }],
        ['post', '/pause', { reason: 'Pause it' }],
        ['post', '/resume', undefined],
        ['post', '/health-check', undefined],
        ['post', '/backfill', { from: new Date(Date.now() - DAY).toISOString() }],
      ] as const) {
        const res = await call(method, `${BASE}/providers/${ctx.integration}${suffix}`, body);
        expect(res.status, suffix).toBe(409);
        expect(res.body.code).toBe('ato_provider_disabled');
      }
    });
  });

  describe('backfill (D8.1)', () => {
    const backfill = (body: object) =>
      call('post', `${BASE}/providers/${ctx.integration}/backfill`, body);

    it('clamps each stream to its provider retention and refuses a running backfill', async () => {
      const res = await backfill({ from: new Date(Date.now() - 20 * DAY).toISOString() });
      expect(res.status).toBe(202);
      const streams = Object.fromEntries(
        (res.body.streamDetails as StreamView[]).map((s) => [s.stream, s]),
      );
      expect(streams.sign_ins!.status).toBe('backfilling');
      expect(Date.now() - Date.parse(streams.mailbox_audit!.backfill.from!)).toBeLessThan(
        7.01 * DAY,
      );
      expect(Date.now() - Date.parse(streams.sign_ins!.backfill.from!)).toBeGreaterThan(19.9 * DAY);
      expect(streams.forwarding_changes!.status).toBe('active');
      const again = await backfill({
        from: new Date(Date.now() - DAY).toISOString(),
        streams: ['sign_ins'],
      });
      expect(again.status).toBe(409);
      expect(again.body).toMatchObject({
        code: 'ato_provider_backfill_active',
        streams: [{ stream: 'sign_ins' }],
      });
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'ato.provider.backfill_requested',
        metadata: { streams: ['sign_ins', 'risk_events', 'oauth_consents', 'mailbox_audit'] },
      });
    });

    it('records the range the stream already ingested as its replay window (review fix)', async () => {
      const row = providers.integrations.find((r) => r.publicId === ctx.integration)!;
      const signIns = providers.streams.find(
        (s) => s.integrationId === row.id && s.stream === 'sign_ins',
      )!;
      const coveredFrom = new Date(Date.now() - 10 * DAY);
      const watermark = new Date(Date.now() - 5 * 60_000);
      signIns.coveredFrom = coveredFrom;
      signIns.watermarkAt = watermark;
      const res = await backfill({
        from: new Date(Date.now() - 20 * DAY).toISOString(),
        streams: ['sign_ins'],
      });
      expect(res.status).toBe(202);
      expect(signIns.status).toBe('backfilling');
      expect(signIns.replayFrom).toEqual(coveredFrom);
      // One margin (1 h) before the earlier watermark: late events there are read again.
      expect(signIns.replayUntil).toEqual(new Date(watermark.getTime() - 3_600_000));
      // Nothing ingested yet (no watermark): no replay window.
      const risk = providers.streams.find(
        (s) => s.integrationId === row.id && s.stream === 'risk_events',
      )!;
      risk.watermarkAt = null;
      await backfill({ from: new Date(Date.now() - DAY).toISOString(), streams: ['risk_events'] });
      expect(risk.replayFrom).toBeNull();
      expect(risk.replayUntil).toBeNull();
    });

    it('refuses ranges and streams it cannot backfill (422 with the reason)', async () => {
      const cases: Array<[object, string]> = [
        [{ from: new Date(Date.now() + DAY).toISOString() }, 'range'],
        [{ from: new Date(Date.now() - 31 * DAY).toISOString() }, 'range'],
        [
          { from: new Date(Date.now() - DAY).toISOString(), streams: ['forwarding_changes'] },
          'stream_not_backfillable',
        ],
      ];
      for (const [body, reason] of cases) {
        const res = await backfill(body);
        expect(res.status, reason).toBe(422);
        expect(res.body).toMatchObject({ code: 'ato_provider_backfill_range_invalid', reason });
      }
      const row = providers.integrations.find((r) => r.publicId === ctx.integration)!;
      for (const s of providers.streams.filter((x) => x.integrationId === row.id))
        s.enabled = false;
      const none = await backfill({ from: new Date(Date.now() - DAY).toISOString() });
      expect(none.body).toMatchObject({ reason: 'no_stream' });
    });
  });

  describe('removal (§6 #11)', () => {
    it('ends in-flight provider actions of the integration `integration_disabled`; idempotent', async () => {
      const row = providers.integrations.find((r) => r.publicId === ctx.integration)!;
      const account = world.accounts.find((a) => a.organizationId === org)!;
      const inFlight = world.addResponse(account, null, {
        actionType: 'suspend_account',
        provider: 'microsoft_entra',
        status: 'approved',
        integrationId: row.id,
      });
      const untouched = world.addResponse(account, null, {
        actionType: 'revoke_sessions',
        provider: 'microsoft_entra',
        status: 'approved',
        integrationId: null,
      });
      const res = await call('delete', `${BASE}/providers/${ctx.integration}`, {
        reason: 'Customer left',
      });
      expect(res.body).toMatchObject({ status: 'disabled', disabledReason: 'user' });
      expect(inFlight).toMatchObject({ status: 'failed', resultCode: 'integration_disabled' });
      expect(untouched.status).toBe('approved');
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'ato.provider.unbound',
        metadata: { endedActions: 1 },
      });
      const again = await call('delete', `${BASE}/providers/${ctx.integration}`, {
        reason: 'Again',
      });
      expect(again.status).toBe(200);
      expect(audit.entries.filter((e) => e.action === 'ato.provider.unbound')).toHaveLength(1);
      const list = await call('get', `${BASE}/providers`);
      expect(list.body.data).toEqual([]);
      const withDisabled = await call('get', `${BASE}/providers?includeDisabled=true`);
      expect(withDisabled.body.data.map((d: { id: string }) => d.id)).toEqual([ctx.integration]);
      expect((await call('get', `${BASE}/providers?includeDisabled=yes`)).status).toBe(400);
    });
  });

  describe('lists and views', () => {
    it('the list shows the stream summary, capabilities and the connection', async () => {
      const res = await call('get', `${BASE}/providers`);
      expect(res.body).toMatchObject({ featureEnabled: true, limit: { max: 5, used: 1 } });
      expect(res.body.data[0]).toMatchObject({
        id: ctx.integration,
        connection: { id: ctx.connection, status: 'active' },
        health: { status: 'healthy', stale: false },
        streams: { enabled: 4, available: 4, failing: 0, backfilling: 0 },
      });
      expect(res.body.data[0].capabilities.actions).toContain('suspend_account');
      expect(res.body.data[0].capabilities.actions).not.toContain('revoke_oauth_grant');
    });

    it('the connections list carries D4 eligibility and the bound integration', async () => {
      const res = await call('get', `${BASE}/providers/connections`);
      const byId = new Map(
        (res.body.data as Array<{ id: string }>).map((c) => [c.id, c as Record<string, unknown>]),
      );
      expect(byId.get(ctx.connection)).toMatchObject({
        eligibility: 'already_bound',
        integrationId: ctx.integration,
      });
      expect(byId.get(ctx.freeConnection)).toMatchObject({ eligibility: 'eligible' });
      expect(byId.has(ctx.foreignConnection)).toBe(false);
    });

    it('a stale probe makes every capability unknown', async () => {
      const row = providers.integrations.find((r) => r.publicId === ctx.integration)!;
      row.healthDetail = {
        ...report(),
        checkedAt: new Date(Date.now() - 4 * 900_000).toISOString(),
      } as never;
      const res = await call('get', `${BASE}/providers/${ctx.integration}`);
      expect(res.body.health.stale).toBe(true);
      expect(
        res.body.actions.every((a: { capability: string }) =>
          ['unknown', 'not_offered', 'disabled'].includes(a.capability),
        ),
      ).toBe(true);
    });

    it('the mailbox state lists present and recently removed items (domains and traits only)', async () => {
      const res = await call('get', `${BASE}/accounts/${ctx.account}/mailbox-state`);
      expect(res.status).toBe(200);
      expect(res.body.items.map((i: { kind: string }) => i.kind).sort()).toEqual([
        'forwarding',
        'inbox_rule',
      ]);
      expect(res.body.items[0]).toMatchObject({
        integrationId: ctx.integration,
        provider: 'microsoft_entra',
        targetDomain: 'external-example.net',
      });
      expect(res.body.identities[0]).toMatchObject({
        integrationId: ctx.integration,
        directoryStatus: 'active',
        refreshSupported: true,
      });
      expect(res.body.integrations[0].lastSweepAt).not.toBeNull();
      expect(JSON.stringify(res.body.items)).not.toContain('@');
    });

    it('refresh flags the identities; 409 when no identity can be refreshed', async () => {
      const res = await call('post', `${BASE}/accounts/${ctx.account}/mailbox-state/refresh`);
      expect(res.status).toBe(202);
      expect(res.body).toMatchObject({ identities: 1, integrationIds: [ctx.integration] });
      expect(providers.identities[0]!.mailboxRefreshRequestedAt).not.toBeNull();
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'ato.mailbox_state.refresh_requested',
        resourceId: ctx.account,
      });
      const lonely = world.addAccount(org);
      providers.addIdentity(null, org, lonely.id);
      const none = await call('post', `${BASE}/accounts/${lonely.publicId}/mailbox-state/refresh`);
      expect(none.status).toBe(409);
      expect(none.body.code).toBe('ato_provider_refresh_unavailable');
      // An integration whose mailbox-state stream was never proven by a probe cannot refresh.
      const row = providers.integrations.find((r) => r.publicId === ctx.integration)!;
      row.healthDetail = null;
      const unproven = await call('post', `${BASE}/accounts/${ctx.account}/mailbox-state/refresh`);
      expect(unproven.status).toBe(409);
    });

    it('8.4 settings list the integrations per provider; account identities name their integration', async () => {
      const settings = await call('get', `${BASE}/settings`);
      expect(SettingsViewSchema.safeParse(settings.body).success).toBe(true);
      expect(settings.body.identityProviders).toEqual([
        {
          provider: 'microsoft_entra',
          integrations: [{ id: ctx.integration, provider: 'microsoft_entra', health: 'healthy' }],
        },
        { provider: 'google_workspace', integrations: [] },
      ]);
      const account = await call('get', `${BASE}/accounts/${ctx.account}`);
      expect(AccountDetailSchema.safeParse(account.body).success).toBe(true);
    });
  });
});
