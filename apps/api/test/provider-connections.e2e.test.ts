/**
 * The Microsoft 365 and Google Workspace connection routes of step 8.2
 * (docs/plan/steps/25-m365-google-connectors.md §5.2 #1–24, §10.4) over HTTP with MySQL, Redis
 * and S3 stubbed: the provider repositories, the destinations service (real step 2.3 planner,
 * seeded presets) and audit replaced by the in-memory `ProviderWorld`, the Idempotency-Key store
 * by `InMemoryIdempotencyStore`; the integration-worker's writes (verification, provider domain
 * checks, probe evidence, run completion) are simulated by `world.worker`. Covered per route:
 * success, strict schemas, coded errors, 403 per permission, cross-tenant 404, Idempotency-Key
 * replay and reuse, ADR-0057 redacted replay (consent URL, probe address, credential upload),
 * signed tenant-bound cursors, per-connection limits, the preview → impact token → apply flow
 * (I4), the route-token masking of the guide, and an audit-secret scan of every audit row the
 * suite produced. The real writer and reader run in integration/provider-connections.test.ts.
 */
// @covers get /api/v1/provider-integrations/catalog
// @covers get /api/v1/provider-connections
// @covers post /api/v1/provider-connections
// @covers get /api/v1/provider-connections/:id
// @covers patch /api/v1/provider-connections/:id
// @covers delete /api/v1/provider-connections/:id
// @covers get /api/v1/provider-connections/:id/wizard
// @covers post /api/v1/provider-connections/:id/grants
// @covers post /api/v1/provider-connections/consent/complete
// @covers put /api/v1/provider-connections/:id/grants/:profile/credentials
// @covers post /api/v1/provider-connections/:id/grants/:profile/verify
// @covers delete /api/v1/provider-connections/:id/grants/:profile
// @covers get /api/v1/provider-connections/:id/domains
// @covers put /api/v1/provider-connections/:id/domains
// @covers post /api/v1/provider-connections/:id/mail-flow/preview
// @covers post /api/v1/provider-connections/:id/mail-flow/apply
// @covers get /api/v1/provider-connections/:id/mail-flow
// @covers post /api/v1/provider-connections/:id/attestations
// @covers post /api/v1/provider-connections/:id/validations
// @covers get /api/v1/provider-connections/:id/validations
// @covers get /api/v1/provider-connections/:id/validations/:runId
// @covers get /api/v1/provider-connections/:id/health
// @covers post /api/v1/provider-connections/:id/health/check
// @covers get /api/v1/provider-connections/:id/setup-guide
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { deriveRouteToken } from '@email-gateway/mail-routing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { loadApiConfig } from '../src/config';
import { PROVIDER_EXAMPLES } from '../src/modules/provider-connections/dto/provider-connections.schemas';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
  stubbedApiEnv,
} from './support/api-test-app';
import {
  overrideProviders,
  ProviderWorld,
  RecordingProviderAudit,
  sha256,
} from './support/provider-fixtures';

const READ = 'integration:read';
const MANAGE = 'integration:manage';
const ROUTING = 'domain:routing_manage';
const CONNECTOR = 'connector:manage';
const ALL = [READ, MANAGE, ROUTING, CONNECTOR];
const OTHER_ORG = 2n;
const P = '/api/v1/provider-connections';
const M365_APP_ID = '11111111-2222-3333-4444-555555555555';
const GOOGLE_SA_CLIENT_ID = '123456789012345678901';
const CLIENT_SECRET = 'e2e-client-secret-value-0123456789';

/** JSON with bigint ids as strings (rows of the in-memory world carry bigint ids). */
const json = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

/** A fresh RSA key for the service-account upload (generated at runtime, never committed). */
const SA_PRIVATE_KEY = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ format: 'pem', type: 'pkcs8' })
  .toString();

describe('provider-connection routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ProviderWorld();
  const audit = new RecordingProviderAudit();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  /** Every secret the suite ever sent or received (scanned against the audit rows at the end). */
  const secrets = new Set<string>([CLIENT_SECRET, SA_PRIVATE_KEY.slice(40, 120)]);
  const auditSeen: string[] = [];

  beforeAll(async () => {
    const env = {
      PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: M365_APP_ID,
      PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID: GOOGLE_SA_CLIENT_ID,
    };
    const hostConfig = loadApiConfig(stubbedApiEnv(env));
    api = await createStubbedApiApp(env, {
      override: (b) => store.override(overrideProviders(b, world, audit, hostConfig)),
    });
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    auditSeen.push(...audit.entries.map((e) => json(e)));
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.user(ALL, { mfaAuthenticated: true });
    api.principals.apiKeyWith([]);
  });

  const auth = () => api.principals.bearer();
  const key = () => ({ 'Idempotency-Key': randomUUID() });
  const get = async (path: string) =>
    api
      .http()
      .get(path)
      .set(await auth());
  const send = async (
    method: 'post' | 'put' | 'patch' | 'delete',
    path: string,
    body?: object,
    headers: Record<string, string> = key(),
  ) => {
    const req = api
      .http()
      [method](path)
      .set(await auth())
      .set(headers);
    return body === undefined ? req : req.send(body);
  };

  /** A bound (I10) Microsoft 365 connection with one linked, provider-verified domain. */
  function boundM365(options: { orgId?: bigint } = {}) {
    const orgId = options.orgId ?? org;
    const connection = world.addConnection(orgId, { displayName: `M365 ${randomUUID()}` });
    world.addGrant(connection, {
      requestedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
    });
    const domain = world.addDomain(orgId, `contoso-${world.id()}.example`);
    world.link(connection, domain);
    world.worker.bind(connection);
    return { connection, domain };
  }

  async function previewAndApply(id: string, change: object) {
    const preview = await send('post', `${P}/${id}/mail-flow/preview`, { change }, {});
    expect(preview.status, JSON.stringify(preview.body)).toBe(200);
    const apply = await send('post', `${P}/${id}/mail-flow/apply`, {
      change,
      impactToken: preview.body.impactToken,
      confirm: true,
    });
    return { preview, apply };
  }

  describe('catalogue and connections (#1–#7)', () => {
    it('GET catalog: profiles, auth methods available by configuration, gateway values, egress sets', async () => {
      world.egressSets.push({
        provider: 'microsoft_365',
        version: 1,
        publishedAt: new Date('2026-06-01T00:00:00Z'),
        importedAt: new Date(),
        rangeCount: 8,
      });
      const res = await get('/api/v1/provider-integrations/catalog');
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      const m365 = res.body.providers.find(
        (p: { provider: string }) => p.provider === 'microsoft_365',
      );
      expect(m365.profiles[0]).toMatchObject({
        key: 'm365.mail_flow',
        readOnly: true,
        permissions: ['Organization.Read.All', 'Domain.Read.All'],
      });
      expect(m365.profiles[0].availableAuthMethods).toContain('platform_app');
      expect(m365.egressSet).toMatchObject({ version: 1, rangeCount: 8 });
      expect(res.body.gateway.relayHosts).toEqual([
        'out1.mail-gateway.test',
        'out2.mail-gateway.test',
      ]);
      expect(res.body.probeDomain).toBe(api.config.PROVIDER_PROBE_DOMAIN);
      api.principals.user([]);
      expect((await get('/api/v1/provider-integrations/catalog')).status).toBe(403);
    });

    it('POST creates a draft (201, keyed, replay, reuse, limit, name), audited', async () => {
      const headers = key();
      const body = { provider: 'microsoft_365', displayName: 'Contoso tenant' };
      const created = await send('post', P, body, headers);
      expect(created.status, JSON.stringify(created.body)).toBe(201);
      expect(created.body).toMatchObject({
        status: 'draft',
        provider: 'microsoft_365',
        rowVersion: 1,
      });
      const replay = await send('post', P, body, headers);
      expect(replay.status).toBe(201);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body.id).toBe(created.body.id);
      const reused = await send('post', P, { ...body, displayName: 'Other' }, headers);
      expect(reused.status).toBe(422);
      expect(reused.body.code).toBe('idempotency_key_reused');
      const missing = await send('post', P, body, {});
      expect(missing.status).toBe(400);
      expect(missing.body.code).toBe('idempotency_key_required');
      const dup = await send('post', P, body);
      expect(dup.status).toBe(409);
      expect(dup.body.code).toBe('connection_name_exists');
      const strict = await send('post', P, { ...body, displayName: 'x2', tenant: 'evil' });
      expect(strict.status).toBe(400);
      for (let i = world.connections.length; i < api.config.PROVIDER_MAX_CONNECTIONS_PER_ORG; i++) {
        world.addConnection(org);
      }
      const limit = await send('post', P, {
        provider: 'google_workspace',
        displayName: 'One more',
      });
      expect(limit.status).toBe(409);
      expect(limit.body).toMatchObject({ code: 'connection_limit', limit: 10 });
      expect(
        audit.entries.filter((e) => e.action === 'integration.connection_created'),
      ).toHaveLength(1);
      api.principals.user([READ]);
      expect((await send('post', P, { provider: 'microsoft_365', displayName: 'r' })).status).toBe(
        403,
      );
    });

    it('GET list: newest first, filters, signed tenant-bound v1 cursor; other tenants invisible', async () => {
      const a = world.addConnection(org, { provider: 'microsoft_365' });
      const b = world.addConnection(org, { provider: 'google_workspace' });
      world.addConnection(OTHER_ORG);
      const first = await get(`${P}?limit=1`);
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      expect(first.body.data.map((r: { id: string }) => r.id)).toEqual([b.publicId]);
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const second = await get(`${P}?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`);
      expect(second.body.data.map((r: { id: string }) => r.id)).toEqual([a.publicId]);
      expect(second.body.nextCursor).toBeNull();
      const filtered = await get(`${P}?provider=google_workspace`);
      expect(filtered.body.data.map((r: { id: string }) => r.id)).toEqual([b.publicId]);
      const tampered = await get(`${P}?limit=1&cursor=${first.body.nextCursor}x`);
      expect(tampered.status).toBe(400);
      expect(tampered.body.code).toBe('cursor_invalid');
      // A cursor is bound to its filters (a different filter set refuses it).
      const foreign = await get(
        `${P}?limit=1&provider=microsoft_365&cursor=${encodeURIComponent(first.body.nextCursor)}`,
      );
      expect(foreign.status).toBe(400);
      expect((await get(`${P}?unknown=1`)).status).toBe(400);
    });

    it('GET detail, PATCH rename (rowVersion CAS), wizard; another tenant’s id is 404', async () => {
      const { connection } = boundM365();
      const foreign = boundM365({ orgId: OTHER_ORG }).connection;
      const detail = await get(`${P}/${connection.publicId}`);
      expect(detail.status).toBe(200);
      expect(detail.body).toMatchObject({
        id: connection.publicId,
        status: 'active',
        tenantId: M365_APP_ID,
      });
      expect(JSON.stringify(detail.body)).not.toContain('ciphertext');
      expect((await get(`${P}/${foreign.publicId}`)).body.code).toBe('connection_not_found');
      expect((await get(`${P}/not-a-uuid`)).status).toBe(400);

      const renamed = await send(
        'patch',
        `${P}/${connection.publicId}`,
        { displayName: 'Renamed', rowVersion: detail.body.rowVersion },
        {},
      );
      expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
      expect(renamed.body).toMatchObject({
        displayName: 'Renamed',
        rowVersion: detail.body.rowVersion + 1,
      });
      const stale = await send(
        'patch',
        `${P}/${connection.publicId}`,
        { displayName: 'Again', rowVersion: detail.body.rowVersion },
        {},
      );
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({ code: 'connection_version_conflict' });
      const cross = await send(
        'patch',
        `${P}/${foreign.publicId}`,
        { displayName: 'Mine', rowVersion: 2 },
        {},
      );
      expect(cross.status).toBe(404);

      const wizard = await get(`${P}/${connection.publicId}/wizard`);
      expect(wizard.status).toBe(200);
      const steps = Object.fromEntries(
        wizard.body.steps.map((s: { step: string; status: string }) => [s.step, s.status]),
      );
      expect(steps).toMatchObject({ connect: 'done', domains: 'done', validate: 'blocked' });
      expect(wizard.body.nextAction).toMatchObject({ step: 'inbound' });
      expect((await get(`${P}/${foreign.publicId}/wizard`)).status).toBe(404);
    });
  });

  describe('grants (#8–#12, D2, D3, D5)', () => {
    it('platform_app: consent URL with a single-use state (only its SHA-256 stored); replay redacted', async () => {
      const c = world.addConnection(org);
      const headers = key();
      const body = { profile: 'm365.mail_flow', authMethod: 'platform_app' };
      const res = await send('post', `${P}/${c.publicId}/grants`, body, headers);
      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(res.body.next).toBe('consent');
      const url = new URL(res.body.consent.consentUrl);
      expect(url.pathname).toBe('/organizations/v2.0/adminconsent');
      expect(url.searchParams.get('client_id')).toBe(M365_APP_ID);
      const state = url.searchParams.get('state')!;
      secrets.add(state);
      expect(world.consentStates).toHaveLength(1);
      expect(world.consentStates[0]!.stateSha256).toBe(sha256(state));
      expect(json(world.consentStates)).not.toContain(state);
      expect(world.connections[0]!.status).toBe('connecting');
      // ADR-0057: the stored response carries `consentUrl: null`.
      const replay = await send('post', `${P}/${c.publicId}/grants`, body, headers);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body.consent.consentUrl).toBeNull();
      expect(json([...store.rows.values()])).not.toContain(state);
      const again = await send('post', `${P}/${c.publicId}/grants`, body);
      expect(again.status).toBe(409);
      expect(again.body.code).toBe('grant_exists');
      const wrong = await send('post', `${P}/${c.publicId}/grants`, {
        profile: 'google.mail_flow',
        authMethod: 'platform_service_account',
      });
      expect(wrong.status).toBe(422);
      expect(wrong.body.code).toBe('auth_method_not_allowed');
    });

    it('platform_app refuses API keys (403 user_principal_required)', async () => {
      const c = world.addConnection(org);
      api.principals.apiKeyWith([READ, MANAGE]);
      const res = await api
        .http()
        .post(`${P}/${c.publicId}/grants`)
        .set(api.principals.apiKeyHeaders)
        .set(key())
        .send({ profile: 'm365.mail_flow', authMethod: 'platform_app' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('user_principal_required');
    });

    it('consent completion: single use, bound to organization and user, declined → error', async () => {
      const c = world.addConnection(org);
      const created = await send('post', `${P}/${c.publicId}/grants`, {
        profile: 'm365.mail_flow',
        authMethod: 'platform_app',
      });
      const state = new URL(created.body.consent.consentUrl).searchParams.get('state')!;
      secrets.add(state);
      const done = await send('post', `${P}/consent/complete`, {
        state,
        tenant: M365_APP_ID,
        adminConsent: true,
      });
      expect(done.status, JSON.stringify(done.body)).toBe(200);
      expect(done.body).toMatchObject({ connectionId: c.publicId, status: 'verifying' });
      expect(world.grants[0]).toMatchObject({ status: 'verifying', claimedTenantId: M365_APP_ID });
      const reused = await send('post', `${P}/consent/complete`, {
        state,
        tenant: M365_APP_ID,
        adminConsent: true,
      });
      expect(reused.status).toBe(404);
      expect(reused.body.code).toBe('consent_state_invalid');
      const badTenant = await send('post', `${P}/consent/complete`, {
        state,
        tenant: 'not-a-guid',
        adminConsent: true,
      });
      expect(badTenant.status).toBe(422);
      expect(badTenant.body).toMatchObject({ code: 'credential_invalid', field: 'tenant' });

      // Another user's state, and a state of another organization: both unknown.
      const c2 = world.addConnection(org);
      const g2 = await send('post', `${P}/${c2.publicId}/grants`, {
        profile: 'm365.mail_flow',
        authMethod: 'platform_app',
      });
      const state2 = new URL(g2.body.consent.consentUrl).searchParams.get('state')!;
      secrets.add(state2);
      world.consentStates.at(-1)!.userId = 99n;
      expect(
        (
          await send('post', `${P}/consent/complete`, {
            state: state2,
            adminConsent: true,
            tenant: M365_APP_ID,
          })
        ).status,
      ).toBe(404);
      world.consentStates.at(-1)!.userId = 10n;
      world.consentStates.at(-1)!.organizationId = OTHER_ORG;
      expect(
        (
          await send('post', `${P}/consent/complete`, {
            state: state2,
            adminConsent: true,
            tenant: M365_APP_ID,
          })
        ).status,
      ).toBe(404);
      world.consentStates.at(-1)!.organizationId = org;
      world.consentStates.at(-1)!.expiresAt = new Date(Date.now() - 1000);
      expect(
        (
          await send('post', `${P}/consent/complete`, {
            state: state2,
            adminConsent: true,
            tenant: M365_APP_ID,
          })
        ).status,
      ).toBe(404);
      world.consentStates.at(-1)!.expiresAt = new Date(Date.now() + 60_000);
      const declined = await send('post', `${P}/consent/complete`, {
        state: state2,
        error: 'access_denied',
        errorDescription: 'AADSTS65004: User declined to consent.\u0000<script>',
      });
      expect(declined.status).toBe(200);
      expect(world.grants.find((g) => g.connectionId === c2.id)).toMatchObject({
        status: 'error',
        lastErrorCode: 'consent_declined',
      });
      const row = audit.entries.findLast((e) => e.action === 'integration.grant_consented')!;
      expect(row.metadata).toMatchObject({ outcome: 'declined' });
      expect(JSON.stringify(row.metadata)).not.toContain('\\u0000');
      expect(String(row.metadata?.providerErrorDescription)).toMatch(/^AADSTS65004/);
      // API keys cannot complete a consent.
      api.principals.apiKeyWith([MANAGE]);
      const byKey = await api
        .http()
        .post(`${P}/consent/complete`)
        .set(api.principals.apiKeyHeaders)
        .set(key())
        .send({ state, adminConsent: true, tenant: M365_APP_ID });
      expect(byKey.status).toBe(403);
    });

    it('customer_app_secret: encrypted upload, 12-hex fingerprint, never returned; redacted replay', async () => {
      const c = world.addConnection(org);
      await send('post', `${P}/${c.publicId}/grants`, {
        profile: 'm365.mail_flow',
        authMethod: 'customer_app_secret',
      });
      const headers = key();
      const body = {
        tenantId: M365_APP_ID,
        clientId: '66666666-7777-8888-9999-000000000000',
        clientSecret: CLIENT_SECRET,
        expiresAt: new Date(Date.now() + 90 * 86_400_000).toISOString(),
      };
      const path = `${P}/${c.publicId}/grants/m365.mail_flow/credentials`;
      const res = await send('put', path, body, headers);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({ status: 'verifying', credentialVersion: 1 });
      expect(res.body.credentialFingerprint).toMatch(/^[0-9a-f]{12}$/);
      expect(JSON.stringify(res.body)).not.toContain(CLIENT_SECRET);
      const grant = world.grants[0]!;
      expect(grant.credentialCiphertext).toMatch(/^v1\./);
      expect(grant.credentialCiphertext).not.toContain(CLIENT_SECRET);
      expect(grant.claimedTenantId).toBe(M365_APP_ID);
      const replay = await send('put', path, body, headers);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body.credentialVersion).toBe(1);
      // The stored request fingerprint and response never contain the secret.
      expect(json([...store.rows.values()])).not.toContain(CLIENT_SECRET);
      const reused = await send(
        'put',
        path,
        { ...body, clientSecret: 'another-secret-value' },
        headers,
      );
      expect(reused.status).toBe(422);
      expect(reused.body.code).toBe('idempotency_key_reused');
      const rotated = await send('put', path, { ...body, clientSecret: 'rotated-secret-value' });
      expect(rotated.body.credentialVersion).toBe(2);
      secrets.add('rotated-secret-value').add('another-secret-value');
      const expired = await send('put', path, { ...body, expiresAt: '2020-01-01T00:00:00.000Z' });
      expect(expired.status).toBe(422);
      expect(expired.body).toMatchObject({ code: 'credential_invalid', field: 'expiresAt' });
      const wrongShape = await send('put', path, {
        serviceAccountKey: {},
        subjectEmail: 'a@b.example',
      });
      expect(wrongShape.status).toBe(422);
      expect(wrongShape.body.code).toBe('credential_invalid');
      expect(JSON.stringify(wrongShape.body)).not.toContain('a@b.example');
    });

    it('customer_service_account: key validated (token_uri, RSA ≥ 2048), unknown fields dropped, subject masked', async () => {
      const c = world.addConnection(org, { provider: 'google_workspace' });
      await send('post', `${P}/${c.publicId}/grants`, {
        profile: 'google.mail_flow',
        authMethod: 'customer_service_account',
      });
      const path = `${P}/${c.publicId}/grants/google.mail_flow/credentials`;
      const keyFile = {
        type: 'service_account',
        project_id: 'dropped-field',
        client_email: 'reader@project.iam.gserviceaccount.example',
        private_key: SA_PRIVATE_KEY,
        private_key_id: '0123456789abcdef0123',
        token_uri: api.config.PROVIDER_GOOGLE_TOKEN_URL,
        client_id: '109876543210987654321',
      };
      const res = await send('put', path, {
        serviceAccountKey: keyFile,
        subjectEmail: 'Admin@Contoso.example',
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.subjectEmail).not.toBe('admin@contoso.example');
      expect(res.body.subjectEmail).toMatch(/•/);
      expect(world.grants[0]!.subjectEmail).toBe('admin@contoso.example');
      expect(JSON.stringify(res.body)).not.toContain('PRIVATE KEY');
      const badUri = await send('put', path, {
        serviceAccountKey: { ...keyFile, token_uri: 'https://evil.example/token' },
        subjectEmail: 'admin@contoso.example',
      });
      expect(badUri.body).toMatchObject({ code: 'credential_invalid', field: 'token_uri' });
      const smallKey = generateKeyPairSync('rsa', { modulusLength: 1024 })
        .privateKey.export({ format: 'pem', type: 'pkcs8' })
        .toString();
      const weak = await send('put', path, {
        serviceAccountKey: { ...keyFile, private_key: smallKey },
        subjectEmail: 'admin@contoso.example',
      });
      expect(weak.body).toMatchObject({ code: 'credential_invalid', field: 'private_key' });
      // A customer method only: the platform method has no credential upload.
      const c2 = world.addConnection(org, { provider: 'google_workspace' });
      await send('post', `${P}/${c2.publicId}/grants`, {
        profile: 'google.mail_flow',
        authMethod: 'platform_service_account',
      });
      const platform = await send(
        'put',
        `${P}/${c2.publicId}/grants/google.mail_flow/credentials`,
        {
          serviceAccountKey: keyFile,
          subjectEmail: 'admin@contoso.example',
        },
      );
      expect(platform.body.code).toBe('auth_method_not_allowed');
    });

    it('platform_service_account: delegation steps, verify with subjectEmail, re-verify; unknown grant 404', async () => {
      const c = world.addConnection(org, { provider: 'google_workspace' });
      const created = await send('post', `${P}/${c.publicId}/grants`, {
        profile: 'google.mail_flow',
        authMethod: 'platform_service_account',
      });
      expect(created.status).toBe(201);
      expect(created.body.delegation).toMatchObject({ clientId: GOOGLE_SA_CLIENT_ID });
      expect(created.body.delegation.scopes.every((s: string) => s.endsWith('.readonly'))).toBe(
        true,
      );
      const path = `${P}/${c.publicId}/grants/google.mail_flow/verify`;
      const missing = await send('post', path, {});
      expect(missing.body).toMatchObject({ code: 'credential_invalid', field: 'subjectEmail' });
      const ok = await send('post', path, { subjectEmail: 'admin@contoso.example' });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body.status).toBe('verifying');
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'integration.grant_consented',
        metadata: expect.objectContaining({ outcome: 'delegation_confirmed' }),
      });
      const again = await send('post', path, {});
      expect(again.status).toBe(200);
      expect(audit.entries.at(-1)!.action).toBe('integration.grant_verification_requested');
      expect(
        (await send('post', `${P}/${c.publicId}/grants/m365.mail_flow/verify`, {})).body.code,
      ).toBe('grant_not_found');
      expect((await send('post', `${P}/${c.publicId}/grants/NOT A KEY/verify`, {})).status).toBe(
        400,
      );
    });

    it('revoke: ciphertext wiped, binding released, removal steps; refused while outbound is on', async () => {
      const c = world.addConnection(org);
      world.addGrant(c, {
        authMethod: 'customer_app_secret',
        status: 'active',
        credentialCiphertext: 'v1.k.iv.tag.ct',
        credentialKeyId: 'k',
      });
      c.activeTenantKey = 'microsoft_365:x';
      const res = await send('delete', `${P}/${c.publicId}/grants/m365.mail_flow`);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.grant.status).toBe('revoked');
      expect(res.body.providerRemovalSteps[0]).toMatch(/App registrations/);
      expect(world.grants[0]).toMatchObject({ credentialCiphertext: null, credentialKeyId: null });
      expect(world.connections[0]).toMatchObject({ status: 'draft', activeTenantKey: null });
      const gone = await send('delete', `${P}/${c.publicId}/grants/m365.mail_flow`);
      expect(gone.body.code).toBe('grant_not_found');
      const { connection } = boundM365();
      connection.outboundMode = 'probe_only';
      const busy = await send('delete', `${P}/${connection.publicId}/grants/m365.mail_flow`);
      expect(busy.status).toBe(409);
      expect(busy.body.code).toBe('outbound_active');
    });
  });

  describe('domains (#13, #14, D4)', () => {
    it('step API-4 B4: links a verified (not yet active) domain; pending stays 422', async () => {
      const c = world.addConnection(org, { status: 'configuring' });
      const verified = world.addDomain(org, 'v4.example', { status: 'verified' });
      const pending = world.addDomain(org, 'p4.example', { status: 'pending_verification' });
      const path = `${P}/${c.publicId}/domains`;
      const ok = await send('put', path, { domainIds: [verified.publicId] });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body.data).toEqual([expect.objectContaining({ id: verified.publicId })]);
      const refused = await send('put', path, { domainIds: [pending.publicId] });
      expect(refused.status).toBe(422);
      expect(refused.body.code).toBe('domain_not_verified');
    });

    it('links active domains of the organization; refuses pending, foreign and elsewhere-linked ones', async () => {
      const c = world.addConnection(org, { status: 'configuring' });
      const active = world.addDomain(org, 'a.example');
      const pending = world.addDomain(org, 'p.example', { status: 'pending' });
      const foreign = world.addDomain(OTHER_ORG, 'f.example');
      const other = world.addConnection(org);
      const taken = world.addDomain(org, 't.example');
      world.link(other, taken);
      const path = `${P}/${c.publicId}/domains`;
      const ok = await send('put', path, { domainIds: [active.publicId] });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body.data).toEqual([
        expect.objectContaining({
          id: active.publicId,
          name: 'a.example',
          providerVerification: 'unknown',
        }),
      ]);
      expect(c.nextHealthCheckAt).not.toBeNull();
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'integration.domains_linked',
        metadata: { linked: ['a.example'], unlinked: [], count: 1 },
      });
      expect((await send('put', path, { domainIds: [pending.publicId] })).body.code).toBe(
        'domain_not_verified',
      );
      const cross = await send('put', path, { domainIds: [foreign.publicId] });
      expect(cross.status).toBe(404);
      expect(cross.body.code).toBe('domain_not_in_organization');
      expect((await send('put', path, { domainIds: [taken.publicId] })).body.code).toBe(
        'domain_linked_elsewhere',
      );
      const dup = await send('put', path, { domainIds: [active.publicId, active.publicId] });
      expect(dup.status).toBe(400);
      const list = await get(path);
      expect(list.status).toBe(200);
      expect(list.body.data[0]).toMatchObject({ gatewayStatus: 'active', dns: { mx: 'valid' } });
      c.outboundMode = 'probe_only';
      const unlink = await send('put', path, { domainIds: [] });
      expect(unlink.body.code).toBe('outbound_active');
    });
  });

  describe('mail flow: preview → impact token → apply (#15–#17, D13, I4)', () => {
    it('inbound before binding is 409 connection_not_bound', async () => {
      const c = world.addConnection(org, { status: 'configuring' });
      const d = world.addDomain(org, 'nb.example');
      world.link(c, d);
      const res = await send(
        'post',
        `${P}/${c.publicId}/mail-flow/preview`,
        { change: { kind: 'inbound', domainIds: [d.publicId] } },
        {},
      );
      expect(res.status).toBe(409);
      expect(res.body.code).toBe('connection_not_bound');
    });

    it('inbound: preview shows current vs proposed; apply writes destinations, events and audit', async () => {
      const { connection, domain } = boundM365();
      world.destinations.set(domain.id, [
        {
          host: 'mail.contoso.example',
          port: 25,
          priority: 10,
          tlsMode: 'verify',
          provider: 'custom',
        },
      ]);
      const change = { kind: 'inbound', domainIds: [domain.publicId] };
      const { preview, apply } = await previewAndApply(connection.publicId, change);
      expect(preview.body.changeSet.domains[0]).toMatchObject({
        name: domain.name,
        changed: true,
        current: { provider: 'custom' },
        proposed: { provider: 'microsoft_365' },
      });
      expect(preview.body.impactToken).toMatch(/^[A-Za-z0-9_-]{43}\.\d+$/);
      expect(
        audit.entries.find((e) => e.action === 'integration.mail_flow_previewed')?.metadata,
      ).toMatchObject({ kind: 'inbound', domains: 1, changedDomains: 1 });
      expect(apply.status, JSON.stringify(apply.body)).toBe(200);
      expect(world.destinations.get(domain.id)).toEqual([
        expect.objectContaining({
          provider: 'microsoft_365',
          host: `${domain.name.replace(/\./g, '-')}.mail.protection.outlook.com`,
        }),
      ]);
      expect(world.routingEvents).toHaveLength(1);
      expect(world.links[0]!.inboundAppliedAt).not.toBeNull();
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'integration.mail_flow_applied',
        resourceType: 'provider_connection',
        resourceId: connection.publicId,
      });
      // The same token again (another key): the row version moved → 409 impact_changed.
      const stale = await send('post', `${P}/${connection.publicId}/mail-flow/apply`, {
        change,
        impactToken: preview.body.impactToken,
        confirm: true,
      });
      expect(stale.status).toBe(409);
      expect(stale.body.code).toBe('impact_changed');
      const state = await get(`${P}/${connection.publicId}/mail-flow`);
      expect(state.status).toBe(200);
      expect(state.body.domains[0].destinations.provider).toBe('microsoft_365');
    });

    it('refuses tampered, foreign-user and unconfirmed tokens and missing second permissions', async () => {
      const { connection, domain } = boundM365();
      const change = { kind: 'inbound', domainIds: [domain.publicId] };
      const preview = await send(
        'post',
        `${P}/${connection.publicId}/mail-flow/preview`,
        { change },
        {},
      );
      const token = preview.body.impactToken as string;
      const apply = (body: object) =>
        send('post', `${P}/${connection.publicId}/mail-flow/apply`, body);
      const tampered = `${token.slice(0, 10)}${token[10] === 'A' ? 'B' : 'A'}${token.slice(11)}`;
      expect((await apply({ change, impactToken: tampered, confirm: true })).body.code).toBe(
        'impact_changed',
      );
      expect((await apply({ change, impactToken: 'garbage', confirm: true })).body.code).toBe(
        'impact_changed',
      );
      expect((await apply({ change, impactToken: token, confirm: false })).status).toBe(400);
      // Another change with this token.
      const other = { kind: 'outbound', mode: 'probe_only' };
      expect((await apply({ change: other, impactToken: token, confirm: true })).body.code).toBe(
        'impact_changed',
      );
      // I4: the change's own permission is required on preview and apply.
      api.principals.user([READ, MANAGE, CONNECTOR], { mfaAuthenticated: true });
      expect(
        (await send('post', `${P}/${connection.publicId}/mail-flow/preview`, { change }, {}))
          .status,
      ).toBe(403);
      expect((await apply({ change, impactToken: token, confirm: true })).status).toBe(403);
      api.principals.user([READ, MANAGE, ROUTING], { mfaAuthenticated: true });
      expect(
        (await send('post', `${P}/${connection.publicId}/mail-flow/preview`, { change: other }, {}))
          .status,
      ).toBe(403);
      // Disconnect is applied through DELETE only.
      api.principals.user(ALL, { mfaAuthenticated: true });
      const dis = await apply({ change: { kind: 'disable' }, impactToken: token, confirm: true });
      expect(dis.status).toBe(409);
      expect(dis.body.code).toBe('change_not_applicable');
      expect(world.destinations.get(domain.id)).toBeUndefined();
    });

    it('a failing destination write rolls the whole apply back (one transaction)', async () => {
      const { connection, domain } = boundM365();
      const change = { kind: 'inbound', domainIds: [domain.publicId] };
      const preview = await send(
        'post',
        `${P}/${connection.publicId}/mail-flow/preview`,
        { change },
        {},
      );
      world.failNextDestinationWrite = true;
      const res = await send('post', `${P}/${connection.publicId}/mail-flow/apply`, {
        change,
        impactToken: preview.body.impactToken,
        confirm: true,
      });
      expect(res.status).toBe(500);
      expect(audit.entries.some((e) => e.action === 'integration.mail_flow_applied')).toBe(false);
    });

    it('outbound probe_only creates the provider_relay connector; activate needs validation and a probe', async () => {
      const { connection } = boundM365();
      const out = await previewAndApply(connection.publicId, {
        kind: 'outbound',
        mode: 'probe_only',
      });
      expect(out.preview.body.changeSet.connector).toEqual({ action: 'create', id: null });
      expect(out.apply.status, JSON.stringify(out.apply.body)).toBe(200);
      expect(world.connectors).toHaveLength(1);
      expect(world.connectors[0]).toMatchObject({
        providerConnectionId: connection.id,
        status: 'active',
      });
      expect(connection.outboundMode).toBe('probe_only');
      // Connector cap.
      const second = boundM365().connection;
      world.otherConnectors.set(org, api.config.SMTP_CONNECTORS_MAX_PER_ORGANIZATION);
      const capped = await previewAndApply(second.publicId, {
        kind: 'outbound',
        mode: 'probe_only',
      });
      expect(capped.apply.status).toBe(409);
      world.otherConnectors.clear();

      const activate = { kind: 'activate', outboundMode: 'active', internalRouting: false };
      const early = await send(
        'post',
        `${P}/${connection.publicId}/mail-flow/preview`,
        { change: activate },
        {},
      );
      expect(early.status).toBe(409);
      expect(early.body.code).toBe('validation_required');
      // Inbound applied + attestations + a passed full run → validate done; then a probe pass.
      world.destinations.set(world.links[0]!.domainId, [
        {
          host: 'x.mail.protection.outlook.com',
          port: 25,
          priority: 0,
          tlsMode: 'verify',
          provider: 'microsoft_365',
        },
      ]);
      for (const code of [
        'm365.inbound_connector_created',
        'm365.enhanced_filtering_enabled',
        'm365.direct_delivery_locked_down',
      ]) {
        const att = await send('post', `${P}/${connection.publicId}/attestations`, {
          code,
          attested: true,
        });
        expect(att.status, JSON.stringify(att.body)).toBe(200);
      }
      const run = await send('post', `${P}/${connection.publicId}/validations`, { kind: 'full' });
      expect(run.status).toBe(201);
      world.worker.completeRun(connection, 'passed');
      const noProbe = await send(
        'post',
        `${P}/${connection.publicId}/mail-flow/preview`,
        { change: activate },
        {},
      );
      expect(noProbe.body).toMatchObject({ code: 'validation_required' });
      world.worker.probePassed(connection);
      const done = await previewAndApply(connection.publicId, activate);
      expect(done.apply.status, JSON.stringify(done.apply.body)).toBe(200);
      expect(connection.outboundMode).toBe('active');
      // Suspend, then disable outbound (connector disabled, kept).
      expect((await previewAndApply(connection.publicId, { kind: 'suspend' })).apply.status).toBe(
        200,
      );
      expect(connection.outboundMode).toBe('suspended');
      expect(
        (await previewAndApply(connection.publicId, { kind: 'disable_outbound' })).apply.status,
      ).toBe(200);
      expect(world.connectors[0]!.status).toBe('disabled');
      expect(connection.outboundMode).toBe('off');
    });

    it('proof policy changes are bounded per provider (422 proof_policy_invalid)', async () => {
      const { connection } = boundM365();
      const bad = await send(
        'post',
        `${P}/${connection.publicId}/mail-flow/preview`,
        { change: { kind: 'proof', relayProof: { tenantHeader: 'off', dkimAligned: 'off' } } },
        {},
      );
      expect(bad.status).toBe(422);
      expect(bad.body.code).toBe('proof_policy_invalid');
    });

    it('GET mail-flow: the route token only with integration:manage (masked otherwise)', async () => {
      const { connection } = boundM365();
      const token = deriveRouteToken(api.config.PROVIDER_ROUTE_TOKEN_KEY, connection.publicId, 1);
      secrets.add(token);
      const full = await get(`${P}/${connection.publicId}/mail-flow`);
      expect(full.body.routeToken).toMatchObject({ version: 1, value: token });
      api.principals.user([READ]);
      const masked = await get(`${P}/${connection.publicId}/mail-flow`);
      expect(masked.status).toBe(200);
      expect(masked.body.routeToken.value).toBeNull();
      expect(masked.body.routeToken.masked).toMatch(/^•+/);
      expect(JSON.stringify(masked.body)).not.toContain(token);
      expect(
        (await get(`${P}/${boundM365({ orgId: OTHER_ORG }).connection.publicId}/mail-flow`)).status,
      ).toBe(404);
    });
  });

  describe('attestations, validations, health, guide (#18–#24)', () => {
    it('attestations: provider codes only; withdraw; audited', async () => {
      const { connection } = boundM365();
      const path = `${P}/${connection.publicId}/attestations`;
      const ok = await send('post', path, {
        code: 'm365.inbound_connector_created',
        attested: true,
      });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body.attestations).toEqual([
        expect.objectContaining({
          code: 'm365.inbound_connector_created',
          userId: api.principals.ids.user,
        }),
      ]);
      const google = await send('post', path, {
        code: 'google.inbound_gateway_configured',
        attested: true,
      });
      expect(google.status).toBe(422);
      expect(google.body.code).toBe('attestation_unknown');
      const withdrawn = await send('post', path, {
        code: 'm365.inbound_connector_created',
        attested: false,
      });
      expect(withdrawn.body.attestations).toEqual([]);
      expect(
        audit.entries.filter((e) => e.action === 'integration.attestation_recorded'),
      ).toHaveLength(2);
    });

    it('validations: probe address once (only its SHA-256 stored), list with cursor, detail, 10/hour per connection', async () => {
      const { connection } = boundM365();
      connection.outboundMode = 'probe_only';
      const path = `${P}/${connection.publicId}/validations`;
      const headers = key();
      const created = await send('post', path, { kind: 'full' }, headers);
      expect(created.status, JSON.stringify(created.body)).toBe(201);
      const probe = created.body.probeAddress as string;
      expect(probe).toMatch(
        new RegExp(
          `^eg-probe-[a-z2-7]{26}@${api.config.PROVIDER_PROBE_DOMAIN.replace(/\./g, '\\.')}$`,
        ),
      );
      secrets.add(probe.split('@')[0]!);
      const token = probe.slice('eg-probe-'.length, probe.indexOf('@'));
      expect(json(world.runs)).not.toContain(token);
      expect(world.runs[0]!.probeTokenSha256).toMatch(/^[0-9a-f]{64}$/);
      const replay = await send('post', path, { kind: 'full' }, headers);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body.probeAddress).toBeNull();
      const inbound = await send('post', path, { kind: 'inbound' });
      expect(inbound.body.probeAddress).toBeNull();
      world.worker.completeRun(connection, 'passed');

      const page = await get(`${path}?limit=1`);
      expect(page.status).toBe(200);
      expect(page.body.data[0].id).toBe(inbound.body.id);
      const next = await get(`${path}?limit=1&cursor=${encodeURIComponent(page.body.nextCursor)}`);
      expect(next.body.data[0].id).toBe(created.body.id);
      // A cursor of one connection is refused on another.
      const other = boundM365().connection;
      const cross = await get(
        `${P}/${other.publicId}/validations?limit=1&cursor=${encodeURIComponent(page.body.nextCursor)}`,
      );
      expect(cross.status).toBe(400);
      const detail = await get(`${path}/${inbound.body.id}`);
      expect(detail.status).toBe(200);
      expect(detail.body.results[0]).toMatchObject({ code: 'credentials.token', status: 'pass' });
      expect((await get(`${path}/${randomUUID()}`)).body.code).toBe('validation_run_not_found');
      expect((await get(`${P}/${other.publicId}/validations/${inbound.body.id}`)).status).toBe(404);

      // 3 requests so far (the replay counts too): 7 more reach the limit of 10 per hour.
      for (let i = 0; i < 7; i += 1) {
        expect((await send('post', path, { kind: 'credentials' })).status).toBe(201);
      }
      const limited = await send('post', path, { kind: 'credentials' });
      expect(limited.status).toBe(429);
      expect(limited.body.code).toBe('rate_limited');
      expect(limited.headers['retry-after']).toBeDefined();
      // Another connection has its own window.
      expect(
        (await send('post', `${P}/${other.publicId}/validations`, { kind: 'credentials' })).status,
      ).toBe(201);
    });

    it('health: latest checks and transitions; check now 202 (6/hour)', async () => {
      const { connection } = boundM365();
      world.healthChecks.push({
        organizationId: org,
        connectionId: connection.id,
        checkCode: 'dns.mx_gateway',
        subject: 'contoso.example',
        status: 'fail',
        severity: 'critical',
        evidence: { observed: ['contoso-example.mail.protection.outlook.com'] },
        firstFailedAt: new Date(),
        checkedAt: new Date(),
      });
      world.healthEvents.push({
        organizationId: org,
        connectionId: connection.id,
        fromStatus: 'healthy',
        toStatus: 'critical',
        failingChecks: ['dns.mx_gateway'],
        createdAt: new Date(),
      });
      const res = await get(`${P}/${connection.publicId}/health`);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.checks[0]).toMatchObject({ code: 'dns.mx_gateway', status: 'fail' });
      expect(res.body.transitions[0]).toMatchObject({
        from: 'healthy',
        to: 'critical',
        failingChecks: ['dns.mx_gateway'],
      });
      const path = `${P}/${connection.publicId}/health/check`;
      for (let i = 0; i < 6; i += 1) expect((await send('post', path)).status).toBe(202);
      expect((await send('post', path)).status).toBe(429);
      expect(
        audit.entries.filter((e) => e.action === 'integration.health_check_requested'),
      ).toHaveLength(6);
    });

    it('setup guide: JSON and Markdown download; route token masked without integration:manage; no secret-shaped text', async () => {
      const { connection } = boundM365();
      const token = deriveRouteToken(api.config.PROVIDER_ROUTE_TOKEN_KEY, connection.publicId, 1);
      const json = await get(`${P}/${connection.publicId}/setup-guide`);
      expect(json.status, JSON.stringify(json.body)).toBe(200);
      expect(json.body.schema).toBe('setup-guide/1');
      expect(JSON.stringify(json.body)).toContain(token);
      const md = await get(`${P}/${connection.publicId}/setup-guide?format=markdown`);
      expect(md.status).toBe(200);
      expect(md.headers['content-type']).toMatch(/^text\/markdown; charset=utf-8/);
      expect(md.headers['content-disposition']).toMatch(
        /^attachment; filename="setup-microsoft-365-.*\.md"$/,
      );
      expect(md.text).toContain('New-InboundConnector');
      api.principals.user([READ]);
      const masked = await get(`${P}/${connection.publicId}/setup-guide`);
      expect(JSON.stringify(masked.body)).not.toContain(token);
      for (const bad of ['whsec_', 'AKIA', 'ghp_', 'sk-', 'egk_', '-----BEGIN']) {
        expect(md.text).not.toContain(bad);
        expect(JSON.stringify(masked.body)).not.toContain(bad);
      }
      expect((await get(`${P}/${connection.publicId}/setup-guide?format=pdf`)).status).toBe(400);
    });
  });

  describe('disconnect (#6, D13)', () => {
    it('needs a disable preview token; revokes grants, disables the connector, keeps destinations', async () => {
      const { connection, domain } = boundM365();
      world.grants[0]!.credentialCiphertext = 'v1.k.iv.tag.ct';
      await previewAndApply(connection.publicId, { kind: 'inbound', domainIds: [domain.publicId] });
      await previewAndApply(connection.publicId, { kind: 'outbound', mode: 'probe_only' });
      const preview = await send(
        'post',
        `${P}/${connection.publicId}/mail-flow/preview`,
        { change: { kind: 'disable' } },
        {},
      );
      expect(preview.body.changeSet).toMatchObject({
        grantsRevoked: 1,
        connector: { action: 'disable' },
      });
      api.principals.user([READ, MANAGE, ROUTING], { mfaAuthenticated: true });
      expect(
        (
          await send('delete', `${P}/${connection.publicId}`, {
            impactToken: preview.body.impactToken,
            confirm: true,
          })
        ).status,
      ).toBe(403);
      api.principals.user(ALL, { mfaAuthenticated: true });
      const res = await send('delete', `${P}/${connection.publicId}`, {
        impactToken: preview.body.impactToken,
        confirm: true,
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({
        destinationsKept: true,
        connection: { status: 'disabled' },
      });
      expect(res.body.providerCleanupSteps.length).toBeGreaterThan(0);
      expect(world.grants[0]).toMatchObject({ status: 'revoked', credentialCiphertext: null });
      expect(world.connectors[0]!.status).toBe('disabled');
      expect(connection).toMatchObject({ activeTenantKey: null, outboundMode: 'off' });
      expect(world.destinations.get(domain.id)?.[0]?.provider).toBe('microsoft_365');
      expect(audit.entries.at(-1)!.action).toBe('integration.connection_disconnected');
      // Disabled connections refuse further changes.
      const after = await send('post', `${P}/${connection.publicId}/attestations`, {
        code: 'm365.inbound_connector_created',
        attested: true,
      });
      expect(after.body.code).toBe('connection_disabled');
    });
  });

  describe('audit-secret scan (D12, I5)', () => {
    it('no audit row of the suite contains a credential, consent state, probe token or route token', () => {
      const rows = [...auditSeen, ...audit.entries.map((e) => JSON.stringify(e))];
      expect(rows.length).toBeGreaterThan(20);
      const leaks = rows.filter((row) => [...secrets].some((secret) => row.includes(secret)));
      expect(leaks).toEqual([]);
      for (const row of rows) {
        expect(row).not.toContain('PRIVATE KEY');
        expect(row).not.toMatch(/eg-probe-[a-z2-7]{26}/);
      }
    });
  });

  it('the OpenAPI examples carry no secret-shaped value', () => {
    const text = JSON.stringify(PROVIDER_EXAMPLES);
    for (const bad of ['whsec_', 'AKIA', 'ghp_', 'sk-', 'egk_', '-----BEGIN']) {
      expect(text).not.toContain(bad);
    }
  });
});
