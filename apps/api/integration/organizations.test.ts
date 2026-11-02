/**
 * Organizations (§4.3, D12) against real MySQL (writer + replica) and Redis, in process: creation
 * with materialized settings/limits/features/deployment and an invited administrator, updates and
 * plan changes, suspension (sessions and API keys stop working), settings validation, feature and
 * limit overrides, usage counters, and the deletion workflow (four-eyes, legal hold, archives,
 * cancellation). Every mutation is checked for its audit row.
 */
import { randomBytes, randomInt } from 'node:crypto';
import { LIMIT_KEYS, PLANS } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateApiKey, TokenHasher } from '../src/crypto/tokens';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  uniqueSuffix,
} from './support/fixtures';
import {
  apiKeyHeader,
  bearer,
  login,
  loginWithMfa,
  type TokenResponseBody,
  uniqueIp,
} from './support/http';

let ctx: IntegrationApp;
let fx: Fixtures;
/** Two platform administrators with MFA sessions (four-eyes). */
let adminA: FixtureUser;
let adminB: FixtureUser;
let tokenA: string;
let tokenB: string;

const POLL = { timeout: 10_000, interval: 200 };
const DAY = 24 * 60 * 60 * 1000;
const standard = PLANS.find((p) => p.code === 'standard')!;
const enterprise = PLANS.find((p) => p.code === 'enterprise')!;

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  adminA = await fx.createPlatformUser(['platform_admin']);
  adminB = await fx.createPlatformUser(['platform_admin']);
  tokenA = (await loginWithMfa(ctx, fx, adminA)).accessToken;
  tokenB = (await loginWithMfa(ctx, fx, adminB)).accessToken;
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const asA = () => bearer(tokenA);
const asB = () => bearer(tokenB);
const orgPath = (org: { publicId: string } | string, suffix = '') =>
  `/api/v1/organizations/${typeof org === 'string' ? org : org.publicId}${suffix}`;

const auditRows = (action: string, resourceId: string) =>
  ctx.prisma.auditLog.findMany({ where: { action, resourceId }, orderBy: { id: 'asc' } });

const memberLogin = async (user: FixtureUser): Promise<TokenResponseBody> => {
  const res = await login(ctx, {
    email: user.email,
    password: user.password,
    organization: user.organization.slug,
  }).expect(200);
  return res.body as TokenResponseBody;
};

/** An API key row for the organization (the identity-admin endpoints are WP4's). */
async function createApiKey(org: FixtureOrganization, scopes: string[]): Promise<string> {
  const { key, prefix } = generateApiKey();
  await ctx.prisma.apiKey.create({
    data: {
      organizationId: org.id,
      name: `it-${prefix}`,
      keyPrefix: prefix,
      keyHash: ctx.get(TokenHasher).hmacHex(key),
      scopes,
      expiresAt: new Date(Date.now() + DAY),
    },
  });
  return key;
}

/** Response body of `POST /organizations` (created organization or error). */
type CreateBody = Record<string, unknown> & {
  id: string;
  deployments: unknown;
  initialAdmin: unknown;
  message: string[];
};

/** Creates an organization through the API and registers it for cleanup. */
async function createViaApi(
  body: Record<string, unknown>,
): Promise<{ status: number; body: CreateBody }> {
  const res = await ctx.http.post('/api/v1/organizations').set(asA()).send(body);
  if (res.status === 201) {
    const row = await ctx.prisma.organization.findUniqueOrThrow({
      where: { publicId: res.body.id as string },
      select: { id: true },
    });
    fx.trackOrganization(row.id);
  }
  return { status: res.status, body: res.body as CreateBody };
}

const newSlug = () => `it-org-${uniqueSuffix()}`;

describe('create', () => {
  it('materializes settings, limits, features and the deployment, and invites the admin', async () => {
    const slug = newSlug();
    const adminEmail = `owner-${uniqueSuffix()}@example.test`;
    const res = await createViaApi({
      name: 'Acme Integration',
      slug,
      planCode: 'standard',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
      settings: { timezone: 'Asia/Kolkata', locale: 'en-IN', digestSchedule: '30 7 * * 1-5' },
      initialAdmin: { email: adminEmail.toUpperCase(), displayName: 'Acme Owner' },
    });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      slug,
      name: 'Acme Integration',
      kind: 'customer',
      status: 'active',
      plan: { code: 'standard', name: standard.name },
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
      deployments: [
        {
          deploymentMode: 'saas',
          region: 'ap-south-1',
          environment: ctx.config.APP_ENV,
          status: 'active',
        },
      ],
      deletion: null,
      initialAdmin: { email: adminEmail, status: 'invited', invitationSent: true },
    });
    expect(JSON.stringify(res.body)).not.toMatch(/"(planId|organizationId)"/);

    const org = await ctx.prisma.organization.findUniqueOrThrow({
      where: { publicId: res.body.id },
      include: { settings: true, limits: true, features: true, deployments: true },
    });
    expect(org.settings).toMatchObject({
      timezone: 'Asia/Kolkata',
      locale: 'en-IN',
      digestSchedule: '30 7 * * 1-5',
      mfaRequired: false,
      // Platform default (30) within the plan limit (standard: 30).
      quarantineRetentionDays: Math.min(30, standard.limits.quarantine_retention_days),
    });
    expect(org.limits).toHaveLength(LIMIT_KEYS.length);
    for (const limit of org.limits) {
      expect(limit.source).toBe('plan');
      expect(limit.limitValue).toBe(
        BigInt(standard.limits[limit.limitKey as keyof typeof standard.limits]),
      );
    }
    expect(org.features.every((f) => f.source === 'plan')).toBe(true);
    expect(org.features.find((f) => f.featureKey === 'api_access')?.enabled).toBe(true);
    expect(org.features.find((f) => f.featureKey === 'sso')?.enabled).toBe(false);

    const invited = await ctx.prisma.user.findFirstOrThrow({
      where: { organizationId: org.id, email: adminEmail },
      include: { userRoles: { include: { role: true } } },
    });
    expect(invited.status).toBe('invited');
    expect(invited.passwordHash).toBeNull();
    expect(invited.userRoles.map((r) => r.role.key)).toEqual(['organization_admin']);
    expect(
      await ctx.prisma.userToken.count({
        where: { userId: invited.id, purpose: 'invitation', consumedAt: null },
      }),
    ).toBe(1);
    const email = ctx.emails.sent.find((m) => m.to === adminEmail);
    expect(email?.kind).toBe('invitation');
    expect(email?.devLink ?? email?.text).toContain('/auth/accept-invitation#token=egt_');

    const created = await auditRows('organization.created', org.publicId);
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({
      organizationId: org.id,
      actorType: 'user',
      actorId: adminA.publicId,
    });
    expect(created[0]!.metadata).toMatchObject({ slug, planCode: 'standard' });
    expect(await auditRows('user.invited', invited.publicId)).toHaveLength(1);
  });

  it('records a dedicated deployment as provisioning with the given region', async () => {
    const res = await createViaApi({
      name: 'Dedicated Co',
      slug: newSlug(),
      planCode: 'dedicated',
      deploymentMode: 'dedicated',
      dataRegion: 'eu-west-1',
      deployment: { region: 'eu-central-1', environment: 'prod-eu' },
    });
    expect(res.status).toBe(201);
    expect(res.body.deployments).toEqual([
      expect.objectContaining({
        deploymentMode: 'dedicated',
        region: 'eu-central-1',
        environment: 'prod-eu',
        status: 'provisioning',
        provisionedAt: null,
      }),
    ]);
    expect(res.body.initialAdmin).toBeNull();
  });

  it('caps the default quarantine retention by the plan and rejects larger values', async () => {
    const trial = PLANS.find((p) => p.code === 'trial')!;
    const ok = await createViaApi({
      name: 'Trial Co',
      slug: newSlug(),
      planCode: 'trial',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
    });
    expect(ok.status).toBe(201);
    const settings = await ctx.http.get(orgPath(ok.body.id, '/settings')).set(asA());
    expect(settings.body).toMatchObject({
      quarantineRetentionDays: trial.limits.quarantine_retention_days,
      quarantineRetentionMaxDays: trial.limits.quarantine_retention_days,
    });

    const tooLong = await createViaApi({
      name: 'Trial Co 2',
      slug: newSlug(),
      planCode: 'trial',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
      settings: { quarantineRetentionDays: trial.limits.quarantine_retention_days + 1 },
    });
    expect(tooLong.status).toBe(400);
    expect(tooLong.body.message).toEqual([
      `settings.quarantineRetentionDays: must be at most ${trial.limits.quarantine_retention_days}`,
    ]);
  });

  it('answers 409 for a duplicate slug and 400 for an unknown plan', async () => {
    const existing = await fx.createOrganization();
    const dup = await createViaApi({
      name: 'Dup',
      slug: existing.slug,
      planCode: 'standard',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
    });
    expect(dup.status).toBe(409);
    const unknown = await createViaApi({
      name: 'Unknown plan',
      slug: newSlug(),
      planCode: 'platinum',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
    });
    expect(unknown.status).toBe(400);
    expect(unknown.body.message).toEqual(['planCode: unknown or inactive plan']);
  });
});

describe('read and update', () => {
  it('lists with filters on the reader and pages with a cursor', async () => {
    const one = await fx.createOrganization();
    const two = await fx.createOrganization({ planCode: 'enterprise' });
    // Every fixture slug starts with "it-", so this query has at least two matches.
    const prefix = 'it-';
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get(`/api/v1/organizations?q=${two.slug}&planCode=enterprise`)
          .set(asA());
        return (res.body.data as Array<{ id: string }>).map((o) => o.id);
      }, POLL)
      .toEqual([two.publicId]);

    await expect
      .poll(async () => {
        const res = await ctx.http.get(`/api/v1/organizations?q=${one.slug}`).set(asA());
        return (res.body.data as unknown[]).length;
      }, POLL)
      .toBe(1);
    const page1 = await ctx.http.get(`/api/v1/organizations?q=${prefix}&limit=1`).set(asA());
    expect(page1.status).toBe(200);
    expect(page1.body.data).toHaveLength(1);
    expect(page1.body.nextCursor).toEqual(expect.any(String));
    const page2 = await ctx.http
      .get(`/api/v1/organizations?q=${prefix}&limit=1&cursor=${page1.body.nextCursor}`)
      .set(asA());
    expect(page2.body.data[0].id).not.toBe(page1.body.data[0].id);
    await ctx.http.get('/api/v1/organizations?cursor=!!!').set(asA()).expect(400);
  });

  it('lets a member rename its organization but not change the plan', async () => {
    const org = await fx.createOrganization();
    const admin = await fx.createUser(org, { roles: ['organization_admin'] });
    const { accessToken } = await memberLogin(admin);
    const res = await ctx.http
      .put(orgPath(org))
      .set(bearer(accessToken))
      .send({ name: 'Renamed by member' })
      .expect(200);
    expect(res.body.name).toBe('Renamed by member');
    const audit = await auditRows('organization.updated', org.publicId);
    expect(audit[0]?.metadata).toMatchObject({
      changedFields: ['name'],
      changes: { name: { to: 'Renamed by member' } },
    });
    await ctx.http
      .put(orgPath(org))
      .set(bearer(accessToken))
      .send({ name: 'x', planCode: 'enterprise' })
      .expect(403);
    await ctx.http
      .put(orgPath(org))
      .set(bearer(accessToken))
      .send({ name: 'x', slug: 'new-slug' })
      .expect(400);
  });

  it('re-materializes plan limits and features on a plan change and keeps overrides', async () => {
    const org = await fx.createOrganization({ planCode: 'standard' });
    await ctx.http.put(orgPath(org, '/limits/max_users')).set(asA()).send({ value: 7 }).expect(200);
    await ctx.http
      .put(orgPath(org, '/features/webhooks'))
      .set(asA())
      .send({ enabled: false, config: { reason: 'contract' } })
      .expect(200);

    const res = await ctx.http
      .put(orgPath(org))
      .set(asA())
      .send({ name: org.name, planCode: 'enterprise' })
      .expect(200);
    expect(res.body.plan).toEqual({ code: 'enterprise', name: enterprise.name });

    const limits = (await ctx.http.get(orgPath(org, '/limits')).set(asA()).expect(200)).body
      .data as Array<{ key: string; value: number; source: string }>;
    expect(limits.find((l) => l.key === 'max_users')).toMatchObject({
      value: 7,
      source: 'override',
    });
    expect(limits.find((l) => l.key === 'max_domains')).toMatchObject({
      value: enterprise.limits.max_domains,
      source: 'plan',
    });
    const features = (await ctx.http.get(orgPath(org, '/features')).set(asA()).expect(200)).body
      .data as Array<{ key: string; enabled: boolean; source: string; config: unknown }>;
    expect(features.find((f) => f.key === 'webhooks')).toMatchObject({
      enabled: false,
      source: 'override',
      config: { reason: 'contract' },
    });
    expect(features.find((f) => f.key === 'sso')).toMatchObject({ enabled: true, source: 'plan' });

    const audit = await auditRows('organization.updated', org.publicId);
    expect(audit.at(-1)?.metadata).toMatchObject({
      changes: { planCode: { from: 'standard', to: 'enterprise' } },
    });
  });
});

describe('status', () => {
  it('suspension stops member sessions and API keys; reactivation restores API access', async () => {
    const org = await fx.createOrganization();
    const member = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = await memberLogin(member);
    const key = await createApiKey(org, ['organization:read']);
    await ctx.http.get(orgPath(org)).set(bearer(session.accessToken)).expect(200);
    await ctx.http.get(orgPath(org)).set(apiKeyHeader(key)).expect(200);

    await ctx.http
      .patch(orgPath(org, '/status'))
      .set(asA())
      .send({ status: 'suspended' })
      .expect(400);
    const suspended = await ctx.http
      .patch(orgPath(org, '/status'))
      .set(asA())
      .send({ status: 'suspended', reason: 'Unpaid invoices' })
      .expect(200);
    expect(suspended.body).toMatchObject({ status: 'suspended', statusReason: 'Unpaid invoices' });

    await ctx.http.get(orgPath(org)).set(bearer(session.accessToken)).expect(401);
    await ctx.http.get(orgPath(org)).set(apiKeyHeader(key)).expect(401);
    await ctx.http
      .post('/api/v1/auth/refresh')
      .set('X-Forwarded-For', uniqueIp())
      .send({ refreshToken: session.refreshToken })
      .expect(401);
    expect(
      await ctx.prisma.userSession.count({
        where: { userId: member.id, revokedAt: null },
      }),
    ).toBe(0);
    await login(ctx, {
      email: member.email,
      password: member.password,
      organization: org.slug,
    }).expect(401);
    await ctx.http
      .patch(orgPath(org, '/status'))
      .set(asA())
      .send({ status: 'suspended', reason: 'Again' })
      .expect(409);

    await ctx.http.patch(orgPath(org, '/status')).set(asA()).send({ status: 'active' }).expect(200);
    await ctx.http.get(orgPath(org)).set(apiKeyHeader(key)).expect(200);
    const again = await memberLogin(member);
    await ctx.http.get(orgPath(org)).set(bearer(again.accessToken)).expect(200);

    const audit = await auditRows('organization.status_changed', org.publicId);
    expect(audit.map((r) => r.metadata)).toEqual([
      { from: 'active', to: 'suspended', reason: 'Unpaid invoices' },
      { from: 'suspended', to: 'active', reason: null },
    ]);
  });

  it('never suspends the platform organization', async () => {
    const platform = await fx.platformOrg();
    const res = await ctx.http
      .patch(orgPath(platform, '/status'))
      .set(asA())
      .send({ status: 'suspended', reason: 'Should not work' })
      .expect(409);
    expect(res.body.message).toBe('The platform organization cannot be suspended');
  });
});

describe('settings', () => {
  it('validates and updates settings; member managers may change their own', async () => {
    const org = await fx.createOrganization();
    const admin = await fx.createUser(org, { roles: ['organization_admin'] });
    const { accessToken } = await memberLogin(admin);
    const auth = bearer(accessToken);

    const before = await ctx.http.get(orgPath(org, '/settings')).set(auth).expect(200);
    expect(before.body).toMatchObject({ timezone: 'UTC', quarantineRetentionMaxDays: 30 });

    const updated = await ctx.http
      .put(orgPath(org, '/settings'))
      .set(auth)
      .send({
        timezone: 'Europe/Berlin',
        quarantineRetentionDays: 30,
        digestSchedule: '0 9 * * MON',
        notificationEmail: 'SOC@Example.Test',
        preferences: { theme: 'dark' },
      })
      .expect(200);
    expect(updated.body).toMatchObject({
      timezone: 'Europe/Berlin',
      quarantineRetentionDays: 30,
      digestSchedule: '0 9 * * MON',
      notificationEmail: 'soc@example.test',
      preferences: { theme: 'dark' },
    });
    const audit = await auditRows('organization.settings_updated', org.publicId);
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toEqual({
      changedFields: ['timezone', 'digestSchedule', 'notificationEmail', 'preferences'],
    });
    expect(JSON.stringify(audit[0]!.metadata)).not.toContain('soc@example.test');

    const tooLong = await ctx.http
      .put(orgPath(org, '/settings'))
      .set(auth)
      .send({ quarantineRetentionDays: 31 })
      .expect(400);
    expect(tooLong.body.message).toEqual(['quarantineRetentionDays: must be at most 30']);
    await ctx.http
      .put(orgPath(org, '/settings'))
      .set(auth)
      .send({ timezone: 'Mars/Olympus' })
      .expect(400);
    await ctx.http
      .put(orgPath(org, '/settings'))
      .set(auth)
      .send({ preferences: { blob: 'x'.repeat(17_000) } })
      .expect(400);

    // A platform override of the limit raises the bound (still capped by the platform maximum).
    await ctx.http
      .put(orgPath(org, '/limits/quarantine_retention_days'))
      .set(asA())
      .send({ value: 365 })
      .expect(200);
    const platformMax = await ctx.prisma.systemSetting.findUnique({
      where: { key: 'quarantine.max_retention_days' },
    });
    const max = typeof platformMax?.value === 'number' ? platformMax.value : 365;
    await ctx.http
      .put(orgPath(org, '/settings'))
      .set(auth)
      .send({ quarantineRetentionDays: max })
      .expect(200);
    await ctx.http
      .put(orgPath(org, '/settings'))
      .set(auth)
      .send({ quarantineRetentionDays: max + 1 })
      .expect(400);
  });

  it('applies mfaRequired to existing sessions immediately', async () => {
    const org = await fx.createOrganization();
    const member = await fx.createUser(org, { roles: ['read_only_user'] });
    const { accessToken } = await memberLogin(member);
    await ctx.http.get(orgPath(org)).set(bearer(accessToken)).expect(200);
    await ctx.http
      .put(orgPath(org, '/settings'))
      .set(asA())
      .send({ mfaRequired: true })
      .expect(200);
    const res = await ctx.http.get(orgPath(org)).set(bearer(accessToken)).expect(403);
    expect(res.body.message).toBe('MFA enrollment required');
    const audit = await auditRows('organization.settings_updated', org.publicId);
    expect(audit.at(-1)?.metadata).toEqual({ changedFields: ['mfaRequired'], mfaRequired: true });
  });

  it('keeps MFA mandatory for the platform organization', async () => {
    const platform = await fx.platformOrg();
    const res = await ctx.http
      .put(orgPath(platform, '/settings'))
      .set(asA())
      .send({ mfaRequired: false })
      .expect(409);
    expect(res.body.message).toBe('MFA is mandatory for the platform organization');
  });
});

describe('features and limits', () => {
  it('overrides and resets features; api_access applies to API keys immediately', async () => {
    const org = await fx.createOrganization();
    const key = await createApiKey(org, ['organization:read']);
    await ctx.http.get(orgPath(org, '/features')).set(apiKeyHeader(key)).expect(200);

    const off = await ctx.http
      .put(orgPath(org, '/features/api_access'))
      .set(asA())
      .send({ enabled: false })
      .expect(200);
    expect(off.body).toMatchObject({ key: 'api_access', enabled: false, source: 'override' });
    await ctx.http.get(orgPath(org, '/features')).set(apiKeyHeader(key)).expect(401);

    await ctx.http.delete(orgPath(org, '/features/api_access')).set(asA()).expect(204);
    const features = await ctx.http
      .get(orgPath(org, '/features'))
      .set(apiKeyHeader(key))
      .expect(200);
    expect(
      (features.body.data as Array<{ key: string }>).find((f) => f.key === 'api_access'),
    ).toMatchObject({ enabled: true, source: 'plan', config: null });

    expect(
      (await auditRows('organization.feature_overridden', org.publicId))[0]?.metadata,
    ).toMatchObject({
      featureKey: 'api_access',
      enabled: false,
      previous: { enabled: true, source: 'plan' },
    });
    expect(
      (await auditRows('organization.feature_reset', org.publicId))[0]?.metadata,
    ).toMatchObject({
      featureKey: 'api_access',
      enabled: true,
    });
  });

  it('overrides and resets limits', async () => {
    const org = await fx.createOrganization();
    const res = await ctx.http
      .put(orgPath(org, '/limits/max_users'))
      .set(asA())
      .send({ value: 3 })
      .expect(200);
    expect(res.body).toMatchObject({ key: 'max_users', value: 3, source: 'override' });
    await ctx.http.delete(orgPath(org, '/limits/max_users')).set(asA()).expect(204);
    const row = await ctx.prisma.organizationLimit.findUniqueOrThrow({
      where: { organizationId_limitKey: { organizationId: org.id, limitKey: 'max_users' } },
    });
    expect(row).toMatchObject({ limitValue: BigInt(standard.limits.max_users), source: 'plan' });
    expect(await auditRows('organization.limit_overridden', org.publicId)).toHaveLength(1);
    expect((await auditRows('organization.limit_reset', org.publicId))[0]?.metadata).toMatchObject({
      limitKey: 'max_users',
      value: String(standard.limits.max_users),
    });
  });
});

describe('usage', () => {
  it('counts users, domains, messages, quarantine, API keys and sessions', async () => {
    const org = await fx.createOrganization();
    const active = await fx.createUser(org, { roles: ['organization_admin'] });
    await fx.createUser(org, { roles: ['read_only_user'], status: 'invited' });
    await fx.createUser(org, { roles: ['read_only_user'], status: 'disabled' });
    await memberLogin(active);
    await createApiKey(org, ['organization:read']);

    fx.registerCleanup(async () => {
      await ctx.prisma.quarantineMessage.deleteMany({ where: { organizationId: org.id } });
      await ctx.prisma.emailMessage.deleteMany({ where: { organizationId: org.id } });
      await ctx.prisma.domain.deleteMany({ where: { organizationId: org.id } });
    });
    await ctx.prisma.domain.createMany({
      data: [
        { organizationId: org.id, name: `a-${uniqueSuffix()}.test`, status: 'verified' },
        { organizationId: org.id, name: `b-${uniqueSuffix()}.test` },
      ],
    });
    const now = new Date();
    const message = (direction: 'inbound' | 'outbound' | 'internal', receivedAt: Date) => ({
      id: BigInt(Date.now()) * 1000n + BigInt(randomInt(0, 1000)),
      receivedAt,
      organizationId: org.id,
      direction,
      statusChangedAt: receivedAt,
      envelopeFrom: 'sender@example.test',
      sizeBytes: 1024,
      recipientCount: 1,
      emlObjectKey: `it/${randomBytes(8).toString('hex')}.eml`,
      emlSha256: randomBytes(32).toString('hex'),
    });
    const yesterday = new Date(now.getTime() - DAY);
    const rows = [
      message('inbound', now),
      message('inbound', yesterday),
      message('outbound', yesterday),
      message('internal', yesterday),
    ];
    for (const row of rows) await ctx.prisma.emailMessage.create({ data: row });
    await ctx.prisma.quarantineMessage.create({
      data: {
        organizationId: org.id,
        messageId: rows[1]!.id,
        messageReceivedAt: yesterday,
        recipientId: 1n,
        recipientAddress: 'user@example.test',
        reason: 'spam',
        envelopeFrom: 'sender@example.test',
        emlObjectKey: rows[1]!.emlObjectKey,
        quarantinedAt: yesterday,
        expiresAt: new Date(now.getTime() + 10 * DAY),
      },
    });

    type Usage = {
      users: Record<string, number>;
      domains: Record<string, number>;
      messages: Record<string, number>;
      quarantine: { active: number };
      apiKeys: { active: number };
      sessions: { active: number };
      limits: Array<{ key: string; value: number; source: string; used: number | null }>;
    };
    let usage: Usage | undefined;
    await expect
      .poll(async () => {
        const res = await ctx.http.get(orgPath(org, '/usage')).set(asA());
        usage = res.body as Usage;
        return res.status === 200 ? usage.messages.total : -1;
      }, POLL)
      .toBe(4);
    expect(usage).toMatchObject({
      users: { total: 3, active: 1, invited: 1, disabled: 1, locked: 0 },
      domains: { total: 2, verified: 1, pendingVerification: 1 },
      messages: { total: 4, inbound: 2, outbound: 1, internal: 1 },
      quarantine: { active: 1 },
      apiKeys: { active: 1 },
      sessions: { active: 1 },
    });
    // A UTC-midnight boundary between the inserts and the query can only lower "today".
    expect(usage!.messages.today).toBeGreaterThanOrEqual(0);
    expect(usage!.messages.today).toBeLessThanOrEqual(1);
    expect(usage!.limits.find((l) => l.key === 'max_users')).toMatchObject({
      value: standard.limits.max_users,
      used: 3,
    });
    expect(usage!.limits.find((l) => l.key === 'max_domains')).toMatchObject({ used: 2 });
    expect(usage!.limits.find((l) => l.key === 'messages_per_day')?.used).toBe(
      usage!.messages.today,
    );
    expect(usage!.limits.find((l) => l.key === 'max_message_size_bytes')?.used).toBeNull();

    // A period ending before yesterday's messages sees none of them.
    const from = new Date(now.getTime() - 10 * DAY).toISOString();
    const to = new Date(now.getTime() - 2 * DAY).toISOString();
    const early = await ctx.http
      .get(orgPath(org, `/usage?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`))
      .set(asA())
      .expect(200);
    expect(early.body.messages).toMatchObject({ total: 0, inbound: 0 });
    expect(early.body.period).toEqual({ from, to });

    const tooLong = new Date(now.getTime() - 40 * DAY).toISOString();
    await ctx.http
      .get(orgPath(org, `/usage?from=${encodeURIComponent(tooLong)}`))
      .set(asA())
      .expect(400);
    await ctx.http
      .get(orgPath(org, `/usage?from=${encodeURIComponent(to)}&to=${encodeURIComponent(from)}`))
      .set(asA())
      .expect(400);
  });
});

describe('deletion workflow', () => {
  const reason = 'Customer offboarded per contract';

  async function suspendedOrg(): Promise<{
    org: FixtureOrganization;
    key: string;
    member: FixtureUser;
  }> {
    const org = await fx.createOrganization();
    const member = await fx.createUser(org, { roles: ['read_only_user'] });
    const key = await createApiKey(org, ['organization:read']);
    await ctx.http
      .patch(orgPath(org, '/status'))
      .set(asA())
      .send({ status: 'suspended', reason: 'Offboarding' })
      .expect(200);
    return { org, key, member };
  }

  it('request → four-eyes confirm → cancel within the purge window', async () => {
    const { org, key } = await suspendedOrg();
    fx.registerCleanup(() =>
      ctx.prisma.emailArchive.deleteMany({ where: { organizationId: org.id } }),
    );
    const retainUntil = new Date(Date.now() + 400 * DAY);
    await ctx.prisma.emailArchive.create({
      data: {
        receivedAt: new Date(),
        messageId: BigInt(Date.now()) * 1000n + BigInt(randomInt(0, 1000)),
        organizationId: org.id,
        archiveObjectKey: `it/${randomBytes(8).toString('hex')}.eml`,
        sha256: randomBytes(32).toString('hex'),
        sizeBytes: 2048,
        retainUntil,
        archivedAt: new Date(),
      },
    });

    await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: 'not-the-slug' })
      .expect(400);
    const requested = await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: org.slug })
      .expect(200);
    expect(requested.body).toMatchObject({
      state: 'pending_deletion',
      status: 'pending_deletion',
      requestedBy: adminA.publicId,
      reason,
      cancellable: true,
      confirmedAt: null,
    });
    // Frozen while pending.
    await ctx.http.put(orgPath(org)).set(asA()).send({ name: 'Nope' }).expect(409);
    await ctx.http.patch(orgPath(org, '/status')).set(asA()).send({ status: 'active' }).expect(409);

    // Four eyes: the requester cannot confirm.
    await ctx.http
      .post(orgPath(org, '/deletion/confirm'))
      .set(asA())
      .send({ confirmSlug: org.slug })
      .expect(403);
    const confirmed = await ctx.http
      .post(orgPath(org, '/deletion/confirm'))
      .set(asB())
      .send({ confirmSlug: org.slug })
      .expect(200);
    expect(confirmed.body).toMatchObject({
      state: 'deleted',
      requestedBy: adminA.publicId,
      confirmedBy: adminB.publicId,
      cancellable: true,
      // The latest archive outlives the retention period, so the purge waits for it.
      purgeAfter: retainUntil.toISOString(),
    });
    const row = await ctx.prisma.organization.findUniqueOrThrow({ where: { id: org.id } });
    expect(row.deletedAt).not.toBeNull();
    expect(
      await ctx.prisma.apiKey.count({ where: { organizationId: org.id, revokedAt: null } }),
    ).toBe(0);
    await ctx.http.get(orgPath(org)).set(apiKeyHeader(key)).expect(401);

    // Deleted organizations appear only when asked for.
    await expect
      .poll(async () => {
        const res = await ctx.http.get(`/api/v1/organizations?q=${org.slug}`).set(asA());
        return (res.body.data as unknown[]).length;
      }, POLL)
      .toBe(0);
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get(`/api/v1/organizations?q=${org.slug}&status=deleted`)
          .set(asA());
        return (res.body.data as Array<{ id: string }>).map((o) => o.id);
      }, POLL)
      .toEqual([org.publicId]);

    const state = await ctx.http.get(orgPath(org, '/deletion')).set(asB()).expect(200);
    expect(state.body).toMatchObject({ state: 'deleted', confirmedBy: adminB.publicId });

    const cancelled = await ctx.http
      .post(orgPath(org, '/deletion/cancel'))
      .set(asB())
      .send({ reason: 'Customer renewed the contract' })
      .expect(200);
    expect(cancelled.body).toMatchObject({
      state: 'none',
      status: 'suspended',
      requestedAt: null,
      purgeAfter: null,
      cancellable: false,
    });
    const restored = await ctx.prisma.organization.findUniqueOrThrow({ where: { id: org.id } });
    expect(restored).toMatchObject({
      status: 'suspended',
      deletedAt: null,
      deletionRequestedAt: null,
      deletionRequestedByUserId: null,
      deletionConfirmedAt: null,
      purgeAfter: null,
      statusBeforeDeletion: null,
    });
    await ctx.http
      .post(orgPath(org, '/deletion/cancel'))
      .set(asB())
      .send({ reason: 'Nothing left to cancel' })
      .expect(409);

    expect(await auditRows('organization.deletion_requested', org.publicId)).toHaveLength(1);
    expect(
      (await auditRows('organization.deletion_confirmed', org.publicId))[0]?.metadata,
    ).toMatchObject({ purgeAfter: retainUntil.toISOString(), apiKeysRevoked: 1 });
    expect(
      (await auditRows('organization.deletion_cancelled', org.publicId))[0]?.metadata,
    ).toMatchObject({
      reason: 'Customer renewed the contract',
      fromStatus: 'deleted',
      requestedBy: adminA.publicId,
      confirmedBy: adminB.publicId,
    });
  });

  it('uses the retention period without archives and refuses cancellation after purge_after', async () => {
    const { org } = await suspendedOrg();
    await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: org.slug })
      .expect(200);
    const before = Date.now();
    const confirmed = await ctx.http
      .post(orgPath(org, '/deletion/confirm'))
      .set(asB())
      .send({ confirmSlug: org.slug })
      .expect(200);
    const purgeAfter = new Date(confirmed.body.purgeAfter as string).getTime();
    const retention = ctx.config.ORG_DELETION_RETENTION_DAYS * DAY;
    expect(purgeAfter).toBeGreaterThanOrEqual(before + retention - 1000);
    expect(purgeAfter).toBeLessThanOrEqual(Date.now() + retention + 1000);

    await ctx.prisma.organization.update({
      where: { id: org.id },
      data: { purgeAfter: new Date(Date.now() - 1000) },
    });
    const res = await ctx.http
      .post(orgPath(org, '/deletion/cancel'))
      .set(asA())
      .send({ reason: 'Too late to cancel this' })
      .expect(409);
    expect(res.body.message).toMatch(/purge time/);
  });

  it('is blocked by an active legal hold and needs a suspended organization', async () => {
    const active = await fx.createOrganization();
    await ctx.http
      .post(orgPath(active, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: active.slug })
      .expect(409);

    const { org } = await suspendedOrg();
    const hold = await ctx.prisma.archiveLegalHold.create({
      data: {
        organizationId: org.id,
        name: 'Litigation 42',
        reason: 'Pending litigation',
        criteria: { all: true },
      },
    });
    const blocked = await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: org.slug })
      .expect(409);
    expect(blocked.body.message).toBe('Active legal hold');

    // A hold placed after the request blocks the confirmation too.
    await ctx.prisma.archiveLegalHold.update({
      where: { id: hold.id },
      data: { status: 'released', releasedAt: new Date() },
    });
    await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: org.slug })
      .expect(200);
    await ctx.prisma.archiveLegalHold.update({
      where: { id: hold.id },
      data: { status: 'active', releasedAt: null },
    });
    const confirmBlocked = await ctx.http
      .post(orgPath(org, '/deletion/confirm'))
      .set(asB())
      .send({ confirmSlug: org.slug })
      .expect(409);
    expect(confirmBlocked.body.message).toBe('Active legal hold');
  });

  it('expires an unconfirmed request after the confirmation window', async () => {
    const { org } = await suspendedOrg();
    await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: org.slug })
      .expect(200);
    const windowMs = ctx.config.ORG_DELETION_CONFIRM_WINDOW_HOURS * 60 * 60 * 1000;
    await ctx.prisma.organization.update({
      where: { id: org.id },
      data: { deletionRequestedAt: new Date(Date.now() - windowMs - 60_000) },
    });
    const res = await ctx.http
      .post(orgPath(org, '/deletion/confirm'))
      .set(asB())
      .send({ confirmSlug: org.slug })
      .expect(409);
    expect(res.body.message).toMatch(/confirmation window/);
    // Cancel and request again.
    await ctx.http
      .post(orgPath(org, '/deletion/cancel'))
      .set(asA())
      .send({ reason: 'Window elapsed, restarting' })
      .expect(200);
    await ctx.http
      .post(orgPath(org, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: org.slug })
      .expect(200);
  });

  it('never deletes the platform organization', async () => {
    const platform = await fx.platformOrg();
    await ctx.http
      .post(orgPath(platform, '/deletion'))
      .set(asA())
      .send({ reason, confirmSlug: platform.slug })
      .expect(409);
  });
});
