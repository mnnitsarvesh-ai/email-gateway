/**
 * Cross-tenant isolation of the pre-6.1 tenant-scoped routes that had no dedicated tenant
 * isolation suite (step 6.1 WP4, docs/plan/steps/18-rest-api.md §3.8, §9): departments and
 * members, policies and policy versions, policy settings, risk profile versions and the profile
 * view, scan settings, BEC executives / vendors / trusted senders, DLP policies / rules /
 * exceptions / patterns / dictionaries / compliance, quarantine settings and the message-scoped
 * policy, risk, BEC and DLP routes. Against the real writer and replica, Redis and the real
 * services.
 *
 * Tenant A's organization administrator (every tenant permission, MFA session) and an A API
 * key get `404` for every id of tenant B (and B's message), A's lists never contain B's rows,
 * A's singleton settings are A's own (B's change is invisible to A), and B's rows are unchanged
 * afterwards. (Users, sessions, roles, API keys, login events: tenant-isolation-identity;
 * domains: -domains; connectors and recipients: -smtp; destinations and deliveries: -routing;
 * organizations: -organizations; messages: -messages.)
 */
import { randomUUID } from 'node:crypto';
import type { Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { BecTenantDataRepository } from '../src/modules/tenant-data/bec-tenant-data.repository';
import { DlpTenantDataRepository } from '../src/modules/tenant-data/dlp-tenant-data.repository';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import { QuarantineTenantDataRepository } from '../src/modules/tenant-data/quarantine-tenant-data.repository';
import { RiskTenantDataRepository } from '../src/modules/tenant-data/risk-tenant-data.repository';
import { tagAllDefinition } from '../test/support/policy-fixtures';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, idem, loginWithMfa, uniqueIp } from './support/http';
import { insertLifecycleMessage, type LifecycleMessage } from './support/lifecycle';
import {
  deleteQuarantineFixtures,
  type FixtureEntry,
  insertApproval,
  insertEntry,
  windowAround,
} from './support/quarantine';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let userA: FixtureUser;
let adminA: Record<string, string>;
let keyA: Record<string, string>;
let adminB: Record<string, string>;
let messageB: LifecycleMessage;
let heldB: LifecycleMessage;
let entryB: FixtureEntry;
let policyRowVersionB: number;
let approvalB: { id: bigint; publicId: string };

/** Ids of tenant B's rows, created through the API by B's administrator. */
const b = {} as {
  department: string;
  member: string;
  policy: string;
  riskVersion: string;
  executive: string;
  vendor: string;
  trustedSender: string;
  dlpPolicy: string;
  dlpRule: string;
  dlpException: string;
  dlpPattern: string;
  dlpDictionary: string;
};

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const asB = (req: Test) => req.set(headers(adminB));

/** The read and write permissions an API key of A may hold for these routes (all tenant ones). */
const KEY_SCOPES = [
  'user:read',
  'user:manage',
  'policy:read',
  'policy:manage',
  'policy:publish',
  'bec:read',
  'bec:manage',
  'dlp:read',
  'dlp:manage',
  'quarantine:read',
  'quarantine:preview',
  'quarantine:release',
  'quarantine:request_release',
  'quarantine:reject',
  'quarantine:delete',
  'settings:manage',
  'scan:settings_manage',
  'message:read',
];

const dataOf = (body: { data?: Array<{ id: string }>; items?: Array<{ id: string }> }) =>
  (body.data ?? body.items ?? []).map((row) => row.id);

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(async () => {
    const ids = [orgA.id, orgB.id];
    for (const id of ids) {
      const scope = systemScope(id);
      await ctx.get(PolicyTenantDataRepository).purgeOrganization(scope);
      await ctx.get(RiskTenantDataRepository).purgeOrganization(scope);
      await ctx.get(BecTenantDataRepository).purgeOrganization(scope);
      await ctx.get(DlpTenantDataRepository).purgeOrganization(scope);
      await ctx.get(QuarantineTenantDataRepository).purgeOrganization(scope);
    }
    await ctx.prisma.scanEngineSetting.deleteMany({ where: { organizationId: { in: ids } } });
    // Quarantine rows, then the messages and their scan rows.
    await deleteQuarantineFixtures(ctx, ids);
  });
  userA = await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true });
  adminA = bearer((await loginWithMfa(ctx, fx, userA)).accessToken);
  // Downloads on for A, so a download grant reaches the entry lookup.
  const settingsA = await ctx.http.get('/api/v1/quarantine/settings').set(headers(adminA));
  await ctx.http
    .put('/api/v1/quarantine/settings')
    .set(headers(adminA))
    .send({
      settings: { download: { enabled: true } },
      expectedRowVersion: settingsA.body.rowVersion,
    })
    .expect(200);
  keyA = apiKeyHeader(await fx.createApiKey(orgA, KEY_SCOPES));
  const userB = await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true });
  adminB = bearer((await loginWithMfa(ctx, fx, userB)).accessToken);
  messageB = await insertLifecycleMessage(ctx, orgB, { state: 'scanned', direction: 'outbound' });
  // Two quarantined recipients of a B message: a held entry and one awaiting an approval.
  const held = await insertLifecycleMessage(ctx, orgB, {
    state: 'quarantined',
    recipients: [
      { address: 'held@tenant-b.example', status: 'quarantined' },
      { address: 'review@tenant-b.example', status: 'quarantined' },
    ],
  });
  heldB = held;
  entryB = await insertEntry(ctx, held, { rcptSeq: 0 });
  approvalB = await insertApproval(ctx, await insertEntry(ctx, held, { rcptSeq: 1 }), orgB.id);

  const created = async (req: Test): Promise<Record<string, unknown>> => {
    const res = await asB(req);
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return res.body as Record<string, unknown>;
  };
  // @covers post /api/v1/departments
  b.department = (await created(ctx.http.post('/api/v1/departments').send({ name: 'Finance B' })))
    .id as string;
  b.member = (
    await created(
      ctx.http.post(`/api/v1/departments/${b.department}/members`).send({ userId: userB.publicId }),
    )
  ).id as string;
  // @covers post /api/v1/policies
  b.policy = (
    (
      await created(
        ctx.http
          .post('/api/v1/policies')
          .send({ name: 'Tag external B', definition: tagAllDefinition() }),
      )
    ).policy as { id: string }
  ).id;
  // @covers post /api/v1/risk-scoring/profile/versions
  b.riskVersion = (
    await created(
      ctx.http
        .post('/api/v1/risk-scoring/profile/versions')
        .send({ overrides: { thresholds: { high: 700 } }, changeNote: 'tenant B draft' }),
    )
  ).id as string;
  // @covers post /api/v1/bec/executives
  b.executive = (
    await created(ctx.http.post('/api/v1/bec/executives').send({ displayName: 'Bianca Rossi' }))
  ).id as string;
  // @covers post /api/v1/bec/vendors
  b.vendor = (
    await created(
      ctx.http
        .post('/api/v1/bec/vendors')
        .send({ name: 'B Supplies', domains: ['b-supplies.example'] }),
    )
  ).id as string;
  // @covers post /api/v1/bec/trusted-senders
  b.trustedSender = (
    await created(
      ctx.http
        .post('/api/v1/bec/trusted-senders')
        .send({ kind: 'address', value: 'ops@b-partner.example', reason: 'B partner' }),
    )
  ).id as string;
  // @covers post /api/v1/dlp/policies
  b.dlpPolicy = (await created(ctx.http.post('/api/v1/dlp/policies').send({ name: 'B cards' })))
    .id as string;
  b.dlpRule = (
    await created(
      ctx.http.post(`/api/v1/dlp/policies/${b.dlpPolicy}/rules`).send({
        name: 'B block cards',
        conditions: { selectors: { categories: ['payment_card'] } },
        action: 'block',
      }),
    )
  ).id as string;
  // @covers post /api/v1/dlp/exceptions
  b.dlpException = (
    await created(
      ctx.http.post('/api/v1/dlp/exceptions').send({
        scope: 'recipient_domain',
        value: 'b-auditor.example',
        reason: 'B auditor',
        expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(),
      }),
    )
  ).id as string;
  // @covers post /api/v1/dlp/patterns
  b.dlpPattern = (
    await created(
      ctx.http
        .post('/api/v1/dlp/patterns')
        .send({ name: 'B employee id', pattern: 'BEMP-[0-9]{6}', severity: 'low' }),
    )
  ).id as string;
  // @covers post /api/v1/dlp/dictionaries
  b.dlpDictionary = (
    await created(
      ctx.http.post('/api/v1/dlp/dictionaries').send({
        name: 'B projects',
        category: 'confidential',
        severity: 'high',
        terms: ['bluebird', 'nightjar'],
      }),
    )
  ).id as string;
  // B's policy is active, so A's policy test would see it if the snapshot leaked.
  const published = await asB(
    ctx.http
      .post(`/api/v1/policies/${b.policy}/versions/1/publish`)
      .set(idem())
      .send({ expectedRowVersion: 1 }),
  );
  expect(published.status, JSON.stringify(published.body)).toBe(200);
  policyRowVersionB = (published.body as { policy: { rowVersion: number } }).policy.rowVersion;
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('tenant A versus tenant B (pre-6.1 tenant-scoped routes)', () => {
  /** Every by-id route of B's rows, with a valid body so only the tenant scope can refuse. */
  const byIdRoutes = (totpCode = '000000'): Array<[string, () => Test]> => {
    const P = `/api/v1/policies/${b.policy}`;
    const R = `/api/v1/risk-scoring/profile/versions/${b.riskVersion}`;
    const D = `/api/v1/departments/${b.department}`;
    const scan = `/api/v1/messages/${messageB.publicId}/scans/1`;
    const Q = '/api/v1/quarantine';
    const h = ctx.http;
    return [
      // @covers get /api/v1/departments/:departmentId
      ['GET department', () => h.get(D)],
      // @covers patch /api/v1/departments/:departmentId
      ['PATCH department', () => h.patch(D).send({ name: 'x', expectedRowVersion: 1 })],
      // @covers delete /api/v1/departments/:departmentId
      ['DELETE department', () => h.delete(`${D}?expectedRowVersion=1`)],
      // @covers get /api/v1/departments/:departmentId/members
      ['GET members', () => h.get(`${D}/members`)],
      // @covers post /api/v1/departments/:departmentId/members
      ['POST member', () => h.post(`${D}/members`).send({ address: 'intruder@tenant-a.example' })],
      // @covers delete /api/v1/departments/:departmentId/members/:memberId
      ['DELETE member', () => h.delete(`${D}/members/${b.member}`)],
      // @covers get /api/v1/policies/:policyId
      ['GET policy', () => h.get(P)],
      // @covers patch /api/v1/policies/:policyId
      ['PATCH policy', () => h.patch(P).send({ name: 'x', expectedRowVersion: 1 })],
      // @covers post /api/v1/policies/:policyId/disable
      ['POST disable', () => h.post(`${P}/disable`).send({})],
      // @covers post /api/v1/policies/:policyId/enable
      ['POST enable', () => h.post(`${P}/enable`).send({})],
      // @covers delete /api/v1/policies/:policyId
      ['DELETE policy', () => h.delete(`${P}?expectedRowVersion=1`)],
      // @covers get /api/v1/policies/:policyId/versions
      ['GET versions', () => h.get(`${P}/versions`)],
      // @covers post /api/v1/policies/:policyId/versions
      ['POST version', () => h.post(`${P}/versions`).send({ basedOnVersionNo: 1 })],
      // @covers get /api/v1/policies/:policyId/versions/:versionNo
      ['GET version', () => h.get(`${P}/versions/1`)],
      // @covers put /api/v1/policies/:policyId/versions/:versionNo
      [
        'PUT version',
        () =>
          h
            .put(`${P}/versions/1`)
            .send({ definition: tagAllDefinition('x'), expectedRowVersion: 1 }),
      ],
      // @covers delete /api/v1/policies/:policyId/versions/:versionNo
      ['DELETE version', () => h.delete(`${P}/versions/1?expectedRowVersion=1`)],
      // @covers post /api/v1/policies/:policyId/versions/:versionNo/publish
      [
        'POST publish',
        () => h.post(`${P}/versions/1/publish`).set(idem()).send({ expectedRowVersion: 1 }),
      ],
      // @covers post /api/v1/policies/:policyId/versions/:versionNo/activate
      ['POST activate', () => h.post(`${P}/versions/1/activate`).set(idem()).send({})],
      // @covers get /api/v1/risk-scoring/profile/versions/:versionId
      ['GET risk version', () => h.get(R)],
      // @covers put /api/v1/risk-scoring/profile/versions/:versionId
      [
        'PUT risk version',
        () => h.put(R).send({ overrides: { thresholds: { high: 650 } }, expectedRowVersion: 1 }),
      ],
      // @covers delete /api/v1/risk-scoring/profile/versions/:versionId
      ['DELETE risk version', () => h.delete(`${R}?expectedRowVersion=1`)],
      // @covers post /api/v1/risk-scoring/profile/versions/:versionId/publish
      [
        'POST risk publish',
        () => h.post(`${R}/publish`).set(idem()).send({ expectedRowVersion: 1 }),
      ],
      // @covers post /api/v1/risk-scoring/profile/versions/:versionId/activate
      ['POST risk activate', () => h.post(`${R}/activate`).set(idem()).send({})],
      // @covers get /api/v1/bec/executives/:id
      ['GET executive', () => h.get(`/api/v1/bec/executives/${b.executive}`)],
      // @covers patch /api/v1/bec/executives/:id
      [
        'PATCH executive',
        () => h.patch(`/api/v1/bec/executives/${b.executive}`).send({ version: 1, title: 'x' }),
      ],
      // @covers delete /api/v1/bec/executives/:id
      ['DELETE executive', () => h.delete(`/api/v1/bec/executives/${b.executive}?version=1`)],
      // @covers get /api/v1/bec/vendors/:id
      ['GET vendor', () => h.get(`/api/v1/bec/vendors/${b.vendor}`)],
      // @covers patch /api/v1/bec/vendors/:id
      [
        'PATCH vendor',
        () => h.patch(`/api/v1/bec/vendors/${b.vendor}`).send({ version: 1, name: 'A Supplies' }),
      ],
      // @covers delete /api/v1/bec/vendors/:id
      ['DELETE vendor', () => h.delete(`/api/v1/bec/vendors/${b.vendor}?version=1`)],
      // @covers patch /api/v1/bec/trusted-senders/:id
      [
        'PATCH trusted sender',
        () =>
          h
            .patch(`/api/v1/bec/trusted-senders/${b.trustedSender}`)
            .send({ version: 1, reason: 'x' }),
      ],
      // @covers delete /api/v1/bec/trusted-senders/:id
      [
        'DELETE trusted sender',
        () => h.delete(`/api/v1/bec/trusted-senders/${b.trustedSender}?version=1`),
      ],
      // @covers get /api/v1/dlp/policies/:id
      ['GET dlp policy', () => h.get(`/api/v1/dlp/policies/${b.dlpPolicy}`)],
      // @covers patch /api/v1/dlp/policies/:id
      [
        'PATCH dlp policy',
        () => h.patch(`/api/v1/dlp/policies/${b.dlpPolicy}`).send({ version: 1, enabled: false }),
      ],
      // @covers delete /api/v1/dlp/policies/:id
      ['DELETE dlp policy', () => h.delete(`/api/v1/dlp/policies/${b.dlpPolicy}?version=1`)],
      // @covers post /api/v1/dlp/policies/:id/rules
      [
        'POST dlp rule',
        () =>
          h.post(`/api/v1/dlp/policies/${b.dlpPolicy}/rules`).send({
            name: 'A rule',
            conditions: { selectors: { categories: ['payment_card'] } },
            action: 'alert',
          }),
      ],
      // @covers patch /api/v1/dlp/policies/:id/rules/:ruleId
      [
        'PATCH dlp rule',
        () =>
          h
            .patch(`/api/v1/dlp/policies/${b.dlpPolicy}/rules/${b.dlpRule}`)
            .send({ version: 1, enabled: false }),
      ],
      // @covers delete /api/v1/dlp/policies/:id/rules/:ruleId
      [
        'DELETE dlp rule',
        () => h.delete(`/api/v1/dlp/policies/${b.dlpPolicy}/rules/${b.dlpRule}?version=1`),
      ],
      // @covers patch /api/v1/dlp/exceptions/:id
      [
        'PATCH dlp exception',
        () =>
          h.patch(`/api/v1/dlp/exceptions/${b.dlpException}`).send({ version: 1, enabled: false }),
      ],
      // @covers delete /api/v1/dlp/exceptions/:id
      [
        'DELETE dlp exception',
        () => h.delete(`/api/v1/dlp/exceptions/${b.dlpException}?version=1`),
      ],
      // @covers get /api/v1/dlp/patterns/:id
      ['GET dlp pattern', () => h.get(`/api/v1/dlp/patterns/${b.dlpPattern}`)],
      // @covers patch /api/v1/dlp/patterns/:id
      [
        'PATCH dlp pattern',
        () => h.patch(`/api/v1/dlp/patterns/${b.dlpPattern}`).send({ version: 1, name: 'x' }),
      ],
      // @covers delete /api/v1/dlp/patterns/:id
      ['DELETE dlp pattern', () => h.delete(`/api/v1/dlp/patterns/${b.dlpPattern}?version=1`)],
      // @covers get /api/v1/dlp/dictionaries/:id
      ['GET dlp dictionary', () => h.get(`/api/v1/dlp/dictionaries/${b.dlpDictionary}`)],
      // @covers patch /api/v1/dlp/dictionaries/:id
      [
        'PATCH dlp dictionary',
        () =>
          h.patch(`/api/v1/dlp/dictionaries/${b.dlpDictionary}`).send({ version: 1, name: 'x' }),
      ],
      // @covers delete /api/v1/dlp/dictionaries/:id
      [
        'DELETE dlp dictionary',
        () => h.delete(`/api/v1/dlp/dictionaries/${b.dlpDictionary}?version=1`),
      ],
      // Message-scoped routes on B's message.
      // @covers get /api/v1/messages/:messageId/policy-evaluations
      [
        'GET policy evaluations',
        () => h.get(`/api/v1/messages/${messageB.publicId}/policy-evaluations`),
      ],
      // @covers post /api/v1/messages/:messageId/scans/:scanId/policy/dry-run
      ['POST policy dry-run', () => h.post(`${scan}/policy/dry-run`).send({})],
      // @covers post /api/v1/messages/:messageId/scans/:scanId/risk/dry-run
      ['POST risk dry-run', () => h.post(`${scan}/risk/dry-run`).send({ profile: 'platform' })],
      // @covers post /api/v1/messages/:messageId/scans/:scanId/bec-feedback
      ['POST bec feedback', () => h.post(`${scan}/bec-feedback`).send({ kind: 'false_negative' })],
      // @covers get /api/v1/messages/:messageId/scans/:scanId/dlp-evidence
      ['GET dlp evidence', () => h.get(`${scan}/dlp-evidence`)],
      // @covers delete /api/v1/messages/:messageId/scans/:scanId/dlp-evidence
      ['DELETE dlp evidence', () => h.delete(`${scan}/dlp-evidence`).set(idem())],
      // Quarantine entries and approvals of B (the keyed routes take their Idempotency-Key).
      // @covers get /api/v1/quarantine/entries/:entryId/history
      ['GET entry history', () => h.get(`${Q}/entries/${entryB.publicId}/history`)],
      // @covers get /api/v1/quarantine/entries/:entryId/preview
      ['GET entry preview', () => h.get(`${Q}/entries/${entryB.publicId}/preview`)],
      // @covers post /api/v1/quarantine/entries/:entryId/download-grants
      [
        'POST download grant',
        () =>
          h
            .post(`${Q}/entries/${entryB.publicId}/download-grants`)
            .send({ object: 'eml', password: userA.password, totpCode }),
      ],
      // @covers post /api/v1/quarantine/entries/:entryId/release
      [
        'POST entry release',
        () => h.post(`${Q}/entries/${entryB.publicId}/release`).set(idem()).send({ reason: 'x' }),
      ],
      // @covers post /api/v1/quarantine/entries/:entryId/request-release
      [
        'POST entry request-release',
        () =>
          h
            .post(`${Q}/entries/${entryB.publicId}/request-release`)
            .set(idem())
            .send({ reason: 'x' }),
      ],
      // @covers post /api/v1/quarantine/entries/:entryId/reject
      [
        'POST entry reject',
        () => h.post(`${Q}/entries/${entryB.publicId}/reject`).set(idem()).send({ reason: 'x' }),
      ],
      // @covers post /api/v1/quarantine/entries/:entryId/delete
      [
        'POST entry delete',
        () => h.post(`${Q}/entries/${entryB.publicId}/delete`).set(idem()).send({ reason: 'x' }),
      ],
      // @covers post /api/v1/quarantine/approvals/:approvalId/approve
      [
        'POST approve',
        () =>
          h.post(`${Q}/approvals/${approvalB.publicId}/approve`).set(idem()).send({ reason: 'x' }),
      ],
      // @covers post /api/v1/quarantine/approvals/:approvalId/deny
      [
        'POST deny',
        () => h.post(`${Q}/approvals/${approvalB.publicId}/deny`).set(idem()).send({ reason: 'x' }),
      ],
      // @covers post /api/v1/quarantine/approvals/:approvalId/cancel
      [
        'POST cancel',
        () =>
          h.post(`${Q}/approvals/${approvalB.publicId}/cancel`).set(idem()).send({ reason: 'x' }),
      ],
    ];
  };

  /** User-only or MFA routes: an API key is refused before any lookup. */
  const keyRefused = new Set([
    'POST bec feedback',
    'GET dlp evidence',
    'DELETE dlp evidence',
    'POST download grant',
    'POST approve',
    'POST deny',
  ]);

  it('A’s administrator gets 404 for every id of B and changes nothing', async () => {
    const failures: string[] = [];
    for (const [name, send] of byIdRoutes(await fx.totpNow(userA))) {
      const res = await send().set(headers(adminA));
      if (res.status !== 404) failures.push(`${name} → ${res.status} ${JSON.stringify(res.body)}`);
    }
    expect(failures).toEqual([]);
  });

  it('an A API key with every scope gets 404 too (403 on user-only and MFA routes)', async () => {
    const failures: string[] = [];
    for (const [name, send] of byIdRoutes()) {
      const res = await send().set(headers(keyA));
      const expected = keyRefused.has(name) ? 403 : 404;
      if (res.status !== expected)
        failures.push(`${name} → ${res.status} ${JSON.stringify(res.body)}`);
    }
    expect(failures).toEqual([]);
  });

  it('A’s lists never contain B’s rows', async () => {
    const lists: Array<[string, string, string]> = [
      // @covers get /api/v1/departments
      ['/api/v1/departments', b.department, 'departments'],
      // @covers get /api/v1/policies
      ['/api/v1/policies', b.policy, 'policies'],
      // @covers get /api/v1/risk-scoring/profile/versions
      ['/api/v1/risk-scoring/profile/versions', b.riskVersion, 'risk versions'],
      // @covers get /api/v1/bec/executives
      ['/api/v1/bec/executives', b.executive, 'executives'],
      // @covers get /api/v1/bec/vendors
      ['/api/v1/bec/vendors', b.vendor, 'vendors'],
      // @covers get /api/v1/bec/trusted-senders
      ['/api/v1/bec/trusted-senders', b.trustedSender, 'trusted senders'],
      // @covers get /api/v1/dlp/policies
      ['/api/v1/dlp/policies', b.dlpPolicy, 'dlp policies'],
      // @covers get /api/v1/dlp/exceptions
      ['/api/v1/dlp/exceptions', b.dlpException, 'dlp exceptions'],
      // @covers get /api/v1/dlp/patterns
      ['/api/v1/dlp/patterns', b.dlpPattern, 'dlp patterns'],
      // @covers get /api/v1/dlp/dictionaries
      ['/api/v1/dlp/dictionaries', b.dlpDictionary, 'dlp dictionaries'],
    ];
    for (const auth of [adminA, keyA]) {
      for (const [url, foreign, name] of lists) {
        const res = await ctx.http.get(url).set(headers(auth));
        expect(res.status, name).toBe(200);
        expect(dataOf(res.body), name).not.toContain(foreign);
      }
    }
    // B sees its own rows (the fixture is real): the read replica catches up.
    await expect
      .poll(async () =>
        dataOf((await asB(ctx.http.get('/api/v1/departments'))).body).includes(b.department),
      )
      .toBe(true);
  });

  it('A’s singleton settings stay A’s own when B changes its settings', async () => {
    const singletons = [
      // @covers get /api/v1/policy-settings
      '/api/v1/policy-settings',
      // @covers get /api/v1/scan-settings
      '/api/v1/scan-settings',
      // @covers get /api/v1/quarantine/settings
      '/api/v1/quarantine/settings',
      // @covers get /api/v1/risk-scoring/profile
      '/api/v1/risk-scoring/profile',
      // @covers get /api/v1/dlp/compliance
      '/api/v1/dlp/compliance',
    ];
    const snapshot = async () => {
      const out: Record<string, unknown> = {};
      for (const url of singletons) {
        const res = await ctx.http.get(url).set(headers(adminA));
        expect(res.status, url).toBe(200);
        out[url] = res.body;
      }
      return out;
    };
    const before = await snapshot();

    // B changes each of them.
    // @covers put /api/v1/policy-settings
    await asB(
      ctx.http
        .put('/api/v1/policy-settings')
        .send({ settings: { allowRecommendationOverrides: true }, expectedRowVersion: 0 }),
    ).expect(200);
    // @covers put /api/v1/scan-settings/:engine
    await asB(
      ctx.http
        .put('/api/v1/scan-settings/rspamd')
        .send({ expectedVersion: 0, settings: { spamScore: 9 } }),
    ).expect(200);
    const qs = await asB(ctx.http.get('/api/v1/quarantine/settings')).expect(200);
    // @covers put /api/v1/quarantine/settings
    await asB(
      ctx.http.put('/api/v1/quarantine/settings').send({
        settings: { endUser: { selfRelease: true, selfReleaseReasons: ['spam'] } },
        expectedRowVersion: qs.body.rowVersion,
      }),
    ).expect(200);
    const published = await asB(
      ctx.http
        .post(`/api/v1/risk-scoring/profile/versions/${b.riskVersion}/publish`)
        .set(idem())
        .send({ expectedRowVersion: 1 }),
    );
    expect(published.status, JSON.stringify(published.body)).toBe(200);

    // @covers put /api/v1/dlp/compliance/aadhaar
    const aadhaar = await asB(
      ctx.http
        .put('/api/v1/dlp/compliance/aadhaar')
        .set(idem())
        .send({
          expectedVersion: 0,
          basis: 'regulatory_obligation',
          reference: 'Tenant B KYC direction',
          attested: true,
          reviewDueAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
        }),
    );
    expect(aadhaar.status, JSON.stringify(aadhaar.body)).toBe(200);

    expect(await snapshot()).toEqual(before);

    // A's own pointer and switch changes never reach B.
    // @covers post /api/v1/risk-scoring/profile/reset
    await ctx.http
      .post('/api/v1/risk-scoring/profile/reset')
      .set(headers(adminA))
      .set(idem())
      .send({})
      .expect(200);
    // @covers delete /api/v1/dlp/compliance/aadhaar
    await ctx.http
      .delete('/api/v1/dlp/compliance/aadhaar')
      .set(headers(adminA))
      .set(idem())
      .expect(200);
    const profileB = await asB(ctx.http.get('/api/v1/risk-scoring/profile')).expect(200);
    expect(profileB.body.active).toMatchObject({ versionId: b.riskVersion });
    const complianceB = await asB(ctx.http.get('/api/v1/dlp/compliance')).expect(200);
    expect(JSON.stringify(complianceB.body)).toContain('Tenant B KYC direction');
    // A's own engine row is untouched by B's override (and its reset refers to A's row only).
    const engines = (await ctx.http.get('/api/v1/scan-settings').set(headers(adminA))).body as {
      data: Array<{ engine: string; override: unknown }>;
    };
    expect(engines.data.find((e) => e.engine === 'rspamd')?.override).toBeNull();
    // A's reset acts on A's own (absent) override only: B's row stays.
    // @covers delete /api/v1/scan-settings/:engine
    const reset = await ctx.http
      .delete('/api/v1/scan-settings/rspamd?expectedVersion=0')
      .set(headers(adminA));
    expect(reset.status, JSON.stringify(reset.body)).toBeLessThan(300);
    expect(await ctx.prisma.scanEngineSetting.count({ where: { organizationId: orgB.id } })).toBe(
      1,
    );
  });

  it('B’s rows are unchanged by everything above', async () => {
    const checks: Array<[string, Record<string, unknown>]> = [
      [`/api/v1/departments/${b.department}`, { name: 'Finance B', rowVersion: 1 }],
      [`/api/v1/bec/executives/${b.executive}`, { displayName: 'Bianca Rossi', version: 1 }],
      [`/api/v1/bec/vendors/${b.vendor}`, { name: 'B Supplies', version: 1 }],
      [`/api/v1/dlp/policies/${b.dlpPolicy}`, { name: 'B cards', version: 1 }],
      [`/api/v1/dlp/patterns/${b.dlpPattern}`, { name: 'B employee id', version: 1 }],
      [`/api/v1/dlp/dictionaries/${b.dlpDictionary}`, { name: 'B projects', version: 1 }],
    ];
    for (const [url, expected] of checks) {
      const res = await asB(ctx.http.get(url));
      expect(res.status, url).toBe(200);
      expect(res.body, url).toMatchObject(expected);
    }
    const policy = await asB(ctx.http.get(`/api/v1/policies/${b.policy}`)).expect(200);
    expect(policy.body).toMatchObject({ name: 'Tag external B', rowVersion: policyRowVersionB });
    const members = await asB(ctx.http.get(`/api/v1/departments/${b.department}/members`));
    expect(dataOf(members.body)).toEqual([b.member]);
    const entry = await ctx.prisma.quarantineMessage.findUniqueOrThrow({
      where: { id: entryB.id },
    });
    expect(entry.status).toBe('held');
    const approval = await ctx.prisma.quarantineApprovalRequest.findUniqueOrThrow({
      where: { id: approvalB.id },
    });
    expect(approval.status).toBe('pending');
  });

  it('A’s policy test, quarantine bulk, manual quarantine and quarantine lists never reach B', async () => {
    // @covers post /api/v1/policies/test
    const tested = await ctx.http
      .post('/api/v1/policies/test')
      .set(headers(adminA))
      .send({ facts: { direction: 'inbound' } });
    expect(tested.status, JSON.stringify(tested.body)).toBe(200);
    expect(JSON.stringify(tested.body)).not.toContain(b.policy);

    // @covers post /api/v1/quarantine/bulk
    const bulk = await ctx.http
      .post('/api/v1/quarantine/bulk')
      .set(headers(adminA))
      .set(idem())
      .send({ action: 'release', ids: [entryB.publicId], reason: 'cross-tenant probe' });
    expect(bulk.status, JSON.stringify(bulk.body)).toBe(200);
    expect(bulk.body.results).toEqual([
      expect.objectContaining({ id: entryB.publicId, status: 'not_found' }),
    ]);
    // @covers post /api/v1/quarantine/entries
    await ctx.http
      .post('/api/v1/quarantine/entries')
      .set(headers(adminA))
      .set(idem())
      .send({ messageId: heldB.publicId, reason: 'cross-tenant probe' })
      .expect(404);

    const window = windowAround();
    const search = `/api/v1/quarantine/entries?from=${window.from}&to=${window.to}`;
    // @covers get /api/v1/quarantine/entries
    const entries = await ctx.http.get(search).set(headers(adminA)).expect(200);
    expect(dataOf(entries.body)).not.toContain(entryB.publicId);
    // @covers get /api/v1/quarantine/approvals
    const approvals = await ctx.http
      .get('/api/v1/quarantine/approvals')
      .set(headers(adminA))
      .expect(200);
    expect(dataOf(approvals.body)).not.toContain(approvalB.publicId);
    // @covers get /api/v1/quarantine/approvals/:approvalId
    await ctx.http
      .get(`/api/v1/quarantine/approvals/${approvalB.publicId}`)
      .set(headers(adminA))
      .expect(404);
    // @covers get /api/v1/quarantine/entries/:entryId
    await ctx.http
      .get(`/api/v1/quarantine/entries/${entryB.publicId}`)
      .set(headers(adminA))
      .expect(404);
    // B sees its own entry (the fixture is real).
    await expect
      .poll(async () => dataOf((await asB(ctx.http.get(search))).body))
      .toContain(entryB.publicId);
  });

  it('an unknown id is answered exactly like B’s id (no existence oracle)', async () => {
    const unknown = randomUUID();
    const own = await ctx.http.get(`/api/v1/bec/vendors/${unknown}`).set(headers(adminA));
    const foreign = await ctx.http.get(`/api/v1/bec/vendors/${b.vendor}`).set(headers(adminA));
    expect(foreign.status).toBe(own.status);
    expect(foreign.body.code).toBe(own.body.code);
    expect(foreign.body.message).toBe(own.body.message);
  });
});
