/**
 * Step 8.6 api on the real writer and replica (docs/plan/steps/27-journal-intake-and-archive-
 * split.md D1, D5, D11–D13, §9.4): the journaling routes end to end (only hashes stored, the
 * clear address only in the live response, reveal and rotation audited, CAS, cross-tenant 404),
 * the gateway views excluding journal intake messages (Email Explorer, message detail and
 * sub-routes, rescan, reports, usage), the record-detail re-scope with a migrated-style
 * organization admin (organization_admin + compliance_officer), the audited archive access
 * assignment, the archive-only profile (/auth/me, domains), the reserved intake domain, the purge
 * of the journal intake tables and the EXPLAIN plans of the report and explorer statements.
 * Synthetic `it-*` organizations only; intake messages are inserted directly on the writer (the
 * smtp-adapter intake listener is WP3's).
 */
// @covers get /api/v1/journaling/settings
// @covers put /api/v1/journaling/settings
// @covers get /api/v1/journaling/status
// @covers get /api/v1/journaling/intake-sources
// @covers post /api/v1/journaling/intake-sources
// @covers get /api/v1/journaling/intake-sources/:sourceId
// @covers patch /api/v1/journaling/intake-sources/:sourceId
// @covers delete /api/v1/journaling/intake-sources/:sourceId
// @covers post /api/v1/journaling/intake-sources/:sourceId/rotate-address
// @covers get /api/v1/journaling/intake-sources/:sourceId/wizard
// @covers get /api/v1/journaling/intake-sources/:sourceId/setup-guide
// @covers post /api/v1/journaling/intake-sources/:sourceId/attestations
import { createHash, randomUUID } from 'node:crypto';
import {
  deriveIntakeAddressToken,
  intakeAddressHash,
  intakeLocalPart,
  parseIntakeAddressSecret,
} from '@email-gateway/archive';
import { RedisService, S3Service } from '@email-gateway/common';
import { SYSTEM_ROLES } from '@email-gateway/database';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { KeyValueStore } from '../src/kv/key-value-store';
import { DlpResultsRepository } from '../src/modules/dlp/repositories/dlp-results.repository';
import { messagesPageSql } from '../src/modules/messages/repositories/message-list-drivers';
import { reportSql } from '../src/modules/reports/reports.repository';
import { JournalIntakeTenantDataRepository } from '../src/modules/tenant-data/journal-intake-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { InMemoryKeyValueStore } from '../test/support/in-memory-key-value-store';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import { explain } from './support/insights';
import { deleteMessagesData, type SeededMessage, seedMessage } from './support/messages-data';
import { insertDomain, type InsertedDomain } from './support/smtp';

const J = '/api/v1/journaling';
const SRC = `${J}/intake-sources`;
const TENANT = '3b1c2d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d';
const POLL = { timeout: 15_000, interval: 200 };
const sha256 = (v: string | Buffer) => createHash('sha256').update(v).digest('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let orgArchiveOnly: FixtureOrganization;
let adminA: Record<string, string>;
let adminB: Record<string, string>;
let officerA: Record<string, string>;
let readerA: Record<string, string>;
let adminArchiveOnly: Record<string, string>;
let adminAUser: { id: bigint; publicId: string };
let domainA: InsertedDomain;
let connectionA: { id: bigint; publicId: string };
let secret: Buffer;

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'put' | 'patch' | 'delete',
  path: string,
  body?: object,
  keyed = method === 'post' || method === 'put' || method === 'patch',
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (keyed) req = req.set('Idempotency-Key', `it-${randomUUID()}`);
  return body === undefined ? req : req.send(body);
}

/** A replica read that must observe a write just made on the writer. */
async function eventually(make: () => Test, accept: (res: Response) => boolean): Promise<Response> {
  let last: Response | undefined;
  await expect
    .poll(async () => {
      last = await make();
      return accept(last);
    }, POLL)
    .toBe(true);
  return last!;
}

/** Archiving enabled with a default retention policy (written directly: no admin may). */
async function enableArchiving(org: FixtureOrganization): Promise<void> {
  const policy = await ctx.prisma.archiveRetentionPolicy.create({
    data: { organizationId: org.id, name: 'Seven years', retentionDays: 2555, priority: 100 },
    select: { id: true },
  });
  await ctx.prisma.archiveSetting.create({
    data: {
      organizationId: org.id,
      enabled: true,
      defaultRetentionPolicyId: policy.id,
      journalEnabledAt: new Date(),
      generation: 1n,
    },
  });
}

/** A bound Microsoft 365 connection with one linked verified domain (the 8.2 end state). */
async function boundConnection(org: FixtureOrganization, domain: InsertedDomain) {
  const c = await ctx.prisma.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `Contoso ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: TENANT,
      activeTenantKey: `microsoft_365:${randomUUID()}`,
      tenantVerifiedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  await ctx.prisma.providerConnectionDomain.create({
    data: {
      organizationId: org.id,
      connectionId: c.id,
      domainId: domain.id,
      providerVerification: 'verified',
    },
  });
  return c;
}

/** One journal intake message inserted the way the intake LMTP commits it (registry rows). */
async function insertIntakeMessage(
  org: FixtureOrganization,
  sourceId: bigint,
  receivedAt = new Date(Date.now() - 30_000),
) {
  const p = ctx.prisma;
  const identity = await p.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:${sha256(randomUUID())}`, receivedAt },
    select: { id: true, publicId: true },
  });
  await p.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      domainId: domainA.id,
      direction: 'inbound',
      status: 'journaled',
      statusChangedAt: receivedAt,
      version: 2,
      ingestSource: 'journal_intake',
      envelopeFrom: 'sender@external.example',
      headerFrom: 'Sender <sender@external.example>',
      subject: 'Journaled message',
      internetMessageId: `<${randomUUID()}@external.example>`,
      sizeBytes: 1024,
      recipientCount: 1,
      attachmentCount: 0,
      emlObjectKey: `org/${org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha256('intake'),
      clientIp: '40.92.0.10',
      clientHelo: 'mail.protection.outlook.com',
      mtaQueueId: 'JOURNALQ1',
    },
  });
  await p.emailRecipient.create({
    data: {
      receivedAt,
      messageId: identity.id,
      organizationId: org.id,
      rcptSeq: 0,
      address: 'alice@corp.example',
      status: 'journaled',
      direction: 'inbound',
    },
  });
  await p.journalIntakeMessage.create({
    data: {
      messageId: identity.id,
      receivedAt,
      organizationId: org.id,
      sourceId,
      kind: 'microsoft_365_journal',
      format: 'journal_report',
      envelope: {
        v: 1,
        sender: 'sender@external.example',
        onBehalfOf: null,
        messageId: null,
        recipients: [{ address: 'alice@corp.example', field: 'to' }],
        truncated: false,
        envelopeMismatch: false,
      },
      proof: {
        v: 1,
        network: 'provider_egress',
        tls: true,
        clientCert: 'n/a',
        tenantHeader: 'match',
        headerToken: 'n/a',
        dkim: { result: 'n/a', domains: [] },
        result: 'pass',
      },
      reportSha256: sha256('report'),
      reportSizeBytes: 2048,
      scanRequested: false,
    },
  });
  return { id: identity.id, publicId: identity.publicId, receivedAt };
}

/**
 * A completed scan round of a message with a blocking DLP result and a (stored) evidence row, as
 * the email-worker writes them for an opted-in intake scan (D4: DLP results as for gateway mail).
 * No evidence object: every request of this suite must answer before the object is read.
 */
async function insertDlpRound(
  message: { id: bigint; receivedAt: Date; scanId?: bigint },
  org: FixtureOrganization,
) {
  const base = { receivedAt: message.receivedAt, messageId: message.id, organizationId: org.id };
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  // A seeded gateway message already has its round 0 scan.
  const scan =
    message.scanId !== undefined
      ? { id: message.scanId }
      : await ctx.prisma.emailScan.create({
          data: {
            ...base,
            scanKind: 'initial',
            status: 'completed',
            lifecycleRound: 0,
            scanVerdict: 'suspicious',
            requiredEngines: ['dlp'],
            reasonCodes: ['dlp.action.block'],
            startedAt,
            completedAt: new Date(startedAt.getTime() + 500),
            deadlineAt: new Date(startedAt.getTime() + 1_800_000),
          },
          select: { id: true },
        });
  await ctx.prisma.dlpScanResult.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      direction: 'inbound',
      engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
      rulesVersion: 'dlp-map/1',
      settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
      policyVersion: 'pol/1;h=0123456789ab',
      extractorVersion: 'dlp-extract/1',
      verdict: 'suspicious',
      action: 'block',
      actionSource: 'default_policy',
      coverage: 'complete',
      coverageDetail: { aadhaar: 'disabled', sources: [] },
      categories: [{ category: 'national_id', count: 1, maxSeverity: 'high', maxConfidence: 0.85 }],
      findings: [],
      policy: { winner: null, matched: [], exceptionsApplied: [] },
      findingCount: 1,
      evidenceStatus: 'stored',
      durationMs: 500,
    },
  });
  await ctx.prisma.dlpEvidence.create({
    data: {
      ...base,
      scanId: scan.id,
      objectKey: `org/${org.id.toString()}/dlp-evidence/2026/11/${scan.id.toString()}-${randomUUID()}.bin`,
      objectSha256: sha256(`evidence-${scan.id.toString()}`),
      objectSizeBytes: 64,
      wrappedKey: 'wrapped-key-fixture',
      keyId: 'fixture1',
      algorithm: 'dlp-evidence/1',
      matchCount: 1,
      expiresAt: new Date(Date.now() + 30 * 86_400_000),
    },
  });
  return scan.id;
}

beforeAll(async () => {
  ctx = await createIntegrationApp(
    { REDIS_DKIM_URL: '' },
    {
      override: (builder) =>
        builder
          .overrideProvider(RedisService)
          .useValue({ healthName: 'redis', checkHealth: () => Promise.resolve() })
          .overrideProvider(S3Service)
          .useValue({ healthName: 's3', checkHealth: () => Promise.resolve() })
          .overrideProvider(KeyValueStore)
          .useValue(new InMemoryKeyValueStore()),
    },
  );
  if (ctx.config.JOURNAL_INTAKE_DOMAIN === undefined) {
    throw new Error('JOURNAL_INTAKE_DOMAIN must be set in .env for this suite');
  }
  secret = parseIntakeAddressSecret(ctx.config.JOURNAL_INTAKE_ADDRESS_SECRET!);
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization({ planCode: 'enterprise' });
  orgB = await fx.createOrganization({ planCode: 'enterprise' });
  orgArchiveOnly = await fx.createOrganization({ planCode: 'archive_only' });
  const login = async (org: FixtureOrganization, roles: string[]) => {
    const user = await fx.createUser(org, { roles, mfa: true });
    return { user, headers: bearer((await loginWithMfa(ctx, fx, user)).accessToken) };
  };
  const admin = await login(orgA, ['organization_admin']);
  adminA = admin.headers;
  adminAUser = admin.user;
  adminB = (await login(orgB, ['organization_admin'])).headers;
  // What the step 8.6 migration gives every existing organization admin.
  officerA = (await login(orgA, ['organization_admin', 'compliance_officer'])).headers;
  readerA = (await login(orgA, ['read_only_user'])).headers;
  adminArchiveOnly = (await login(orgArchiveOnly, ['organization_admin'])).headers;
  for (const org of [orgA, orgB]) await enableArchiving(org);
  domainA = await insertDomain(ctx, orgA, { status: 'verified', label: 'jrnl' });
  const domainB = await insertDomain(ctx, orgB, { status: 'verified', label: 'jrnl' });
  connectionA = await boundConnection(orgA, domainA);
  await boundConnection(orgB, domainB);
  const intakePurge = ctx.get(JournalIntakeTenantDataRepository);
  const providerPurge = ctx.get(ProviderTenantDataRepository);
  // Intake sources reference provider connections (RESTRICT): intake first, then providers.
  fx.registerCleanup(async () => {
    const orgs = [orgA, orgB, orgArchiveOnly];
    for (const org of orgs) await intakePurge.purgeOrganization(systemScope(org.id));
    for (const org of orgs) await providerPurge.purgeOrganization(systemScope(org.id));
    await deleteMessagesData(
      ctx,
      orgs.map((o) => o.id),
    );
    const where = { organizationId: { in: orgs.map((o) => o.id) } };
    await ctx.prisma.archiveSetting.deleteMany({ where });
    await ctx.prisma.archiveRetentionPolicy.deleteMany({ where });
    await ctx.prisma.auditLog.deleteMany({ where });
  });
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('journal intake sources on the real writer (D1, D11)', () => {
  let sourceId: string;

  it('creates a Microsoft 365 source: the address once, only its hash stored, audited', async () => {
    const key = `it-${randomUUID()}`;
    const body = {
      kind: 'microsoft_365_journal',
      displayName: 'Contoso Microsoft 365',
      providerConnectionId: connectionA.publicId,
    };
    const res = await ctx.http
      .post(SRC)
      .set(adminA)
      .set('X-Forwarded-For', uniqueIp())
      .set('Idempotency-Key', key)
      .send(body);
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    sourceId = res.body.source.id as string;
    const token = deriveIntakeAddressToken(secret, sourceId, 1);
    expect(res.body.address).toBe(`journal-${token}@${ctx.config.JOURNAL_INTAKE_DOMAIN}`);
    const row = await ctx.prisma.journalIntakeSource.findUniqueOrThrow({
      where: { publicId: sourceId },
    });
    expect(row).toMatchObject({
      organizationId: orgA.id,
      status: 'pending_verification',
      providerConnectionId: connectionA.id,
      addressHash: intakeAddressHash(intakeLocalPart(token)),
      headerTokenHash: null,
      requireTls: true,
      silenceAlertMinutes: 240,
    });
    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: orgA.id, idempotencyKey: key },
    });
    expect(JSON.stringify(stored.response)).not.toContain(token);
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgA.id, action: 'journal_intake.source_created' },
    });
    expect(audit.resourceId).toBe(sourceId);
    expect(JSON.stringify(audit.metadata)).not.toContain(token);
    const replay = await ctx.http
      .post(SRC)
      .set(adminA)
      .set('X-Forwarded-For', uniqueIp())
      .set('Idempotency-Key', key)
      .send(body);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body.address).toBeNull();
    expect(await ctx.prisma.journalIntakeSource.count({ where: { organizationId: orgA.id } })).toBe(
      1,
    );
  });

  it('lists and reads masked; reveal is audited; another tenant gets 404', async () => {
    const list = await eventually(
      () => call(readerA, 'get', `${SRC}?status=pending_verification`),
      (r) => r.status === 200 && (r.body.data as unknown[]).length === 1,
    );
    expect(list.body.data[0]).toMatchObject({ id: sourceId, revealed: false });
    expect(await call(readerA, 'get', `${SRC}/${sourceId}?reveal=true`)).toMatchObject({
      status: 403,
    });
    const revealed = await call(adminA, 'get', `${SRC}/${sourceId}?reveal=true`);
    expect(revealed.body.revealed).toBe(true);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'journal_intake.address_revealed' },
      }),
    ).toBe(1);
    for (const [method, path] of [
      ['get', `${SRC}/${sourceId}`],
      ['get', `${SRC}/${sourceId}/wizard`],
      ['get', `${SRC}/${sourceId}/setup-guide`],
      ['patch', `${SRC}/${sourceId}`],
      ['delete', `${SRC}/${sourceId}`],
      ['post', `${SRC}/${sourceId}/rotate-address`],
      ['post', `${SRC}/${sourceId}/attestations`],
    ] as const) {
      const body =
        method === 'patch'
          ? { expectedRowVersion: 1, displayName: 'Hijack' }
          : path.endsWith('attestations')
            ? { code: 'journal.m365.rule_created', attested: true }
            : undefined;
      const res = await call(adminB, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(404);
      expect(res.body.code).toBe('journal_intake_source_not_found');
    }
    const listB = await call(adminB, 'get', SRC);
    expect(listB.body.data).toEqual([]);
  });

  it('rotates with an overlap, patches with CAS, attests, computes the wizard and the guide', async () => {
    const before = await ctx.prisma.journalIntakeSource.findUniqueOrThrow({
      where: { publicId: sourceId },
    });
    const rotated = await call(adminA, 'post', `${SRC}/${sourceId}/rotate-address`);
    expect(rotated.status, JSON.stringify(rotated.body)).toBe(200);
    const after = await ctx.prisma.journalIntakeSource.findUniqueOrThrow({
      where: { publicId: sourceId },
    });
    expect(after).toMatchObject({
      addressVersion: 2,
      previousAddressHash: before.addressHash,
      addressHash: intakeAddressHash(
        intakeLocalPart(deriveIntakeAddressToken(secret, sourceId, 2)),
      ),
    });
    expect(after.previousValidUntil!.getTime()).toBeGreaterThan(Date.now() + 6 * 86_400_000);
    const stale = await call(adminA, 'patch', `${SRC}/${sourceId}`, {
      expectedRowVersion: 1,
      status: 'paused',
    });
    expect(stale.status).toBe(409);
    expect(stale.body.code).toBe('journal_intake_source_conflict');
    const paused = await call(adminA, 'patch', `${SRC}/${sourceId}`, {
      expectedRowVersion: after.rowVersion,
      status: 'paused',
    });
    expect(paused.body).toMatchObject({ status: 'paused' });
    const resumed = await call(adminA, 'patch', `${SRC}/${sourceId}`, {
      expectedRowVersion: after.rowVersion + 1,
      status: 'active',
    });
    expect(resumed.body).toMatchObject({ status: 'pending_verification' });
    for (const code of ['journal.m365.rule_created', 'journal.m365.ndr_mailbox_set']) {
      const res = await call(adminA, 'post', `${SRC}/${sourceId}/attestations`, {
        code,
        attested: true,
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
    }
    const wizard = await eventually(
      () => call(readerA, 'get', `${SRC}/${sourceId}/wizard`),
      (r) => r.status === 200 && r.body.missingAttestations.length === 0,
    );
    expect(wizard.body.nextAction).toEqual({ step: 'verify', action: 'send_first_message' });
    const guide = await call(readerA, 'get', `${SRC}/${sourceId}/setup-guide?format=markdown`);
    expect(guide.headers['content-type']).toMatch(/^text\/markdown/);
    expect(guide.text).not.toContain(deriveIntakeAddressToken(secret, sourceId, 2));
  });

  it('settings PUT writes the shared archive_settings row; the status counts sources', async () => {
    const current = await ctx.prisma.archiveSetting.findUniqueOrThrow({
      where: { organizationId: orgA.id },
    });
    const res = await call(adminA, 'put', `${J}/settings`, {
      expectedRowVersion: current.rowVersion,
      settings: { intake: { scanEnabled: true } },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const row = await ctx.prisma.archiveSetting.findUniqueOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(row.rowVersion).toBe(current.rowVersion + 1);
    expect(row.settings).toMatchObject({ intake: { scanEnabled: true } });
    const status = await eventually(
      () => call(readerA, 'get', `${J}/status`),
      (r) => r.status === 200 && r.body.sources.total === 1,
    );
    expect(status.body.settings).toMatchObject({ enabled: true, intakeEntitled: true });
    const view = await eventually(
      () => call(readerA, 'get', `${J}/settings`),
      (r) => r.body.rowVersion === row.rowVersion,
    );
    expect(view.body.settings.intake).toEqual({ scanEnabled: true });
    // An organization admin cannot change the Archive-area paths through /archive/settings.
    const forbidden = await call(adminA, 'put', '/api/v1/archive/settings', {
      expectedRowVersion: row.rowVersion,
      immutability: 'governance',
    });
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.code).toBe('archive_settings_forbidden_path');
  });

  it('disables a source for good (DELETE) and keeps the row', async () => {
    const res = await call(adminA, 'delete', `${SRC}/${sourceId}`);
    expect(res.body.status).toBe('disabled');
    const row = await ctx.prisma.journalIntakeSource.findUniqueOrThrow({
      where: { publicId: sourceId },
    });
    expect(row.disabledAt).not.toBeNull();
    expect(row.disabledByUserId).toBe(adminAUser.id);
  });
});

describe('gateway views exclude journal intake messages (D5)', () => {
  let gateway: SeededMessage;
  let intake: { id: bigint; publicId: string; receivedAt: Date };

  beforeAll(async () => {
    const source = await ctx.prisma.journalIntakeSource.findFirstOrThrow({
      where: { organizationId: orgA.id },
      select: { id: true },
    });
    gateway = await seedMessage(ctx, orgA, { domainId: domainA.id });
    intake = await insertIntakeMessage(orgA, source.id);
  });

  it('the Email Explorer lists gateway messages only', async () => {
    const from = new Date(Date.now() - 3_600_000).toISOString();
    const to = new Date(Date.now() + 60_000).toISOString();
    const res = await eventually(
      () =>
        call(
          adminA,
          'get',
          `/api/v1/messages?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
        ),
      (r) =>
        r.status === 200 &&
        (r.body.data as Array<{ id: string }>).some((m) => m.id === gateway.publicId),
    );
    const ids = (res.body.data as Array<{ id: string }>).map((m) => m.id);
    expect(ids).not.toContain(intake.publicId);
    // The sender filter (a residual on another driver) excludes it too.
    const bySender = await call(
      adminA,
      'get',
      `/api/v1/messages?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}` +
        '&sender=sender@external.example',
    );
    expect((bySender.body.data as Array<{ id: string }>).map((m) => m.id)).not.toContain(
      intake.publicId,
    );
  });

  it('detail and every sub-route answer 404 for an intake message; rescan is refused', async () => {
    await eventually(
      () => call(adminA, 'get', `/api/v1/messages/${gateway.publicId}`),
      (r) => r.status === 200,
    );
    for (const path of [
      `/api/v1/messages/${intake.publicId}`,
      `/api/v1/messages/${intake.publicId}/recipients`,
      `/api/v1/messages/${intake.publicId}/lifecycle`,
      `/api/v1/messages/${intake.publicId}/scans`,
      `/api/v1/messages/${intake.publicId}/headers`,
      `/api/v1/messages/${intake.publicId}/deliveries`,
    ]) {
      const res = await call(adminA, 'get', path);
      expect(res.status, path).toBe(404);
    }
    const reveal = await call(
      adminA,
      'post',
      `/api/v1/messages/${intake.publicId}/reveal`,
      {
        fields: ['subject'],
      },
      false,
    );
    expect(reveal.status).toBe(404);
    const rescan = await call(adminA, 'post', `/api/v1/messages/${intake.publicId}/rescan`, {
      expectedVersion: 2,
      reason: 'integration rescan of an intake message',
    });
    expect(rescan.status, JSON.stringify(rescan.body)).toBe(404);
  });

  it('DLP evidence and incidents, risk dry-run, BEC feedback and scan training exclude intake (review fix)', async () => {
    const gatewayScan = await insertDlpRound(gateway, orgA);
    const intakeScan = await insertDlpRound(intake, orgA);
    fx.registerCleanup(async () => {
      const where = { organizationId: orgA.id };
      await ctx.prisma.dlpEvidence.deleteMany({ where });
      await ctx.prisma.dlpScanResult.deleteMany({ where });
      await ctx.prisma.becFeedback.deleteMany({ where });
      await ctx.prisma.emailScan.deleteMany({ where });
    });
    // An organization admin holds dlp:read and dlp:evidence_read but no archive access: the
    // DLP incidents list (replica) shows the gateway result only.
    const incidents = await eventually(
      () => call(adminA, 'get', '/api/v1/dlp/incidents?limit=100'),
      (r) =>
        r.status === 200 &&
        (r.body.data as Array<{ messageId: string }>).some((i) => i.messageId === gateway.publicId),
    );
    const listed = (incidents.body.data as Array<{ messageId: string; scanId: string }>).map(
      (i) => [i.messageId, i.scanId],
    );
    expect(listed).toContainEqual([gateway.publicId, gatewayScan.toString()]);
    expect(listed.map(([m]) => m)).not.toContain(intake.publicId);
    expect(JSON.stringify(incidents.body)).not.toContain(intakeScan.toString());

    const subRoutes: Array<[string, string, object | undefined]> = [
      ['get', `scans/${intakeScan.toString()}/dlp-evidence`, undefined],
      ['post', `scans/${intakeScan.toString()}/risk/dry-run`, { profile: 'active' }],
      [
        'post',
        `scans/${intakeScan.toString()}/bec-feedback`,
        { kind: 'false_negative', reasonCodes: ['bec.reply_to.freemail'] },
      ],
    ];
    for (const [method, path, body] of subRoutes) {
      const res = await call(
        adminA,
        method as 'get' | 'post',
        `/api/v1/messages/${intake.publicId}/${path}`,
        body,
        false,
      );
      expect(res.status, `${path} ${JSON.stringify(res.body)}`).toBe(404);
      expect(res.body.code, path).toBe('message_not_found');
    }
    // Nothing was read or written for the intake message.
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, resourceId: intake.publicId },
      }),
    ).toBe(0);
    expect(await ctx.prisma.becFeedback.count({ where: { organizationId: orgA.id } })).toBe(0);
    // The evidence door's message lookup finds the gateway message and not the intake one.
    const results = ctx.get(DlpResultsRepository);
    const scope = systemScope(orgA.id);
    expect(await results.findMessage(ctx.prisma, scope, gateway.publicId)).toMatchObject({
      id: gateway.id,
    });
    expect(await results.findMessage(ctx.prisma, scope, intake.publicId)).toBeNull();

    // Platform scan training never feeds intake mail to the shared classifiers.
    const platform = await fx.createPlatformUser(['platform_admin']);
    const platformAuth = bearer((await loginWithMfa(ctx, fx, platform)).accessToken);
    const training = await call(
      platformAuth,
      'post',
      `/api/v1/platform/organizations/${orgA.publicId}/messages/${intake.publicId}/scan-training`,
      { operation: 'learn_spam', reason: 'integration intake training refusal' },
    );
    expect(training.status, JSON.stringify(training.body)).toBe(404);
    expect(training.body.code).toBe('message_not_found');
  });

  it('reports count gateway messages only; usage counts intake on its own', async () => {
    const from = new Date(
      Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate()),
    );
    const to = new Date(from.getTime() + 86_400_000);
    const traffic = await eventually(
      () =>
        call(
          adminA,
          'get',
          `/api/v1/reports/traffic?from=${encodeURIComponent(from.toISOString())}` +
            `&to=${encodeURIComponent(to.toISOString())}&granularity=day`,
        ),
      (r) => r.status === 200 && r.body.totals.total >= 1,
    );
    expect(traffic.body.totals.total).toBe(1);
    const usage = await eventually(
      () => call(adminA, 'get', `/api/v1/organizations/${orgA.publicId}/usage`),
      (r) => r.status === 200 && r.body.messages.journalIntakeToday === 1,
    );
    expect(usage.body.messages).toMatchObject({ today: 1, journalIntakeToday: 1 });
  });

  it('EXPLAIN: report counts stay index-only on the new index; the explorer keeps its plan', async () => {
    const scope = systemScope(orgA.id);
    const window = { from: new Date(Date.now() - 7 * 86_400_000), to: new Date() };
    const plans: Record<string, unknown> = {};
    for (const [name, sql] of [
      ['traffic', reportSql.traffic(scope, window, 'day', undefined, 10_000)],
      ['directions', reportSql.directions(scope, window, 10_000)],
      ['outcomes', reportSql.outcomes(scope, window, 10_000)],
      ['domainVerdicts', reportSql.domainVerdicts(scope, window, 10_000)],
    ] as const) {
      const { tables, text } = await explain(ctx, sql);
      const t = tables.find((x) => x.table_name === 'email_messages')!;
      expect(t.key, `${name} ${text}`).toBe('email_messages_org_received_dir_verdict_src_idx');
      expect(t.using_index, `${name} ${text}`).toBe(true);
      expect(text, name).toContain('ingest_source');
      plans[name] = { key: t.key, access_type: t.access_type, using_index: t.using_index };
    }
    const explorer = await explain(
      ctx,
      messagesPageSql({
        organizationId: orgA.id,
        range: window,
        direction: 'desc',
        nonce: 'it',
        driver: 'none',
        take: 26,
      }),
    );
    // The explorer statement aliases the table `m`.
    const m = explorer.tables.find((x) => x.table_name === 'm')!;
    expect(m.key, explorer.text).toBe('email_messages_organization_id_received_at_id_idx');
    expect(['range', 'ref']).toContain(m.access_type);
    expect(explorer.text).toContain('ingest_source');
    plans.explorer = { key: m.key, access_type: m.access_type };
    // Recorded in the step note §13.5 (index names and access types only).
    process.stdout.write(`EXPLAIN step 8.6: ${JSON.stringify(plans)}\n`);
  });
});

describe('the Journaling / Archive split on the real writer (D12)', () => {
  it('an organization admin cannot open archived records; the migrated admin (with compliance_officer) can', async () => {
    const id = randomUUID();
    const admin = await call(adminA, 'get', `/api/v1/archive/messages/${id}`);
    expect(admin.status).toBe(403);
    const officer = await call(officerA, 'get', `/api/v1/archive/messages/${id}`);
    expect(officer.status).toBe(404);
    expect(officer.body.code).toBe('archive_message_not_found');
    const reader = await call(readerA, 'get', `/api/v1/archive/messages/${id}`);
    expect(reader.status).toBe(403);
    expect((await call(readerA, 'get', '/api/v1/archive/settings')).status).toBe(200);
  });

  it('assigning compliance_officer is allowed to an organization admin and audited', async () => {
    const target = await fx.createUser(orgA, { roles: ['read_only_user'] });
    const res = await call(
      adminA,
      'put',
      `/api/v1/users/${target.publicId}/roles`,
      { roleKeys: ['read_only_user', 'compliance_officer'] },
      false,
    );
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const rows = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, action: { startsWith: 'rbac.archive_access_' } },
      select: { action: true, resourceId: true, metadata: true },
    });
    expect(rows).toEqual([
      expect.objectContaining({
        action: 'rbac.archive_access_granted',
        resourceId: target.publicId,
        metadata: expect.objectContaining({ roleKey: 'compliance_officer' }),
      }),
    ]);
    const removed = await call(
      adminA,
      'put',
      `/api/v1/users/${target.publicId}/roles`,
      { roleKeys: ['read_only_user'] },
      false,
    );
    expect(removed.status).toBe(200);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'rbac.archive_access_revoked' },
      }),
    ).toBe(1);
  });

  it('archive access is never self-granted, nor granted by an API key or without MFA (review fix)', async () => {
    const audited = () =>
      ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: { startsWith: 'rbac.archive_access_' } },
      });
    const before = await audited();
    // Self-grant in one call: refused, nothing changed.
    const self = await call(
      adminA,
      'put',
      `/api/v1/users/${adminAUser.publicId}/roles`,
      { roleKeys: ['organization_admin', 'compliance_officer'] },
      false,
    );
    expect(self.status, JSON.stringify(self.body)).toBe(403);
    expect(JSON.stringify(self.body)).toContain('cannot grant yourself archive access');
    const roles = await ctx.prisma.userRole.findMany({
      where: { userId: adminAUser.id },
      select: { role: { select: { key: true } } },
    });
    expect(roles.map((r) => r.role.key)).toEqual(['organization_admin']);

    const target = await fx.createUser(orgA, { roles: ['read_only_user'] });
    // An API key with every scope an organization admin's key can hold (user:manage included,
    // an API-key capable route) cannot delegate archive access.
    const adminScopes = SYSTEM_ROLES.find(
      (r) => r.key === 'organization_admin',
    )!.permissions.filter((p) => !['apikey:manage', 'role:manage', 'session:manage'].includes(p));
    const key = apiKeyHeader(await fx.createApiKey(orgA, [...adminScopes]));
    const byKey = await ctx.http
      .put(`/api/v1/users/${target.publicId}/roles`)
      .set(key)
      .set('X-Forwarded-For', uniqueIp())
      .send({ roleKeys: ['read_only_user', 'compliance_officer'] });
    expect(byKey.status, JSON.stringify(byKey.body)).toBe(403);
    expect(byKey.body.code).toBe('user_required');
    // An organization admin whose session has no MFA cannot either.
    const noMfaUser = await fx.createUser(orgA, { roles: ['organization_admin'] });
    const noMfa = bearer((await loginWithMfa(ctx, fx, noMfaUser)).accessToken);
    const withoutMfa = await call(
      noMfa,
      'put',
      `/api/v1/users/${target.publicId}/roles`,
      { roleKeys: ['read_only_user', 'compliance_officer'] },
      false,
    );
    expect(withoutMfa.status, JSON.stringify(withoutMfa.body)).toBe(403);
    expect(JSON.stringify(withoutMfa.body)).toContain('multi-factor');
    expect(withoutMfa.body.code).toBe('mfa_required');
    expect(await audited()).toBe(before);
    const targetRoles = await ctx.prisma.userRole.findMany({
      where: { userId: target.id },
      select: { role: { select: { key: true } } },
    });
    expect(targetRoles.map((r) => r.role.key)).toEqual(['read_only_user']);
  });
});

describe('archive-only profile and the reserved intake domain (D1, D13)', () => {
  it('/auth/me and the organization view return the service profile', async () => {
    const me = await call(adminArchiveOnly, 'get', '/api/v1/auth/me');
    expect(me.body.organization.serviceProfile).toBe('archive_only');
    const gw = await call(adminA, 'get', '/api/v1/auth/me');
    expect(gw.body.organization.serviceProfile).toBe('gateway');
    const view = await call(
      adminArchiveOnly,
      'get',
      `/api/v1/organizations/${orgArchiveOnly.publicId}`,
    );
    expect(view.body.serviceProfile).toBe('archive_only');
  });

  it('archive-only domains are created without inbound; inbound true is 403; the intake domain is reserved', async () => {
    const created = await call(
      adminArchiveOnly,
      'post',
      '/api/v1/domains',
      { name: `ao-${randomUUID().slice(0, 8)}.example.test` },
      false,
    );
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body).toMatchObject({ inboundEnabled: false });
    const refused = await call(
      adminArchiveOnly,
      'post',
      '/api/v1/domains',
      { name: `ao2-${randomUUID().slice(0, 8)}.example.test`, inboundEnabled: true },
      false,
    );
    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('mail_filtering_not_enabled');
    for (const name of [
      ctx.config.JOURNAL_INTAKE_DOMAIN!,
      `x.${ctx.config.JOURNAL_INTAKE_DOMAIN!}`,
    ]) {
      const res = await call(adminA, 'post', '/api/v1/domains', { name }, false);
      expect(res.status, name).toBe(422);
      expect(res.body.code).toBe('domain_reserved');
    }
  });
});

describe('organization purge of the journal intake tables', () => {
  it('deletes counters, intake messages and sources of one organization only', async () => {
    const source = await ctx.prisma.journalIntakeSource.findFirstOrThrow({
      where: { organizationId: orgA.id },
      select: { id: true },
    });
    await ctx.prisma.journalIntakeCounter.create({
      data: {
        organizationId: orgA.id,
        sourceId: source.id,
        day: new Date('2026-11-20'),
        accepted: 3,
      },
    });
    const otherSource = await call(adminB, 'post', SRC, {
      kind: 'smtp_bcc',
      displayName: 'B relay',
      networks: ['198.51.100.32/28'],
    });
    expect(otherSource.status, JSON.stringify(otherSource.body)).toBe(201);
    const repo = ctx.get(JournalIntakeTenantDataRepository);
    const counts = await repo.purgeOrganization(systemScope(orgA.id), 1);
    expect(counts.journal_intake_counters).toBe(1);
    expect(counts.journal_intake_messages).toBeGreaterThanOrEqual(1);
    expect(counts.journal_intake_sources).toBe(1);
    for (const model of [
      ctx.prisma.journalIntakeCounter,
      ctx.prisma.journalIntakeMessage,
      ctx.prisma.journalIntakeSource,
    ] as unknown as Array<{ count: (a: object) => Promise<number> }>) {
      expect(await model.count({ where: { organizationId: orgA.id } })).toBe(0);
    }
    expect(await ctx.prisma.journalIntakeSource.count({ where: { organizationId: orgB.id } })).toBe(
      1,
    );
    expect(
      Object.values(await repo.purgeOrganization(systemScope(orgA.id))).every((n) => n === 0),
    ).toBe(true);
  });
});
