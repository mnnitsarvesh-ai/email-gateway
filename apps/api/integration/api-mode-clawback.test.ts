/**
 * Step API-3 api on the real writer and replica (docs/plan/steps/37-api-mode-clawback-reporting.md
 * C6, C7, C9.1, C11, C13, C14, C15, §3.4, §9.4): admin clawbacks (Message-ID normalized to the
 * dedupe hash, a seeded campaign), the mailbox-worker's materialization simulated with SQL, the
 * target page with `remediation:purge` gating, submit below and above the organization threshold
 * (the `api_mode_purge_approval` outbox row and its `notification_alert_windows` throttle),
 * approval by a second user, deny, cancel and the bulk restore request (`quarantine:release`),
 * user reports (triage with group resolution, the `mail.report.feedback_requested.v1` rows and
 * the `reports_resolved` counter; the clawback from a report), report-mailbox designation (by
 * mailbox and by address, creating a discovered mailbox), the organization settings with CAS, the
 * overview and detection additions, cross-tenant 404s, the organization purge of the four tenant
 * tables in the §3.4 order and the assistant registry's API-3 reads. Synthetic `it-apiclaw-*`
 * organizations only.
 */
// @covers post /api/v1/api-mode/clawbacks
// @covers get /api/v1/api-mode/clawbacks
// @covers get /api/v1/api-mode/clawbacks/:clawbackId
// @covers get /api/v1/api-mode/clawbacks/:clawbackId/targets
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/submit
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/submit-hard-delete
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/approve
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/deny
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/cancel
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/restore
// @covers get /api/v1/api-mode/reports
// @covers get /api/v1/api-mode/reports/:reportId
// @covers post /api/v1/api-mode/reports/:reportId/triage
// @covers post /api/v1/api-mode/reports/:reportId/clawback
// @covers get /api/v1/api-mode/report-mailboxes
// @covers post /api/v1/api-mode/report-mailboxes
// @covers put /api/v1/api-mode/mailboxes/:mailboxId/report-mailbox
// @covers get /api/v1/api-mode/settings
// @covers put /api/v1/api-mode/settings
import { createHash, randomUUID } from 'node:crypto';
import { findTool, OPERATION_TOOLS } from '@email-gateway/assistant';
import { RedisService, S3Service, uuidv7 } from '@email-gateway/common';
import { EventTypes } from '@email-gateway/event-contracts';
import { copyMessageIdHash } from '@email-gateway/mailbox-api';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { KeyValueStore } from '../src/kv/key-value-store';
import {
  API_MODE_PURGE_ORDER,
  ApiModeTenantDataRepository,
} from '../src/modules/tenant-data/api-mode-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { InMemoryKeyValueStore } from '../test/support/in-memory-key-value-store';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa, uniqueIp } from './support/http';
import { deleteMessagesData } from './support/messages-data';
import { insertDomain, type InsertedDomain } from './support/smtp';

const BASE = '/api/v1/api-mode';
const REASON = 'Integration: clawback';
const POLL = { timeout: 15_000, interval: 200 };
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let admin2A: Record<string, string>;
let readerA: Record<string, string>;
let remediatorA: Record<string, string>;
let adminB: Record<string, string>;
let worldA: World;
let worldB: World;

interface World {
  org: FixtureOrganization;
  domain: InsertedDomain;
  connectionId: bigint;
  apiConnectionId: bigint;
  mailboxes: Array<{ id: bigint; publicId: string; address: string }>;
}

interface SeededCopy {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  messageId: bigint;
  mailboxId: bigint;
}

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'put',
  path: string,
  body?: object,
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (method !== 'get') req = req.set('Idempotency-Key', `it-${randomUUID()}`);
  return body === undefined ? req : req.send(body);
}

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

/** A bound connection with the active grant, its API-mode row, an `api` domain and mailboxes. */
async function seedWorld(org: FixtureOrganization, mailboxCount: number): Promise<World> {
  const p = ctx.prisma;
  const domain = await insertDomain(ctx, org, { status: 'verified', label: 'apiclaw' });
  await p.domain.update({ where: { id: domain.id }, data: { protectionMode: 'api' } });
  const connection = await p.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `Clawback ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: '7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f',
      activeTenantKey: `microsoft_365:${randomUUID()}`,
      tenantVerifiedAt: new Date(),
    },
    select: { id: true },
  });
  await p.providerConnectionGrant.create({
    data: {
      organizationId: org.id,
      connectionId: connection.id,
      profile: 'm365.mailbox_remediation',
      profileVersion: 1,
      authMethod: 'platform_app',
      status: 'active',
      requestedPermissions: ['Mail.ReadWrite', 'User.Read.All'],
      observedPermissions: ['Mail.ReadWrite', 'User.Read.All'],
      verifiedAt: new Date(),
    },
  });
  await p.providerConnectionDomain.create({
    data: { organizationId: org.id, connectionId: connection.id, domainId: domain.id },
  });
  const api = await p.apiModeConnection.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      providerConnectionId: connection.id,
      provider: 'microsoft_365',
      healthStatus: 'healthy',
    },
    select: { id: true },
  });
  const mailboxes: World['mailboxes'] = [];
  for (let i = 0; i < mailboxCount; i += 1) {
    const address = `claw${i}-${randomUUID().slice(0, 6)}@${domain.name}`;
    const publicId = uuidv7();
    const mailbox = await p.apiMailbox.create({
      data: {
        publicId,
        organizationId: org.id,
        apiConnectionId: api.id,
        providerUserId: `user-${randomUUID()}`,
        primaryAddress: address,
        domainId: domain.id,
        status: 'active',
        coverageState: 'covered',
      },
      select: { id: true },
    });
    mailboxes.push({ id: mailbox.id, publicId, address });
  }
  return { org, domain, connectionId: connection.id, apiConnectionId: api.id, mailboxes };
}

/** A scanned copy of one Message-ID in a mailbox, with its registry message and recipient row. */
async function seedCopy(
  w: World,
  mailbox: World['mailboxes'][number],
  internetMessageId: string,
  patch: { direction?: 'inbound' | 'internal' } = {},
): Promise<SeededCopy> {
  const p = ctx.prisma;
  const receivedAt = new Date(Date.now() - 3_600_000 - Math.floor(Math.random() * 60_000));
  const identity = await p.messageIdentity.create({
    data: { organizationId: w.org.id, ingestKey: `v2:mbx:${sha256(randomUUID())}`, receivedAt },
    select: { id: true },
  });
  await p.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: w.org.id,
      domainId: w.domain.id,
      direction: patch.direction ?? 'inbound',
      status: 'journaled',
      statusChangedAt: receivedAt,
      version: 2,
      ingestSource: 'mailbox_api',
      envelopeFrom: 'billing@fabrikam.example',
      headerFrom: 'billing@fabrikam.example',
      subject: 'RE: Invoice overdue',
      internetMessageId,
      sizeBytes: 1024,
      recipientCount: 1,
      attachmentCount: 0,
      emlObjectKey: `org/${w.org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha256('copy'),
    },
  });
  await p.emailRecipient.create({
    data: {
      receivedAt,
      messageId: identity.id,
      organizationId: w.org.id,
      rcptSeq: 0,
      address: mailbox.address,
      status: 'journaled',
      direction: patch.direction ?? 'inbound',
    },
  });
  const publicId = uuidv7();
  const copy = await p.apiMessageCopy.create({
    data: {
      publicId,
      receivedAt,
      organizationId: w.org.id,
      apiConnectionId: w.apiConnectionId,
      mailboxId: mailbox.id,
      messageId: identity.id,
      messageIdHash: copyMessageIdHash(w.org.id, internetMessageId),
      direction: patch.direction ?? 'inbound',
      source: 'journal',
      seenJournal: true,
      status: 'scanned',
      verdict: 'phishing',
      riskScore: 910,
      verdictAt: new Date(receivedAt.getTime() + 5_000),
    },
    select: { id: true },
  });
  return { id: copy.id, publicId, receivedAt, messageId: identity.id, mailboxId: mailbox.id };
}

/** What the mailbox-worker's `clawback` role leaves after materializing a search (C4.3, C5.2). */
async function materialize(w: World, clawbackPublicId: string, copies: SeededCopy[]) {
  const p = ctx.prisma;
  const row = await p.apiClawback.findUniqueOrThrow({ where: { publicId: clawbackPublicId } });
  for (const c of copies) {
    await p.apiClawbackTarget.create({
      data: {
        clawbackId: row.id,
        organizationId: w.org.id,
        apiConnectionId: w.apiConnectionId,
        mailboxId: c.mailboxId,
        copyId: c.id,
        copyReceivedAt: c.receivedAt,
        messageId: c.messageId,
        matchKeys: ['message_id'],
        status: 'matched',
      },
    });
  }
  const mailboxes = new Set(copies.map((c) => c.mailboxId)).size;
  await p.apiClawback.update({
    where: { id: row.id },
    data: {
      status: 'ready',
      targetsTotal: copies.length,
      mailboxesTotal: mailboxes,
      targetsEligible: copies.length,
      mailboxesEligible: mailboxes,
      rowVersion: { increment: 1 },
    },
  });
  return p.apiClawback.findUniqueOrThrow({ where: { id: row.id } });
}

/** A user report as the mailbox-worker's `reports` role leaves it (`pending_triage`). */
async function seedReport(
  w: World,
  reportMailboxId: bigint,
  copy: SeededCopy,
  internetMessageId: string,
  reporter: string,
) {
  const hash = copyMessageIdHash(w.org.id, internetMessageId)!;
  return ctx.prisma.apiUserReport.create({
    data: {
      publicId: uuidv7(),
      organizationId: w.org.id,
      apiConnectionId: w.apiConnectionId,
      reportMailboxId,
      reportCopyId: copy.id,
      reportCopyReceivedAt: copy.receivedAt,
      reportMessageId: copy.messageId,
      reporterAddress: reporter,
      status: 'pending_triage',
      identification: 'attachment',
      original: {
        v: 1,
        messageIdHash: hash,
        sender: 'billing@fabrikam.example',
        subjectKey: 'Invoice overdue',
        date: new Date(Date.now() - 2 * 3_600_000).toISOString(),
        attachmentSha256: [],
        urlSha256: [],
        extraOriginals: 0,
      },
      originalMessageIdHash: hash,
      groupKey: hash,
      scanVerdict: 'phishing',
      scanRiskScore: 910,
      scanLevel: 'critical',
      assessment: 'malicious',
      ackFeedback: 'queued',
      reportedAt: copy.receivedAt,
    },
  });
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
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization({ planCode: 'enterprise', slugPrefix: 'apiclaw' });
  orgB = await fx.createOrganization({ planCode: 'enterprise', slugPrefix: 'apiclaw' });
  const login = async (org: FixtureOrganization, roles: string[]) => {
    const user = await fx.createUser(org, { roles, mfa: true });
    return bearer((await loginWithMfa(ctx, fx, user)).accessToken);
  };
  adminA = await login(orgA, ['organization_admin']);
  admin2A = await login(orgA, ['organization_admin']);
  readerA = await login(orgA, ['read_only_user']);
  remediatorA = await login(orgA, [
    await fx.createCustomRole(orgA, ['remediation:read', 'remediation:write']),
  ]);
  adminB = await login(orgB, ['organization_admin']);
  worldA = await seedWorld(orgA, 4);
  worldB = await seedWorld(orgB, 1);

  const orgs = [orgA, orgB];
  fx.registerCleanup(async () => {
    const where = { organizationId: { in: orgs.map((o) => o.id) } };
    for (const org of orgs) {
      await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(org.id));
      await ctx.get(ProviderTenantDataRepository).purgeOrganization(systemScope(org.id));
    }
    await ctx.prisma.messageOutbox.deleteMany({ where });
    await ctx.prisma.notificationAlertWindow.deleteMany({ where });
    await deleteMessagesData(
      ctx,
      orgs.map((o) => o.id),
    );
    await ctx.prisma.auditLog.deleteMany({ where });
  });
}, 120_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('clawbacks on the writer (C14 #1-#10)', () => {
  it('create → materialized → targets (gated) → submit below the threshold → cancel request', async () => {
    const mid = `<it-claw-${randomUUID()}@fabrikam.example>`;
    const copies = [
      await seedCopy(worldA, worldA.mailboxes[0]!, mid),
      await seedCopy(worldA, worldA.mailboxes[1]!, mid, { direction: 'internal' }),
    ];
    const window = {
      from: new Date(Date.now() - 86_400_000).toISOString(),
      to: new Date().toISOString(),
    };
    const created = await call(adminA, 'post', `${BASE}/clawbacks`, {
      criteria: { messageId: mid, ...window },
      reason: REASON,
    });
    expect(created.status, JSON.stringify(created.body)).toBe(202);
    const row = await ctx.prisma.apiClawback.findUniqueOrThrow({
      where: { publicId: created.body.id },
    });
    expect(row).toMatchObject({ organizationId: orgA.id, trigger: 'admin', status: 'searching' });
    expect((row.criteria as { keys: object }).keys).toEqual({
      messageIdHashes: [copyMessageIdHash(orgA.id, mid)],
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: orgA.id,
        action: 'api_mode.clawback_created',
        resourceId: row.publicId,
      },
    });
    expect(JSON.stringify(audit.metadata)).not.toContain('fabrikam');

    const ready = await materialize(worldA, row.publicId, copies);
    const masked = await eventually(
      () => call(readerA, 'get', `${BASE}/clawbacks/${row.publicId}/targets`),
      (res) => res.body.data?.length === 2,
    );
    expect(masked.body.data[0]).toMatchObject({ headerFrom: null, subject: null });
    expect(masked.body.data[0].mailbox.address).toContain('***@');
    const full = await call(adminA, 'get', `${BASE}/clawbacks/${row.publicId}/targets`);
    expect(full.body.data[0]).toMatchObject({
      headerFrom: 'billing@fabrikam.example',
      subject: 'RE: Invoice overdue',
    });

    const submit = await call(adminA, 'post', `${BASE}/clawbacks/${row.publicId}/submit`, {
      mode: 'explicit',
      action: 'move_junk',
      reason: REASON,
      expectedRowVersion: ready.rowVersion,
    });
    expect(submit.status, JSON.stringify(submit.body)).toBe(202);
    expect(submit.body).toMatchObject({ status: 'queued', requiresApproval: false });
    const queued = await ctx.prisma.apiClawback.findUniqueOrThrow({ where: { id: row.id } });
    expect(queued).toMatchObject({
      status: 'queued',
      decisionMode: 'explicit',
      action: 'move_junk',
      approvalStatus: null,
    });
    expect(queued.nextStepAt).not.toBeNull();
    const stale = await call(adminA, 'post', `${BASE}/clawbacks/${row.publicId}/submit`, {
      mode: 'policy',
      reason: REASON,
      expectedRowVersion: ready.rowVersion,
    });
    expect(stale.status).toBe(409);

    const cancel = await call(adminA, 'post', `${BASE}/clawbacks/${row.publicId}/cancel`, {
      reason: REASON,
    });
    expect(cancel.body).toMatchObject({ status: 'queued', cancelRequested: true });
    // The api never queued a mailbox action itself (the worker does, C-I1).
    expect(await ctx.prisma.apiRemediationAction.count({ where: { clawbackId: row.id } })).toBe(0);
  });

  it('above the threshold: pending_approval, one alert row, the requester refused, a second admin approves', async () => {
    const mid = `<it-claw-${randomUUID()}@fabrikam.example>`;
    const copies = [];
    for (const m of worldA.mailboxes) copies.push(await seedCopy(worldA, m, mid));
    const settings = await call(adminA, 'put', `${BASE}/settings`, {
      internalMailEnabled: true,
      autoClawback: 'enforce',
      autoMaxMailboxes: 500,
      purgeApprovalMailboxes: 2,
      clawbackLookbackDays: 14,
      tiMinConfidence: 80,
      reportAckEnabled: true,
      reportFeedbackEnabled: true,
      reason: REASON,
      expectedRowVersion: null,
    });
    expect(settings.status, JSON.stringify(settings.body)).toBe(200);
    const created = await call(adminA, 'post', `${BASE}/clawbacks`, {
      criteria: {
        messageId: mid,
        from: new Date(Date.now() - 86_400_000).toISOString(),
        to: new Date().toISOString(),
      },
      reason: REASON,
    });
    const ready = await materialize(worldA, created.body.id, copies);
    const submit = await call(adminA, 'post', `${BASE}/clawbacks/${created.body.id}/submit`, {
      mode: 'policy',
      verdict: 'phishing',
      reason: REASON,
      expectedRowVersion: ready.rowVersion,
    });
    expect(submit.body).toMatchObject({
      status: 'pending_approval',
      approvalReasons: ['mailbox_threshold'],
    });
    const alerts = await ctx.prisma.messageOutbox.findMany({
      where: {
        organizationId: orgA.id,
        eventType: EventTypes.NotificationAlertRequested,
        correlationId: `api-mode-clawback:${created.body.id}`,
      },
    });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.payload).toMatchObject({
      kind: 'api_mode_purge_approval',
      refs: { clawbackId: created.body.id },
    });
    expect(
      await ctx.prisma.notificationAlertWindow.count({
        where: { organizationId: orgA.id, scopeKey: created.body.id },
      }),
    ).toBe(1);
    const own = await call(adminA, 'post', `${BASE}/clawbacks/${created.body.id}/approve`, {
      reason: REASON,
      expectedRowVersion: submit.body.rowVersion,
    });
    expect(own.status).toBe(403);
    expect(own.body.reason).toBe('requester');
    const approve = await call(admin2A, 'post', `${BASE}/clawbacks/${created.body.id}/approve`, {
      reason: 'Second pair of eyes',
      expectedRowVersion: submit.body.rowVersion,
    });
    expect(approve.status, JSON.stringify(approve.body)).toBe(200);
    expect(approve.body).toMatchObject({ status: 'queued', approval: { status: 'approved' } });
    const row = await ctx.prisma.apiClawback.findUniqueOrThrow({
      where: { publicId: created.body.id },
    });
    expect(row.approverPermissionsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.approvedByUserId).not.toBeNull();
    expect(row.signalVerdict).toBe('phishing');
    // Hard delete stays off on this platform.
    const hard = await call(
      adminA,
      'post',
      `${BASE}/clawbacks/${created.body.id}/submit-hard-delete`,
      {
        reason: REASON,
        expectedRowVersion: row.rowVersion,
      },
    );
    expect(hard.status).toBe(422);
    // Deny of another pending clawback.
    const other = await call(adminA, 'post', `${BASE}/clawbacks`, {
      criteria: {
        messageId: `<other-${randomUUID()}@fabrikam.example>`,
        from: new Date(Date.now() - 86_400_000).toISOString(),
        to: new Date().toISOString(),
      },
      reason: REASON,
    });
    const otherReady = await materialize(worldA, other.body.id, copies.slice(0, 3));
    const otherSubmit = await call(adminA, 'post', `${BASE}/clawbacks/${other.body.id}/submit`, {
      mode: 'explicit',
      action: 'move_quarantine',
      reason: REASON,
      expectedRowVersion: otherReady.rowVersion,
    });
    const deny = await call(admin2A, 'post', `${BASE}/clawbacks/${other.body.id}/deny`, {
      reason: 'Not this one',
      expectedRowVersion: otherSubmit.body.rowVersion,
    });
    expect(deny.body).toMatchObject({ status: 'denied' });
    // Settings back to the defaults for the other tests (CAS on the stored version).
    const current = await call(adminA, 'get', `${BASE}/settings`);
    await call(adminA, 'put', `${BASE}/settings`, {
      ...current.body.settings,
      purgeApprovalMailboxes: 50,
      reason: REASON,
      expectedRowVersion: current.body.rowVersion,
    });
  });

  it('a threshold raised by an admin still needs a second approver for that admin’s purges', async () => {
    const resetSettings = () =>
      ctx.prisma.apiModeOrgSetting.updateMany({
        where: { organizationId: orgA.id },
        data: {
          purgeApprovalMailboxes: 2,
          purgeApprovalRaisedBy: null,
          purgeApprovalBeforeRaise: null,
        },
      });
    await resetSettings();
    const current = await call(adminA, 'get', `${BASE}/settings`);
    const raised = await call(adminA, 'put', `${BASE}/settings`, {
      ...current.body.settings,
      purgeApprovalMailboxes: 1000,
      reason: REASON,
      expectedRowVersion: current.body.rowVersion,
    });
    expect(raised.status, JSON.stringify(raised.body)).toBe(200);
    const stored = await ctx.prisma.apiModeOrgSetting.findUniqueOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(stored).toMatchObject({ purgeApprovalMailboxes: 1000, purgeApprovalBeforeRaise: 2 });
    expect(stored.purgeApprovalRaisedBy).toMatch(/^user:[0-9a-f-]{36}$/);

    const submitAs = async (who: Record<string, string>, eligible: number) => {
      const mid = `<it-claw-${randomUUID()}@fabrikam.example>`;
      const copies = [];
      for (const m of worldA.mailboxes.slice(0, eligible)) {
        copies.push(await seedCopy(worldA, m, mid));
      }
      const created = await call(who, 'post', `${BASE}/clawbacks`, {
        criteria: {
          messageId: mid,
          from: new Date(Date.now() - 86_400_000).toISOString(),
          to: new Date().toISOString(),
        },
        reason: REASON,
      });
      const ready = await materialize(worldA, created.body.id, copies);
      return call(who, 'post', `${BASE}/clawbacks/${created.body.id}/submit`, {
        mode: 'explicit',
        action: 'move_junk',
        reason: REASON,
        expectedRowVersion: ready.rowVersion,
      });
    };
    // The raiser is still checked against 2 mailboxes; another admin against 1000.
    const own = await submitAs(adminA, 3);
    expect(own.body).toMatchObject({
      status: 'pending_approval',
      approvalReasons: ['mailbox_threshold'],
    });
    const other = await submitAs(admin2A, 3);
    expect(other.body).toMatchObject({ status: 'queued', requiresApproval: false });
    await resetSettings();
    await ctx.prisma.apiModeOrgSetting.updateMany({
      where: { organizationId: orgA.id },
      data: { purgeApprovalMailboxes: 50 },
    });
  });

  it('restore needs quarantine:release; lists, detail, cursors and cross-tenant 404', async () => {
    const mid = `<it-claw-${randomUUID()}@fabrikam.example>`;
    const copy = await seedCopy(worldA, worldA.mailboxes[2]!, mid);
    const created = await call(adminA, 'post', `${BASE}/clawbacks`, {
      seedDetectionId: copy.publicId,
      expand: { senderSubjectHours: 24 },
      reason: REASON,
    });
    expect(created.status, JSON.stringify(created.body)).toBe(202);
    expect(created.body.trigger).toBe('campaign');
    const stored = await ctx.prisma.apiClawback.findUniqueOrThrow({
      where: { publicId: created.body.id },
    });
    expect((stored.criteria as { keys: { senderSubject?: object } }).keys.senderSubject).toEqual({
      sender: 'billing@fabrikam.example',
      subjectKey: 'Invoice overdue',
    });
    await ctx.prisma.apiClawback.update({
      where: { id: stored.id },
      data: { status: 'completed', targetsSucceeded: 1, completedAt: new Date() },
    });
    const noRelease = await call(
      remediatorA,
      'post',
      `${BASE}/clawbacks/${created.body.id}/restore`,
      {
        reason: REASON,
      },
    );
    expect(noRelease.status).toBe(403);
    const restore = await call(adminA, 'post', `${BASE}/clawbacks/${created.body.id}/restore`, {
      reason: REASON,
    });
    expect(restore.body.restore.status).toBe('requested');
    const list = await eventually(
      () => call(adminA, 'get', `${BASE}/clawbacks`).query({ limit: '1' }),
      (res) => res.body.data?.length === 1 && typeof res.body.nextCursor === 'string',
    );
    const next = await call(adminA, 'get', `${BASE}/clawbacks`).query({
      limit: '1',
      cursor: list.body.nextCursor,
    });
    expect(next.status).toBe(200);
    expect(next.body.data[0].id).not.toBe(list.body.data[0].id);
    const detail = await eventually(
      () => call(adminA, 'get', `${BASE}/clawbacks/${created.body.id}`),
      (res) => res.body.restore?.status === 'requested',
    );
    expect(detail.body.signal.seedDetectionId).toBe(copy.publicId);
    for (const path of [
      `${BASE}/clawbacks/${created.body.id}`,
      `${BASE}/clawbacks/${created.body.id}/targets`,
    ]) {
      expect((await call(adminB, 'get', path)).status, path).toBe(404);
    }
    const foreign = await call(adminB, 'post', `${BASE}/clawbacks/${created.body.id}/cancel`, {
      reason: REASON,
    });
    expect(foreign.status).toBe(404);
    const seedForeign = await call(adminB, 'post', `${BASE}/clawbacks`, {
      seedDetectionId: copy.publicId,
      reason: REASON,
    });
    expect(seedForeign.status).toBe(404);
    const listB = await call(adminB, 'get', `${BASE}/clawbacks`);
    expect(listB.body.data.map((k: { id: string }) => k.id)).not.toContain(created.body.id);
    // The detection shows the clawback; the overview counts it.
    const detection = await eventually(
      () => call(adminA, 'get', `${BASE}/detections/${copy.publicId}`),
      (res) => res.status === 200,
    );
    expect(detection.body).toMatchObject({ direction: 'inbound', verdictRevision: 0 });
    const overview = await eventually(
      () => call(adminA, 'get', `${BASE}/overview`),
      (res) => (res.body.clawback?.completed24h ?? 0) >= 1,
    );
    expect(overview.body.internal).toEqual({ copies24h: 0, enabled: true });
  });
});

describe('user reports and report mailboxes on the writer (C14 #11-#17)', () => {
  it('designate a report mailbox, triage a group with feedback rows and counters, clawback from a report', async () => {
    const reportMailbox = worldA.mailboxes[3]!;
    const designate = await call(
      remediatorA,
      'put',
      `${BASE}/mailboxes/${reportMailbox.publicId}/report-mailbox`,
      { enabled: true, reason: REASON },
    );
    expect(designate.status, JSON.stringify(designate.body)).toBe(200);
    expect(designate.body.mailbox.reportMailbox).toBe(true);
    const byAddress = await call(remediatorA, 'post', `${BASE}/report-mailboxes`, {
      address: `abuse-${randomUUID().slice(0, 6)}@${worldA.domain.name}`,
      reason: REASON,
    });
    expect(byAddress.status, JSON.stringify(byAddress.body)).toBe(200);
    expect(byAddress.body).toMatchObject({ created: true, mailbox: { status: 'discovered' } });
    const outOfScope = await call(remediatorA, 'post', `${BASE}/report-mailboxes`, {
      address: 'someone@not-ours.example',
      reason: REASON,
    });
    expect(outOfScope.status).toBe(422);
    const listMailboxes = await eventually(
      () => call(readerA, 'get', `${BASE}/report-mailboxes`),
      (res) => res.body.data?.length === 2,
    );
    expect(listMailboxes.body.max).toBe(5);

    const mid = `<it-report-${randomUUID()}@fabrikam.example>`;
    const reportCopy1 = await seedCopy(worldA, reportMailbox, `<r1-${randomUUID()}@x.example>`);
    const reportCopy2 = await seedCopy(worldA, reportMailbox, `<r2-${randomUUID()}@x.example>`);
    const r1 = await seedReport(worldA, reportMailbox.id, reportCopy1, mid, 'sam@x.example');
    const r2 = await seedReport(worldA, reportMailbox.id, reportCopy2, mid, 'kim@x.example');
    const triage = await call(remediatorA, 'post', `${BASE}/reports/${r1.publicId}/triage`, {
      status: 'resolved',
      verdict: 'malicious',
      note: 'Phishing kit',
      expectedRowVersion: r1.rowVersion,
    });
    expect(triage.status, JSON.stringify(triage.body)).toBe(200);
    expect(triage.body).toMatchObject({ groupResolved: 1, feedbackQueued: 2 });
    const rows = await ctx.prisma.apiUserReport.findMany({
      where: { id: { in: [r1.id, r2.id] } },
    });
    expect(rows.every((r) => r.status === 'resolved' && r.resultFeedback === 'queued')).toBe(true);
    const feedback = await ctx.prisma.messageOutbox.findMany({
      where: { organizationId: orgA.id, eventType: EventTypes.ReportFeedbackRequested },
    });
    expect(feedback.map((f) => (f.payload as { reportId: string }).reportId).sort()).toEqual(
      [r1.publicId, r2.publicId].sort(),
    );
    const counter = await ctx.prisma.apiModeCounter.aggregate({
      where: { organizationId: orgA.id, apiConnectionId: worldA.apiConnectionId },
      _sum: { reportsResolved: true },
    });
    expect(counter._sum.reportsResolved).toBeGreaterThanOrEqual(2);
    const detail = await eventually(
      () => call(readerA, 'get', `${BASE}/reports/${r1.publicId}`),
      (res) => res.body.status === 'resolved' && res.body.history?.length === 1,
    );
    expect(detail.body).toMatchObject({
      analyst: { verdict: 'malicious', note: 'Phishing kit' },
      group: { size: 2 },
      history: [expect.objectContaining({ from: 'pending_triage', to: 'resolved' })],
    });
    const clawback = await call(adminA, 'post', `${BASE}/reports/${r1.publicId}/clawback`, {
      reason: REASON,
    });
    expect(clawback.status, JSON.stringify(clawback.body)).toBe(202);
    expect(clawback.body.trigger).toBe('report');
    const linked = await ctx.prisma.apiUserReport.findUniqueOrThrow({ where: { id: r1.id } });
    const k = await ctx.prisma.apiClawback.findUniqueOrThrow({
      where: { publicId: clawback.body.clawbackId },
    });
    expect(linked.clawbackId).toBe(k.id);
    expect(k.reportId).toBe(r1.id);
    const list = await eventually(
      () => call(readerA, 'get', `${BASE}/reports`).query({ status: 'resolved' }),
      (res) => (res.body.data?.length ?? 0) >= 2,
    );
    expect(list.body.data[0].groupSize).toBe(2);
    for (const [method, path, body] of [
      ['get', `${BASE}/reports/${r1.publicId}`],
      [
        'post',
        `${BASE}/reports/${r1.publicId}/triage`,
        { status: 'in_review', expectedRowVersion: 1 },
      ],
      ['post', `${BASE}/reports/${r1.publicId}/clawback`, { reason: REASON }],
      [
        'put',
        `${BASE}/mailboxes/${reportMailbox.publicId}/report-mailbox`,
        { enabled: false, reason: REASON },
      ],
    ] as Array<['get' | 'post' | 'put', string, object?]>) {
      expect((await call(adminB, method, path, body)).status, path).toBe(404);
    }
    const overview = await eventually(
      () => call(readerA, 'get', `${BASE}/overview`),
      (res) => (res.body.reports?.reportMailboxes ?? 0) === 2,
    );
    expect(overview.body.reports.resolved24h).toBeGreaterThanOrEqual(2);
  });
});

describe('organization purge of the API-3 tables (§3.4)', () => {
  it('deletes targets, clawbacks, reports and settings of the organization only, in the §3.4 order', async () => {
    const at = (t: (typeof API_MODE_PURGE_ORDER)[number]) => API_MODE_PURGE_ORDER.indexOf(t);
    expect(at('api_user_reports')).toBeLessThan(at('api_remediation_actions'));
    const mid = `<it-purge-${randomUUID()}@fabrikam.example>`;
    const copy = await seedCopy(worldB, worldB.mailboxes[0]!, mid);
    const created = await call(adminB, 'post', `${BASE}/clawbacks`, {
      criteria: {
        messageId: mid,
        from: new Date(Date.now() - 86_400_000).toISOString(),
        to: new Date().toISOString(),
      },
      reason: REASON,
    });
    await materialize(worldB, created.body.id, [copy]);
    await ctx.prisma.apiMailbox.update({
      where: { id: worldB.mailboxes[0]!.id },
      data: { reportMailbox: true, reportMailboxAt: new Date() },
    });
    await seedReport(worldB, worldB.mailboxes[0]!.id, copy, mid, 'x@y.example');
    await ctx.prisma.apiModeOrgSetting.create({ data: { organizationId: orgB.id } });
    const beforeA = await ctx.prisma.apiClawback.count({ where: { organizationId: orgA.id } });
    const counts = await ctx
      .get(ApiModeTenantDataRepository)
      .purgeOrganization(systemScope(orgB.id), 1);
    expect(counts).toMatchObject({
      api_clawback_targets: 1,
      api_clawbacks: 1,
      api_user_reports: 1,
      api_mode_org_settings: 1,
      api_mailboxes: 1,
      api_mode_connections: 1,
    });
    const byB = { where: { organizationId: orgB.id } };
    expect(
      await Promise.all([
        ctx.prisma.apiClawbackTarget.count(byB),
        ctx.prisma.apiClawback.count(byB),
        ctx.prisma.apiUserReport.count(byB),
        ctx.prisma.apiModeOrgSetting.count(byB),
      ]),
    ).toEqual([0, 0, 0, 0]);
    expect(await ctx.prisma.apiClawback.count({ where: { organizationId: orgA.id } })).toBe(
      beforeA,
    );
    expect(
      Object.values(
        await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(orgB.id)),
      ),
    ).toEqual(Array(12).fill(0));
  });
});

describe('assistant registry (C15)', () => {
  it('the seven API-3 reads are enabled read tools; hard delete is not a tool', () => {
    for (const id of [
      'ApiModeClawbackController_list_v1',
      'ApiModeClawbackController_detail_v1',
      'ApiModeClawbackController_targets_v1',
      'ApiModeReportsController_list_v1',
      'ApiModeReportsController_detail_v1',
      'ApiModeReportsController_listMailboxes_v1',
      'ApiModeSettingsController_get_v1',
    ]) {
      const tool = OPERATION_TOOLS.find((t) => t.operationId === id);
      expect(tool?.enabled, id).toBe(true);
      expect(tool?.access, id).toBe('read');
    }
    expect(
      OPERATION_TOOLS.find(
        (t) => t.operationId === 'ApiModeClawbackController_submitHardDelete_v1',
      ),
    ).toBeUndefined();
    expect(findTool('api_mode_clawback_submit')?.risk).toBe('high');
  });
});
