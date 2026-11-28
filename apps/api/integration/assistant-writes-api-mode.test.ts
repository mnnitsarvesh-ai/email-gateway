/**
 * Step API-3 API-mode write tools through chat (docs/plan/steps/37-api-mode-clawback-reporting.md
 * C15, §9.4; the `testedBy` of the 20 API-mode writes in
 * docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md). Each write is proposed through a directive turn
 * (the deterministic fake provider; never a real LLM) by an MFA-enrolled `organization_admin` and
 * confirmed through the confirm route (password + TOTP for the high-risk ones); the api's own
 * state and the operation's own audit row (correlated to the result execution) are asserted on
 * the writer:
 *
 * - remediation: remediate (medium), restore of a tag (high), retry of a failed action (low),
 *   organization policy put (high; `expectedRowVersion: null` creates), domain policy put and
 *   delete (high);
 * - connection: settings with the CAS version injected from the read (high; the remediation
 *   pause), inventory sync and mailbox resync (low);
 * - clawbacks: create (medium), submit (high: re-authentication), approve (high) and deny (low)
 *   of another administrator's purge, cancel (medium), bulk restore (high);
 * - the four-eyes guard: the requester's own approve is `denied_guard` before anything is stored;
 * - the hard-delete purge is never a tool (`denied_not_applicable`, no loopback request);
 * - reports: triage (medium; the result feedback row), clawback from a report (medium), report
 *   mailbox by address and by id (medium); the organization settings put (high).
 * - step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md B10): the mailbox scope put
 *   (high: narrowing removes protection; re-authenticated) and the ownership check of a pending
 *   domain through the bound provider tenant (low).
 *
 * Synthetic `it-apiclaw-*` organizations and `.test` names only; nothing reaches a provider (the
 * api only writes the rows the mailbox-worker executes).
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/api-mode/detections/:detectionId/remediate
// @covers post /api/v1/api-mode/detections/:detectionId/restore
// @covers post /api/v1/api-mode/remediations/:remediationId/retry
// @covers put /api/v1/api-mode/remediation-policy
// @covers put /api/v1/api-mode/remediation-policy/domains/:domainId
// @covers delete /api/v1/api-mode/remediation-policy/domains/:domainId
// @covers put /api/v1/api-mode/connections/:connectionId/settings
// @covers post /api/v1/api-mode/connections/:connectionId/inventory-sync
// @covers post /api/v1/api-mode/mailboxes/:mailboxId/resync
// @covers post /api/v1/api-mode/clawbacks
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/submit
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/approve
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/deny
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/cancel
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/restore
// @covers post /api/v1/api-mode/reports/:reportId/triage
// @covers post /api/v1/api-mode/reports/:reportId/clawback
// @covers post /api/v1/api-mode/report-mailboxes
// @covers put /api/v1/api-mode/mailboxes/:mailboxId/report-mailbox
// @covers put /api/v1/api-mode/settings
// @covers put /api/v1/api-mode/domains/:domainId/scope
// @covers post /api/v1/domains/:domainId/ownership/provider-check
import { createHash, randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import { EventTypes } from '@email-gateway/event-contracts';
import { copyMessageIdHash, remediationActionKey } from '@email-gateway/mailbox-api';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { ApiModeTenantDataRepository } from '../src/modules/tenant-data/api-mode-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  auditByCorrelation,
  type ChatWrite,
  clearAssistantCounters,
  createAssistantApp,
  directive,
  enableAssistant,
  expectExecuted,
  member,
  type Member,
  newConversation,
  platformMember,
  proposeAndConfirm,
  recordLoopback,
  resultCorrelationId,
  turn,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { deleteMessagesData } from './support/messages-data';
import { insertDomain, type InsertedDomain } from './support/smtp';

const REASON = 'Chat: API-mode write';
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: Member;
let admin2: Member;
let world: World;

interface World {
  domain: InsertedDomain;
  connectionPublicId: string;
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

const chat = (
  tool: string,
  args: Record<string, unknown>,
  who: Member = admin,
): Promise<ChatWrite> => proposeAndConfirm(ctx, fx, who, tool, args);

/** The operation's own audit row (this organization, the result execution's correlation id). */
async function audited(result: ChatWrite, action: string, who: Member = admin) {
  const correlationId = await resultCorrelationId(ctx, result.res);
  const rows = (await auditByCorrelation(ctx, org.id, correlationId)).filter(
    (r) => r.action === action,
  );
  expect(rows, action).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(who.user.publicId);
  return rows[0]!;
}

async function seedWorld(): Promise<World> {
  const p = ctx.prisma;
  const domain = await insertDomain(ctx, org, { status: 'verified', label: 'apiclaw' });
  await p.domain.update({ where: { id: domain.id }, data: { protectionMode: 'api' } });
  const connection = await p.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `Chat clawback ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: '7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f',
      activeTenantKey: `microsoft_365:${randomUUID()}`,
      tenantVerifiedAt: new Date(),
      // Not due for a live integration-worker health run during the suite.
      nextHealthCheckAt: new Date(Date.now() + 24 * 3_600_000),
    },
    select: { id: true, publicId: true },
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
  for (let i = 0; i < 3; i += 1) {
    const address = `chat${i}-${randomUUID().slice(0, 6)}@${domain.name}`;
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
  return {
    domain,
    connectionPublicId: connection.publicId,
    apiConnectionId: api.id,
    mailboxes,
  };
}

async function seedCopy(
  mailbox: World['mailboxes'][number],
  patch: { state?: 'none' | 'remediated' | 'failed'; action?: 'tag' | 'move_junk' } = {},
): Promise<SeededCopy> {
  const p = ctx.prisma;
  const receivedAt = new Date(Date.now() - 3_600_000 - Math.floor(Math.random() * 60_000));
  const internetMessageId = `<chat-${randomUUID()}@fabrikam.test>`;
  const identity = await p.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:mbx:${sha256(randomUUID())}`, receivedAt },
    select: { id: true },
  });
  await p.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      domainId: world.domain.id,
      direction: 'inbound',
      status: 'journaled',
      statusChangedAt: receivedAt,
      version: 2,
      ingestSource: 'mailbox_api',
      envelopeFrom: 'billing@fabrikam.test',
      headerFrom: 'billing@fabrikam.test',
      subject: 'Invoice overdue',
      internetMessageId,
      sizeBytes: 1024,
      recipientCount: 1,
      attachmentCount: 0,
      emlObjectKey: `org/${org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha256('copy'),
    },
  });
  const publicId = uuidv7();
  const copy = await p.apiMessageCopy.create({
    data: {
      publicId,
      receivedAt,
      organizationId: org.id,
      apiConnectionId: world.apiConnectionId,
      mailboxId: mailbox.id,
      messageId: identity.id,
      messageIdHash: copyMessageIdHash(org.id, internetMessageId),
      source: 'journal',
      seenJournal: true,
      status: 'scanned',
      verdict: 'phishing',
      riskScore: 910,
      verdictAt: new Date(receivedAt.getTime() + 5_000),
      remediationState: patch.state ?? 'none',
      remediationAction: patch.action ?? null,
    },
    select: { id: true },
  });
  return { id: copy.id, publicId, receivedAt, messageId: identity.id, mailboxId: mailbox.id };
}

async function seedAction(
  copy: SeededCopy,
  action: 'tag' | 'move_junk',
  status: 'succeeded' | 'failed',
) {
  const row = await ctx.prisma.apiRemediationAction.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      apiConnectionId: world.apiConnectionId,
      mailboxId: copy.mailboxId,
      copyId: copy.id,
      copyReceivedAt: copy.receivedAt,
      messageId: copy.messageId,
      action,
      generation: 0,
      actionKey: remediationActionKey(copy.publicId, action, 0),
      trigger: 'policy',
      status,
      requestedByType: 'system',
      attempts: status === 'failed' ? 8 : 1,
      lastErrorCode: status === 'failed' ? 'provider_unavailable' : null,
      completedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  if (status === 'succeeded') {
    await ctx.prisma.apiMessageCopy.updateMany({
      where: { id: copy.id, receivedAt: copy.receivedAt },
      data: { remediationState: 'remediated', remediationAction: action, lastActionId: row.id },
    });
  }
  return row;
}

/** A clawback as the mailbox-worker leaves it (default `ready`, one eligible mailbox). */
async function seedClawback(patch: Record<string, unknown> = {}) {
  const now = new Date();
  return ctx.prisma.apiClawback.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      trigger: 'admin',
      signal: { v: 1, kind: 'admin', refs: {}, facts: null, signalAt: now.toISOString() },
      criteria: {
        v: 1,
        window: { from: new Date(now.getTime() - 86_400_000).toISOString(), to: now.toISOString() },
        keys: { messageIdHashes: [sha256(randomUUID())] },
        directions: ['inbound', 'internal'],
        includeReportMailboxes: false,
      },
      criteriaSha256: sha256(randomUUID()),
      status: 'ready',
      targetsTotal: 1,
      mailboxesTotal: 1,
      targetsEligible: 1,
      mailboxesEligible: 1,
      requestedByType: 'user',
      requestedByUserId: admin2.user.id,
      requestReason: 'Seeded',
      signalAt: now,
      ...patch,
    },
  });
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ planCode: 'enterprise', slugPrefix: 'apiclaw' });
  admin = await member(ctx, fx, org, ['organization_admin']);
  admin2 = await member(ctx, fx, org, ['organization_admin']);
  await enableAssistant(ctx, operator, org, admin);
  world = await seedWorld();
  fx.registerCleanup(async () => {
    await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(org.id));
    await ctx.get(ProviderTenantDataRepository).purgeOrganization(systemScope(org.id));
    await ctx.prisma.messageOutbox.deleteMany({ where: { organizationId: org.id } });
    await ctx.prisma.notificationAlertWindow.deleteMany({ where: { organizationId: org.id } });
    await deleteMessagesData(ctx, [org.id]);
  });
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
});

describe('remediation and connection writes through chat (C15)', () => {
  it('remediate (medium), restore of a tag (high), retry of a failed action (low)', async () => {
    const copy = await seedCopy(world.mailboxes[0]!);
    const remediated = await chat('api_mode_remediation_remediate', {
      detectionId: copy.publicId,
      body: { action: 'move_junk', reason: REASON },
    });
    expect(remediated.proposal.confirmation.risk).toBe('medium');
    expectExecuted(remediated, 202);
    await audited(remediated, 'api_mode.remediation_requested');
    expect(
      await ctx.prisma.apiRemediationAction.count({
        where: { copyId: copy.id, action: 'move_junk', trigger: 'admin', status: 'pending' },
      }),
    ).toBe(1);

    const tagged = await seedCopy(world.mailboxes[1]!);
    await seedAction(tagged, 'tag', 'succeeded');
    const restored = await chat('api_mode_remediation_restore', {
      detectionId: tagged.publicId,
      body: { reason: REASON },
    });
    expect(restored.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(restored, 202);
    expect(
      await ctx.prisma.apiRemediationAction.count({
        where: { copyId: tagged.id, action: 'remove_tag', status: 'pending' },
      }),
    ).toBe(1);

    const failedCopy = await seedCopy(world.mailboxes[2]!);
    const failed = await seedAction(failedCopy, 'move_junk', 'failed');
    const retried = await chat('api_mode_remediation_retry', { remediationId: failed.publicId });
    expect(retried.proposal.confirmation.risk).toBe('low');
    expectExecuted(retried, 202);
    expect(
      (await ctx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: failed.id } }))
        .status,
    ).toBe('pending');
    await audited(retried, 'api_mode.remediation_retry_requested');
  });

  it('policy put, domain override put and delete (high, re-authenticated)', async () => {
    const document = {
      v: 1,
      rules: [{ id: 'chat-p1', when: { verdicts: ['malware', 'phishing'] }, action: 'tag' }],
    };
    const put = await chat('api_mode_remediation_put_policy', {
      body: { mode: 'detect_only', document, reason: REASON, expectedRowVersion: null },
    });
    expect(put.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(put, 200);
    await audited(put, 'api_mode.remediation_policy_updated');
    const domainPut = await chat('api_mode_remediation_put_domain_policy', {
      domainId: world.domain.publicId,
      body: { mode: 'enforce', document, reason: REASON, expectedRowVersion: null },
    });
    expectExecuted(domainPut, 200);
    expect(
      await ctx.prisma.apiRemediationPolicy.count({
        where: { organizationId: org.id, domainId: world.domain.id },
      }),
    ).toBe(1);
    const removed = await chat('api_mode_remediation_delete_domain_policy', {
      domainId: world.domain.publicId,
    });
    expectExecuted(removed, 204);
    expect(
      await ctx.prisma.apiRemediationPolicy.count({
        where: { organizationId: org.id, domainId: world.domain.id },
      }),
    ).toBe(0);
  });

  it('connection settings with the CAS version from the read (high); inventory sync and resync (low)', async () => {
    const paused = await chat('api_mode_update_settings', {
      connectionId: world.connectionPublicId,
      // A stale version from the model is replaced by the server's read.
      body: {
        feedsEnabled: false,
        feedMode: 'poll',
        remediationPaused: true,
        expectedRowVersion: 9,
      },
    });
    expect(paused.proposal.confirmation.risk).toBe('high');
    expectExecuted(paused, 200);
    await audited(paused, 'api_mode.settings_updated');
    expect(
      (
        await ctx.prisma.apiModeConnection.findUniqueOrThrow({
          where: { id: world.apiConnectionId },
        })
      ).remediationPaused,
    ).toBe(true);
    const sync = await chat('api_mode_inventory_sync', { connectionId: world.connectionPublicId });
    expect(sync.proposal.confirmation.risk).toBe('low');
    expectExecuted(sync, 202);
    const resync = await chat('api_mode_resync_mailbox', {
      mailboxId: world.mailboxes[0]!.publicId,
    });
    expectExecuted(resync, 202);
    await audited(resync, 'api_mode.mailbox_resync_requested');
  });
});

describe('clawbacks through chat (C15, C-I4)', () => {
  it('create (medium) and submit (high: re-authentication) queue a purge below the threshold', async () => {
    const created = await chat('api_mode_clawback_create', {
      body: {
        criteria: {
          messageId: `<chat-${randomUUID()}@fabrikam.test>`,
          from: new Date(Date.now() - 86_400_000).toISOString(),
          to: new Date().toISOString(),
        },
        reason: REASON,
      },
    });
    expect(created.proposal.confirmation.risk).toBe('medium');
    expectExecuted(created, 202);
    await audited(created, 'api_mode.clawback_created');
    const ready = await seedClawback();
    const submitted = await chat('api_mode_clawback_submit', {
      clawbackId: ready.publicId,
      body: { mode: 'explicit', action: 'move_junk', reason: REASON, expectedRowVersion: 1 },
    });
    expect(submitted.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(submitted, 202);
    await audited(submitted, 'api_mode.clawback_submitted');
    expect(
      (await ctx.prisma.apiClawback.findUniqueOrThrow({ where: { id: ready.id } })).status,
    ).toBe('queued');
  });

  it('approve (high) and deny (low) another administrator’s purge; the requester is refused by the guard', async () => {
    const pending = {
      status: 'pending_approval',
      decisionMode: 'explicit',
      action: 'move_junk',
      requiresApproval: true,
      approvalReasons: ['mailbox_threshold'],
      approvalStatus: 'pending',
      approvalRequestedAt: new Date(),
      approvalExpiresAt: new Date(Date.now() + 3_600_000),
      submittedByUserId: admin2.user.id,
      submittedAt: new Date(),
      mailboxesEligible: 60,
      rowVersion: 3,
    };
    const toApprove = await seedClawback(pending);
    // The requester (admin2) proposing their own approval: denied_guard, nothing stored.
    const conversation = await newConversation(ctx, admin2);
    const recorder = recordLoopback(ctx);
    let own;
    try {
      own = await turn(
        ctx,
        admin2.headers,
        conversation,
        directive('api_mode_clawback_approve', {
          clawbackId: toApprove.publicId,
          body: { reason: REASON, expectedRowVersion: 3 },
        }),
      );
    } finally {
      recorder.restore();
    }
    expect(own.body.confirmations).toEqual([]);
    expect(own.body.executions[0]).toMatchObject({ decision: 'denied_guard', status: 'refused' });
    expect(recorder.calls.filter((c) => c.method !== 'GET')).toEqual([]);

    const approved = await chat('api_mode_clawback_approve', {
      clawbackId: toApprove.publicId,
      body: { reason: REASON, expectedRowVersion: 3 },
    });
    expect(approved.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(approved, 200);
    await audited(approved, 'api_mode.clawback_approved');
    const row = await ctx.prisma.apiClawback.findUniqueOrThrow({ where: { id: toApprove.id } });
    expect(row).toMatchObject({ status: 'queued', approvalStatus: 'approved' });
    expect(row.approvedByUserId).toBe(admin.user.id);

    const toDeny = await seedClawback(pending);
    const denied = await chat('api_mode_clawback_deny', {
      clawbackId: toDeny.publicId,
      body: { reason: REASON, expectedRowVersion: 3 },
    });
    expect(denied.proposal.confirmation.risk).toBe('low');
    expectExecuted(denied, 200);
    expect(
      (await ctx.prisma.apiClawback.findUniqueOrThrow({ where: { id: toDeny.id } })).status,
    ).toBe('denied');
  });

  it('cancel (medium) and bulk restore (high); the hard delete is never a tool', async () => {
    const ready = await seedClawback();
    const cancelled = await chat('api_mode_clawback_cancel', {
      clawbackId: ready.publicId,
      body: { reason: REASON },
    });
    expect(cancelled.proposal.confirmation.risk).toBe('medium');
    expectExecuted(cancelled, 202);
    expect(
      (await ctx.prisma.apiClawback.findUniqueOrThrow({ where: { id: ready.id } })).status,
    ).toBe('cancelled');
    const done = await seedClawback({
      status: 'completed',
      targetsSucceeded: 1,
      completedAt: new Date(),
    });
    const restore = await chat('api_mode_clawback_restore', {
      clawbackId: done.publicId,
      body: { reason: REASON },
    });
    expect(restore.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(restore, 202);
    await audited(restore, 'api_mode.clawback_restore_requested');

    const hard = await seedClawback();
    const conversation = await newConversation(ctx, admin);
    const recorder = recordLoopback(ctx);
    let refused;
    try {
      refused = await turn(
        ctx,
        admin.headers,
        conversation,
        directive('api_mode_clawback_submit_hard_delete', {
          clawbackId: hard.publicId,
          body: { reason: REASON, expectedRowVersion: 1 },
        }),
      );
    } finally {
      recorder.restore();
    }
    expect(refused.body.executions[0]).toMatchObject({
      decision: 'denied_not_applicable',
      status: 'refused',
    });
    expect(recorder.calls.filter((c) => c.path.includes('submit-hard-delete'))).toEqual([]);
    expect(recorder.calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expect(
      (await ctx.prisma.apiClawback.findUniqueOrThrow({ where: { id: hard.id } })).status,
    ).toBe('ready');
  });
});

describe('reports, report mailboxes and settings through chat (C15)', () => {
  it('triage (medium) with feedback, clawback from a report (medium), report mailboxes (medium)', async () => {
    const reportMailbox = world.mailboxes[2]!;
    const byId = await chat('api_mode_reports_set_mailbox', {
      mailboxId: reportMailbox.publicId,
      body: { enabled: true, reason: REASON },
    });
    expect(byId.proposal.confirmation.risk).toBe('medium');
    expectExecuted(byId, 200);
    await audited(byId, 'api_mode.report_mailbox_updated');
    const byAddress = await chat('api_mode_reports_add_mailbox', {
      body: { address: world.mailboxes[1]!.address, reason: REASON },
    });
    expectExecuted(byAddress, 200);
    expect(
      await ctx.prisma.apiMailbox.count({ where: { organizationId: org.id, reportMailbox: true } }),
    ).toBe(2);

    const reportCopy = await seedCopy(reportMailbox);
    const originalId = `<reported-${randomUUID()}@fabrikam.test>`;
    const hash = copyMessageIdHash(org.id, originalId)!;
    const report = await ctx.prisma.apiUserReport.create({
      data: {
        publicId: uuidv7(),
        organizationId: org.id,
        apiConnectionId: world.apiConnectionId,
        reportMailboxId: reportMailbox.id,
        reportCopyId: reportCopy.id,
        reportCopyReceivedAt: reportCopy.receivedAt,
        reportMessageId: reportCopy.messageId,
        reporterAddress: `reporter@${world.domain.name}`,
        status: 'pending_triage',
        identification: 'attachment',
        original: {
          v: 1,
          messageIdHash: hash,
          sender: 'billing@fabrikam.test',
          subjectKey: 'Invoice overdue',
          date: new Date(Date.now() - 3_600_000).toISOString(),
          attachmentSha256: [],
          urlSha256: [],
          extraOriginals: 0,
        },
        originalMessageIdHash: hash,
        groupKey: hash,
        assessment: 'malicious',
        reportedAt: reportCopy.receivedAt,
      },
    });
    const triaged = await chat('api_mode_reports_triage', {
      reportId: report.publicId,
      body: { status: 'resolved', verdict: 'malicious', expectedRowVersion: 9 },
    });
    expect(triaged.proposal.confirmation.risk).toBe('medium');
    expectExecuted(triaged, 200);
    await audited(triaged, 'api_mode.report_triaged');
    expect(
      await ctx.prisma.messageOutbox.count({
        where: {
          organizationId: org.id,
          eventType: EventTypes.ReportFeedbackRequested,
          correlationId: `api-mode-report:${report.publicId}`,
        },
      }),
    ).toBe(1);
    const clawback = await chat('api_mode_reports_clawback', {
      reportId: report.publicId,
      body: { reason: REASON },
    });
    expectExecuted(clawback, 202);
    await audited(clawback, 'api_mode.report_clawback_requested');
    expect(
      (await ctx.prisma.apiUserReport.findUniqueOrThrow({ where: { id: report.id } })).clawbackId,
    ).not.toBeNull();
  });

  it('settings put (high): creates the organization settings', async () => {
    const put = await chat('api_mode_settings_put', {
      body: {
        internalMailEnabled: true,
        autoClawback: 'review',
        autoMaxMailboxes: 300,
        purgeApprovalMailboxes: 25,
        clawbackLookbackDays: 10,
        tiMinConfidence: 85,
        reportAckEnabled: true,
        reportFeedbackEnabled: true,
        reason: REASON,
        expectedRowVersion: null,
      },
    });
    expect(put.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(put, 200);
    await audited(put, 'api_mode.settings_org_updated');
    expect(
      await ctx.prisma.apiModeOrgSetting.findUniqueOrThrow({ where: { organizationId: org.id } }),
    ).toMatchObject({ autoClawback: 'review', purgeApprovalMailboxes: 25 });
  });

  it('step API-4: the mailbox scope put (high, re-authenticated) selects the domain’s mailboxes', async () => {
    const put = await chat('api_mode_onboarding_put_scope', {
      domainId: world.domain.publicId,
      body: {
        scope: { kind: 'mailboxes' },
        mailboxIds: [world.mailboxes[0]!.publicId],
        reason: REASON,
        expectedRowVersion: null,
      },
    });
    expect(put.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(put, 200);
    await audited(put, 'api_mode.scope_updated');
    expect(
      await ctx.prisma.apiModeDomainSetting.findUniqueOrThrow({
        where: { domainId: world.domain.id },
      }),
    ).toMatchObject({ scopeKind: 'mailboxes', rowVersion: 1 });
    expect(
      await ctx.prisma.apiMailbox.count({
        where: { organizationId: org.id, domainId: world.domain.id, scopeSelected: true },
      }),
    ).toBe(1);
  });

  it('step API-4: the provider ownership check of a pending domain (low) writes the provider row', async () => {
    const p = ctx.prisma;
    const connection = await p.providerConnection.findFirstOrThrow({
      where: { organizationId: org.id, publicId: world.connectionPublicId },
      select: { id: true },
    });
    await p.providerConnectionGrant.create({
      data: {
        organizationId: org.id,
        connectionId: connection.id,
        profile: 'm365.mail_flow',
        profileVersion: 1,
        authMethod: 'platform_app',
        status: 'active',
        requestedPermissions: [],
        observedPermissions: [],
        verifiedAt: new Date(),
      },
    });
    const pending = await insertDomain(ctx, org, {
      status: 'pending_verification',
      label: 'apiclaw-p',
    });
    const check = await chat('domains_provider_ownership_check', {
      domainId: pending.publicId,
      body: { connectionId: world.connectionPublicId },
    });
    expect(check.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(check, 202);
    await audited(check, 'domain.provider_verification_requested');
    expect(
      await p.domainVerification.findFirstOrThrow({
        where: { organizationId: org.id, domainId: pending.id, method: 'provider_tenant' },
      }),
    ).toMatchObject({ status: 'pending', providerConnectionId: connection.id });
  });
});
