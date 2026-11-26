/**
 * Step AI-5 archive, journaling and eDiscovery tools through chat (docs/plan/steps/33-ai-chat-
 * compliance-integrations.md D2–D6, D11, D12, I22, I23, §9 item 3; the `testedBy` of the 16
 * compliance writes in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md). The deterministic fake
 * provider proposes every write from a directive turn (never a real LLM); the api listens on its
 * ephemeral loopback port, so precondition reads, confirm-time re-reads and the confirmed writes
 * go through the real `/api/v1` pipeline with the user's own token, MFA session and
 * permissions. Each write asserts the api's state and the operation's own audit row carrying the
 * result execution's correlation id.
 *
 * - An `it-*` organization (enterprise, `archiving` + `journal_intake`) with a default retention
 *   policy, a compliance user (archive, eDiscovery, legal hold, export, search; MFA) and a
 *   journaling administrator (`journal:manage`; MFA).
 * - Retention policies: create (high, re-authenticated), update (rename and lengthen → medium;
 *   shorten → high with the shortening warning; `onExpiry` review → delete or omitted → high;
 *   criteria or priority change → high; the CAS field injected; a concurrent change → `409
 *   assistant_confirmation_state_changed`), delete (high; the default policy → `denied_guard`
 *   with no confirmation; with the guard removed from the shared spec object in a simulated
 *   regression the api's `409 archive_retention_policy_is_default` fires and nothing changes).
 * - Archive and journaling settings (enable only → medium; `settings` given → high; `enabled:
 *   false` → high; CAS injected).
 * - Capture retry of a `failed` intent through the new single read (a `lost` one → `denied_guard`
 *   `capture_not_retryable`).
 * - Intake sources (non-secret fields only): rename / resume low, pause, networks and TLS off
 *   high, attestation medium, disable high and terminal; the intake address never reaches a
 *   stored assistant row or an audit row.
 * - eDiscovery: case create / update (custodians → medium) / close (active holds → `denied_guard`
 *   `case_active_holds`; without → closed), hold create (high, re-authenticated), search create
 *   (queued 202, the archive-worker's completion simulated on the writer), review on refs of the
 *   hits read, export create (high, re-authenticated, malicious warning, the export audit chain);
 *   the export download grant, legal-hold release, disposal and key rotation are
 *   `denied_not_applicable` without a loopback request.
 *
 * The live archive-worker container is paused while the suite runs (it would claim the queued
 * search and export, `live-archive-worker.ts`). Synthetic `it-*` organizations and `.example` /
 * `.test` values only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/assistant/confirmations/:confirmationId/cancel
// @covers get /api/v1/archive/retention-policies/:policyId
// @covers post /api/v1/archive/retention-policies
// @covers put /api/v1/archive/retention-policies/:policyId
// @covers delete /api/v1/archive/retention-policies/:policyId
// @covers get /api/v1/archive/settings
// @covers put /api/v1/archive/settings
// @covers get /api/v1/archive/capture-issues/:messageId
// @covers post /api/v1/archive/capture-issues/:messageId/retry
// @covers get /api/v1/journaling/settings
// @covers put /api/v1/journaling/settings
// @covers get /api/v1/journaling/intake-sources/:sourceId
// @covers patch /api/v1/journaling/intake-sources/:sourceId
// @covers delete /api/v1/journaling/intake-sources/:sourceId
// @covers post /api/v1/journaling/intake-sources/:sourceId/attestations
// @covers post /api/v1/ediscovery/cases
// @covers get /api/v1/ediscovery/cases/:caseId
// @covers patch /api/v1/ediscovery/cases/:caseId
// @covers post /api/v1/ediscovery/cases/:caseId/close
// @covers post /api/v1/ediscovery/cases/:caseId/holds
// @covers post /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits
// @covers post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review
// @covers post /api/v1/ediscovery/cases/:caseId/exports
import { randomUUID } from 'node:crypto';
import {
  AI5_ESCALATION_WARNINGS as W,
  confirmationSpecOf,
  GUARD_MESSAGES,
} from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SeededRecord } from '../test/support/archive-seed';
import type { IntegrationApp } from './support/app';
import { testIndexPrefix } from './support/archive';
import {
  actionsByCorrelation,
  auditByCorrelation,
  call,
  cancelConfirmation,
  type ChatWrite,
  clearAssistantCounters,
  closeReauthWindow,
  confirm,
  confirmationAudit,
  confirmationRow,
  createAssistantApp,
  credentialKeys,
  directive,
  executionRow,
  expectExecuted,
  followUpTranscript,
  type Member,
  newConversation,
  operationActionsOf,
  platformMember,
  propose,
  type Proposal,
  proposeAndConfirm,
  reauthOf,
  recordLoopback,
  type RecordedCall,
  requestsTo,
  resultCorrelationId,
  storedRequestOf,
  turn,
} from './support/assistant';
import {
  ARCHIVE,
  CASES,
  chatUser,
  COMPLIANCE_PERMISSIONS,
  type ComplianceTenant,
  complianceTenant,
  completeSearch,
  createCase,
  createIntakeSource,
  type CreatedIntakeSource,
  HOLDS,
  JOURNALING_PERMISSIONS,
} from './support/assistant-compliance';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { idem } from './support/http';
import { pauseLiveArchiveWorker } from './support/live-archive-worker';

/** A stale row version the model "remembers"; the executor replaces it from the snapshot. */
const STALE = 999;
const DAY_MS = 86_400_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let tenant: ComplianceTenant;
let org: FixtureOrganization;
let compliance: Member;
let journaling: Member;
let resumeLiveArchiveWorker: (() => Promise<void>) | undefined;

const chat = (
  who: Member,
  tool: string,
  args: Record<string, unknown>,
  options: { conversation?: string; reauth?: boolean } = {},
): Promise<ChatWrite> => proposeAndConfirm(ctx, fx, who, tool, args, options);

/**
 * A high-risk write with the re-authentication proven: the session's window is closed first, the
 * proposal needs it, the confirm without password + TOTP is refused (`401
 * assistant_reauth_required`, still pending), then the confirm with it executes.
 */
async function highChat(
  who: Member,
  tool: string,
  args: Record<string, unknown>,
  conversation?: string,
): Promise<ChatWrite> {
  await closeReauthWindow(ctx, who);
  const proposal = await propose(ctx, who, directive(tool, args), conversation);
  expect(proposal.confirmation).toMatchObject({
    tool,
    risk: 'high',
    requiresReauth: true,
    reauthFresh: false,
  });
  const refused = await confirm(ctx, who, proposal);
  expect(refused.status, JSON.stringify(refused.body)).toBe(401);
  expect(refused.body.code).toBe('assistant_reauth_required');
  expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
  const recorder = recordLoopback(ctx);
  try {
    const res = await confirm(ctx, who, proposal, { reauth: await reauthOf(fx, who) });
    return { proposal, res, calls: [...recorder.calls] };
  } finally {
    recorder.restore();
  }
}

/** The operation's own audit row (this organization, the result execution's correlation id). */
async function audited(result: ChatWrite, action: string, actor: Member) {
  const correlationId = await resultCorrelationId(ctx, result.res);
  const rows = (await auditByCorrelation(ctx, org.id, correlationId)).filter(
    (r) => r.action === action,
  );
  expect(
    rows,
    `${action}: ${JSON.stringify(await operationActionsOf(ctx, result.res))}`,
  ).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(actor.user.publicId);
  return rows[0]!;
}

/** The card carries no credential-pattern key (I23). */
function credentialFree(proposal: Proposal): void {
  expect(credentialKeys(proposal.confirmation.summary)).toEqual([]);
}

interface Refusal {
  conversation: string;
  execution: Record<string, unknown>;
  body: Record<string, unknown>;
  calls: RecordedCall[];
}

/** One directive turn that must not propose: the execution, the turn body and the loopback calls. */
async function refusedTurn(
  who: Member,
  tool: string,
  args: Record<string, unknown>,
): Promise<Refusal> {
  const conversation = await newConversation(ctx, who);
  const recorder = recordLoopback(ctx);
  try {
    const res = await turn(ctx, who.headers, conversation, directive(tool, args));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmations, tool).toEqual([]);
    const execution = (res.body.executions as Array<Record<string, unknown>>)[0]!;
    expect(execution.tool).toBe(tool);
    return { conversation, execution, body: res.body, calls: [...recorder.calls] };
  } finally {
    recorder.restore();
  }
}

/** No confirmation row exists in the conversation. */
async function noConfirmationIn(conversation: string): Promise<void> {
  expect(
    await ctx.prisma.aiChatActionConfirmation.count({
      where: { conversation: { publicId: conversation } },
    }),
  ).toBe(0);
}

/** Every stored assistant row of the organization and its audit rows, as one string. */
async function organizationTraces(): Promise<string> {
  const where = { organizationId: org.id };
  const [turns, messages, executions, confirmations, audit] = await Promise.all([
    ctx.prisma.aiChatTurn.findMany({ where }),
    ctx.prisma.aiChatMessage.findMany({ where }),
    ctx.prisma.aiChatToolExecution.findMany({ where }),
    ctx.prisma.aiChatActionConfirmation.findMany({ where }),
    ctx.prisma.auditLog.findMany({ where }),
  ]);
  return JSON.stringify({ turns, messages, executions, confirmations, audit }, (_k, v: unknown) =>
    typeof v === 'bigint' ? v.toString() : v,
  );
}

beforeAll(async () => {
  // The suite simulates the archive-worker; a live one would claim its queued search and export.
  resumeLiveArchiveWorker = await pauseLiveArchiveWorker();
  ({ ctx } = await createAssistantApp({
    env: { ARCHIVE_SEARCH_INDEX_PREFIX: testIndexPrefix() },
  }));
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  tenant = await complianceTenant(ctx, fx, operator);
  org = tenant.org;
  compliance = await chatUser(ctx, fx, org, COMPLIANCE_PERMISSIONS, 'Compliance officer');
  journaling = await chatUser(ctx, fx, org, JOURNALING_PERMISSIONS, 'Journaling admin');
}, 240_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
  await resumeLiveArchiveWorker?.();
}, 180_000);

describe('retention policies through chat (D2, D3, D4, D6 #1–#3)', () => {
  let policyId: string;
  const policyRow = () =>
    ctx.prisma.archiveRetentionPolicy.findUniqueOrThrow({ where: { publicId: policyId } });
  /** A complete PUT body from the stored policy (the route replaces the whole policy). */
  const full = async (overrides: Record<string, unknown> = {}) => {
    const row = await policyRow();
    return {
      expectedRowVersion: STALE,
      name: row.name,
      retentionDays: row.retentionDays,
      onExpiry: row.onExpiry,
      priority: row.priority,
      criteria: row.criteria ?? {},
      ...overrides,
    };
  };

  it('archive_retention_create: always high, re-authenticated; archive.retention_policy_created', async () => {
    const created = await highChat(compliance, 'archive_retention_create', {
      body: { name: 'Chat ninety days', retentionDays: 90, onExpiry: 'review', priority: 50 },
    });
    expect(created.proposal.confirmation.summary!.warnings.length).toBeGreaterThan(0);
    credentialFree(created.proposal);
    expectExecuted(created, 201);
    const row = await ctx.prisma.archiveRetentionPolicy.findFirstOrThrow({
      where: { organizationId: org.id, name: 'Chat ninety days' },
    });
    policyId = row.publicId;
    expect(row).toMatchObject({ retentionDays: 90, onExpiry: 'review', priority: 50 });
    const audit = await audited(created, 'archive.retention_policy_created', compliance);
    expect(audit.resourceId).toBe(policyId);
  });

  it('archive_retention_update: rename and lengthen stay medium; the CAS field is injected', async () => {
    const before = await policyRow();
    const renamed = await chat(compliance, 'archive_retention_update', {
      policyId,
      body: await full({ name: 'Chat ninety days (renamed)', retentionDays: 120 }),
    });
    expect(renamed.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    for (const warning of Object.values(W)) {
      expect(renamed.proposal.confirmation.summary!.warnings).not.toContain(warning);
    }
    expectExecuted(renamed, 200);
    expect(
      (await storedRequestOf(ctx, renamed.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect(await policyRow()).toMatchObject({
      name: 'Chat ninety days (renamed)',
      retentionDays: 120,
      rowVersion: before.rowVersion + 1,
    });
    await audited(renamed, 'archive.retention_policy_updated', compliance);
  });

  it('shortening is high with the shortening warning', async () => {
    const shorter = await chat(compliance, 'archive_retention_update', {
      policyId,
      body: await full({ retentionDays: 30 }),
    });
    expect(shorter.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(shorter.proposal.confirmation.summary!.warnings).toContain(W.retentionShortened);
    expectExecuted(shorter, 200);
    expect((await policyRow()).retentionDays).toBe(30);
    await audited(shorter, 'archive.retention_policy_updated', compliance);
  });

  it('onExpiry review → delete (or omitted: the PUT default) is high', async () => {
    const body = await full();
    delete (body as Record<string, unknown>).onExpiry;
    const omitted = await propose(
      ctx,
      compliance,
      directive('archive_retention_update', { policyId, body }),
    );
    expect(omitted.confirmation).toMatchObject({ risk: 'high' });
    expect(omitted.confirmation.summary!.warnings).toContain(W.expiryDelete);
    expect((await cancelConfirmation(ctx, compliance, omitted.confirmation.id)).status).toBe(200);

    const toDelete = await chat(compliance, 'archive_retention_update', {
      policyId,
      body: await full({ onExpiry: 'delete' }),
    });
    expect(toDelete.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(toDelete.proposal.confirmation.summary!.warnings).toContain(W.expiryDelete);
    expectExecuted(toDelete, 200);
    expect((await policyRow()).onExpiry).toBe('delete');
    await audited(toDelete, 'archive.retention_policy_updated', compliance);
  });

  it('a criteria or priority change is high (which mail the policy matches)', async () => {
    const criteria = await chat(compliance, 'archive_retention_update', {
      policyId,
      body: await full({ criteria: { directions: ['inbound'] } }),
    });
    expect(criteria.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(criteria.proposal.confirmation.summary!.warnings).toContain(W.retentionScope);
    expectExecuted(criteria, 200);
    expect((await policyRow()).criteria).toMatchObject({ directions: ['inbound'] });
    await audited(criteria, 'archive.retention_policy_updated', compliance);

    const priority = await propose(
      ctx,
      compliance,
      directive('archive_retention_update', { policyId, body: await full({ priority: 10 }) }),
    );
    expect(priority.confirmation).toMatchObject({ risk: 'high' });
    expect(priority.confirmation.summary!.warnings).toContain(W.retentionScope);
    expect((await cancelConfirmation(ctx, compliance, priority.confirmation.id)).status).toBe(200);
  });

  it('a change by someone else between proposal and confirm → 409 state_changed; nothing written', async () => {
    const proposal = await propose(
      ctx,
      compliance,
      directive('archive_retention_update', {
        policyId,
        body: await full({ name: 'Chat stale rename' }),
      }),
    );
    const current = await policyRow();
    const direct = await call(
      ctx,
      compliance.headers,
      'put',
      `${ARCHIVE}/retention-policies/${policyId}`,
      {
        expectedRowVersion: current.rowVersion,
        name: 'Changed in the portal',
        retentionDays: current.retentionDays,
        onExpiry: current.onExpiry,
        priority: current.priority,
        criteria: current.criteria ?? {},
      },
    ).set(idem());
    expect(direct.status, JSON.stringify(direct.body)).toBe(200);
    const res = await confirm(ctx, compliance, proposal);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_state_changed');
    expect(await policyRow()).toMatchObject({
      name: 'Changed in the portal',
      rowVersion: current.rowVersion + 1,
    });
  });

  it('archive_retention_delete of the default policy → denied_guard, no confirmation stored', async () => {
    const refusal = await refusedTurn(compliance, 'archive_retention_delete', {
      policyId: tenant.defaultPolicy.publicId,
    });
    expect(refusal.execution).toMatchObject({
      decision: 'denied_guard',
      status: 'refused',
      message: GUARD_MESSAGES.retention_default_policy,
    });
    await noConfirmationIn(refusal.conversation);
    expect(requestsTo({ calls: refusal.calls }, `${ARCHIVE}/retention-policies/{id}`)).toEqual(
      expect.arrayContaining([expect.objectContaining({ method: 'GET' })]),
    );
    expect(
      requestsTo({ calls: refusal.calls }, `${ARCHIVE}/retention-policies/{id}`).filter(
        (c) => c.method !== 'GET',
      ),
    ).toEqual([]);
  });

  it('without the guard (simulated regression) the api’s 409 archive_retention_policy_is_default fires; nothing changes', async () => {
    const spec = confirmationSpecOf('ArchiveRetentionController_delete_v1') as unknown as {
      guards?: unknown;
    };
    const saved = spec.guards;
    expect(saved).toBeDefined();
    let proposal: Proposal;
    try {
      spec.guards = undefined;
      await closeReauthWindow(ctx, compliance);
      proposal = await propose(
        ctx,
        compliance,
        directive('archive_retention_delete', { policyId: tenant.defaultPolicy.publicId }),
      );
      expect(proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
      const res = await confirm(ctx, compliance, proposal, {
        reauth: await reauthOf(fx, compliance),
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.confirmation).toMatchObject({
        status: 'failed',
        result: { httpStatus: 409, error: 'archive_retention_policy_is_default' },
      });
      expect(res.body.execution).toMatchObject({ status: 'failed', httpStatus: 409 });
    } finally {
      spec.guards = saved;
    }
    expect(
      await ctx.prisma.archiveRetentionPolicy.findUniqueOrThrow({
        where: { publicId: tenant.defaultPolicy.publicId },
      }),
    ).toMatchObject({ deletedAt: null });
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: org.id,
          action: 'archive.retention_policy_deleted',
          resourceId: tenant.defaultPolicy.publicId,
        },
      }),
    ).toBe(0);
    expect(
      (await ctx.prisma.archiveSetting.findUniqueOrThrow({ where: { organizationId: org.id } }))
        .defaultRetentionPolicyId,
    ).toBe(tenant.defaultPolicy.id);
  });

  it('archive_retention_delete of another policy: high, soft-deleted, audited', async () => {
    const deleted = await chat(compliance, 'archive_retention_delete', { policyId });
    expect(deleted.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(deleted, 204);
    expect((await policyRow()).deletedAt).not.toBeNull();
    await audited(deleted, 'archive.retention_policy_deleted', compliance);
  });
});

describe('archive and journaling settings through chat (D3, D6 #5–#6)', () => {
  const settingsRow = () =>
    ctx.prisma.archiveSetting.findUniqueOrThrow({ where: { organizationId: org.id } });

  async function settingsAudit(result: ChatWrite, area: 'archive' | 'journaling') {
    const row = await audited(result, 'archive.settings_updated', journaling);
    expect(row.metadata).toMatchObject({ area });
    return row;
  }

  it('archive_admin_update: enabled false → high (archiving stops); CAS injected', async () => {
    const before = await settingsRow();
    const off = await chat(journaling, 'archive_admin_update', {
      body: { expectedRowVersion: STALE, enabled: false },
    });
    expect(off.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(off.proposal.confirmation.summary!.warnings).toContain(W.archiveOff);
    expectExecuted(off, 200);
    expect(
      (await storedRequestOf(ctx, off.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect(await settingsRow()).toMatchObject({
      enabled: false,
      rowVersion: before.rowVersion + 1,
    });
    const audit = await settingsAudit(off, 'archive');
    expect(audit.metadata).toMatchObject({ changedPaths: ['enabled'], enabled: false });
  });

  it('archive_admin_update: enabling alone stays medium', async () => {
    const on = await chat(journaling, 'archive_admin_update', {
      body: { expectedRowVersion: STALE, enabled: true },
    });
    expect(on.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(on.proposal.confirmation.summary!.warnings).not.toContain(W.archiveOff);
    expectExecuted(on, 200);
    expect((await settingsRow()).enabled).toBe(true);
    await settingsAudit(on, 'archive');
  });

  it('archive_admin_update: a settings document is high (replaces the whole document)', async () => {
    const settings = await chat(journaling, 'archive_admin_update', {
      body: {
        expectedRowVersion: STALE,
        settings: { directions: { inbound: true, outbound: true, internal: false } },
      },
    });
    expect(settings.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(settings.proposal.confirmation.summary!.warnings).toContain(W.archiveSettings);
    expectExecuted(settings, 200);
    expect((await settingsRow()).settings).toMatchObject({
      directions: { inbound: true, outbound: true, internal: false },
    });
    const audit = await settingsAudit(settings, 'archive');
    expect(audit.metadata).toMatchObject({ changedPaths: ['settings'] });
  });

  it('journaling_update: enabled false → high, enabling alone → medium, sections → high', async () => {
    const before = await settingsRow();
    const off = await chat(journaling, 'journaling_update', {
      body: { expectedRowVersion: STALE, enabled: false },
    });
    expect(off.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(off.proposal.confirmation.summary!.warnings).toContain(W.journalingOff);
    expectExecuted(off, 200);
    expect(
      (await storedRequestOf(ctx, off.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect((await settingsRow()).enabled).toBe(false);
    await settingsAudit(off, 'journaling');

    const on = await chat(journaling, 'journaling_update', {
      body: { expectedRowVersion: STALE, enabled: true },
    });
    expect(on.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expectExecuted(on, 200);
    expect((await settingsRow()).enabled).toBe(true);
    await settingsAudit(on, 'journaling');

    const sections = await chat(journaling, 'journaling_update', {
      body: { expectedRowVersion: STALE, settings: { intake: { scanEnabled: true } } },
    });
    expect(sections.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(sections.proposal.confirmation.summary!.warnings).toContain(W.journalingSettings);
    expectExecuted(sections, 200);
    expect((await settingsRow()).settings).toMatchObject({ intake: { scanEnabled: true } });
    await settingsAudit(sections, 'journaling');
  });
});

describe('capture retry through the new single read (D4, D8, D6 #4)', () => {
  let failed: SeededRecord;
  let lost: SeededRecord;

  beforeAll(async () => {
    failed = await tenant.ax.record(org, {}, { index: false });
    lost = await tenant.ax.record(org, {}, { index: false });
    for (const [record, status] of [
      [failed, 'failed'],
      [lost, 'lost'],
    ] as const) {
      await ctx.prisma.archiveCaptureIntent.create({
        data: {
          receivedAt: record.row.receivedAt,
          organizationId: org.id,
          messageId: record.row.messageId,
          direction: 'inbound',
          sourceJournal: true,
          status,
          lastErrorCode: 'storage_error',
          attempts: 4,
          nextCheckAt: new Date(Date.now() + DAY_MS),
          settingsGeneration: 1n,
        },
      });
    }
  });

  it('archive_admin_capture_issue reads one intent; archive_admin_retry (medium) re-queues a failed one', async () => {
    const conversation = await newConversation(ctx, journaling);
    const read = await turn(
      ctx,
      journaling.headers,
      conversation,
      directive('archive_admin_capture_issue', { messageId: failed.row.messagePublicId }),
    );
    expect(read.body.executions[0]).toMatchObject({
      tool: 'archive_admin_capture_issue',
      status: 'succeeded',
      httpStatus: 200,
    });
    const retried = await chat(
      journaling,
      'archive_admin_retry',
      { messageId: failed.row.messagePublicId },
      { conversation },
    );
    expect(retried.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(JSON.stringify(retried.proposal.confirmation.summary)).toContain('failed');
    expectExecuted(retried, 200);
    const intent = await ctx.prisma.archiveCaptureIntent.findFirstOrThrow({
      where: { organizationId: org.id, messageId: failed.row.messageId },
    });
    expect(intent.status).toBe('pending');
    const audit = await audited(retried, 'archive.capture_retried', journaling);
    expect(audit.resourceId).toBe(failed.row.messagePublicId);
  });

  it('a lost intent → denied_guard capture_not_retryable; nothing re-queued', async () => {
    const refusal = await refusedTurn(journaling, 'archive_admin_retry', {
      messageId: lost.row.messagePublicId,
    });
    expect(refusal.execution).toMatchObject({
      decision: 'denied_guard',
      status: 'refused',
      message: GUARD_MESSAGES.capture_not_retryable,
    });
    await noConfirmationIn(refusal.conversation);
    expect(requestsTo({ calls: refusal.calls }, `${ARCHIVE}/capture-issues/{id}/retry`)).toEqual(
      [],
    );
    expect(
      (
        await ctx.prisma.archiveCaptureIntent.findFirstOrThrow({
          where: { organizationId: org.id, messageId: lost.row.messageId },
        })
      ).status,
    ).toBe('lost');
  });
});

describe('journal intake sources through chat (D3, D6 #7–#9, D7, I23)', () => {
  let source: CreatedIntakeSource;
  const sourceRow = () =>
    ctx.prisma.journalIntakeSource.findUniqueOrThrow({ where: { publicId: source.id } });

  beforeAll(async () => {
    // Creation returns the address: portal only (N/A in chat); created through the api here.
    source = await createIntakeSource(ctx, journaling, 'Exchange journal');
  });

  it('intake_sources_update: rename is low with the CAS injected; pause is high; resume is low', async () => {
    const before = await sourceRow();
    const renamed = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, displayName: 'Exchange journal (HQ)' },
    });
    expect(renamed.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(renamed, 200);
    expect(
      (await storedRequestOf(ctx, renamed.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect((await sourceRow()).displayName).toBe('Exchange journal (HQ)');
    await audited(renamed, 'journal_intake.source_updated', journaling);

    const paused = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, status: 'paused' },
    });
    expect(paused.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(paused.proposal.confirmation.summary!.warnings).toContain(W.intakePaused);
    expectExecuted(paused, 200);
    expect((await sourceRow()).status).toBe('paused');
    await audited(paused, 'journal_intake.source_paused', journaling);

    const resumed = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, status: 'active' },
    });
    expect(resumed.proposal.confirmation).toMatchObject({ risk: 'low' });
    expectExecuted(resumed, 200);
    expect((await sourceRow()).status).toBe('pending_verification');
    await audited(resumed, 'journal_intake.source_resumed', journaling);
  });

  it('networks and requireTls false are high', async () => {
    const networks = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, networks: ['45.10.20.0/28', '45.10.21.0/28'] },
    });
    expect(networks.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(networks.proposal.confirmation.summary!.warnings).toContain(W.intakeNetworks);
    expectExecuted(networks, 200);
    expect(JSON.stringify((await sourceRow()).networks)).toContain('45.10.21.0/28');
    await audited(networks, 'journal_intake.source_updated', journaling);

    const tls = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, requireTls: false },
    });
    expect(tls.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(tls.proposal.confirmation.summary!.warnings).toContain(W.intakeTls);
    expectExecuted(tls, 200);
    expect((await sourceRow()).requireTls).toBe(false);
    await audited(tls, 'journal_intake.source_updated', journaling);
  });

  it('a lower size limit or turning the silence alert off is high; raising either stays low (I22)', async () => {
    expect((await sourceRow()).maxMessageBytes).toBeNull();
    // No source limit read (the platform limit applies): any limit narrows it (fail closed).
    const first = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, maxMessageBytes: 20_971_520 },
    });
    expect(first.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(first.proposal.confirmation.summary!.warnings).toContain(W.intakeSize);
    expectExecuted(first, 200);
    expect((await sourceRow()).maxMessageBytes).toBe(20_971_520);

    const raised = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, maxMessageBytes: 31_457_280, silenceAlertMinutes: 60 },
    });
    expect(raised.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(raised, 200);
    expect(await sourceRow()).toMatchObject({
      maxMessageBytes: 31_457_280,
      silenceAlertMinutes: 60,
    });

    const lowered = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, maxMessageBytes: 1024 },
    });
    expect(lowered.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(lowered.proposal.confirmation.summary!.warnings).toContain(W.intakeSize);
    expectExecuted(lowered, 200);
    expect((await sourceRow()).maxMessageBytes).toBe(1024);

    const silenced = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, silenceAlertMinutes: null },
    });
    expect(silenced.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(silenced.proposal.confirmation.summary!.warnings).toEqual([W.intakeSilenceOff]);
    expectExecuted(silenced, 200);
    expect((await sourceRow()).silenceAlertMinutes).toBeNull();
    await audited(silenced, 'journal_intake.source_updated', journaling);
  });

  it('intake_sources_attest (medium): journal_intake.attested', async () => {
    const attested = await chat(journaling, 'intake_sources_attest', {
      sourceId: source.id,
      body: { code: 'journal.onprem.journal_recipient_created', attested: true },
    });
    expect(attested.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expectExecuted(attested, 200);
    await audited(attested, 'journal_intake.attested', journaling);
  });

  it('intake_sources_disable (high) is terminal: a later change fails with the route’s code', async () => {
    const disabled = await chat(journaling, 'intake_sources_disable', { sourceId: source.id });
    expect(disabled.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expectExecuted(disabled, 200);
    const row = await sourceRow();
    expect(row.status).toBe('disabled');
    expect(row.disabledAt).not.toBeNull();
    await audited(disabled, 'journal_intake.source_disabled', journaling);

    const later = await chat(journaling, 'intake_sources_update', {
      sourceId: source.id,
      body: { expectedRowVersion: STALE, displayName: 'Exchange journal (revived)' },
    });
    expect(later.res.status, JSON.stringify(later.res.body)).toBe(200);
    expect(later.res.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 409 },
    });
    expect((await sourceRow()).status).toBe('disabled');
  });

  it('the intake address never reached a stored assistant row or an audit row (I23)', async () => {
    expect(source.address).toContain('@');
    expect(await organizationTraces()).not.toContain(source.address);
  });
});

describe('eDiscovery cases and legal holds through chat (D4, D6 #10–#13, I22)', () => {
  let caseId: string;
  let holdId: string;
  const caseRow = () =>
    ctx.prisma.ediscoveryCase.findUniqueOrThrow({ where: { publicId: caseId } });

  it('ediscovery_cases_create (low): ediscovery.case_created', async () => {
    const name = `Matter ${randomUUID().slice(0, 8)}`;
    const created = await chat(compliance, 'ediscovery_cases_create', {
      body: { name, matterReference: 'MR-2026-17' },
    });
    expect(created.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(created, 201);
    const row = await ctx.prisma.ediscoveryCase.findFirstOrThrow({
      where: { organizationId: org.id, name },
    });
    caseId = row.publicId;
    expect(row.status).toBe('open');
    const audit = await audited(created, 'ediscovery.case_created', compliance);
    expect(audit.resourceId).toBe(caseId);
  });

  it('ediscovery_cases_update: custodians → medium; the card shows the count, never the addresses', async () => {
    const custodians = ['legal-one@custodians.example', 'legal-two@custodians.example'];
    const before = await caseRow();
    const updated = await chat(compliance, 'ediscovery_cases_update', {
      caseId,
      body: { expectedRowVersion: STALE, custodians },
    });
    expect(updated.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expect(updated.proposal.confirmation.summary!.warnings).toContain(W.caseCustodians);
    const summary = JSON.stringify(updated.proposal.confirmation.summary);
    for (const address of custodians) expect(summary).not.toContain(address);
    expectExecuted(updated, 200);
    expect(
      (await storedRequestOf(ctx, updated.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect(await ctx.prisma.ediscoveryCustodian.count({ where: { caseId: before.id } })).toBe(2);
    await audited(updated, 'ediscovery.case_updated', compliance);
  });

  it('ediscovery_cases_create_hold: high, re-authenticated; legal_hold.created', async () => {
    const placed = await highChat(compliance, 'ediscovery_cases_create_hold', {
      caseId,
      body: { name: 'Litigation hold', reason: 'Notice received', useCaseCustodians: true },
    });
    expect(placed.proposal.confirmation.summary!.reversible).toBe(false);
    expectExecuted(placed, 201);
    const hold = await ctx.prisma.archiveLegalHold.findFirstOrThrow({
      where: { organizationId: org.id, name: 'Litigation hold' },
    });
    holdId = hold.publicId;
    expect(hold.status).toBe('active');
    const audit = await audited(placed, 'legal_hold.created', compliance);
    expect(audit.resourceId).toBe(holdId);
  });

  it('ediscovery_cases_close with an active hold → denied_guard case_active_holds; no confirmation', async () => {
    const refusal = await refusedTurn(compliance, 'ediscovery_cases_close', { caseId });
    expect(refusal.execution).toMatchObject({
      decision: 'denied_guard',
      status: 'refused',
      message: GUARD_MESSAGES.case_active_holds,
    });
    await noConfirmationIn(refusal.conversation);
    expect(requestsTo({ calls: refusal.calls }, `${CASES}/{id}/close`)).toEqual([]);
    expect((await caseRow()).status).toBe('open');
  });

  it('legal_holds_release, archive_messages_dispose, archive_admin_rotate → denied_not_applicable without a loopback request', async () => {
    const message = await tenant.ax.record(org, {}, { index: false });
    for (const [tool, args, template] of [
      [
        'legal_holds_release',
        { holdId, body: { reason: 'Released with the AI assistant' } },
        `${HOLDS}/{id}/release`,
      ],
      [
        'archive_messages_dispose',
        { messageId: message.row.messagePublicId, body: { reason: 'Reviewed' } },
        `${ARCHIVE}/messages/{id}/dispose`,
      ],
      ['archive_admin_rotate', {}, `${ARCHIVE}/keys/rotate`],
    ] as const) {
      const refusal = await refusedTurn(compliance, tool, args);
      expect(refusal.execution, tool).toMatchObject({
        decision: 'denied_not_applicable',
        status: 'refused',
      });
      expect(requestsTo({ calls: refusal.calls }, template), tool).toEqual([]);
      await noConfirmationIn(refusal.conversation);
    }
    expect(
      (await ctx.prisma.archiveLegalHold.findUniqueOrThrow({ where: { publicId: holdId } })).status,
    ).toBe('active');
    expect(await ctx.prisma.archiveDisposal.count({ where: { organizationId: org.id } })).toBe(0);
    expect(await ctx.prisma.archiveEncryptionKey.count({ where: { organizationId: org.id } })).toBe(
      1,
    );
  });

  it('after the portal released the hold, ediscovery_cases_close (medium) closes the case', async () => {
    const released = await call(ctx, compliance.headers, 'post', `${HOLDS}/${holdId}/release`, {
      reason: 'Matter settled',
    }).set(idem());
    expect(released.status, JSON.stringify(released.body)).toBe(200);
    const closed = await chat(compliance, 'ediscovery_cases_close', { caseId });
    expect(closed.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(closed, 200);
    expect((await caseRow()).status).toBe('closed');
    await audited(closed, 'ediscovery.case_closed', compliance);
  });
});

describe('eDiscovery searches, review and exports through chat (D6 #14–#16, D11, D12)', () => {
  let caseId: string;
  let searchId: string;
  let records: SeededRecord[];

  beforeAll(async () => {
    caseId = await createCase(ctx, compliance);
    records = [
      await tenant.ax.record(org, {}, { index: false }),
      await tenant.ax.record(org, { malicious: true }, { index: false }),
    ];
  });

  it('ediscovery_searches_create (low): queued 202 with the queued outcome line', async () => {
    const now = Date.now();
    const queued = await chat(compliance, 'ediscovery_searches_create', {
      caseId,
      body: {
        criteria: {
          from: new Date(now - 2 * DAY_MS).toISOString(),
          to: new Date(now + DAY_MS).toISOString(),
        },
      },
    });
    expect(queued.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(queued, 202);
    const search = await ctx.prisma.ediscoverySearch.findFirstOrThrow({
      where: { organizationId: org.id, case: { publicId: caseId } },
    });
    searchId = search.publicId;
    expect(search.status).toBe('queued');
    const audit = await audited(queued, 'ediscovery.search_requested', compliance);
    expect(audit.resourceId).toBe(searchId);
    expect(await followUpTranscript(ctx, compliance, queued.proposal.conversation)).toMatch(
      /ediscovery_searches_create \(call r\d+\): the user confirmed it; [^\n]*queued \(HTTP 202\)/,
    );
    // The archive-worker's ediscovery role completes it (simulated on the writer).
    await completeSearch(ctx, org, searchId, records);
  });

  it('ediscovery_searches_review (medium) on a ref of the hits read: ediscovery.review_tagged', async () => {
    const conversation = await newConversation(ctx, compliance);
    const hits = await turn(
      ctx,
      compliance.headers,
      conversation,
      directive('ediscovery_searches_hits', { caseId, searchId }),
    );
    const read = hits.body.executions[0] as { ref: string; status: string };
    expect(read.status).toBe('succeeded');
    const reviewed = await chat(
      compliance,
      'ediscovery_searches_review',
      { caseId, searchId, body: { tag: 'relevant', messageIds: [`@${read.ref}.1`] } },
      { conversation },
    );
    expect(reviewed.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(reviewed, 200);
    const stored = await storedRequestOf(ctx, reviewed.proposal.confirmation.id);
    const [tagged] = stored.body!.messageIds as string[];
    expect(records.map((r) => r.row.messagePublicId)).toContain(tagged);
    expect(
      await ctx.prisma.ediscoverySearchHit.findFirstOrThrow({
        where: { organizationId: org.id, messagePublicId: tagged },
      }),
    ).toMatchObject({ reviewTag: 'relevant' });
    await audited(reviewed, 'ediscovery.review_tagged', compliance);
  });

  it('ediscovery_exports_create: high, re-authenticated, malicious warning; the export audit chain', async () => {
    const exported = await highChat(compliance, 'ediscovery_exports_create', {
      caseId,
      body: { searchId, reviewTags: ['relevant', 'untagged'], acknowledgeMalicious: true },
    });
    expect(exported.proposal.confirmation.summary!.warnings).toContain(W.exportMalicious);
    expect(exported.proposal.confirmation.summary!.reversible).toBe(false);
    // Step AI-6 D13: the api reads the shared ARCHIVE_EXPORT_TTL_HOURS (168 by default).
    expect(ctx.config.ARCHIVE_EXPORT_TTL_HOURS).toBe(168);
    expect(exported.proposal.confirmation.summary!.impact).toContain(
      'Download it on the case page in the portal for 168 hours; chat never shows its content.',
    );
    expect(JSON.stringify(exported.proposal.confirmation.summary)).not.toContain(
      'until it expires',
    );
    expectExecuted(exported, 202);
    const row = await ctx.prisma.ediscoveryExport.findFirstOrThrow({
      where: { organizationId: org.id, search: { publicId: searchId } },
    });
    expect(row.status).toBe('queued');
    const audit = await audited(exported, 'ediscovery.export_requested', compliance);
    expect(audit.resourceId).toBe(row.publicId);

    // The chain: proposal execution → confirmation → the export request (result correlation).
    const proposal = await executionRow(ctx, exported.proposal.execution.id as string);
    const resultCorrelation = await resultCorrelationId(ctx, exported.res);
    const proposed = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, resourceId: exported.proposal.execution.id as string },
    });
    expect(proposed.map((a) => a.action)).toEqual(['assistant.tool_executed']);
    expect(proposed[0]!.metadata).toMatchObject({
      tool: 'ediscovery_exports_create',
      status: 'pending_confirmation',
      correlationId: proposal.correlationId,
    });
    // Nothing but the proposal ran under the proposal's correlation (no export was requested).
    expect(
      (await actionsByCorrelation(ctx, proposal.correlationId)).filter(
        (a) => !a.startsWith('assistant.'),
      ),
    ).toEqual([]);
    const trail = await confirmationAudit(ctx, org.id, exported.proposal.confirmation.id);
    expect(trail.map((a) => a.action)).toEqual([
      'assistant.confirmation_requested',
      'assistant.confirmation_refused',
      'assistant.confirmation_executed',
    ]);
    expect(trail.at(-1)!.metadata).toMatchObject({
      status: 'executed',
      httpStatus: 202,
      correlationId: resultCorrelation,
      reauthUsed: true,
    });
    expect(await actionsByCorrelation(ctx, resultCorrelation)).toContain(
      'ediscovery.export_requested',
    );
    expect(await followUpTranscript(ctx, compliance, exported.proposal.conversation)).toContain(
      'downloaded only on the case page in the portal',
    );
  });

  it('ediscovery_exports_grant → denied_not_applicable; no grant row, no loopback request', async () => {
    const exportRow = await ctx.prisma.ediscoveryExport.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    const refusal = await refusedTurn(compliance, 'ediscovery_exports_grant', {
      caseId,
      exportId: exportRow.publicId,
      body: { password: 'never-sent', totpCode: '000000' },
    });
    expect(refusal.execution).toMatchObject({
      decision: 'denied_not_applicable',
      status: 'refused',
    });
    expect(
      requestsTo({ calls: refusal.calls }, `${CASES}/{id}/exports/{id}/download-grants`),
    ).toEqual([]);
    expect(await ctx.prisma.archiveDownloadGrant.count({ where: { organizationId: org.id } })).toBe(
      0,
    );
    // The stored parameters of the refused call carry no credential-pattern value.
    const row = await executionRow(ctx, refusal.execution.id as string);
    expect(JSON.stringify(row.paramsRedacted)).not.toContain('never-sent');
  });
});

describe('every compliance card and envelope stays content-free (I23)', () => {
  it('no archived body text or intake address in any stored assistant row of the organization', async () => {
    const traces = await organizationTraces();
    // The seeded records' EML body marker (test/support/archive-seed.ts) never reached chat.
    expect(traces).not.toContain('the report is attached');
    expect(traces).not.toMatch(/journal-[a-z2-7]{20,}@/);
  });
});
