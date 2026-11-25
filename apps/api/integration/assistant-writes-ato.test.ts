/**
 * Step AI-4 ATO and incident tools through chat (docs/plan/steps/32-ai-chat-security-
 * operations.md D2–D5, D10, I18, I20, §9 item 3; the `testedBy` of the 19 ATO writes and the 3
 * incident writes, D5 #1–19 and #48–50, in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md). The
 * deterministic fake provider proposes every write from a directive turn (never a real LLM); the
 * api listens on its ephemeral loopback port, so precondition reads, confirm-time re-reads and
 * the confirmed writes go through the real `/api/v1` pipeline with the user's own token, MFA
 * session and permissions. Each write asserts the api's state and the operation's own audit row
 * carrying the result execution's correlation id.
 *
 * - Accounts: protection (escalated to high, `expectedRowVersion` injected; unprotect stays low),
 *   overrides (benign escalated to high; clear low), trusted contexts add (high) and remove (high,
 *   the selected context), mailbox refresh (low, queued 202 with the queued outcome line).
 * - Incidents: create (low, the account read), update (CAS `expectedRowVersion`; resolved →
 *   medium; false positive with category feedback → high), note (low).
 * - Responses through the existing approval model: analyst A requests `restrict_smtp_sending`
 *   (high; `pending_approval`, the request outcome line), analyst B approves through chat (high,
 *   re-authenticated; the gateway action executes, `approvedBy` = B), B rolls it back (the
 *   restriction is lifted); B rejects and A cancels other pending requests.
 * - Settings (high, CAS `expectedRowVersion`, minimum 0) and identity-provider integrations with
 *   the step 8.5 fixtures (`ProviderSeeder`: an 8.2 connection row with a verified domain and a
 *   telemetry grant; no provider endpoint is called by the api): create without settings
 *   (medium) and with settings (escalated to high), update (high, CAS `rowVersion`), pause /
 *   resume (medium), backfill and health check (queued 202), remove (high).
 *
 * Synthetic `it-ato-*` organizations and `.example` / `.test` values only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers patch /api/v1/ato/accounts/:accountId
// @covers post /api/v1/ato/accounts/:accountId/mailbox-state/refresh
// @covers put /api/v1/ato/accounts/:accountId/override
// @covers post /api/v1/ato/accounts/:accountId/override/clear
// @covers post /api/v1/ato/accounts/:accountId/trusted-contexts
// @covers delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId
// @covers post /api/v1/ato/incidents/:incidentId/responses
// @covers post /api/v1/ato/responses/:responseId/approve
// @covers post /api/v1/ato/responses/:responseId/reject
// @covers post /api/v1/ato/responses/:responseId/cancel
// @covers post /api/v1/ato/responses/:responseId/rollback
// @covers put /api/v1/ato/settings
// @covers post /api/v1/ato/providers
// @covers patch /api/v1/ato/providers/:integrationId
// @covers delete /api/v1/ato/providers/:integrationId
// @covers post /api/v1/ato/providers/:integrationId/pause
// @covers post /api/v1/ato/providers/:integrationId/resume
// @covers post /api/v1/ato/providers/:integrationId/backfill
// @covers post /api/v1/ato/providers/:integrationId/health-check
// @covers post /api/v1/incidents
// @covers patch /api/v1/incidents/:incidentId
// @covers post /api/v1/incidents/:incidentId/notes
import { AI4_ESCALATION_WARNINGS as W } from '@email-gateway/assistant';
import { defaultBindingSettings } from '@email-gateway/idp-adapters';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  type ChatWrite,
  clearAssistantCounters,
  createAssistantApp,
  credentialKeys,
  expectExecuted,
  followUpTranscript,
  type Member,
  operationActionsOf,
  platformMember,
  proposeAndConfirm,
  resultCorrelationId,
  auditByCorrelation,
  storedRequestOf,
  waitForRead,
} from './support/assistant';
import {
  ATO,
  type AtoChat,
  atoChatTenant,
  mailboxLabel,
  requestResponse,
  responseRow,
  responseVisible,
} from './support/assistant-ato';
import type { AtoSeeder } from './support/ato';
import { ProviderSeeder } from './support/ato-providers';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';

/** A stale row version the model "remembers"; the executor replaces it from the snapshot. */
const STALE = 999;
const DAY_MS = 86_400_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let chatTenant: AtoChat;
let org: FixtureOrganization;
let seed: AtoSeeder;
let analystA: Member;
let analystB: Member;

const chat = (
  who: Member,
  tool: string,
  args: Record<string, unknown>,
  options: { conversation?: string; reauth?: boolean } = {},
): Promise<ChatWrite> => proposeAndConfirm(ctx, fx, who, tool, args, options);

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

function credentialFree(result: ChatWrite): void {
  expect(credentialKeys(result.proposal.confirmation.summary)).toEqual([]);
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  chatTenant = await atoChatTenant(ctx, fx, operator);
  ({ org, seed, analystA, analystB } = chatTenant);
}, 240_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('ATO accounts through chat (D5 #1, #3–#6)', () => {
  let accountId: string;
  const accountRow = () =>
    ctx.prisma.atoAccount.findUniqueOrThrow({ where: { publicId: accountId } });

  beforeAll(async () => {
    const { account } = await seed.compromised(org.id, mailboxLabel('acct'));
    accountId = account.publicId;
    await waitForRead(ctx, analystA, `${ATO}/accounts/${accountId}`);
  });

  it('ato_accounts_update: protected → high (escalated), expectedRowVersion injected; unprotect stays low', async () => {
    const before = await accountRow();
    const protect = await chat(analystA, 'ato_accounts_update', {
      accountId,
      body: { protected: true, reason: 'VIP mailbox', expectedRowVersion: STALE },
    });
    expect(protect.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(protect.proposal.confirmation.summary!.warnings).toContain(W.atoProtected);
    expectExecuted(protect, 200);
    expect(
      (await storedRequestOf(ctx, protect.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect(await accountRow()).toMatchObject({ protected: true, protectedReason: 'VIP mailbox' });
    await audited(protect, 'ato.account_protected', analystA);
    credentialFree(protect);

    await waitForRead(ctx, analystA, `${ATO}/accounts/${accountId}`, (b) => b.protected === true);
    const unprotect = await chat(analystA, 'ato_accounts_update', {
      accountId,
      body: { protected: false, expectedRowVersion: STALE },
    });
    expect(unprotect.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(unprotect, 200);
    expect((await accountRow()).protected).toBe(false);
    await audited(unprotect, 'ato.account_unprotected', analystA);
  });

  it('ato_accounts_set_override: benign escalates to high; ato_accounts_clear_override is low', async () => {
    const benign = await chat(analystA, 'ato_accounts_set_override', {
      accountId,
      body: { verdict: 'benign', reason: 'User confirmed the trip by phone', expiresInHours: 24 },
    });
    expect(benign.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(benign.proposal.confirmation.summary!.warnings).toContain(W.atoBenign);
    expectExecuted(benign, 200);
    const overridden = await accountRow();
    expect(overridden.overrideId).not.toBeNull();
    await audited(benign, 'ato.override_set', analystA);

    await waitForRead(
      ctx,
      analystA,
      `${ATO}/accounts/${accountId}`,
      (b) => (b.overrideDetail as { verdict?: string } | null)?.verdict === 'benign',
    );
    const clear = await chat(analystA, 'ato_accounts_clear_override', {
      accountId,
      body: { reason: 'Trip over; normal scoring' },
    });
    expect(clear.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(clear, 200);
    expect((await accountRow()).overrideId).toBeNull();
    await audited(clear, 'ato.override_cleared', analystA);
  });

  it('ato_accounts_add_trusted_context (high) and ato_accounts_remove_trusted_context (high, the selected context)', async () => {
    const add = await chat(analystA, 'ato_accounts_add_trusted_context', {
      accountId,
      body: { kind: 'country', value: 'de', reason: 'Business trips', expiresInDays: 30 },
    });
    expect(add.proposal.confirmation).toMatchObject({ risk: 'high' });
    const write = expectExecuted(add, 201);
    expect(write).toMatchObject({
      method: 'POST',
      path: `${ATO}/accounts/${accountId}/trusted-contexts`,
    });
    const contextId = (
      await ctx.prisma.atoTrustedContext.findFirstOrThrow({
        where: { organizationId: org.id, accountId: (await accountRow()).id, kind: 'country' },
      })
    ).publicId;
    await audited(add, 'ato.trusted_context_added', analystA);

    await waitForRead(ctx, analystA, `${ATO}/accounts/${accountId}`, (b) =>
      ((b.trustedContexts as Array<{ id: string }> | undefined) ?? []).some(
        (c) => c.id === contextId,
      ),
    );
    const remove = await chat(analystA, 'ato_accounts_remove_trusted_context', {
      accountId,
      contextId,
    });
    expect(remove.proposal.confirmation).toMatchObject({ risk: 'high' });
    // The card shows the selected context, not the whole account.
    expect(JSON.stringify(remove.proposal.confirmation.summary)).toContain('DE');
    expectExecuted(remove, 204);
    expect(await ctx.prisma.atoTrustedContext.count({ where: { publicId: contextId } })).toBe(0);
    await audited(remove, 'ato.trusted_context_removed', analystA);
  });
});

describe('incidents through chat (D5 #48–#50)', () => {
  let incidentId: string;
  const incidentRow = () =>
    ctx.prisma.securityIncident.findUniqueOrThrow({ where: { publicId: incidentId } });

  it('incidents_create (low): the ATO account read, a manual incident', async () => {
    const account = await seed.mailbox(org.id, mailboxLabel('manual'));
    await waitForRead(ctx, analystA, `${ATO}/accounts/${account.publicId}`);
    const created = await chat(analystA, 'incidents_create', {
      body: {
        category: 'account_takeover',
        subject: { type: 'ato_account', id: account.publicId },
        severity: 'high',
        reason: 'User reported sign-in prompts they did not start',
      },
    });
    expect(created.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(created, 201);
    const row = await ctx.prisma.securityIncident.findFirstOrThrow({
      where: { organizationId: org.id, subjectRefId: account.id },
    });
    incidentId = row.publicId;
    expect(row).toMatchObject({ origin: 'manual', status: 'open', severity: 'high' });
    await audited(created, 'security_incident.created', analystA);
  });

  it('incidents_add_note (low)', async () => {
    await waitForRead(ctx, analystA, `/api/v1/incidents/${incidentId}`);
    const note = await chat(analystA, 'incidents_add_note', {
      incidentId,
      body: { note: 'Called the user; not travelling.' },
    });
    expect(note.proposal.confirmation).toMatchObject({ risk: 'low' });
    expectExecuted(note, 201);
    await audited(note, 'security_incident.note_added', analystA);
  });

  it('incidents_update: CAS injected; a triage step is low; resolved escalates to medium', async () => {
    const before = await incidentRow();
    const confirmIt = await chat(analystA, 'incidents_update', {
      incidentId,
      body: { status: 'investigating', severity: 'critical', expectedRowVersion: STALE },
    });
    expect(confirmIt.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(confirmIt, 200);
    expect(
      (await storedRequestOf(ctx, confirmIt.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(before.rowVersion);
    expect(await incidentRow()).toMatchObject({ status: 'investigating', severity: 'critical' });
    await audited(confirmIt, 'security_incident.status_changed', analystA);

    await waitForRead(
      ctx,
      analystA,
      `/api/v1/incidents/${incidentId}`,
      (b) => b.status === 'investigating',
    );
    const resolve = await chat(analystA, 'incidents_update', {
      incidentId,
      body: {
        status: 'resolved',
        resolution: { code: 'remediated', note: 'Password reset and sessions revoked.' },
        expectedRowVersion: STALE,
      },
    });
    expect(resolve.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expect(resolve.proposal.confirmation.summary!.warnings).toContain(W.incidentResolved);
    expectExecuted(resolve, 200);
    expect((await incidentRow()).status).toBe('resolved');
  });

  it('incidents_update: false_positive with categoryFeedback escalates to high; signals dismissed', async () => {
    const { incident, account } = await seed.compromised(org.id, mailboxLabel('fp'));
    await waitForRead(ctx, analystA, `/api/v1/incidents/${incident.publicId}`);
    const fp = await chat(analystA, 'incidents_update', {
      incidentId: incident.publicId,
      body: {
        status: 'false_positive',
        resolution: { code: 'benign_activity', note: 'Confirmed business trip to Frankfurt.' },
        categoryFeedback: {
          trustedContexts: [
            { kind: 'country', value: 'DE', expiresInDays: 30, reason: 'Business trip' },
          ],
          dismissSignals: true,
        },
        expectedRowVersion: STALE,
      },
    });
    expect(fp.proposal.confirmation).toMatchObject({
      risk: 'high',
      requiresReauth: expect.any(Boolean),
    });
    expect(fp.proposal.confirmation.summary!.warnings).toEqual(
      expect.arrayContaining([W.incidentFalsePositive, W.incidentFeedback]),
    );
    expectExecuted(fp, 200);
    expect(
      (await ctx.prisma.securityIncident.findUniqueOrThrow({ where: { id: incident.id } })).status,
    ).toBe('false_positive');
    const contexts = await ctx.prisma.atoTrustedContext.findMany({
      where: { accountId: account.id },
    });
    expect(contexts.map((c) => [c.kind, c.value, c.source])).toEqual([
      ['country', 'DE', 'false_positive_feedback'],
    ]);
    expect(await operationActionsOf(ctx, fp.res)).toContain('security_incident.status_changed');
  });
});

describe('ATO responses through the existing approval model (D5 #7–#11, I18)', () => {
  it('A requests restrict_smtp_sending (pending approval); B approves through chat; B rolls it back', async () => {
    const { incident, account } = await seed.compromised(org.id, mailboxLabel('restrict'));
    await waitForRead(ctx, analystA, `/api/v1/incidents/${incident.publicId}`);
    const requested = await chat(analystA, 'ato_responses_request', {
      incidentId: incident.publicId,
      body: {
        actionType: 'restrict_smtp_sending',
        durationMinutes: 60,
        reason: 'Outbound burst after impossible travel',
      },
    });
    expect(requested.proposal.confirmation).toMatchObject({ risk: 'high' });
    expectExecuted(requested, 201);
    const action = await ctx.prisma.atoResponseAction.findFirstOrThrow({
      where: { organizationId: org.id, accountId: account.id, actionType: 'restrict_smtp_sending' },
    });
    expect(action).toMatchObject({ status: 'pending_approval', requiresApproval: true });
    expect(await operationActionsOf(ctx, requested.res)).toContain('ato.response_requested');
    // D10: the outcome line of a request says another responder must approve it.
    expect(await followUpTranscript(ctx, analystA, requested.proposal.conversation)).toContain(
      'the user confirmed it; the response was requested (HTTP 201). If it needs approval, another responder must approve it; the requester cannot.',
    );

    const responseId = action.publicId;
    await responseVisible(ctx, analystB, responseId, 'pending_approval');
    const approved = await chat(analystB, 'ato_responses_approve', {
      responseId,
      body: { reason: 'Confirmed by phone' },
    });
    expect(approved.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(JSON.stringify(approved.proposal.confirmation.summary)).toContain(
      'Outbound burst after impossible travel',
    );
    const write = expectExecuted(approved, 200);
    expect(write).toMatchObject({ path: `${ATO}/responses/${responseId}/approve` });
    expect(write.idempotencyKey).toBe(approved.proposal.confirmation.id);
    const executed = await responseRow(ctx, responseId);
    expect(executed.status).toBe('succeeded');
    expect(approved.res.body.execution).toMatchObject({ httpStatus: 200 });
    const view = await waitForRead(
      ctx,
      analystB,
      `${ATO}/responses/${responseId}`,
      (b) => b.status === 'succeeded',
    );
    expect(view).toMatchObject({
      approvedBy: analystB.user.publicId,
      requestedBy: { type: 'user', id: analystA.user.publicId },
      restriction: { kind: 'send_block', status: 'active' },
    });
    await audited(approved, 'ato.response_approved', analystB);

    const rolled = await chat(analystB, 'ato_responses_rollback', {
      responseId,
      body: { reason: 'Password reset done; lift it' },
    });
    expect(rolled.proposal.confirmation).toMatchObject({ risk: 'high' });
    expectExecuted(rolled, 200);
    expect((await responseRow(ctx, responseId)).status).toBe('rolled_back');
    const restriction = await ctx.prisma.atoSmtpRestriction.findFirstOrThrow({
      where: { organizationId: org.id, responseActionId: executed.id },
    });
    expect(restriction.status).toBe('lifted');
    expect(await operationActionsOf(ctx, rolled.res)).toEqual(
      expect.arrayContaining([expect.stringMatching(/^ato\.response_roll/)]),
    );
  });

  it('B rejects a pending request (medium); A cancels its own pending request (medium)', async () => {
    const { incident } = await seed.compromised(org.id, mailboxLabel('decide'));
    const toReject = await requestResponse(ctx, analystA.headers, incident.publicId, {
      actionType: 'require_mfa',
      reason: 'Force MFA for this user',
    });
    expect(toReject.status, JSON.stringify(toReject.body)).toBe(201);
    expect(toReject.body.status).toBe('pending_approval');
    await responseVisible(ctx, analystB, toReject.body.id as string, 'pending_approval');
    const rejected = await chat(analystB, 'ato_responses_reject', {
      responseId: toReject.body.id,
      body: { reason: 'Not needed: travel confirmed' },
    });
    expect(rejected.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expectExecuted(rejected, 200);
    expect((await responseRow(ctx, toReject.body.id as string)).status).toBe('rejected');
    await audited(rejected, 'ato.response_rejected', analystB);

    const toCancel = await requestResponse(ctx, analystA.headers, incident.publicId, {
      actionType: 'suspend_account',
      reason: 'Suspend until the review',
    });
    expect(toCancel.status, JSON.stringify(toCancel.body)).toBe(201);
    await responseVisible(ctx, analystA, toCancel.body.id as string, 'pending_approval');
    const cancelled = await chat(analystA, 'ato_responses_cancel', {
      responseId: toCancel.body.id,
      body: { reason: 'Requested in error' },
    });
    expect(cancelled.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(cancelled, 200);
    expect((await responseRow(ctx, toCancel.body.id as string)).status).toBe('cancelled');
    await audited(cancelled, 'ato.response_cancelled', analystA);
  });
});

describe('ATO settings through chat (D5 #12)', () => {
  it('ato_settings_update (high): expectedRowVersion injected from the settings read', async () => {
    const current = await waitForRead(ctx, analystA, `${ATO}/settings`);
    const result = await chat(analystA, 'ato_settings_update', {
      body: {
        expectedRowVersion: STALE,
        settings: { notifications: { incidentMinSeverity: 'critical' } },
      },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(result.proposal.confirmation.summary!.warnings.length).toBeGreaterThanOrEqual(1);
    expectExecuted(result, 200);
    expect(
      (await storedRequestOf(ctx, result.proposal.confirmation.id)).body!.expectedRowVersion,
    ).toBe(current.rowVersion);
    const row = await ctx.prisma.atoSetting.findUniqueOrThrow({
      where: { organizationId: org.id },
    });
    expect(row.rowVersion).toBe((current.rowVersion as number) + 1);
    await audited(result, 'ato.settings_updated', analystA);
  });
});

describe('identity-provider integrations through chat (D5 #2, #13–#19)', () => {
  let prov: ProviderSeeder;
  let integrationId: string;
  const integrationRow = (publicId: string) =>
    ctx.prisma.atoProviderIntegration.findUniqueOrThrow({ where: { publicId } });

  beforeAll(() => {
    prov = new ProviderSeeder(ctx, fx);
  });

  it('ato_providers_create without settings is medium; with settings it escalates to high', async () => {
    const plain = await prov.connection(org, { provider: 'google_workspace' });
    const medium = await chat(analystA, 'ato_providers_create', {
      body: { connectionId: plain.publicId },
    });
    expect(medium.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expectExecuted(medium, 201);
    const mediumRow = await ctx.prisma.atoProviderIntegration.findFirstOrThrow({
      where: { organizationId: org.id, connectorRef: plain.publicId },
    });
    expect(mediumRow.status).toBe('active');
    await audited(medium, 'ato.provider.bound', analystA);

    // Removed (high) to stay below the per-organization limit.
    await waitForRead(ctx, analystA, `${ATO}/providers/${mediumRow.publicId}`);
    const removed = await chat(analystA, 'ato_providers_remove', {
      integrationId: mediumRow.publicId,
      body: { reason: 'Bound by mistake' },
    });
    expect(removed.proposal.confirmation).toMatchObject({ risk: 'high' });
    expectExecuted(removed, 200);
    expect((await integrationRow(mediumRow.publicId)).status).toBe('disabled');
    await audited(removed, 'ato.provider.unbound', analystA);

    const conn = await prov.connection(org);
    const high = await chat(analystA, 'ato_providers_create', {
      body: { connectionId: conn.publicId, settings: defaultBindingSettings() },
    });
    expect(high.proposal.confirmation).toMatchObject({ risk: 'high' });
    expect(high.proposal.confirmation.summary!.warnings).toContain(W.idpSettings);
    expectExecuted(high, 201);
    integrationId = (
      await ctx.prisma.atoProviderIntegration.findFirstOrThrow({
        where: { organizationId: org.id, connectorRef: conn.publicId },
      })
    ).publicId;
  });

  it('ato_providers_update (high): rowVersion injected', async () => {
    const before = await integrationRow(integrationId);
    await waitForRead(ctx, analystA, `${ATO}/providers/${integrationId}`);
    const next = defaultBindingSettings();
    next.streams.oauth_consents.enabled = false;
    const result = await chat(analystA, 'ato_providers_update', {
      integrationId,
      body: { rowVersion: STALE, settings: next },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high' });
    expectExecuted(result, 200);
    expect((await storedRequestOf(ctx, result.proposal.confirmation.id)).body!.rowVersion).toBe(
      before.rowVersion,
    );
    expect(await integrationRow(integrationId)).toMatchObject({
      rowVersion: before.rowVersion + 1,
      settingsVersion: before.settingsVersion + 1,
    });
    await audited(result, 'ato.provider.updated', analystA);
  });

  it('ato_providers_pause / ato_providers_resume (medium)', async () => {
    await waitForRead(
      ctx,
      analystA,
      `${ATO}/providers/${integrationId}`,
      (b) => b.status === 'active',
    );
    const paused = await chat(analystA, 'ato_providers_pause', {
      integrationId,
      body: { reason: 'Maintenance window' },
    });
    expect(paused.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expectExecuted(paused, 200);
    expect(await integrationRow(integrationId)).toMatchObject({
      status: 'paused',
      pausedReason: 'user',
    });
    await audited(paused, 'ato.provider.paused', analystA);

    await waitForRead(
      ctx,
      analystA,
      `${ATO}/providers/${integrationId}`,
      (b) => b.status === 'paused',
    );
    const resumed = await chat(analystA, 'ato_providers_resume', { integrationId });
    expect(resumed.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(resumed, 200);
    expect(await integrationRow(integrationId)).toMatchObject({
      status: 'active',
      pausedReason: null,
    });
    await audited(resumed, 'ato.provider.resumed', analystA);
  });

  it('ato_providers_health_check (low) and ato_providers_backfill (medium) are queued (202, D10 line)', async () => {
    await waitForRead(
      ctx,
      analystA,
      `${ATO}/providers/${integrationId}`,
      (b) => b.status === 'active',
    );
    const probe = await chat(analystA, 'ato_providers_health_check', { integrationId });
    expect(probe.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(probe, 202);
    await audited(probe, 'ato.provider.health_check_requested', analystA);
    expect(await followUpTranscript(ctx, analystA, probe.proposal.conversation)).toContain(
      'ato_providers_health_check (call r1): the user confirmed it; it was queued (HTTP 202).',
    );

    // What the worker writes when the initial backfill reached `now − settle`.
    const row = await integrationRow(integrationId);
    await ctx.prisma.atoProviderStream.updateMany({
      where: { integrationId: row.id, status: 'backfilling' },
      data: {
        status: 'active',
        backfillCompletedAt: new Date(),
        cursorSeq: 12n,
        coveredFrom: new Date(Date.now() - 2 * DAY_MS),
        watermarkAt: new Date(Date.now() - 5 * 60_000),
      },
    });
    const backfill = await chat(analystA, 'ato_providers_backfill', {
      integrationId,
      body: { from: new Date(Date.now() - 3 * DAY_MS).toISOString() },
    });
    expect(backfill.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(backfill, 202);
    const streams = await ctx.prisma.atoProviderStream.findMany({
      where: { integrationId: row.id },
    });
    expect(streams.find((s) => s.stream === 'sign_ins')).toMatchObject({ status: 'backfilling' });
    await audited(backfill, 'ato.provider.backfill_requested', analystA);
  });

  it('ato_account_mailbox_refresh (low): a probed integration with a resolved identity → queued 202', async () => {
    const account = await seed.mailbox(org.id, mailboxLabel('mbx'));
    const row = await prov.probed(integrationId);
    await prov.identity(account, row);
    await waitForRead(ctx, analystA, `${ATO}/accounts/${account.publicId}`);
    const refresh = await chat(analystA, 'ato_account_mailbox_refresh', {
      accountId: account.publicId,
    });
    expect(refresh.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(refresh, 202);
    expect(refresh.res.body.confirmation).toMatchObject({ result: { httpStatus: 202 } });
    const identity = await ctx.prisma.atoAccountIdentity.findFirstOrThrow({
      where: { accountId: account.id },
    });
    expect(identity.mailboxRefreshRequestedAt).not.toBeNull();
    await audited(refresh, 'ato.mailbox_state.refresh_requested', analystA);
    expect(await followUpTranscript(ctx, analystA, refresh.proposal.conversation)).toContain(
      'ato_account_mailbox_refresh (call r1): the user confirmed it; it was queued (HTTP 202).',
    );
  });
});
