/**
 * Step AI-R report emails through chat on the real stack (docs/plan/steps/31-ai-chat-reports.md
 * D5, D8, D11, I17, §9 item 5; contracts §35.3, §4.3; ADR-0095 and the ADR-0093 amendment; the
 * `testedBy` of the native write `report_send_email` in
 * docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): real MySQL writer and replica, Redis and MinIO
 * from the local `.env`, the api on its ephemeral loopback port, the deterministic fake provider
 * (never a real LLM, never the internet). This suite never sends mail: it asserts the delivery
 * row and its outbox event `assistant.report.email_requested.v1` (ids only); the notification-
 * worker's own suite covers the mail through its in-process SMTP sink.
 *
 * Covered: "send this report to my email" → a `medium` confirmation card (summary checked field
 * by field) → confirm → confirmation `executed`, delivery `queued` with the normalized address,
 * the outbox row (payload ids only, eventId = delivery id), the audit rows correlated; the
 * recipient matrix (own address, an active verified member, invited / disabled / unverified
 * members refused, another organization's user refused, addresses of `verified` and `active`
 * domains, a subdomain refused, `pending_verification` and `suspended` domains refused, an
 * external address refused, upper-case normalization, CR/LF, two addresses and a display name →
 * `denied_schema`); a refused recipient leaves no confirmation and an audit row without the
 * address (domain and SHA-256 only); the per-user and per-tenant daily limits at proposal
 * (`denied_budget`) and at confirm (two confirmations racing past the limit: one executes, the
 * other fails `429` with no delivery); state changes between proposal and confirm (the report
 * purged → refused at confirm, nothing sent; the member disabled → `403`); a foreign `reportId`
 * (another user's, another organization's) → `404` proposal failure. Synthetic `it-*`
 * organizations and `.test` / `.example` addresses only; every row and object is removed.
 */
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers get /api/v1/assistant/reports/:reportId
// Native tool covered (no route): report_send_email (AssistantNative_reportSendEmail).
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TransactionRunner } from '../src/database/transaction-runner';
import { ConversationsRepository } from '../src/modules/assistant/repositories/conversations.repository';
import type { IntegrationApp } from './support/app';
import {
  clearAssistantCounters,
  confirm,
  confirmationAudit,
  confirmationRow,
  createAssistantApp,
  directive,
  enableAssistant,
  executionRow,
  generateReport,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  propose,
  type Proposal,
  REPORTS,
  call,
  reportRow,
  seedDeliveries,
  trackReports,
  turn,
} from './support/assistant';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  uniqueSuffix,
} from './support/fixtures';

const USER_LIMIT = 3;
const TENANT_LIMIT = 20;
const EVENT = 'assistant.report.email_requested.v1';

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let org: FixtureOrganization;
let otherOrg: FixtureOrganization;
let sender: Member;
let colleague: Member;
let activeMember: FixtureUser;
let invited: FixtureUser;
let disabled: FixtureUser;
let unverified: FixtureUser;
let outsider: FixtureUser;
let foreigner: Member;
const orgIds: bigint[] = [];
const domains: Record<'verified' | 'active' | 'pending' | 'suspended', string> = {
  verified: '',
  active: '',
  pending: '',
  suspended: '',
};

const sha = (address: string) => createHash('sha256').update(address.toLowerCase()).digest('hex');

async function organization(): Promise<FixtureOrganization> {
  const created = await fx.createOrganization();
  orgIds.push(created.id);
  return created;
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp({
    env: {
      ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY: String(USER_LIMIT),
      ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY: String(TENANT_LIMIT),
      ASSISTANT_MAX_PENDING_CONFIRMATIONS: '20',
    },
  }));
  fx = createFixtures(ctx);
  trackReports(ctx, fx, orgIds);
  operator = await platformMember(ctx, fx);
  org = await organization();
  otherOrg = await organization();
  sender = await memberWith(ctx, fx, org, {
    permissions: ['report:read', 'assistant:configure', 'organization:read'],
  });
  colleague = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
  foreigner = await memberWith(ctx, fx, otherOrg, {
    permissions: ['report:read', 'assistant:configure', 'organization:read'],
  });
  await enableAssistant(ctx, operator, org, sender);
  await enableAssistant(ctx, operator, otherOrg, foreigner);
  activeMember = await fx.createUser(org, { roles: [] });
  invited = await fx.createUser(org, { roles: [], status: 'invited' });
  disabled = await fx.createUser(org, { roles: [], status: 'disabled' });
  unverified = await fx.createUser(org, { roles: [], emailVerified: false });
  outsider = await fx.createUser(otherOrg, { roles: [] });
  const suffix = uniqueSuffix();
  const statuses = {
    verified: 'verified',
    active: 'active',
    pending: 'pending_verification',
    suspended: 'suspended',
  } as const;
  for (const [label, status] of Object.entries(statuses) as Array<
    [keyof typeof statuses, (typeof statuses)[keyof typeof statuses]]
  >) {
    const name = `${label}-${suffix}.report-it.example`;
    await ctx.prisma.domain.create({
      data: { organizationId: org.id, name, status, statusChangedAt: new Date() },
    });
    domains[label] = name;
  }
}, 180_000);

afterAll(async () => {
  if (ctx) await clearAssistantCounters(ctx, orgIds);
  await fx?.cleanup();
  await ctx?.close();
});

/** A conversation of `who` with one generated (small) report. */
async function withReport(who: Member): Promise<{ conversation: string; reportId: string }> {
  const conversation = await newConversation(ctx, who);
  const { report } = await generateReport(ctx, who, conversation, {
    args: { sections: ['traffic'] },
  });
  return { conversation, reportId: report.reportId };
}

/** A directive turn of `report_send_email` → its execution (and the turn's confirmations). */
async function sendTurn(who: Member, conversation: string, args: Record<string, unknown>) {
  const res = await turn(ctx, who.headers, conversation, directive('report_send_email', args));
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const execution = (res.body.executions as Array<Record<string, unknown>>).find(
    (e) => e.tool === 'report_send_email',
  )!;
  expect(execution).toBeDefined();
  return { res, execution, confirmations: res.body.confirmations as unknown[] };
}

describe('send this report to my email (D5, §9 item 5)', () => {
  it('proposes a medium confirmation, confirm queues one delivery with its outbox event and audit', async () => {
    const { conversation, reportId } = await withReport(sender);
    const report = await reportRow(ctx, reportId);
    const proposal = await propose(ctx, sender, 'send this report to my email', conversation);
    const own = sender.user.email;
    expect(proposal.confirmation).toMatchObject({
      tool: 'report_send_email',
      operationId: 'AssistantNative_reportSendEmail',
      risk: 'medium',
      requiresReauth: false,
      status: 'pending',
    });
    // The summary (assistant-confirmation/1, template report_send_email), field by field.
    const summary = proposal.confirmation.summary!;
    expect(summary).toMatchObject({
      version: 'assistant-confirmation/1',
      title: 'Email security report',
      action: `Sends the security report as an HTML email to ${own}.`,
      reversible: false,
      request: { method: 'POST', path: 'native:report_send_email' },
    });
    const target = Object.fromEntries(summary.target.map((t) => [t.label, t.value]));
    expect(target.Recipient).toBe(own);
    expect(target['Recipient type']).toMatch(/your own address/);
    expect(target.Report).toBe(report.title);
    expect(target.Period).toBe('Last 7 days');
    expect(target.Size).toBeDefined();
    expect(summary.impact.join(' ')).toMatch(/notification mailer/);
    expect(summary.impact.join(' ')).toMatch(/attached/);
    expect(summary.warnings).toEqual(
      expect.arrayContaining([
        'Emails cannot be recalled after sending.',
        `${USER_LIMIT} of ${USER_LIMIT} report emails left today for you (${TENANT_LIMIT} for your organization).`,
      ]),
    );
    const stored = await confirmationRow(ctx, proposal.confirmation.id);
    expect(stored.request).toMatchObject({
      method: 'POST',
      path: 'native:report_send_email',
      body: { reportId, to: own },
    });
    // Nothing is queued before the confirm.
    expect(await ctx.prisma.aiChatReportDelivery.count({ where: { reportId: report.id } })).toBe(0);

    const res = await confirm(ctx, sender, proposal);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 202, error: null },
    });
    expect(res.body.execution).toMatchObject({
      tool: 'report_send_email',
      status: 'succeeded',
      httpStatus: 202,
      card: { kind: 'message', message: `Report email queued to ${own}` },
    });
    const deliveries = await ctx.prisma.aiChatReportDelivery.findMany({
      where: { reportId: report.id },
    });
    expect(deliveries).toHaveLength(1);
    const delivery = deliveries[0]!;
    expect(delivery).toMatchObject({
      organizationId: org.id,
      userId: sender.user.id,
      status: 'queued',
      recipientAddress: own,
      recipientSha256: sha(own),
      recipientKind: 'self',
      confirmationId: stored.id,
      sizeBytes: report.sizeBytes,
      sentAt: null,
    });
    const resultExecution = await executionRow(ctx, res.body.execution.id as string);
    expect(delivery.correlationId).toBe(resultExecution.correlationId.slice(0, 128));

    // The outbox row: ids only (no address, no HTML, no figures), eventId = the delivery id.
    const outbox = await ctx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: EVENT, aggregateId: delivery.publicId },
    });
    expect(outbox).toHaveLength(1);
    expect(outbox[0]).toMatchObject({
      eventId: delivery.publicId,
      aggregateType: 'assistant_report_delivery',
      correlationId: resultExecution.correlationId,
    });
    const payload = outbox[0]!.payload as Record<string, unknown>;
    expect(Object.keys(payload).sort()).toEqual(['deliveryId', 'reportId', 'requestedAt']);
    expect(payload).toMatchObject({ deliveryId: delivery.publicId, reportId });
    expect(JSON.stringify(outbox[0]!.payload)).not.toContain('@');

    // Audit: the confirmation's rows and the request, correlated.
    const confirmationActions = (
      await confirmationAudit(ctx, org.id, proposal.confirmation.id)
    ).map((a) => a.action);
    expect(confirmationActions).toEqual(
      expect.arrayContaining([
        'assistant.confirmation_requested',
        'assistant.confirmation_executed',
      ]),
    );
    const requested = await ctx.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: org.id,
        action: 'assistant.report_email_requested',
        resourceId: delivery.publicId,
      },
    });
    expect(requested.resourceType).toBe('assistant_report_delivery');
    expect(requested.metadata).toMatchObject({
      deliveryId: delivery.publicId,
      reportId,
      confirmationId: proposal.confirmation.id,
      recipientKind: 'self',
      recipientDomain: own.split('@')[1],
      recipientSha256: sha(own),
    });
    // The audit row carries the confirm request's correlation id; the metadata the execution's.
    expect(resultExecution.correlationId.startsWith(requested.correlationId ?? '-')).toBe(true);
    expect(requested.metadata).toMatchObject({ correlationId: resultExecution.correlationId });

    // The owner's report view lists the delivery.
    const view = await call(ctx, sender.headers, 'get', `${REPORTS}/${reportId}`);
    expect(view.body.report.deliveries).toEqual([
      expect.objectContaining({ id: delivery.publicId, to: own, status: 'queued' }),
    ]);
    // A replayed confirm sends nothing more (one confirmation → at most one delivery).
    const again = await confirm(ctx, sender, proposal);
    expect(again.status).toBeGreaterThanOrEqual(400);
    expect(await ctx.prisma.aiChatReportDelivery.count({ where: { reportId: report.id } })).toBe(1);
  });
});

describe('the recipient rule (I17, R-4)', () => {
  it('allows only the own address, active verified members and verified/active domains; refusals leave no confirmation', async () => {
    const { conversation, reportId } = await withReport(colleague);
    type Case = {
      name: string;
      to?: string;
      expect: 'pending' | 'refused' | 'schema';
      kind?: 'self' | 'member' | 'domain';
      stored?: string;
    };
    const cases: Case[] = [
      {
        name: 'own address (default)',
        expect: 'pending',
        kind: 'self',
        stored: colleague.user.email,
      },
      {
        name: 'own address, upper-case domain',
        to: colleague.user.email.replace(/@.*/, (d) => d.toUpperCase()),
        expect: 'pending',
        kind: 'self',
        stored: colleague.user.email,
      },
      { name: 'active verified member', to: activeMember.email, expect: 'pending', kind: 'member' },
      { name: 'invited member', to: invited.email, expect: 'refused' },
      { name: 'disabled member', to: disabled.email, expect: 'refused' },
      { name: 'member without a verified email', to: unverified.email, expect: 'refused' },
      { name: "another organization's user", to: outsider.email, expect: 'refused' },
      {
        name: 'address in a verified domain',
        to: `security-team@${domains.verified}`,
        expect: 'pending',
        kind: 'domain',
      },
      {
        name: 'address in an active domain',
        to: `soc@${domains.active}`,
        expect: 'pending',
        kind: 'domain',
      },
      {
        name: 'upper-case address of a verified domain (domain normalized, local part kept)',
        to: `Board.Members@${domains.verified.toUpperCase()}`,
        expect: 'pending',
        kind: 'domain',
        stored: `Board.Members@${domains.verified}`,
      },
      {
        name: 'subdomain of a verified domain',
        to: `a@sub.${domains.verified}`,
        expect: 'refused',
      },
      { name: 'pending domain', to: `a@${domains.pending}`, expect: 'refused' },
      { name: 'suspended domain', to: `a@${domains.suspended}`, expect: 'refused' },
      { name: 'external address', to: 'someone@outside.test', expect: 'refused' },
      {
        name: 'CR/LF injection',
        to: `a@${domains.verified}\r\nbcc@outside.test`,
        expect: 'schema',
      },
      {
        name: 'two addresses',
        to: `a@${domains.verified}, b@${domains.verified}`,
        expect: 'schema',
      },
      { name: 'display name', to: `"Board" <a@${domains.verified}>`, expect: 'schema' },
    ];
    for (const c of cases) {
      const before = await ctx.prisma.aiChatActionConfirmation.count({
        where: { organizationId: org.id, userId: colleague.user.id },
      });
      const { execution, confirmations } = await sendTurn(
        colleague,
        conversation,
        c.to === undefined ? {} : { to: c.to },
      );
      const after = await ctx.prisma.aiChatActionConfirmation.count({
        where: { organizationId: org.id, userId: colleague.user.id },
      });
      if (c.expect === 'pending') {
        expect(execution, c.name).toMatchObject({
          decision: 'allowed',
          status: 'pending_confirmation',
        });
        expect(confirmations, c.name).toHaveLength(1);
        expect(after - before, c.name).toBe(1);
        const pending = (confirmations[0] as { confirmation: { id: string } }).confirmation;
        const row = await confirmationRow(ctx, pending.id);
        const body = (row.request as { body: { reportId: string; to: string } }).body;
        expect(body, c.name).toEqual({ reportId, to: c.stored ?? c.to });
        const summary = row.summary as { target: Array<{ label: string; value: string }> };
        const recipient = summary.target.find((t) => t.label === 'Recipient type')!.value;
        expect(recipient, c.name).toMatch(
          c.kind === 'self'
            ? /your own address/
            : c.kind === 'member'
              ? /user of your organization/
              : /address in verified domain/,
        );
        continue;
      }
      expect(confirmations, c.name).toEqual([]);
      expect(after - before, c.name).toBe(0);
      if (c.expect === 'schema') {
        expect(execution, c.name).toMatchObject({ decision: 'denied_schema', status: 'refused' });
        continue;
      }
      expect(execution, c.name).toMatchObject({
        decision: 'denied_guard',
        status: 'refused',
        card: null,
      });
      // Audit without the address: the guard, the domain and the SHA-256 only.
      const audit = await ctx.prisma.auditLog.findMany({
        where: { organizationId: org.id, resourceId: execution.id as string },
      });
      expect(
        audit.map((a) => a.action),
        c.name,
      ).toEqual(['assistant.tool_denied']);
      const domain = c.to!.split('@')[1]!.toLowerCase();
      expect(audit[0]!.metadata, c.name).toMatchObject({
        guard: 'report_recipient_not_allowed',
        recipientDomain: domain,
        recipientSha256: sha(c.to!),
      });
      const localPart = c.to!.split('@')[0]!;
      const row = await executionRow(ctx, execution.id as string);
      for (const stored of [
        JSON.stringify(audit[0]!.metadata),
        JSON.stringify(row.paramsRedacted),
      ]) {
        expect(stored, c.name).not.toContain(c.to!.toLowerCase());
        expect(stored, c.name).not.toContain(`${localPart}@`);
      }
    }
    // Nothing was queued by proposals.
    expect(
      await ctx.prisma.aiChatReportDelivery.count({ where: { userId: colleague.user.id } }),
    ).toBe(0);
  });

  it('refuses a foreign reportId (another user, another organization) with 404 at proposal', async () => {
    const mine = await withReport(colleague);
    const theirs = await withReport(sender);
    const foreign = await withReport(foreigner);
    for (const reportId of [theirs.reportId, foreign.reportId, randomUUID()]) {
      const { execution, confirmations } = await sendTurn(colleague, mine.conversation, {
        reportId,
      });
      expect(execution).toMatchObject({
        decision: 'allowed',
        status: 'failed',
        httpStatus: 404,
        errorCode: 'assistant_report_not_found',
      });
      expect(confirmations).toEqual([]);
    }
    // The own report of ANOTHER conversation is not this conversation's either.
    const other = await newConversation(ctx, colleague);
    const { execution } = await sendTurn(colleague, other, { reportId: mine.reportId });
    expect(execution).toMatchObject({ status: 'failed', errorCode: 'assistant_report_not_found' });
  });
});

describe('daily limits (D5 step 3, step 13; R-3)', () => {
  it('refuses at proposal once the user has sent the daily maximum (denied_budget)', async () => {
    const who = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
    const { conversation, reportId } = await withReport(who);
    await seedDeliveries(ctx, await reportRow(ctx, reportId), who.user.id, USER_LIMIT);
    const { execution, confirmations } = await sendTurn(who, conversation, {});
    expect(execution).toMatchObject({
      decision: 'denied_budget',
      status: 'refused',
      errorCode: 'assistant_report_email_limit',
    });
    expect(confirmations).toEqual([]);
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { resourceId: execution.id as string, action: 'assistant.tool_denied' },
    });
    expect(audit.metadata).toMatchObject({ scope: 'user' });
  });

  it('refuses at proposal once the organization has sent the daily maximum (scope tenant)', async () => {
    const tenant = await organization();
    const admin = await memberWith(ctx, fx, tenant, {
      permissions: ['report:read', 'assistant:configure', 'organization:read'],
    });
    await enableAssistant(ctx, operator, tenant, admin);
    const { conversation, reportId } = await withReport(admin);
    // Other users of the organization used the tenant's whole daily allowance.
    const row = await reportRow(ctx, reportId);
    await seedDeliveries(ctx, row, 900_000_001n, USER_LIMIT);
    await seedDeliveries(ctx, row, 900_000_002n, TENANT_LIMIT - USER_LIMIT);
    const { execution } = await sendTurn(admin, conversation, {});
    expect(execution).toMatchObject({
      decision: 'denied_budget',
      errorCode: 'assistant_report_email_limit',
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { resourceId: execution.id as string, action: 'assistant.tool_denied' },
    });
    expect(audit.metadata).toMatchObject({ scope: 'tenant' });
  });

  it('two confirmations racing past the user limit: one executes, the other fails 429 without a delivery', async () => {
    const who = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
    const first = await withReport(who);
    const second = await withReport(who);
    await seedDeliveries(ctx, await reportRow(ctx, first.reportId), who.user.id, USER_LIMIT - 1);
    // Both proposals pass the proposal-time count (pending confirmations reserve nothing).
    const a = await propose(ctx, who, 'send this report to my email', first.conversation);
    const b = await propose(ctx, who, 'send this report to my email', second.conversation);
    const [ra, rb] = await Promise.all([confirm(ctx, who, a), confirm(ctx, who, b)]);
    const results = [ra, rb].map((r) => {
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      return r.body.confirmation as {
        status: string;
        result: { httpStatus: number; error: string };
      };
    });
    expect(results.map((r) => r.status).sort()).toEqual(['executed', 'failed']);
    const lost = results.find((r) => r.status === 'failed')!;
    expect(lost.result).toMatchObject({ httpStatus: 429, error: 'assistant_report_email_limit' });
    const queued = await ctx.prisma.aiChatReportDelivery.count({
      where: { userId: who.user.id, status: 'queued' },
    });
    expect(queued).toBe(1);
    const losing = [a, b][results.indexOf(lost)] as Proposal;
    const losingRow = await confirmationRow(ctx, losing.confirmation.id);
    expect(
      await ctx.prisma.aiChatReportDelivery.count({ where: { confirmationId: losingRow.id } }),
    ).toBe(0);
  });
});

describe('state changes between proposal and confirm (D5 step 12)', () => {
  it('the member disabled after the proposal: the confirm fails 403 and nothing is queued', async () => {
    const who = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
    const target = await fx.createUser(org, { roles: [] });
    const { conversation } = await withReport(who);
    const proposal = await propose(
      ctx,
      who,
      directive('report_send_email', { to: target.email }),
      conversation,
    );
    await ctx.prisma.user.update({ where: { id: target.id }, data: { status: 'disabled' } });
    const res = await confirm(ctx, who, proposal);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.code).toBe('assistant_action_not_allowed');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('failed');
    expect(await ctx.prisma.aiChatReportDelivery.count({ where: { userId: who.user.id } })).toBe(0);
  });

  it('the report purged after the proposal (conversation content purge): the confirm sends nothing', async () => {
    const who = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
    const { conversation, reportId } = await withReport(who);
    const proposal = await propose(ctx, who, 'send this report to my email', conversation);
    const convo = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: conversation },
    });
    const now = new Date();
    await ctx.prisma.aiChatConversation.update({
      where: { id: convo.id },
      data: { purgeAfter: new Date(now.getTime() - 60_000) },
    });
    const repo = ctx.get(ConversationsRepository);
    await ctx.get(TransactionRunner).run(async (tx) => {
      const still = await repo.lockDueForContentPurge(org.id, [convo.id], now, tx);
      await repo.purgeContent(org.id, still, now, tx);
    });
    expect((await reportRow(ctx, reportId)).status).toBe('purged');
    const outboxCount = () =>
      ctx.prisma.messageOutbox.count({ where: { organizationId: org.id, eventType: EVENT } });
    const outboxBefore = await outboxCount();
    const res = await confirm(ctx, who, proposal);
    // The content purge also clears the confirmation's stored request (AI-2 D7), so the confirm
    // stops at the AI-2 step 6 integrity check (`assistant_confirmation_digest_mismatch`, row
    // failed) before the step 12 state re-read; the report row alone purged is the next test.
    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_digest_mismatch');
    const row = await confirmationRow(ctx, proposal.confirmation.id);
    expect(row).toMatchObject({ status: 'failed', request: null });
    expect(await ctx.prisma.aiChatReportDelivery.count({ where: { userId: who.user.id } })).toBe(0);
    expect(await outboxCount()).toBe(outboxBefore);
  });

  it('the report row purged while the conversation keeps its content: 409 state changed', async () => {
    const who = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
    const { conversation, reportId } = await withReport(who);
    const proposal = await propose(ctx, who, 'send this report to my email', conversation);
    await ctx.prisma.aiChatReport.update({
      where: { publicId: reportId },
      data: { status: 'purged', purgedAt: new Date() },
    });
    const res = await confirm(ctx, who, proposal);
    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_state_changed');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('failed');
    expect(await ctx.prisma.aiChatReportDelivery.count({ where: { userId: who.user.id } })).toBe(0);
  });
});
