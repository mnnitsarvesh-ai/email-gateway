import {
  findTool,
  REPORT_SOURCE_DEFS,
  type ReportSourceKey,
  reportStateDigest,
} from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import { testUser } from '../../../../../test/support/assistant-fixtures';
import { reportSourceBodies } from '../../../../../test/support/assistant-report-fixtures';
import { createAssistantHarness } from '../../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../../auth-contracts/tenant-scope';
import { parseStoredRequest } from '../../domain/confirmation-binding';
import { ownerOf } from '../conversation.service';
import { actionUpdatesOf } from '../turn-engine.service';
import type { ExecutionContext, ExecutionOutcome } from '../tool-executor.service';

/**
 * `report_send_email` (step AI-R D5, I17): the proposal (report resolution, the recipient rule,
 * the daily limits, the bound state), the confirm-time re-check and the confirmed delivery with
 * its outbox event and audit. In-memory doubles; synthetic `.test` addresses only.
 */

const ORG = 7001n;
const SELF = 'it-analyst@example.test';
const REPORT = '0193d000-0000-7000-8000-00000000a001';
const AUTH = { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' };
const SHA = 'ab'.repeat(32);

function setup(env: Record<string, string> = {}, user: UserPrincipal = defaultUser()) {
  const h = createAssistantHarness(env, undefined, user);
  h.world.enable(ORG);
  const scope = scopeFromPrincipal(user);
  const owner = ownerOf(user, scope);
  const conversation = h.world.addConversation(owner);
  const rw = h.world.reportWorld;
  rw.users.push(
    {
      id: user.userId,
      organizationId: ORG,
      email: SELF,
      status: 'active',
      verified: true,
      deleted: false,
    },
    {
      id: 601n,
      organizationId: ORG,
      email: 'it-member@example.test',
      status: 'active',
      verified: true,
      deleted: false,
    },
    {
      id: 602n,
      organizationId: ORG,
      email: 'it-invited@example.test',
      status: 'invited',
      verified: false,
      deleted: false,
    },
    {
      id: 603n,
      organizationId: ORG,
      email: 'it-disabled@example.test',
      status: 'disabled',
      verified: true,
      deleted: false,
    },
    {
      id: 701n,
      organizationId: 7002n,
      email: 'it-other@other.test',
      status: 'active',
      verified: true,
      deleted: false,
    },
  );
  rw.domains.push(
    { organizationId: ORG, name: 'corp.example.test', status: 'verified', deleted: false },
    { organizationId: ORG, name: 'live.example.test', status: 'active', deleted: false },
    {
      organizationId: ORG,
      name: 'pending.example.test',
      status: 'pending_verification',
      deleted: false,
    },
    { organizationId: ORG, name: 'paused.example.test', status: 'suspended', deleted: false },
  );
  const addReport = (overrides: Record<string, unknown> = {}) => {
    const id = rw.id();
    rw.reports.push({
      id,
      publicId: REPORT,
      organizationId: ORG,
      userId: user.userId,
      platformOverrideId: null,
      conversationId: conversation.id,
      conversationPublicId: conversation.publicId,
      executionId: null,
      status: 'available',
      title: 'Security report: Last 7 days',
      periodFrom: new Date('2026-11-16T09:00:00.000Z'),
      periodTo: new Date('2026-11-23T09:00:00.000Z'),
      granularity: 'day',
      sections: { included: ['summary'], omitted: [], atoRange: '7d', label: 'Last 7 days' },
      figures: [{ label: 'Messages', value: '120' }],
      templateVersion: 'assistant-report/1',
      objectKey: `org/7001/assistant/report/2026/11/23/${REPORT}.html`,
      sizeBytes: 4096,
      sha256: SHA,
      errorCode: null,
      purgedAt: null,
      objectDeletedAt: null,
      createdAt: new Date('2026-11-23T09:00:31.000Z'),
      updatedAt: new Date('2026-11-23T09:00:31.000Z'),
      ...overrides,
    } as never);
    return rw.reports.at(-1)!;
  };
  const nextSeq = () =>
    h.world.executions
      .filter((e) => e.conversationId === conversation.id)
      .reduce((max, e) => Math.max(max, e.seq), 0) + 1;
  const ctx = (): ExecutionContext => ({
    principal: user,
    owner,
    conversationId: conversation.id,
    conversationPublicId: conversation.publicId,
    turnId: null,
    turnPublicId: null,
    parentExecutionId: null,
    parentExecutionPublicId: null,
    ...AUTH,
    correlationBase: 'it-corr-0001',
    signal: new AbortController().signal,
    allocateSeq: nextSeq,
  });
  const propose = (args: Record<string, unknown> = {}) =>
    h.executor.execute(ctx(), { name: 'report_send_email', arguments: args }, 0);
  const confirm = (outcome: ExecutionOutcome) =>
    h.confirmations.confirm(
      user,
      scope,
      outcome.confirmation!.view.id,
      {
        token: outcome.confirmation!.token,
        actionDigest: outcome.confirmation!.view.actionDigest,
      },
      AUTH,
    );
  return { h, rw, user, scope, owner, conversation, addReport, propose, confirm };
}

function defaultUser(overrides: Partial<UserPrincipal> = {}): UserPrincipal {
  return testUser({ permissions: new Set(['assistant:use', 'report:read']), ...overrides });
}

const json = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

const coded = async (promise: Promise<unknown>): Promise<{ status: number; code: string }> => {
  try {
    await promise;
  } catch (error) {
    const e = error as { getStatus(): number; code: string };
    if (typeof e.getStatus !== 'function') throw error;
    return { status: e.getStatus(), code: e.code };
  }
  throw new Error('expected a coded error');
};

describe('report_send_email proposal (D5 steps 1–5)', () => {
  it('defaults to the latest report and the own address; stores POST native:report_send_email', async () => {
    const t = setup();
    t.addReport();
    const out = await t.propose();
    expect(out).toMatchObject({ decision: 'allowed', status: 'pending_confirmation' });
    const view = out.confirmation!.view;
    expect(view).toMatchObject({
      tool: 'report_send_email',
      risk: 'medium',
      requiresReauth: false,
    });
    expect(view.summary).toMatchObject({
      title: 'Email security report',
      action: `Sends the security report as an HTML email to ${SELF}.`,
      reversible: false,
      portalRoute: `/assistant/reports/${REPORT}`,
      request: { method: 'POST', path: 'native:report_send_email' },
    });
    expect(view.summary!.warnings).toContain(
      '10 of 10 report emails left today for you (50 for your organization).',
    );
    const row = t.h.world.confirmations[0]!;
    expect(parseStoredRequest(row.request)).toEqual({
      method: 'POST',
      path: 'native:report_send_email',
      body: { reportId: REPORT, to: SELF },
      params: {},
    });
    expect(row.stateDigest).toBe(
      reportStateDigest({
        reportId: REPORT,
        sha256: SHA,
        status: 'available',
        recipientKind: 'self',
      }),
    );
    // Nothing was sent through the loopback and nothing was queued.
    expect(t.h.loopback.toolCalls).toHaveLength(0);
    expect(t.rw.deliveries).toHaveLength(0);
  });

  it('classifies members and verified/active domains; refuses everything else without a confirmation', async () => {
    const cases: Array<[string, 'pending_confirmation' | 'denied_guard']> = [
      ['it-member@example.test', 'pending_confirmation'],
      ['IT-Member@EXAMPLE.test', 'pending_confirmation'],
      ['someone@corp.example.test', 'pending_confirmation'],
      ['someone@live.example.test', 'pending_confirmation'],
      ['it-invited@example.test', 'denied_guard'],
      ['it-disabled@example.test', 'denied_guard'],
      ['it-other@other.test', 'denied_guard'],
      ['someone@sub.corp.example.test', 'denied_guard'],
      ['someone@pending.example.test', 'denied_guard'],
      ['someone@paused.example.test', 'denied_guard'],
      ['attacker@outside.test', 'denied_guard'],
    ];
    for (const [to, expected] of cases) {
      const t = setup();
      t.addReport();
      const out = await t.propose({ to });
      expect([to, out.status === 'pending_confirmation' ? out.status : out.decision]).toEqual([
        to,
        expected,
      ]);
      if (expected === 'denied_guard') {
        expect(t.h.world.confirmations).toHaveLength(0);
        expect(out.denialMessage).toMatch(/only to your own address/);
        const meta = t.h.audit.entries[0]!.metadata as Record<string, unknown>;
        expect(meta).toMatchObject({ guard: 'report_recipient_not_allowed' });
        expect(meta.recipientDomain).toBe(to.split('@')[1]!.toLowerCase());
        expect(meta.recipientSha256).toMatch(/^[0-9a-f]{64}$/);
        expect(json(t.h.audit.entries)).not.toContain(to);
      }
    }
  });

  it('resolves a report ref @r<seq>.1 of this conversation (a generated report)', async () => {
    const t = setup({}, defaultUser({ permissions: new Set(['assistant:use', 'report:read']) }));
    const bodies = reportSourceBodies({
      from: '2026-11-16T09:00:00.000Z',
      to: '2026-11-23T09:00:00.000Z',
    });
    for (const key of Object.keys(REPORT_SOURCE_DEFS) as ReportSourceKey[]) {
      const path = findTool(REPORT_SOURCE_DEFS[key].tool)!.pathTemplate;
      t.h.loopback.on(`GET ${path}`, () => ({ kind: 'response', status: 200, body: bodies[key] }));
    }
    const generated = await t.h.executor.execute(
      {
        principal: t.user,
        owner: t.owner,
        conversationId: t.conversation.id,
        conversationPublicId: t.conversation.publicId,
        turnId: null,
        turnPublicId: null,
        parentExecutionId: null,
        parentExecutionPublicId: null,
        ...AUTH,
        correlationBase: 'it-corr-0001',
        signal: new AbortController().signal,
        allocateSeq: () => 1,
      },
      { name: 'report_generate', arguments: {} },
      0,
    );
    const reportId = generated.card!.report!.reportId;
    const out = await t.propose({ reportId: '@r1.1' });
    expect(out.status).toBe('pending_confirmation');
    expect(parseStoredRequest(t.h.world.confirmations[0]!.request)!.body).toEqual({
      reportId,
      to: SELF,
    });
    // An unknown ref of this conversation is denied_ref (nothing proposed).
    expect((await t.propose({ reportId: '@r9.1' })).decision).toBe('denied_ref');
  });

  it('resolves a report by id; another conversation’s or a missing one is 404, purged 410', async () => {
    const t = setup();
    t.addReport({ conversationId: 999n });
    const foreign = await t.propose({ reportId: REPORT });
    expect(foreign).toMatchObject({
      status: 'failed',
      httpStatus: 404,
      errorCode: 'assistant_report_not_found',
    });

    const purged = setup();
    purged.addReport({ status: 'purged' });
    expect(await purged.propose({ reportId: REPORT })).toMatchObject({
      httpStatus: 410,
      errorCode: 'assistant_report_purged',
    });

    const none = setup();
    expect(await none.propose()).toMatchObject({
      httpStatus: 404,
      errorCode: 'assistant_report_not_found',
    });

    const big = setup({ ASSISTANT_REPORT_MAX_HTML_BYTES: '65536' });
    big.addReport({ sizeBytes: 70_000 });
    expect(await big.propose()).toMatchObject({
      httpStatus: 413,
      errorCode: 'assistant_report_too_large',
    });
  });

  it('the per-user and per-tenant daily limits refuse at proposal (denied_budget)', async () => {
    const t = setup({ ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY: '1' });
    const report = t.addReport();
    t.rw.deliveries.push({
      id: 1n,
      publicId: '0193d000-0000-7000-8000-00000000d001',
      organizationId: ORG,
      userId: t.user.userId,
      conversationId: t.conversation.id,
      reportId: report.id,
      confirmationId: 1n,
      recipientAddress: SELF,
      recipientSha256: SHA,
      recipientKind: 'self',
      status: 'sent',
      errorCode: null,
      sizeBytes: 4096,
      correlationId: 'it-corr',
      requestedAt: new Date(),
      sentAt: new Date(),
    });
    const out = await t.propose();
    expect(out).toMatchObject({
      decision: 'denied_budget',
      errorCode: 'assistant_report_email_limit',
    });
    expect(t.h.audit.entries[0]!.metadata).toMatchObject({ scope: 'user' });
  });

  it('ASSISTANT_REPORT_EMAIL_ENABLED=false hides the tool (denied_disabled)', async () => {
    const t = setup({ ASSISTANT_REPORT_EMAIL_ENABLED: 'false' });
    t.addReport();
    expect((await t.propose()).decision).toBe('denied_disabled');
  });
});

describe('stored native requests (D5 step 4)', () => {
  it('parses native:<name> paths only in their exact form', () => {
    const base = { method: 'POST', body: { reportId: REPORT, to: SELF }, params: {} };
    expect(parseStoredRequest({ ...base, path: 'native:report_send_email' })).not.toBeNull();
    for (const path of [
      'native:../x',
      'native:Report',
      'native:a/b',
      'nativex:report_send_email',
    ]) {
      expect(parseStoredRequest({ ...base, path }), path).toBeNull();
    }
  });
});

describe('report_send_email confirm (D5 steps 12–13)', () => {
  it('locks the tenant, writes the delivery, the outbox event (ids only) and the audit; 202 queued', async () => {
    const t = setup();
    const report = t.addReport();
    const proposal = await t.propose();
    const result = await t.confirm(proposal);
    expect(result.confirmation.status).toBe('executed');
    expect(result.execution).toMatchObject({
      status: 'succeeded',
      httpStatus: 202,
      operationId: 'AssistantNative_reportSendEmail',
      card: { kind: 'message', message: `Report email queued to ${SELF}` },
    });
    expect(t.rw.log).toEqual(['lock', 'delivery', 'outbox']);
    const delivery = t.rw.deliveries[0]!;
    expect(delivery).toMatchObject({
      status: 'queued',
      recipientAddress: SELF,
      recipientKind: 'self',
      reportId: report.id,
      confirmationId: t.h.world.confirmations[0]!.id,
    });
    expect(t.rw.outbox).toEqual([
      expect.objectContaining({
        eventId: delivery.publicId,
        aggregateId: delivery.publicId,
        aggregateType: 'assistant_report_delivery',
        eventType: 'assistant.report.email_requested.v1',
        payload: {
          deliveryId: delivery.publicId,
          reportId: REPORT,
          requestedAt: expect.any(String),
        },
      }),
    ]);
    expect(json(t.rw.outbox)).not.toContain(SELF);
    const actions = t.h.audit.entries.map((e) => e.action);
    expect(actions).toContain('assistant.report_email_requested');
    const requested = t.h.audit.entries.find(
      (e) => e.action === 'assistant.report_email_requested',
    )!;
    expect(requested).toMatchObject({
      resourceType: 'assistant_report_delivery',
      resourceId: delivery.publicId,
    });
    expect(requested.metadata).toMatchObject({
      deliveryId: delivery.publicId,
      reportId: REPORT,
      recipientKind: 'self',
      recipientDomain: 'example.test',
    });

    // The next turn's action update names the queued address.
    const updates = actionUpdatesOf(
      await t.h.world.confirmationsDouble().unreported(t.owner, t.conversation.id, 20),
    );
    expect(updates[0]).toMatchObject({
      tool: 'report_send_email',
      status: 'executed',
      recipient: SELF,
    });
  });

  it('a limit reached since the proposal fails the confirmation with 429 and writes nothing', async () => {
    const t = setup({ ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY: '1' });
    t.addReport();
    const first = await t.propose();
    const second = await t.propose();
    expect((await t.confirm(first)).confirmation.status).toBe('executed');
    const raced = await t.confirm(second);
    expect(raced.confirmation.status).toBe('failed');
    expect(raced.execution).toMatchObject({
      httpStatus: 429,
      errorCode: 'assistant_report_email_limit',
    });
    expect(t.rw.deliveries).toHaveLength(1);
    expect(t.rw.outbox).toHaveLength(1);
  });

  it('a purged report since the proposal is 409 state changed; a member disabled since is 403', async () => {
    const t = setup();
    const report = t.addReport();
    const proposal = await t.propose();
    report.status = 'purged';
    expect(await coded(t.confirm(proposal))).toEqual({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.h.world.confirmations[0]!.status).toBe('failed');
    expect(t.rw.deliveries).toHaveLength(0);

    const m = setup();
    m.addReport();
    const toMember = await m.propose({ to: 'it-member@example.test' });
    m.rw.users.find((u) => u.id === 601n)!.status = 'disabled';
    expect(await coded(m.confirm(toMember))).toEqual({
      status: 403,
      code: 'assistant_action_not_allowed',
    });
    expect(m.h.world.confirmations[0]).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_action_not_allowed',
    });
    expect(m.rw.deliveries).toHaveLength(0);
  });
});
