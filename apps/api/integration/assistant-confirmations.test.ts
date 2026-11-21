/**
 * Step AI-2 action confirmations on the real stack (docs/plan/steps/29-ai-chat-confirmations-
 * mail-writes.md D1, D2, D3, D6, D7, §9 item 4; contracts §35.1; ADR-0093 amended): the api
 * listens on its ephemeral loopback port, so every precondition read, definition validation and
 * confirmed write goes through the real `/api/v1` pipeline with the user's own bearer; MySQL
 * writer and replica and Redis are the Compose infrastructure; the provider is the deterministic
 * fake (`assertFakeProvider`), never a real LLM, and nothing reaches the internet.
 *
 * Covered:
 * - the acceptance flow "Create an inbound policy that quarantines executables" (the fake's plan
 *   validate → test → create) as `assistant-stream/1`: events in order, the token only in
 *   `confirmation.required` (never in transcripts, executions, confirmation or audit rows, the
 *   messages route or the logs), no policy until the confirm, the confirmed `policy.created`
 *   audit row carrying the result execution's correlation id; "publish it" in the next turn sees
 *   the action update and proposes the publish (medium, impact lines) whose confirm activates
 *   the policy with `Idempotency-Key` = the confirmation id;
 * - every refusal of the confirm route in its documented order: replay, two concurrent confirms,
 *   expiry (clock moved past the TTL; the sweeper expires pending rows), another session of the
 *   same user (403) / another user / another organization (404), changed state between proposal
 *   and confirm, wrong tokens (the fifth cancels), digest mismatch (body, tampered storage),
 *   re-authentication of a high-risk delete (required, failed with its reason, password + TOTP,
 *   the session's window, a user without MFA), cancel, the conversation's turn lock;
 * - the sweeper's `outcome_unknown` for a confirmation stuck in `executing`, conversation delete
 *   cancelling pending confirmations, the content purge and the organization purge.
 *
 * Synthetic `it-*` organizations only.
 */
// @covers get /api/v1/assistant/confirmations/:confirmationId
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/assistant/confirmations/:confirmationId/cancel
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers get /api/v1/assistant/conversations/:conversationId/messages
// @covers delete /api/v1/assistant/conversations/:conversationId
import { randomUUID } from 'node:crypto';
import {
  ACTION_UPDATES_HEADER,
  FAKE_EXECUTABLES_DEFINITION,
  FAKE_EXECUTABLES_POLICY_NAME,
  FAKE_PENDING_TEXT,
} from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { TransactionRunner } from '../src/database/transaction-runner';
import { assistantKeys } from '../src/modules/assistant/assistant.constants';
import { ConversationsRepository } from '../src/modules/assistant/repositories/conversations.repository';
import { AssistantRetentionService } from '../src/modules/assistant/services/assistant-retention.service';
import { AssistantTenantDataRepository } from '../src/modules/tenant-data/assistant-tenant-data.repository';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  type AssistantApp,
  call,
  cancelConfirmation,
  clearAssistantCounters,
  confirm,
  confirmationAudit,
  confirmationClock,
  confirmationRow,
  createAssistantApp,
  directive,
  enableAssistant,
  envelopesOf,
  executionRow,
  getConfirmation,
  member,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  propose,
  reauthOf,
  recordLoopback,
  requiredOf,
  secondSession,
  storedTraces,
  streamTurn,
  turn,
  waitForRead,
  wrongToken,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';

const P = '/api/v1/policies';
const POLL = { timeout: 15_000, interval: 200 };

let app: AssistantApp;
let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let role: string;
let admin: Member;
let adminNoMfa: Member;
let otherA: Member;
let adminB: Member;
const orgIds: bigint[] = [];

const tag = (): string => randomUUID().slice(0, 8);

/** A draft policy of organization A created through the api, visible on the replica. */
async function createPolicy(name = `it policy ${tag()}`): Promise<string> {
  const res = await call(ctx, admin.headers, 'post', P, {
    name,
    definition: FAKE_EXECUTABLES_DEFINITION,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const id = res.body.policy.id as string;
  await waitForRead(ctx, admin, `${P}/${id}`);
  return id;
}

const policiesNamed = (org: FixtureOrganization, name: string) =>
  ctx.prisma.emailPolicy.findMany({ where: { organizationId: org.id, name } });

/** A create proposal of a uniquely named policy (directive turn; no precondition read). */
async function proposeCreate(who: Member = admin, conversation?: string) {
  const name = `it chat ${tag()}`;
  const proposal = await propose(
    ctx,
    who,
    directive('policy_management_create', {
      body: { name, definition: FAKE_EXECUTABLES_DEFINITION },
    }),
    conversation,
  );
  return { ...proposal, name };
}

beforeAll(async () => {
  app = await createAssistantApp();
  ctx = app.ctx;
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  orgIds.push(orgA.id, orgB.id);
  fx.registerCleanup(async () => {
    const repo = ctx.get(PolicyTenantDataRepository);
    for (const id of orgIds) await repo.purgeOrganization(systemScope(id));
  });
  role = await fx.createCustomRole(orgA, [...ALL_TENANT_PERMISSIONS]);
  admin = await member(ctx, fx, orgA, [role]);
  adminNoMfa = await memberWith(ctx, fx, orgA, { roles: [role] }, { mfa: false });
  otherA = await member(ctx, fx, orgA, [role]);
  adminB = await member(ctx, fx, orgB, [
    await fx.createCustomRole(orgB, [...ALL_TENANT_PERMISSIONS]),
  ]);
  await enableAssistant(ctx, operator, orgA, admin);
  await enableAssistant(ctx, operator, orgB, adminB);
}, 180_000);

afterAll(async () => {
  if (ctx) await clearAssistantCounters(ctx, orgIds);
  await fx?.cleanup();
  await ctx?.close();
});

describe('acceptance: create an inbound policy that quarantines executables (§9 item 4)', () => {
  let conversation: string;
  let createConfirmation: { id: string; token: string; actionDigest: string };

  it('streams validate → test → create proposal; the token only in confirmation.required', async () => {
    conversation = await newConversation(ctx, admin);
    const before = await policiesNamed(orgA, FAKE_EXECUTABLES_POLICY_NAME);
    expect(before).toHaveLength(0);
    const { res, raw, events } = await streamTurn(
      ctx,
      admin.headers,
      conversation,
      'Create an inbound policy that quarantines executables',
    );
    expect(res.status).toBe(200);
    const names = events.map(([name]) => name).filter((n) => n !== 'text.delta');
    expect(names).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'tool.started',
      'tool.completed',
      'tool.started',
      'tool.completed',
      'confirmation.required',
      'turn.completed',
    ]);
    const started = events.filter(([n]) => n === 'tool.started').map(([, d]) => d.tool);
    expect(started).toEqual([
      'policy_tools_validate',
      'policy_tools_test',
      'policy_management_create',
    ]);
    const completed = events.filter(([n]) => n === 'tool.completed').map(([, d]) => d);
    expect(completed.map((d) => d.status)).toEqual([
      'succeeded',
      'succeeded',
      'pending_confirmation',
    ]);
    expect(completed[2]).toMatchObject({ decision: 'allowed' });
    // `confirmation.required` comes right after the proposal's `tool.completed`.
    const index = events.findIndex(([n]) => n === 'confirmation.required');
    expect(events[index - 1]![0]).toBe('tool.completed');
    const [required] = requiredOf(events);
    expect(required!.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(required!.confirmation).toMatchObject({
      executionId: completed[2]!.executionId,
      conversationId: conversation,
      tool: 'policy_management_create',
      operationId: 'PolicyManagementController_create_v1',
      risk: 'low',
      requiresReauth: false,
      status: 'pending',
      resultExecutionId: null,
      result: null,
    });
    expect(required!.confirmation.actionDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(required!.confirmation.summary).toMatchObject({
      version: 'assistant-confirmation/1',
      request: { method: 'POST', path: P },
    });
    expect(JSON.stringify(required!.confirmation.summary)).toContain(FAKE_EXECUTABLES_POLICY_NAME);
    // The token appears exactly once in the whole stream: in `confirmation.required`.
    expect(raw.split(required!.token).length - 1).toBe(1);
    const text = events
      .filter(([n]) => n === 'text.delta')
      .map(([, d]) => d.text as string)
      .join('');
    expect(text).toBe(FAKE_PENDING_TEXT);

    // Nothing changed: no policy, the proposal execution is pending, its envelope has no token.
    expect(await policiesNamed(orgA, FAKE_EXECUTABLES_POLICY_NAME)).toHaveLength(0);
    const proposalRow = await executionRow(ctx, completed[2]!.executionId as string);
    expect(proposalRow).toMatchObject({ status: 'pending_confirmation', httpStatus: null });
    const turnId = events[0]![1].turnId as string;
    const envelopes = await envelopesOf(ctx, turnId);
    expect(envelopes.map((e) => e.parsed.status)).toEqual(['ok', 'ok', 'pending_confirmation']);
    expect(envelopes[2]!.parsed).toMatchObject({
      kind: 'tool_result/1',
      tool: 'policy_management_create',
      status: 'pending_confirmation',
      confirmationId: required!.confirmation.id,
      risk: 'low',
      requiresReauth: false,
    });
    expect(envelopes[2]!.parsed.note).toMatch(/Nothing has changed yet/);
    expect(envelopes[2]!.raw).not.toContain(required!.confirmation.actionDigest);
    const row = await confirmationRow(ctx, required!.confirmation.id);
    expect(row).toMatchObject({
      status: 'pending',
      organizationId: orgA.id,
      userId: admin.user.id,
    });
    expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.tokenHash).not.toBe(required!.token);

    // The token is nowhere stored, audited, logged or served by another route.
    expect(await storedTraces(ctx, orgA.id, conversation)).not.toContain(required!.token);
    await expect
      .poll(async () => {
        const page = await call(
          ctx,
          admin.headers,
          'get',
          `${A}/conversations/${conversation}/messages`,
        );
        return (page.body.data as unknown[] | undefined)?.length;
      }, POLL)
      .toBe(2);
    const page = await call(
      ctx,
      admin.headers,
      'get',
      `${A}/conversations/${conversation}/messages`,
    );
    const listed = (page.body.data as Array<{ executions: Array<Record<string, unknown>> }>)[1]!
      .executions;
    expect(listed.at(-1)!.confirmation).toMatchObject({
      id: required!.confirmation.id,
      status: 'pending',
    });
    expect(JSON.stringify(page.body)).not.toContain(required!.token);
    const view = await getConfirmation(ctx, admin, required!.confirmation.id);
    expect(view.status).toBe(200);
    expect(view.body).toMatchObject({ id: required!.confirmation.id, status: 'pending' });
    expect(JSON.stringify(view.body)).not.toContain(required!.token);
    expect(ctx.logs.join('\n')).not.toContain(required!.token);
    const requested = await confirmationAudit(ctx, orgA.id, required!.confirmation.id);
    expect(requested.map((a) => a.action)).toEqual(['assistant.confirmation_requested']);
    expect(requested[0]!.metadata).toMatchObject({
      conversationId: conversation,
      executionId: completed[2]!.executionId,
      tool: 'policy_management_create',
      risk: 'low',
      status: 'pending',
    });
    createConfirmation = {
      id: required!.confirmation.id,
      token: required!.token,
      actionDigest: required!.confirmation.actionDigest,
    };
  });

  it('confirm creates the draft; policy.created carries the execution correlation id', async () => {
    const pending = {
      token: createConfirmation.token,
      confirmation: {
        id: createConfirmation.id,
        actionDigest: createConfirmation.actionDigest,
      } as never,
    };
    const res = await confirm(ctx, admin, pending);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      id: createConfirmation.id,
      status: 'executed',
      result: { httpStatus: 201, error: null },
    });
    expect(res.body.execution).toMatchObject({
      conversationId: conversation,
      turnId: null,
      tool: 'policy_management_create',
      access: 'write',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 201,
    });
    expect(res.body.confirmation.resultExecutionId).toBe(res.body.execution.id);
    const policies = await policiesNamed(orgA, FAKE_EXECUTABLES_POLICY_NAME);
    expect(policies).toHaveLength(1);
    expect(policies[0]!.status).toBe('draft');
    const version = await ctx.prisma.policyVersion.findFirstOrThrow({
      where: { organizationId: orgA.id, policyId: policies[0]!.id },
    });
    expect(version).toMatchObject({ version: 1, status: 'draft', ruleCount: 1 });

    const result = await executionRow(ctx, res.body.execution.id as string);
    const proposal = await ctx.prisma.aiChatToolExecution.findFirstOrThrow({
      where: { publicId: res.body.confirmation.executionId as string },
    });
    expect(result.parentExecutionId).toBe(proposal.id);
    expect(result.turnId).toBeNull();
    const created = await ctx.prisma.auditLog.findMany({
      where: {
        organizationId: orgA.id,
        action: 'policy.created',
        resourceId: policies[0]!.publicId,
      },
    });
    expect(created).toHaveLength(1);
    expect(created[0]!.correlationId).toBe(result.correlationId);
    expect(created[0]!.actorId).toBe(admin.user.publicId);
    const trail = await confirmationAudit(ctx, orgA.id, createConfirmation.id);
    expect(trail.map((a) => a.action)).toEqual([
      'assistant.confirmation_requested',
      'assistant.confirmation_executed',
    ]);
    expect(trail[1]!.metadata).toMatchObject({
      status: 'executed',
      httpStatus: 201,
      resultExecutionId: res.body.execution.id,
      correlationId: result.correlationId,
      reauthUsed: false,
    });
    expect(JSON.stringify(res.body)).not.toContain(createConfirmation.token);

    // Replay: the same confirmation again is refused; still exactly one policy.
    const replay = await confirm(ctx, admin, pending);
    expect(replay.status).toBe(409);
    expect(replay.body).toMatchObject({
      code: 'assistant_confirmation_not_pending',
      status: 'executed',
    });
    expect(await policiesNamed(orgA, FAKE_EXECUTABLES_POLICY_NAME)).toHaveLength(1);
    const refused = await confirmationAudit(ctx, orgA.id, createConfirmation.id);
    expect(refused.at(-1)).toMatchObject({ action: 'assistant.confirmation_refused' });
    expect(refused.at(-1)!.metadata).toMatchObject({ reason: 'not_pending' });
  });

  it('"publish it" sees the action update, proposes the publish (medium); confirm activates', async () => {
    const policy = (await policiesNamed(orgA, FAKE_EXECUTABLES_POLICY_NAME))[0]!;
    await waitForRead(ctx, admin, `${P}/${policy.publicId}/versions/1`);
    const proposal = await propose(ctx, admin, 'publish it', conversation);
    expect(proposal.confirmation).toMatchObject({
      tool: 'policy_management_publish',
      risk: 'medium',
      requiresReauth: false,
      status: 'pending',
    });
    expect(proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    expect(proposal.confirmation.summary!.request).toEqual({
      method: 'POST',
      path: `${P}/${policy.publicId}/versions/1/publish`,
    });
    // The model saw the outcome of the create as a server-authored prefix of the user entry.
    const turnRow = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: proposal.res.body.turn.id as string },
    });
    const transcript = turnRow.providerTranscript!;
    expect(transcript).toContain(ACTION_UPDATES_HEADER);
    expect(transcript).toMatch(
      /- policy_management_create \(call r3\): the user confirmed it; it succeeded \(HTTP 201\)\. Result: ref r4, row ref r4\.1\./,
    );
    // The stored user message is the user's text only.
    const userMessage = await ctx.prisma.aiChatMessage.findFirstOrThrow({
      where: { conversation: { publicId: conversation }, role: 'user' },
      orderBy: { seq: 'desc' },
    });
    expect(userMessage.content).toBe('publish it');
    const confirmationRowBefore = await confirmationRow(ctx, createConfirmation.id);
    expect(confirmationRowBefore.reportedAt).not.toBeNull();

    const recorder = recordLoopback(ctx);
    let res;
    try {
      res = await confirm(ctx, admin, proposal);
    } finally {
      recorder.restore();
    }
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 200 },
    });
    const write = recorder.calls.filter((c) => c.method === 'POST');
    expect(write).toHaveLength(1);
    expect(write[0]).toMatchObject({
      path: `${P}/${policy.publicId}/versions/1/publish`,
      idempotencyKey: proposal.confirmation.id,
    });
    const stored = await ctx.prisma.apiIdempotencyKey.findFirst({
      where: { organizationId: orgA.id, idempotencyKey: proposal.confirmation.id },
    });
    expect(stored).not.toBeNull();
    const after = await ctx.prisma.emailPolicy.findUniqueOrThrow({ where: { id: policy.id } });
    expect(after.status).toBe('active');
    expect(after.activeVersionId).not.toBeNull();
  });
});

describe('confirm refusals (D2, in order)', () => {
  it('two concurrent confirms: exactly one executes', async () => {
    const proposal = await proposeCreate();
    const answers = await Promise.all([
      confirm(ctx, admin, proposal),
      confirm(ctx, admin, proposal),
    ]);
    expect(answers.map((r) => r.status).sort()).toEqual([200, 409]);
    const loser = answers.find((r) => r.status === 409)!;
    expect(['assistant_confirmation_not_pending', 'assistant_turn_in_progress']).toContain(
      loser.body.code,
    );
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(1);
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('executed');
    expect(
      await ctx.prisma.aiChatToolExecution.count({
        where: {
          conversation: { publicId: proposal.conversation },
          toolName: 'policy_management_create',
        },
      }),
    ).toBe(2);
  });

  it('expired: 410 past the TTL and nothing written; the sweeper expires pending rows', async () => {
    const proposal = await proposeCreate();
    const restore = confirmationClock(
      ctx,
      new Date(new Date(proposal.confirmation.expiresAt).getTime() + 1_000),
    );
    try {
      const view = await getConfirmation(ctx, admin, proposal.confirmation.id);
      expect(view.body.status).toBe('expired');
      const res = await confirm(ctx, admin, proposal);
      expect(res.status).toBe(410);
      expect(res.body.code).toBe('assistant_confirmation_expired');
    } finally {
      restore();
    }
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('expired');
    const again = await confirm(ctx, admin, proposal);
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({ status: 'expired' });

    // The retention job's sweeper: a pending row past expires_at becomes expired (audited).
    const stale = await proposeCreate();
    await ctx.prisma.aiChatActionConfirmation.update({
      where: { publicId: stale.confirmation.id },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    expect((await getConfirmation(ctx, admin, stale.confirmation.id)).body.status).toBe('expired');
    const swept = await ctx.get(AssistantRetentionService).expireConfirmations(new Date());
    expect(swept).toBeGreaterThanOrEqual(1);
    expect((await confirmationRow(ctx, stale.confirmation.id)).status).toBe('expired');
    const audit = await confirmationAudit(ctx, orgA.id, stale.confirmation.id);
    expect(audit.map((a) => a.action)).toEqual([
      'assistant.confirmation_requested',
      'assistant.confirmation_expired',
    ]);
    expect(audit[1]!.actorType).toBe('system');
    expect(await policiesNamed(orgA, stale.name)).toHaveLength(0);

    // The next turn reports it to the model.
    const next = await turn(ctx, admin.headers, stale.conversation, '/text ok');
    expect(next.status).toBe(200);
    const row = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: next.body.turn.id as string },
    });
    expect(row.providerTranscript).toMatch(
      /- policy_management_create \(call r1\): expired without confirmation; nothing changed\./,
    );
  });

  it('another session of the same user 403; another user or organization 404', async () => {
    const proposal = await proposeCreate();
    const second = await secondSession(ctx, fx, admin);
    const mismatch = await confirm(ctx, second, proposal);
    expect(mismatch.status).toBe(403);
    expect(mismatch.body.code).toBe('assistant_confirmation_session_mismatch');
    const cancelled = await cancelConfirmation(ctx, second, proposal.confirmation.id);
    expect(cancelled.status).toBe(403);
    expect(cancelled.body.code).toBe('assistant_confirmation_session_mismatch');
    // Any session of the owner can read it (never the token).
    const view = await getConfirmation(ctx, second, proposal.confirmation.id);
    expect(view.status).toBe(200);
    expect(view.body).toMatchObject({ status: 'pending', reauthFresh: false });

    for (const stranger of [otherA, adminB]) {
      const res = await confirm(ctx, stranger, proposal);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('assistant_confirmation_not_found');
      expect((await cancelConfirmation(ctx, stranger, proposal.confirmation.id)).status).toBe(404);
      expect((await getConfirmation(ctx, stranger, proposal.confirmation.id)).status).toBe(404);
    }
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
    const refusals = (await confirmationAudit(ctx, orgA.id, proposal.confirmation.id)).filter(
      (a) => a.action === 'assistant.confirmation_refused',
    );
    // The session mismatches are audited; the 404s are not.
    expect(refusals.map((a) => (a.metadata as { reason: string }).reason)).toEqual([
      'session_mismatch',
      'session_mismatch',
    ]);
    expect((await confirm(ctx, admin, proposal)).status).toBe(200);
  });

  it('changed state between proposal and confirm: 409, the assistant changed nothing', async () => {
    const policyId = await createPolicy();
    const proposal = await propose(
      ctx,
      admin,
      directive('policy_management_disable', { policyId }),
    );
    expect(proposal.confirmation).toMatchObject({
      tool: 'policy_management_disable',
      risk: 'medium',
    });
    const current = await waitForRead(ctx, admin, `${P}/${policyId}`);
    const renamed = `it renamed ${tag()}`;
    const patch = await call(ctx, admin.headers, 'patch', `${P}/${policyId}`, {
      name: renamed,
      expectedRowVersion: current.rowVersion,
    });
    expect(patch.status, JSON.stringify(patch.body)).toBe(200);
    await waitForRead(ctx, admin, `${P}/${policyId}`, (b) => b.name === renamed);
    const res = await confirm(ctx, admin, proposal);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_state_changed');
    expect(await confirmationRow(ctx, proposal.confirmation.id)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_state_changed',
      resultExecutionId: null,
    });
    const policy = await ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });
    expect(policy).toMatchObject({ name: renamed, status: 'draft' });
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'policy.disabled', resourceId: policyId },
      }),
    ).toBe(0);
    // No write execution was recorded.
    expect(
      await ctx.prisma.aiChatToolExecution.count({
        where: { conversation: { publicId: proposal.conversation } },
      }),
    ).toBe(1);
  });

  it('wrong token: 403; the fifth wrong token cancels the confirmation', async () => {
    const proposal = await proposeCreate();
    for (let i = 1; i <= 5; i += 1) {
      const res = await confirm(ctx, admin, proposal, { token: wrongToken() });
      expect(res.status, `attempt ${i}`).toBe(403);
      expect(res.body.code).toBe('assistant_confirmation_token_invalid');
      const row = await confirmationRow(ctx, proposal.confirmation.id);
      expect(row.failedAttempts).toBe(i);
      expect(row.status).toBe(i < 5 ? 'pending' : 'cancelled');
    }
    expect((await confirmationRow(ctx, proposal.confirmation.id)).errorCode).toBe(
      'assistant_confirmation_token_locked',
    );
    const right = await confirm(ctx, admin, proposal);
    expect(right.status).toBe(409);
    expect(right.body).toMatchObject({
      code: 'assistant_confirmation_not_pending',
      status: 'cancelled',
    });
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
    // A malformed token is a validation error, not an attempt.
    expect((await confirm(ctx, admin, proposal, { token: 'short' })).status).toBe(400);
  });

  it('digest mismatch: a wrong body digest 409 (pending); tampered storage 409 and failed', async () => {
    const proposal = await proposeCreate();
    const wrong = await confirm(ctx, admin, proposal, { actionDigest: 'f'.repeat(64) });
    expect(wrong.status).toBe(409);
    expect(wrong.body.code).toBe('assistant_confirmation_digest_mismatch');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');

    // Tampered storage: the stored request names another policy.
    const row = await confirmationRow(ctx, proposal.confirmation.id);
    const request = row.request as { body: { name: string } };
    const tamperedName = `it tampered ${tag()}`;
    await ctx.prisma.aiChatActionConfirmation.update({
      where: { id: row.id },
      data: { request: { ...request, body: { ...request.body, name: tamperedName } } },
    });
    const res = await confirm(ctx, admin, proposal);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_digest_mismatch');
    expect(await confirmationRow(ctx, proposal.confirmation.id)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_digest_mismatch',
    });
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
    expect(await policiesNamed(orgA, tamperedName)).toHaveLength(0);
  });

  it('cancel: pending → cancelled (idempotent); confirm afterwards 409; reported next turn', async () => {
    const proposal = await proposeCreate();
    const res = await cancelConfirmation(ctx, admin, proposal.confirmation.id);
    expect(res.status).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      id: proposal.confirmation.id,
      status: 'cancelled',
    });
    const again = await cancelConfirmation(ctx, admin, proposal.confirmation.id);
    expect(again.status).toBe(200);
    expect(again.body.confirmation.status).toBe('cancelled');
    const confirmed = await confirm(ctx, admin, proposal);
    expect(confirmed.status).toBe(409);
    expect(confirmed.body).toMatchObject({
      code: 'assistant_confirmation_not_pending',
      status: 'cancelled',
    });
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
    const audit = await confirmationAudit(ctx, orgA.id, proposal.confirmation.id);
    expect(audit.filter((a) => a.action === 'assistant.confirmation_cancelled')).toHaveLength(1);
    const next = await turn(ctx, admin.headers, proposal.conversation, '/text ok');
    const row = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: next.body.turn.id as string },
    });
    expect(row.providerTranscript).toMatch(
      /- policy_management_create \(call r1\): the user cancelled it; nothing changed\./,
    );
    // Reported once: a later turn has no action updates.
    const later = await turn(ctx, admin.headers, proposal.conversation, '/text again');
    const laterRow = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: later.body.turn.id as string },
    });
    const entries = JSON.parse(laterRow.providerTranscript!) as Array<{
      role: string;
      text?: string;
    }>;
    expect(entries.filter((e) => e.role === 'user').at(-1)!.text).toBe('/text again');
  });

  it('confirm while a turn of the conversation runs: 409 assistant_turn_in_progress', async () => {
    const proposal = await proposeCreate();
    const held = turn(ctx, admin.headers, proposal.conversation, '/hold').then((r) => r);
    await expect.poll(() => app.provider.holding, POLL).toBe(1);
    try {
      const res = await confirm(ctx, admin, proposal);
      expect(res.status).toBe(409);
      expect(res.body.code).toBe('assistant_turn_in_progress');
      expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
    } finally {
      app.provider.release();
    }
    expect((await held).status).toBe(200);
    const res = await confirm(ctx, admin, proposal);
    expect(res.status).toBe(200);
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(1);
  });
});

describe('high-risk confirmations need re-authentication (D2 step 9)', () => {
  it('required, failed with its reason, password + TOTP; the window skips the next one', async () => {
    const policyId = await createPolicy();
    const proposal = await propose(ctx, admin, directive('policy_management_remove', { policyId }));
    expect(proposal.confirmation).toMatchObject({
      tool: 'policy_management_remove',
      risk: 'high',
      requiresReauth: true,
      reauthFresh: false,
    });
    expect(proposal.confirmation.summary!.warnings.length).toBeGreaterThanOrEqual(1);
    expect(proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);

    const none = await confirm(ctx, admin, proposal);
    expect(none.status).toBe(401);
    expect(none.body.code).toBe('assistant_reauth_required');
    const badPassword = await confirm(ctx, admin, proposal, {
      reauth: { password: `${admin.user.password}x`, totpCode: await fx.totpNow(admin.user) },
    });
    expect(badPassword.status).toBe(401);
    expect(badPassword.body).toMatchObject({ code: 'assistant_reauth_failed', reason: 'password' });
    const noCode = await confirm(ctx, admin, proposal, {
      reauth: { password: admin.user.password },
    });
    expect(noCode.status).toBe(401);
    expect(noCode.body).toMatchObject({ code: 'assistant_reauth_failed', reason: 'totp_required' });
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
    expect(await ctx.kv.get(assistantKeys.reauthWindow(sessionOf(admin)))).toBeNull();
    const reasons = (await confirmationAudit(ctx, orgA.id, proposal.confirmation.id))
      .filter((a) => a.action === 'assistant.confirmation_refused')
      .map((a) => (a.metadata as { reason: string }).reason);
    expect(reasons).toEqual(['reauth_required', 'reauth_failed', 'reauth_failed']);

    const ok = await confirm(ctx, admin, proposal, { reauth: await reauthOf(fx, admin) });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.confirmation).toMatchObject({ status: 'executed' });
    const removed = await ctx.prisma.emailPolicy.findFirstOrThrow({
      where: { publicId: policyId },
    });
    expect(removed.deletedAt).not.toBeNull();
    expect((await confirmationRow(ctx, proposal.confirmation.id)).reauthUsed).toBe(true);
    expect(await ctx.kv.get(assistantKeys.reauthWindow(sessionOf(admin)))).toBe('1');

    // Within the window the next high-risk confirmation of this session needs no re-auth.
    const second = await createPolicy();
    const next = await propose(
      ctx,
      admin,
      directive('policy_management_remove', { policyId: second }),
    );
    expect(next.confirmation).toMatchObject({ requiresReauth: true, reauthFresh: true });
    const fresh = await confirm(ctx, admin, next);
    expect(fresh.status, JSON.stringify(fresh.body)).toBe(200);
    expect((await confirmationRow(ctx, next.confirmation.id)).reauthUsed).toBe(false);
    // The window belongs to the session family: another session of the user must re-authenticate.
    const other = await secondSession(ctx, fx, admin);
    const third = await createPolicy();
    const elsewhere = await propose(
      ctx,
      other,
      directive('policy_management_remove', { policyId: third }),
    );
    expect(elsewhere.confirmation.reauthFresh).toBe(false);
    expect((await confirm(ctx, other, elsewhere)).status).toBe(401);
    await cancelConfirmation(ctx, other, elsewhere.confirmation.id);
  });

  it('a user without MFA re-authenticates with the password alone', async () => {
    const policyId = await createPolicy();
    const proposal = await propose(
      ctx,
      adminNoMfa,
      directive('policy_management_remove', { policyId }),
    );
    expect((await confirm(ctx, adminNoMfa, proposal)).status).toBe(401);
    const res = await confirm(ctx, adminNoMfa, proposal, {
      reauth: { password: adminNoMfa.user.password },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation.status).toBe('executed');
  });
});

describe('sweeps, deletes and purges (D7)', () => {
  it('a confirmation stuck in executing becomes failed outcome_unknown (never re-executed)', async () => {
    const proposal = await proposeCreate();
    const retention = ctx.get(AssistantRetentionService);
    const timeout = ctx.config.ASSISTANT_TOOL_TIMEOUT_MS;
    const where = { publicId: proposal.confirmation.id };
    // Still re-reading preconditions (no write started) past the write's budget: not stale yet.
    await ctx.prisma.aiChatActionConfirmation.update({
      where,
      data: { status: 'executing', decidedAt: new Date(Date.now() - timeout - 61_000) },
    });
    await retention.failStaleConfirmations(new Date());
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('executing');
    // The write started longer ago than timeout + 60 s (a crash during the write): stale.
    await ctx.prisma.aiChatActionConfirmation.update({
      where,
      data: { executionStartedAt: new Date(Date.now() - timeout - 61_000) },
    });
    const swept = await retention.failStaleConfirmations(new Date());
    expect(swept).toBeGreaterThanOrEqual(1);
    expect(await confirmationRow(ctx, proposal.confirmation.id)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_outcome_unknown',
      resultExecutionId: null,
    });
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
    const audit = await confirmationAudit(ctx, orgA.id, proposal.confirmation.id);
    expect(audit.at(-1)).toMatchObject({
      action: 'assistant.confirmation_failed',
      actorType: 'system',
    });
    expect((await confirm(ctx, admin, proposal)).status).toBe(409);
  });

  it('deleting the conversation cancels its pending confirmations and purges their content', async () => {
    const proposal = await proposeCreate();
    const del = await call(
      ctx,
      admin.headers,
      'delete',
      `${A}/conversations/${proposal.conversation}`,
    );
    expect(del.status).toBe(204);
    expect(await confirmationRow(ctx, proposal.confirmation.id)).toMatchObject({
      status: 'cancelled',
      request: null,
      preconditions: null,
      summary: null,
    });
    const audit = await confirmationAudit(ctx, orgA.id, proposal.confirmation.id);
    expect(audit.map((a) => a.action)).toContain('assistant.confirmation_cancelled');
    expect((await getConfirmation(ctx, admin, proposal.confirmation.id)).status).toBe(404);
    expect((await confirm(ctx, admin, proposal)).status).toBe(404);
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
  });

  it('the content purge nulls the stored request, preconditions and summary', async () => {
    const proposal = await proposeCreate();
    const conversation = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: proposal.conversation },
    });
    const repo = ctx.get(ConversationsRepository);
    await ctx
      .get(TransactionRunner)
      .run((tx) => repo.purgeContent(orgA.id, [conversation.id], new Date(), tx));
    const row = await confirmationRow(ctx, proposal.confirmation.id);
    expect(row).toMatchObject({
      request: null,
      preconditions: null,
      summary: null,
      status: 'pending',
    });
    const view = await getConfirmation(ctx, admin, proposal.confirmation.id);
    expect(view.body).toMatchObject({ summary: null });
    // Nothing left to run: the confirm fails the row (digest from storage) and writes nothing.
    const res = await confirm(ctx, admin, proposal);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_digest_mismatch');
    expect(await policiesNamed(orgA, proposal.name)).toHaveLength(0);
  });

  it('the organization purge deletes the organization’s confirmations first', async () => {
    const org = await fx.createOrganization();
    orgIds.push(org.id);
    const orgAdmin = await member(ctx, fx, org, [
      await fx.createCustomRole(org, [...ALL_TENANT_PERMISSIONS]),
    ]);
    await enableAssistant(ctx, operator, org, orgAdmin);
    const proposal = await propose(
      ctx,
      orgAdmin,
      directive('policy_management_create', {
        body: { name: `it purge ${tag()}`, definition: FAKE_EXECUTABLES_DEFINITION },
      }),
    );
    const counts = await ctx
      .get(AssistantTenantDataRepository)
      .purgeOrganization(systemScope(org.id), 1);
    expect(counts.ai_chat_action_confirmations).toBe(1);
    expect(counts.ai_chat_tool_executions).toBe(1);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({ where: { organizationId: org.id } }),
    ).toBe(0);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({ where: { organizationId: orgA.id } }),
    ).toBeGreaterThan(0);
    void proposal;
  });
});

/** The session family of a member's access token (the `sid` claim). */
function sessionOf(who: Member): string {
  const payload = JSON.parse(
    Buffer.from(who.token.split('.')[1]!, 'base64url').toString('utf8'),
  ) as { sid: string };
  return payload.sid;
}
