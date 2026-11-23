import { createHash } from 'node:crypto';
import {
  actionDigest,
  ESCALATION_WARNINGS,
  findTool,
  GUARD_MESSAGES,
  hashConfirmationToken,
  PENDING_CONFIRMATION_NOTE,
  stateDigest,
} from '@email-gateway/assistant';
import { Logger } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  REAUTH_PASSWORD,
  REAUTH_TOTP,
  type StoredConfirmation,
  testUser,
} from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { assistantKeys } from '../assistant.constants';
import {
  digestInputOf,
  parseStoredPreconditions,
  parseStoredRequest,
} from '../domain/confirmation-binding';
import { availableTools, toolAvailability } from '../domain/tool-catalog';
import { ownerOf } from './conversation.service';
import { definitionInvalidMessage, PENDING_CAP_MESSAGE } from './confirmation-proposer.service';
import type { LoopbackCall } from './loopback-client';
import type { ExecutionContext, ExecutionOutcome } from './tool-executor.service';

/**
 * Step AI-2 D1–D3, D7, D11 at the service level (design §9 item 2): proposals never send a
 * write; confirm runs its checks in order with each code; the digest binds every stored column.
 * In-memory doubles, the fake loopback, synthetic ids only.
 */

const POLICY = '0193c000-0000-7000-8000-000000000001';
const MESSAGE = '0193c000-0000-7000-8000-00000000a001';
const ENTRY = (n: number) => `0193c000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const AUTH = { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' };
const PERMISSIONS = [
  'assistant:use',
  'policy:read',
  'policy:manage',
  'policy:publish',
  'message:read',
  'message:rescan',
  'quarantine:read',
  'quarantine:release',
];

function setup(env: Record<string, string> = {}, user: UserPrincipal = defaultUser()) {
  const h = createAssistantHarness(env, undefined, user);
  h.world.enable(user.override?.targetOrganizationId ?? user.organizationId);
  const scope = scopeFromPrincipal(user);
  const owner = ownerOf(user, scope);
  const conversation = h.world.addConversation(owner);
  const policy = {
    id: POLICY,
    name: 'Block executables',
    description: null as string | null,
    status: 'active',
    direction: 'inbound',
    priority: 100,
    rowVersion: 3,
    activeVersionNo: 1,
    latestVersionNo: 1,
  };
  const message = {
    id: MESSAGE,
    subject: 'Invoice 42',
    envelopeFrom: 'billing@example.test',
    direction: 'inbound',
    status: 'delivered',
    version: 2,
    lifecycleRound: 1,
  };
  /** Write requests that reached the (fake) api. */
  const writes: LoopbackCall[] = [];
  h.loopback.on(`GET /api/v1/policies/${POLICY}`, () => ({
    kind: 'response',
    status: 200,
    body: structuredClone(policy),
  }));
  h.loopback.on(`POST /api/v1/policies/${POLICY}/disable`, (call) => {
    writes.push(call);
    policy.status = 'disabled';
    policy.rowVersion += 1;
    return { kind: 'response', status: 200, body: structuredClone(policy) };
  });
  h.loopback.on(`DELETE /api/v1/policies/${POLICY}`, (call) => {
    writes.push(call);
    return { kind: 'response', status: 204, body: null };
  });
  h.loopback.on('POST /api/v1/policies/validate', () => ({
    kind: 'response',
    status: 200,
    body: {
      dslVersion: 'policy-dsl/1',
      valid: true,
      violations: [],
      referenceViolations: [],
      ruleCount: 1,
      hasOverrideRules: false,
      references: { departmentIds: [], userIds: [] },
      definitionSha256: 'ab'.repeat(32),
    },
  }));
  h.loopback.on('POST /api/v1/policies', (call) => {
    writes.push(call);
    return {
      kind: 'response',
      status: 201,
      body: { id: '0193c000-0000-7000-8000-000000000002', name: 'New', status: 'draft' },
    };
  });
  h.loopback.on(`GET /api/v1/messages/${MESSAGE}`, () => ({
    kind: 'response',
    status: 200,
    body: structuredClone(message),
  }));
  h.loopback.on(`POST /api/v1/messages/${MESSAGE}/rescan`, (call) => {
    writes.push(call);
    return { kind: 'response', status: 202, body: { messageId: MESSAGE, status: 'rescanning' } };
  });
  // Conversation-wide sequences, as `nextSeq` + the lock give them (confirms allocate too).
  const nextSeq = () =>
    h.world.executions
      .filter((e) => e.conversationId === conversation.id)
      .reduce((max, e) => Math.max(max, e.seq), 0) + 1;
  const ctx = (overrides: Partial<ExecutionContext> = {}): ExecutionContext => ({
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
    ...overrides,
  });
  const propose = (name: string, args: Record<string, unknown>, who?: ExecutionContext) =>
    h.executor.execute(who ?? ctx(), { name, arguments: args }, 0);
  const disable = () => propose('policy_management_disable', { policyId: POLICY });
  const confirm = (
    outcome: ExecutionOutcome,
    body: Partial<{
      token: string;
      actionDigest: string;
      reauth: { password: string; totpCode?: string };
    }> = {},
    who: UserPrincipal = user,
  ) =>
    h.confirmations.confirm(
      who,
      scopeFromPrincipal(who),
      outcome.confirmation!.view.id,
      {
        token: outcome.confirmation!.token,
        actionDigest: outcome.confirmation!.view.actionDigest,
        ...body,
      },
      AUTH,
    );
  const row = (outcome: ExecutionOutcome): StoredConfirmation =>
    h.world.confirmations.find((k) => k.publicId === outcome.confirmation!.view.id)!;
  return {
    h,
    user,
    scope,
    owner,
    conversation,
    policy,
    message,
    writes,
    ctx,
    propose,
    disable,
    confirm,
    row,
  };
}

function defaultUser(overrides: Partial<UserPrincipal> = {}): UserPrincipal {
  return testUser({ permissions: new Set(PERMISSIONS), ...overrides });
}

const coded = async (
  promise: Promise<unknown>,
): Promise<{ status: number; code: string; details: Record<string, unknown> }> => {
  try {
    await promise;
  } catch (error) {
    const e = error as { getStatus(): number; code: string; details?: Record<string, unknown> };
    if (typeof e.getStatus !== 'function') throw error;
    return { status: e.getStatus(), code: e.code, details: e.details ?? {} };
  }
  throw new Error('expected a coded error');
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('proposal (D1): a write call becomes a pending confirmation, never a write', () => {
  it('stores the confirmation, returns the pending envelope and sends only reads', async () => {
    const t = setup();
    const out = await t.disable();
    expect(out).toMatchObject({
      decision: 'allowed',
      status: 'pending_confirmation',
      httpStatus: null,
    });
    expect(out.envelope).toEqual({
      kind: 'tool_result/1',
      tool: 'policy_management_disable',
      status: 'pending_confirmation',
      confirmationId: out.confirmation!.view.id,
      risk: 'medium',
      requiresReauth: false,
      expiresAt: out.confirmation!.view.expiresAt,
      note: PENDING_CONFIRMATION_NOTE,
    });
    expect(out.card).toMatchObject({ kind: 'message', message: 'Waiting for your confirmation' });
    expect(out.view.confirmation).toMatchObject({ status: 'pending', risk: 'medium' });
    // Nothing but the precondition read reached the api; no write, no idempotency key.
    expect(t.writes).toHaveLength(0);
    expect(t.h.loopback.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `GET /api/v1/policies/${POLICY}`,
    ]);
    expect(t.h.loopback.calls[0]!.executionId).toBeNull();
    // The precondition read uses the writer, never a lagging replica (AI-2 review).
    expect(t.h.loopback.calls[0]!.readPrimary).toBe(true);
    // The row: hash only, digest, CAS injected from the read, TTL.
    const stored = t.row(out);
    const token = out.confirmation!.token;
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(stored.tokenHash).toBe(createHash('sha256').update(token).digest('hex'));
    expect(stored).toMatchObject({
      status: 'pending',
      risk: 'medium',
      requiresReauth: false,
      sessionFamilyId: t.user.sessionId,
      platformOverrideId: null,
      actionDigest: out.confirmation!.view.actionDigest,
    });
    expect(stored.request).toEqual({
      method: 'POST',
      path: `/api/v1/policies/${POLICY}/disable`,
      body: { expectedRowVersion: 3 },
      params: { policyId: POLICY },
    });
    expect(stored.expiresAt.getTime() - stored.createdAt.getTime()).toBe(300_000);
    // Audit: the execution (pending_confirmation) and the request, in one transaction.
    expect(t.h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.tool_executed',
      'assistant.confirmation_requested',
    ]);
    expect(t.h.audit.entries[0]!.metadata).toMatchObject({ status: 'pending_confirmation' });
    expect(t.h.audit.entries[1]).toMatchObject({
      resourceType: 'assistant_action_confirmation',
      resourceId: out.confirmation!.view.id,
    });
    // The token never leaves the stream answer: not in the envelope, rows or audit.
    const everywhere = JSON.stringify(
      {
        envelope: out.envelope,
        rows: t.h.world.confirmations,
        executions: t.h.world.executions,
        audit: t.h.audit.entries,
      },
      (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    );
    expect(everywhere).not.toContain(token);
    expect(JSON.stringify(out.envelope)).not.toContain(out.confirmation!.view.actionDigest);
  });

  it('CAS injection overrides a model value; a required CAS field gets the placeholder first', async () => {
    const t = setup();
    const out = await t.propose('policy_management_update', {
      policyId: POLICY,
      body: { name: 'Renamed', expectedRowVersion: 99 },
    });
    expect(out.status).toBe('pending_confirmation');
    expect((t.row(out).request as { body: unknown }).body).toEqual({
      name: 'Renamed',
      expectedRowVersion: 3,
    });
    // Required expectedRowVersion omitted by the model: still a proposal (placeholder → read).
    const omitted = await t.propose('policy_management_update', {
      policyId: POLICY,
      body: { name: 'Renamed' },
    });
    expect(omitted.status).toBe('pending_confirmation');
    expect((t.row(omitted).request as { body: unknown }).body).toEqual({
      name: 'Renamed',
      expectedRowVersion: 3,
    });
    // Query injection (DELETE ?expectedRowVersion=) and a min-0 body field (rescan).
    const remove = await t.propose('policy_management_remove', { policyId: POLICY });
    expect((t.row(remove).request as { path: string }).path).toBe(
      `/api/v1/policies/${POLICY}?expectedRowVersion=3`,
    );
    const rescan = await t.propose('message_lifecycle_rescan', {
      messageId: MESSAGE,
      body: { reason: 'Re-check after the signature update' },
    });
    expect(rescan.status).toBe('pending_confirmation');
    expect((t.row(rescan).request as { body: unknown }).body).toEqual({
      reason: 'Re-check after the signature update',
      expectedVersion: 2,
    });
    expect(t.writes).toHaveLength(0);
  });

  it('refuses beyond ASSISTANT_MAX_PENDING_CONFIRMATIONS (denied_budget), counting live ones only', async () => {
    const t = setup({ ASSISTANT_MAX_PENDING_CONFIRMATIONS: '1' });
    expect((await t.disable()).status).toBe('pending_confirmation');
    const second = await t.disable();
    expect(second).toMatchObject({ decision: 'denied_budget', denialMessage: PENDING_CAP_MESSAGE });
    expect(t.h.world.confirmations).toHaveLength(1);
    // An expired pending row does not count.
    t.h.world.confirmations[0]!.expiresAt = new Date(Date.now() - 1000);
    expect((await t.disable()).status).toBe('pending_confirmation');
  });

  it('validates policy definitions first; invalid → assistant_definition_invalid (≤ 20 violations)', async () => {
    const t = setup();
    const definition = { dslVersion: 'policy-dsl/1', direction: 'inbound', priority: 1, rules: [] };
    const ok = await t.propose('policy_management_create', {
      body: { name: 'Quarantine executables', definition },
    });
    expect(ok.status).toBe('pending_confirmation');
    expect(t.h.loopback.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /api/v1/policies/validate',
    ]);
    expect(t.h.loopback.calls[0]!.body).toEqual({ definition });
    expect(t.h.loopback.calls[0]!.readPrimary).toBeUndefined();
    expect(t.row(ok).preconditions).toMatchObject({
      definitionSha256: 'ab'.repeat(32),
      ruleCount: 1,
    });

    const violations = Array.from({ length: 25 }, (_, i) => ({
      path: `rules[${i}].when`,
      code: 'unknown_field',
      message: 'Unknown field',
    }));
    t.h.loopback.on('POST /api/v1/policies/validate', () => ({
      kind: 'response',
      status: 200,
      body: {
        valid: false,
        violations,
        referenceViolations: [],
        ruleCount: null,
        definitionSha256: null,
      },
    }));
    const bad = await t.propose('policy_management_create', {
      body: { name: 'Bad', definition },
    });
    expect(bad).toMatchObject({
      decision: 'allowed',
      status: 'failed',
      httpStatus: 422,
      errorCode: 'assistant_definition_invalid',
      confirmation: null,
    });
    expect(bad.envelope).toMatchObject({ status: 'error', code: 'assistant_definition_invalid' });
    const message = (bad.envelope as { message: string }).message;
    expect(message).toContain('rules[19].when unknown_field');
    expect(message).not.toContain('rules[20].when');
    expect(message).toContain('(5 more)');
    expect(definitionInvalidMessage(violations.slice(0, 1))).toContain('rules[0].when');
    // Reference violations refuse too.
    t.h.loopback.on('POST /api/v1/policies/validate', () => ({
      kind: 'response',
      status: 200,
      body: {
        valid: true,
        violations: [],
        referenceViolations: [{ path: 'rules[0]', code: 'department_unknown', message: 'x' }],
      },
    }));
    expect(
      (await t.propose('policy_management_create', { body: { name: 'Ref', definition } }))
        .errorCode,
    ).toBe('assistant_definition_invalid');
    expect(t.h.world.confirmations).toHaveLength(1);
    expect(t.writes).toHaveLength(0);
  });

  it('a failing precondition read fails the proposal with the read’s coded error (no row)', async () => {
    const t = setup();
    t.h.loopback.on(`GET /api/v1/policies/${POLICY}`, () => ({
      kind: 'response',
      status: 404,
      body: { statusCode: 404, code: 'policy_not_found', message: 'Policy not found' },
    }));
    const out = await t.disable();
    expect(out).toMatchObject({ status: 'failed', httpStatus: 404, errorCode: 'policy_not_found' });
    expect(out.card).toMatchObject({ kind: 'error' });
    expect(t.h.world.confirmations).toHaveLength(0);
    expect(t.h.audit.entries.map((e) => e.action)).toEqual(['assistant.tool_executed']);
    // A 401 ends the turn like any tool call.
    t.h.loopback.on(`GET /api/v1/policies/${POLICY}`, () => ({
      kind: 'response',
      status: 401,
      body: { statusCode: 401, code: 'unauthorized', message: 'Unauthorized' },
    }));
    expect((await t.disable()).sessionExpired).toBe(true);
  });

  it('bulk: reads the first 25 ids (approvals for approve/deny), keeps per-item state', async () => {
    const t = setup(
      {},
      defaultUser({ permissions: new Set([...PERMISSIONS, 'quarantine:delete']) }),
    );
    for (let i = 1; i <= 30; i += 1) {
      t.h.loopback.on(`GET /api/v1/quarantine/entries/${ENTRY(i)}`, () => ({
        kind: 'response',
        status: 200,
        body: { id: ENTRY(i), state: 'quarantined', rowVersion: i },
      }));
    }
    const ids = Array.from({ length: 30 }, (_, i) => ENTRY(i + 1));
    const out = await t.propose('quarantine_tools_bulk', {
      body: { action: 'release', ids, reason: 'False positive campaign' },
    });
    expect(out.status).toBe('pending_confirmation');
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(t.h.loopback.calls).toHaveLength(25);
    const pre = parseStoredPreconditions(t.row(out).preconditions)!;
    expect(pre.items).toHaveLength(25);
    expect(pre.total).toBe(30);
    expect(pre.items![0]).toMatchObject({ id: ENTRY(1), status: 'quarantined', rowVersion: 1 });
    expect(t.row(out).stateDigest).toBeNull();
    t.h.loopback.calls.length = 0;
    for (const id of ids.slice(0, 2)) {
      t.h.loopback.on(`GET /api/v1/quarantine/approvals/${id}`, () => ({
        kind: 'response',
        status: 200,
        body: { id, status: 'pending', kind: 'release' },
      }));
    }
    await t.propose('quarantine_tools_bulk', {
      body: { action: 'approve', ids: ids.slice(0, 2), reason: 'Approved after review' },
    });
    expect(t.h.loopback.calls.map((c) => c.path)).toEqual(
      ids.slice(0, 2).map((id) => `/api/v1/quarantine/approvals/${id}`),
    );
    expect(t.h.loopback.calls.every((c) => c.readPrimary === true)).toBe(true);
  });

  it('marks reauthFresh on a high-risk proposal when the session window is open', async () => {
    const t = setup();
    await t.h.kv.set(assistantKeys.reauthWindow(t.user.sessionId), '1', 300);
    const out = await t.propose('policy_management_remove', { policyId: POLICY });
    expect(out.confirmation!.view).toMatchObject({
      risk: 'high',
      requiresReauth: true,
      reauthFresh: true,
    });
  });
});

describe('confirm (D2): checks in order, each refusal coded and audited', () => {
  it('executes the stored request once: result execution, row executed, audits, replay refused', async () => {
    const t = setup();
    const out = await t.disable();
    t.h.audit.entries.length = 0;
    const result = await t.confirm(out);
    expect(result.confirmation).toMatchObject({
      id: out.confirmation!.view.id,
      status: 'executed',
      result: { httpStatus: 200, error: null },
      resultExecutionId: result.execution.id,
    });
    expect(result.execution).toMatchObject({
      parentExecutionId: out.executionId,
      turnId: null,
      status: 'succeeded',
      httpStatus: 200,
      access: 'write',
    });
    expect(t.writes).toHaveLength(1);
    expect(t.writes[0]).toMatchObject({
      method: 'POST',
      path: `/api/v1/policies/${POLICY}/disable`,
      body: { expectedRowVersion: 3 },
      authorization: AUTH.authorization,
      executionId: result.execution.id,
    });
    // policy_management_disable has no idempotency: no key is sent.
    expect(t.writes[0]!.idempotencyKey).toBeUndefined();
    expect(t.writes[0]!.correlationId).toMatch(/\.2$/);
    expect(t.row(out)).toMatchObject({ status: 'executed', resultHttpStatus: 200 });
    expect(t.h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.tool_executed',
      'assistant.confirmation_executed',
    ]);
    // Replay: the second confirm is refused, nothing runs again.
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_not_pending',
      details: { status: 'executed' },
    });
    expect(t.writes).toHaveLength(1);
    expect(t.h.audit.entries.at(-1)).toMatchObject({
      action: 'assistant.confirmation_refused',
      metadata: { reason: 'not_pending' },
    });
  });

  it('sends Idempotency-Key = the confirmation id for required/legacy operations; 202 is executed', async () => {
    const t = setup();
    const out = await t.propose('message_lifecycle_rescan', {
      messageId: MESSAGE,
      body: { reason: 'Re-check after the signature update' },
    });
    const result = await t.confirm(out);
    expect(t.writes[0]!.idempotencyKey).toBe(out.confirmation!.view.id);
    expect(result.confirmation).toMatchObject({ status: 'executed', result: { httpStatus: 202 } });
  });

  it('a write the operation refuses is a 200 with confirmation.status failed', async () => {
    const t = setup();
    t.h.loopback.on(`POST /api/v1/policies/${POLICY}/disable`, (call) => {
      t.writes.push(call);
      return {
        kind: 'response',
        status: 409,
        body: { statusCode: 409, code: 'policy_conflict', message: 'Conflict' },
      };
    });
    const out = await t.disable();
    const result = await t.confirm(out);
    expect(result.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 409, error: 'policy_conflict' },
    });
    expect(result.execution.card).toMatchObject({ kind: 'error' });
    expect(t.h.audit.entries.at(-1)!.action).toBe('assistant.confirmation_failed');
  });

  it('another user or organization: 404 (not audited); another session: 403, row unchanged', async () => {
    const t = setup();
    const out = await t.disable();
    t.h.audit.entries.length = 0;
    const otherUser = defaultUser({
      userId: 777n,
      userPublicId: '0193b000-0000-7000-8000-000000000777',
    });
    expect(await coded(t.confirm(out, {}, otherUser))).toMatchObject({
      status: 404,
      code: 'assistant_confirmation_not_found',
    });
    const otherOrg = defaultUser({
      organizationId: 7002n,
      organizationPublicId: '0193b000-0000-7000-8000-000000007002',
    });
    expect((await coded(t.confirm(out, {}, otherOrg))).status).toBe(404);
    expect(t.h.audit.entries).toHaveLength(0);
    const otherSession = defaultUser({ sessionId: '0193b000-0000-7000-8000-0000000000bb' });
    expect(await coded(t.confirm(out, {}, otherSession))).toMatchObject({
      status: 403,
      code: 'assistant_confirmation_session_mismatch',
    });
    expect(t.row(out).status).toBe('pending');
    expect(t.h.audit.entries[0]).toMatchObject({
      action: 'assistant.confirmation_refused',
      metadata: { reason: 'session_mismatch' },
    });
    // GET works from any session of the owner and never shows the token.
    const view = await t.h.confirmations.get(otherSession, t.scope, out.confirmation!.view.id);
    expect(view.status).toBe('pending');
    expect(JSON.stringify(view)).not.toContain(out.confirmation!.token);
    expect(t.writes).toHaveLength(0);
  });

  it('expired: 410 and the row becomes expired (audited); GET shows a stale pending row as expired', async () => {
    const t = setup();
    const out = await t.disable();
    t.row(out).expiresAt = new Date(Date.now() - 1);
    // Still pending in storage, shown as expired.
    expect((await t.h.confirmations.get(t.user, t.scope, out.confirmation!.view.id)).status).toBe(
      'expired',
    );
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 410,
      code: 'assistant_confirmation_expired',
    });
    expect(t.row(out).status).toBe('expired');
    expect(t.h.audit.entries.at(-1)!.action).toBe('assistant.confirmation_expired');
    expect(t.writes).toHaveLength(0);
  });

  it('a wrong token: 403; the fifth cancels the confirmation (token_locked)', async () => {
    const t = setup();
    const out = await t.disable();
    const wrong = 'A'.repeat(43);
    for (let i = 1; i <= 4; i += 1) {
      expect(await coded(t.confirm(out, { token: wrong }))).toMatchObject({
        status: 403,
        code: 'assistant_confirmation_token_invalid',
      });
      expect(t.row(out)).toMatchObject({ status: 'pending', failedAttempts: i });
    }
    expect((await coded(t.confirm(out, { token: wrong }))).code).toBe(
      'assistant_confirmation_token_invalid',
    );
    expect(t.row(out)).toMatchObject({
      status: 'cancelled',
      errorCode: 'assistant_confirmation_token_locked',
    });
    // The right token cannot revive it.
    expect((await coded(t.confirm(out))).code).toBe('assistant_confirmation_not_pending');
    expect(t.writes).toHaveLength(0);
  });

  it('digest: a body digest that differs → 409 (row pending); tampered storage → 409 + row failed', async () => {
    const t = setup();
    const out = await t.disable();
    expect(await coded(t.confirm(out, { actionDigest: 'f'.repeat(64) }))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_digest_mismatch',
    });
    expect(t.row(out).status).toBe('pending');
    (t.row(out).request as { body: Record<string, unknown> }).body.expectedRowVersion = 1;
    expect((await coded(t.confirm(out))).code).toBe('assistant_confirmation_digest_mismatch');
    expect(t.row(out)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_digest_mismatch',
    });
    expect(t.writes).toHaveLength(0);
  });

  it('tool changed (operation no longer the tool’s) → 409, row failed; lost permission → 403, row failed', async () => {
    const t = setup();
    const out = await t.disable();
    // Re-sign the tampered row so only the tool check can catch it.
    const stored = t.row(out);
    stored.operationId = 'PolicyManagementController_enable_v1';
    stored.actionDigest = actionDigest(
      digestInputOf({
        confirmationId: stored.publicId,
        organizationPublicId: t.user.organizationPublicId,
        userPublicId: t.user.userPublicId,
        sessionFamilyId: stored.sessionFamilyId,
        overrideId: null,
        conversationId: t.conversation.publicId,
        executionId: out.executionId,
        tool: stored.toolName,
        operationId: stored.operationId,
        risk: stored.risk,
        requiresReauth: stored.requiresReauth,
        request: parseStoredRequest(stored.request)!,
        stateDigest: stored.stateDigest,
        preconditions: parseStoredPreconditions(stored.preconditions)!,
        expiresAt: stored.expiresAt,
      }),
    );
    expect(await coded(t.confirm(out, { actionDigest: stored.actionDigest }))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_tool_changed',
    });
    expect(stored.status).toBe('failed');

    const second = await t.disable();
    const demoted = defaultUser({ permissions: new Set(['assistant:use', 'policy:read']) });
    expect(await coded(t.confirm(second, {}, demoted))).toMatchObject({
      status: 403,
      code: 'forbidden',
    });
    expect(t.row(second)).toMatchObject({ status: 'failed', errorCode: 'forbidden' });
    expect(t.writes).toHaveLength(0);
  });

  it('availability gates apply (the row stays pending)', async () => {
    const t = setup();
    const out = await t.disable();
    t.h.world.settings.get(t.user.organizationId)!.enabled = false;
    expect((await coded(t.confirm(out))).code).toBe('assistant_tenant_disabled');
    expect(t.row(out).status).toBe('pending');
  });

  it('high risk: 401 reauth_required, 401 reauth_failed with reason, then the window marker', async () => {
    const t = setup();
    const out = await t.propose('policy_management_remove', { policyId: POLICY });
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 401,
      code: 'assistant_reauth_required',
    });
    expect(await coded(t.confirm(out, { reauth: { password: 'wrong-password' } }))).toMatchObject({
      status: 401,
      code: 'assistant_reauth_failed',
      details: { reason: 'password' },
    });
    expect(
      (await coded(t.confirm(out, { reauth: { password: REAUTH_PASSWORD } }))).details,
    ).toEqual({ reason: 'totp_required' });
    expect(t.row(out).status).toBe('pending');
    expect(t.writes).toHaveLength(0);
    const ok = await t.confirm(out, {
      reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP },
    });
    expect(ok.confirmation.status).toBe('executed');
    expect(t.row(out).reauthUsed).toBe(true);
    expect(await t.h.kv.ttl(assistantKeys.reauthWindow(t.user.sessionId))).toBeGreaterThan(0);
    // Inside the window the next high-risk confirm needs no password.
    const next = await t.propose('policy_management_remove', { policyId: POLICY });
    expect(next.confirmation!.view.reauthFresh).toBe(true);
    expect((await t.confirm(next)).confirmation.status).toBe('executed');
    // Audit metadata never carries the password or the code.
    const audit = JSON.stringify(t.h.audit.entries, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    expect(audit).not.toContain(REAUTH_PASSWORD);
    expect(audit).not.toContain('wrong-password');
    expect(
      t.h.audit.entries
        .filter((e) => e.action === 'assistant.confirmation_refused')
        .map((e) => (e.metadata as { reason: string }).reason),
    ).toEqual(['reauth_required', 'reauth_failed', 'reauth_failed']);
  });

  it('ASSISTANT_REAUTH_WINDOW_SECONDS=0: no marker, every high-risk confirm asks again', async () => {
    const t = setup({ ASSISTANT_REAUTH_WINDOW_SECONDS: '0' });
    const first = await t.propose('policy_management_remove', { policyId: POLICY });
    await t.confirm(first, { reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } });
    expect(await t.h.kv.exists(assistantKeys.reauthWindow(t.user.sessionId))).toBe(false);
    const second = await t.propose('policy_management_remove', { policyId: POLICY });
    expect(second.confirmation!.view.reauthFresh).toBe(false);
    expect((await coded(t.confirm(second))).code).toBe('assistant_reauth_required');
  });

  it('a running turn holds the conversation lock: 409 assistant_turn_in_progress, row pending', async () => {
    const t = setup();
    const out = await t.disable();
    await t.h.limits.acquireLock(t.conversation.publicId, 'a-running-turn');
    expect((await coded(t.confirm(out))).code).toBe('assistant_turn_in_progress');
    expect(t.row(out).status).toBe('pending');
    await t.h.limits.releaseLock(t.conversation.publicId, 'a-running-turn');
    expect((await t.confirm(out)).confirmation.status).toBe('executed');
  });

  it('the atomic transition: a loser answers 409 not_pending and nothing runs twice', async () => {
    const t = setup();
    const out = await t.disable();
    const [a, b] = await Promise.allSettled([t.confirm(out), t.confirm(out)]);
    const fulfilled = [a, b].filter((r) => r.status === 'fulfilled');
    expect(fulfilled).toHaveLength(1);
    expect(t.writes).toHaveLength(1);
    // A lost transition (another pod won between the checks and the UPDATE).
    const next = await t.disable();
    const repo = (
      t.h.confirmations as unknown as { confirmations: { beginExecuting: () => Promise<number> } }
    ).confirmations;
    vi.spyOn(repo, 'beginExecuting').mockResolvedValueOnce(0);
    expect((await coded(t.confirm(next))).code).toBe('assistant_confirmation_not_pending');
    expect(t.writes).toHaveLength(1);
  });

  it('changed state since the proposal → 409 state_changed, row failed, no write', async () => {
    const t = setup();
    const out = await t.disable();
    t.policy.rowVersion = 4; // renamed by someone else
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.row(out)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_state_changed',
    });
    // A re-read that fails (deleted meanwhile) refuses the same way, with the status.
    const next = await t.disable();
    t.h.loopback.on(`GET /api/v1/policies/${POLICY}`, () => ({
      kind: 'response',
      status: 404,
      body: { statusCode: 404, code: 'policy_not_found', message: 'gone' },
    }));
    expect(await coded(t.confirm(next))).toMatchObject({
      code: 'assistant_confirmation_state_changed',
      details: { httpStatus: 404 },
    });
    expect(t.writes).toHaveLength(0);
  });

  it('a slow precondition re-read is not swept; the claim (execution_started_at) precedes the write', async () => {
    const t = setup();
    const out = await t.disable();
    const timeout = t.h.config.ASSISTANT_TOOL_TIMEOUT_MS;
    let swept = -1;
    // The re-read takes longer than the write's budget (timeout + 60 s): still not stale.
    t.h.loopback.on(`GET /api/v1/policies/${POLICY}`, async () => {
      swept = await t.h.retention.failStaleConfirmations(new Date(Date.now() + timeout + 61_000));
      expect(t.row(out).executionStartedAt).toBeNull();
      return { kind: 'response', status: 200, body: structuredClone(t.policy) };
    });
    const result = await t.confirm(out);
    expect(swept).toBe(0);
    expect(result.confirmation.status).toBe('executed');
    expect(t.row(out).executionStartedAt).toBeInstanceOf(Date);
    expect(t.row(out).executionStartedAt!.getTime()).toBeGreaterThanOrEqual(
      t.row(out).decidedAt!.getTime(),
    );
  });

  it('swept as outcome unknown during the re-read: the claim fails, 409, nothing is sent (AI-2 review)', async () => {
    const t = setup();
    const out = await t.disable();
    const timeout = t.h.config.ASSISTANT_TOOL_TIMEOUT_MS;
    t.h.loopback.on(`GET /api/v1/policies/${POLICY}`, async () => {
      // A crashed-api sweep long after the decision (worst-case re-read exceeded).
      expect(
        await t.h.retention.failStaleConfirmations(new Date(Date.now() + 27 * timeout + 61_000)),
      ).toBe(1);
      return { kind: 'response', status: 200, body: structuredClone(t.policy) };
    });
    t.h.audit.entries.length = 0;
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_not_pending',
      details: { status: 'failed' },
    });
    expect(t.writes).toHaveLength(0);
    expect(t.row(out)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_outcome_unknown',
      executionStartedAt: null,
      resultExecutionId: null,
    });
    expect(t.h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.confirmation_failed',
      'assistant.confirmation_refused',
    ]);
  });

  it('swept as outcome unknown while the write ran: the real outcome replaces it, audited reconciledFrom', async () => {
    const t = setup();
    const out = await t.disable();
    const timeout = t.h.config.ASSISTANT_TOOL_TIMEOUT_MS;
    t.h.loopback.on(`POST /api/v1/policies/${POLICY}/disable`, async (call) => {
      t.writes.push(call);
      expect(t.row(out).executionStartedAt).toBeInstanceOf(Date);
      // The write outlived timeout + 60 s: the sweep fails the row meanwhile.
      expect(
        await t.h.retention.failStaleConfirmations(new Date(Date.now() + timeout + 61_000)),
      ).toBe(1);
      t.row(out).reportedAt = new Date(); // already told to the model as failed
      t.policy.status = 'disabled';
      return { kind: 'response', status: 200, body: structuredClone(t.policy) };
    });
    t.h.audit.entries.length = 0;
    const result = await t.confirm(out);
    expect(t.writes).toHaveLength(1);
    expect(result.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 200, error: null },
    });
    expect(t.row(out)).toMatchObject({
      status: 'executed',
      errorCode: null,
      resultHttpStatus: 200,
      reportedAt: null,
    });
    expect(t.h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.confirmation_failed',
      'assistant.tool_executed',
      'assistant.confirmation_executed',
    ]);
    expect(t.h.audit.entries.at(-1)!.metadata).toMatchObject({
      status: 'executed',
      reconciledFrom: 'assistant_confirmation_outcome_unknown',
    });
  });

  it('a stored request the arguments would not rebuild is never sent (digest_mismatch)', async () => {
    const t = setup();
    const out = await t.disable();
    // `params` is outside the digest; the executor's equality check refuses the request.
    const stored = t.row(out);
    (stored.request as { params: Record<string, unknown> }).params.policyId =
      '0193c000-0000-7000-8000-000000000009';
    t.h.loopback.on('GET /api/v1/policies/0193c000-0000-7000-8000-000000000009', () => ({
      kind: 'response',
      status: 200,
      body: { ...t.policy },
    }));
    expect((await coded(t.confirm(out))).code).toBe('assistant_confirmation_digest_mismatch');
    expect(stored.status).toBe('failed');
    expect(t.writes).toHaveLength(0);
  });
});

describe('cancel (D2)', () => {
  it('pending → cancelled (audited), idempotent, then confirm 409; another session 403', async () => {
    const t = setup();
    const out = await t.disable();
    const otherSession = defaultUser({ sessionId: '0193b000-0000-7000-8000-0000000000bb' });
    expect(
      (
        await coded(
          t.h.confirmations.cancel(otherSession, t.scope, out.confirmation!.view.id, null),
        )
      ).code,
    ).toBe('assistant_confirmation_session_mismatch');
    const first = await t.h.confirmations.cancel(t.user, t.scope, out.confirmation!.view.id, null);
    expect(first.confirmation.status).toBe('cancelled');
    const again = await t.h.confirmations.cancel(t.user, t.scope, out.confirmation!.view.id, null);
    expect(again.confirmation.status).toBe('cancelled');
    expect(
      t.h.audit.entries.filter((e) => e.action === 'assistant.confirmation_cancelled'),
    ).toHaveLength(1);
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 409,
      details: { status: 'cancelled' },
    });
    // An executed confirmation cannot be cancelled.
    const done = await t.disable();
    t.policy.status = 'active';
    await t.confirm(done);
    expect(
      await coded(t.h.confirmations.cancel(t.user, t.scope, done.confirmation!.view.id, null)),
    ).toMatchObject({ status: 409, details: { status: 'executed' } });
  });
});

describe('digest binding (D3): a seeded mutation of any single stored column is refused', () => {
  /** Deterministic PRNG (mulberry32) so a failure is reproducible from the seed. */
  function prng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  type Mutation = (row: StoredConfirmation, rnd: () => number) => void;
  const req = (row: StoredConfirmation) =>
    row.request as { method: string; path: string; body: Record<string, unknown> };
  const pre = (row: StoredConfirmation) => row.preconditions as Record<string, unknown>;
  const MUTATIONS: Record<string, Mutation> = {
    'request.method': (row) => (req(row).method = 'PUT'),
    'request.path': (row) => (req(row).path = `${req(row).path}x`),
    'request.body leaf': (row, rnd) =>
      (req(row).body.expectedRowVersion = 4 + Math.floor(rnd() * 9)),
    'request.body extra member': (row) => (req(row).body.extra = true),
    'preconditions.rowVersion': (row, rnd) => (pre(row).rowVersion = 10 + Math.floor(rnd() * 9)),
    'preconditions.definitionSha256': (row) => (pre(row).definitionSha256 = 'c'.repeat(64)),
    stateDigest: (row) => (row.stateDigest = 'd'.repeat(64)),
    risk: (row) => (row.risk = 'low'),
    requiresReauth: (row) => (row.requiresReauth = true),
    expiresAt: (row, rnd) =>
      (row.expiresAt = new Date(row.expiresAt.getTime() + 1 + Math.floor(rnd() * 60_000))),
    toolName: (row) => (row.toolName = 'policy_management_enable'),
    operationId: (row) => (row.operationId = 'PolicyManagementController_enable_v1'),
    sessionFamilyId: (row) => (row.sessionFamilyId = '0193b000-0000-7000-8000-0000000000cc'),
    platformOverrideId: (row) => (row.platformOverrideId = '0193b000-0000-7000-8000-0000000000dd'),
    publicId: (row) => (row.publicId = '0193b000-0000-7000-8000-0000000000ee'),
    executionId: (row, rnd) => (row.executionId = 900_000n + BigInt(Math.floor(rnd() * 99))),
    conversationId: (row) => (row.conversationId = 123_456n),
    tokenHash: (row) => (row.tokenHash = hashConfirmationToken('B'.repeat(43))),
  };

  it.each([0x5eed, 0xa11ce, 0xc0ffee])(
    'seed %i: every single-column mutation is refused, nothing is written',
    async (seed) => {
      const rnd = prng(seed);
      const names = Object.keys(MUTATIONS).sort(() => rnd() - 0.5);
      for (const name of names) {
        const t = setup();
        const out = await t.disable();
        MUTATIONS[name]!(t.row(out), rnd);
        const refused = await t.confirm(out).then(
          () => false,
          () => true,
        );
        expect(refused, `${name} (seed ${seed})`).toBe(true);
        expect(t.writes, name).toHaveLength(0);
      }
    },
  );

  it('the untouched row confirms (control)', async () => {
    const t = setup();
    expect((await t.confirm(await t.disable())).confirmation.status).toBe('executed');
  });
});

describe('catalogue and logs', () => {
  it('enabled writes are available tools for a permitted user (no longer denied_disabled)', () => {
    const tool = findTool('policy_management_disable')!;
    expect(tool).toMatchObject({ access: 'write', enabled: true });
    expect(toolAvailability(defaultUser(), tool)).toEqual({ available: true });
    expect(availableTools(defaultUser()).some((t) => t.name === 'policy_management_disable')).toBe(
      true,
    );
  });

  it('never logs the token, the digest input, request bodies or passwords', async () => {
    const lines: string[] = [];
    for (const level of ['log', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(Logger.prototype, level).mockImplementation((...args: unknown[]) => {
        lines.push(JSON.stringify(args, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}` : v)));
      });
    }
    const t = setup();
    const out = await t.propose('policy_management_remove', { policyId: POLICY });
    await coded(t.confirm(out, { reauth: { password: 'wrong-password' } }));
    await coded(t.confirm(out, { token: 'C'.repeat(43) }));
    await t.confirm(out, { reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } });
    const logged = lines.join('\n');
    expect(lines.length).toBeGreaterThan(0);
    for (const secret of [
      out.confirmation!.token,
      'C'.repeat(43),
      REAUTH_PASSWORD,
      'wrong-password',
      REAUTH_TOTP,
      t.row(out).tokenHash,
      'expectedRowVersion',
    ]) {
      expect(logged).not.toContain(secret);
    }
  });
});

describe('step AI-3: guards after the read, effective risk, selected items, confirm re-checks', () => {
  const SELF = defaultUser().userPublicId;
  const OTHER = '0193b000-0000-7000-8000-000000000502';
  const ROLE = 'it_custom';
  const WEBHOOK = '0193c000-0000-7000-8000-0000000000b1';
  const SESSION = '0193c000-0000-7000-8000-0000000005e1';
  const ORG = '0193b000-0000-7000-8000-000000007002';
  const REAUTH = { reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } };
  const admin = () =>
    defaultUser({
      permissions: new Set([
        ...PERMISSIONS,
        'user:read',
        'user:manage',
        'session:manage',
        'role:read',
        'role:manage',
        'webhook:read',
        'webhook:manage',
        'scan:settings_manage',
      ]),
    });

  /** `setup` with the identity, role, webhook, session and scan-settings reads and writes. */
  function identity(env: Record<string, string> = {}, user: UserPrincipal = admin()) {
    const t = setup(env, user);
    const role = {
      key: ROLE,
      name: 'IT custom',
      description: null as string | null,
      permissions: ['policy:read', 'assistant:configure'],
      system: false,
    };
    const webhook = {
      id: WEBHOOK,
      name: 'SIEM',
      url: 'https://hooks.example.test/siem',
      status: 'active',
      rowVersion: 2,
    };
    const sessions = [
      {
        id: SESSION,
        authenticatedAt: '2026-11-21T08:00:00.000Z',
        expiresAt: '2026-11-22T08:00:00.000Z',
        lastUsedAt: '2026-11-21T09:00:00.000Z',
        ipAddress: '198.51.100.20',
        userAgent: 'IT browser',
        mfaAuthenticated: true,
        // Not a state, row-version or display field: never stored anywhere.
        internalMarker: 'raw-only-marker-1',
      },
    ];
    const engines = [
      {
        engine: 'rspamd',
        version: 4,
        override: { spamScore: 8 },
        required: false,
        overrideApplied: true,
        internalMarker: 'raw-only-marker-2',
      },
    ];
    const userBody = (id: string) => ({
      id,
      email: `${id === SELF ? 'me' : 'other'}@example.test`,
      displayName: id === SELF ? 'Me' : 'Other',
      status: 'active',
      lockedUntil: null,
      mfaEnabled: true,
      roles: [{ key: 'security_analyst' }],
    });
    const ok = (body: unknown) => ({ kind: 'response' as const, status: 200, body });
    for (const id of [SELF, OTHER]) {
      t.h.loopback.on(`GET /api/v1/users/${id}`, () => ok(userBody(id)));
      t.h.loopback.on(`PATCH /api/v1/users/${id}`, (call) => {
        t.writes.push(call);
        return ok(userBody(id));
      });
    }
    t.h.loopback.on(`GET /api/v1/users/${OTHER}/sessions`, () =>
      ok({ data: structuredClone(sessions) }),
    );
    t.h.loopback.on(`DELETE /api/v1/users/${OTHER}/sessions/${SESSION}`, (call) => {
      t.writes.push(call);
      return { kind: 'response', status: 204, body: null };
    });
    t.h.loopback.on(`GET /api/v1/roles/${ROLE}`, () => ok(structuredClone(role)));
    t.h.loopback.on(`PUT /api/v1/roles/${ROLE}`, (call) => {
      t.writes.push(call);
      return ok(structuredClone(role));
    });
    t.h.loopback.on(`GET /api/v1/webhooks/${WEBHOOK}`, () => ok(structuredClone(webhook)));
    t.h.loopback.on(`PATCH /api/v1/webhooks/${WEBHOOK}`, (call) => {
      t.writes.push(call);
      webhook.rowVersion += 1;
      return ok(structuredClone(webhook));
    });
    t.h.loopback.on('GET /api/v1/scan-settings', () => ok({ data: structuredClone(engines) }));
    t.h.loopback.on('PUT /api/v1/scan-settings/rspamd', (call) => {
      t.writes.push(call);
      return ok(structuredClone(engines[0]));
    });
    return { ...t, role, webhook, sessions, engines };
  }

  /** Re-signs a (tampered) row so that only the AI-3 checks can catch the change. */
  const resign = (t: ReturnType<typeof identity>, out: ExecutionOutcome): string => {
    const stored = t.row(out);
    stored.actionDigest = actionDigest(
      digestInputOf({
        confirmationId: stored.publicId,
        organizationPublicId: t.user.organizationPublicId,
        userPublicId: t.user.userPublicId,
        sessionFamilyId: stored.sessionFamilyId,
        overrideId: null,
        conversationId: t.conversation.publicId,
        executionId: out.executionId,
        tool: stored.toolName,
        operationId: stored.operationId,
        risk: stored.risk,
        requiresReauth: stored.requiresReauth,
        request: parseStoredRequest(stored.request)!,
        stateDigest: stored.stateDigest,
        preconditions: parseStoredPreconditions(stored.preconditions)!,
        expiresAt: stored.expiresAt,
      }),
    );
    return stored.actionDigest;
  };
  const metricOf = async (t: ReturnType<typeof identity>, outcome: string): Promise<number> =>
    (await t.h.metrics.confirmations.get()).values
      .filter((v) => v.labels.outcome === outcome)
      .reduce((sum, v) => sum + v.value, 0);
  const serialized = (value: unknown) =>
    JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

  it('roles_update: adding or removing assistant:configure → denied_guard after the read (no row)', async () => {
    for (const [before, after] of [
      [['policy:read'], ['policy:read', 'assistant:configure']],
      [['policy:read', 'assistant:configure'], ['policy:read']],
    ]) {
      const t = identity();
      t.role.permissions = before!;
      const out = await t.propose('roles_update', {
        key: ROLE,
        body: { name: 'IT custom', permissions: after },
      });
      expect(out).toMatchObject({
        decision: 'denied_guard',
        status: 'refused',
        denialMessage: GUARD_MESSAGES.assistant_configure,
      });
      expect(out.envelope).toMatchObject({ status: 'denied', decision: 'denied_guard' });
      // Only the precondition read reached the api.
      expect(t.h.loopback.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
        `GET /api/v1/roles/${ROLE}`,
      ]);
      expect(t.h.world.confirmations).toHaveLength(0);
      expect(t.h.audit.entries.map((e) => e.action)).toEqual(['assistant.tool_denied']);
      expect(t.h.audit.entries[0]!.metadata).toMatchObject({
        decision: 'denied_guard',
        guard: 'deny_permission_change',
      });
    }
  });

  it('roles_update keeping assistant:configure is a high-risk proposal that confirms', async () => {
    const t = identity();
    const out = await t.propose('roles_update', {
      key: ROLE,
      body: {
        name: 'IT custom',
        permissions: ['policy:read', 'assistant:configure', 'message:read'],
      },
    });
    expect(out.status).toBe('pending_confirmation');
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    expect((await t.confirm(out, REAUTH)).confirmation.status).toBe('executed');
    expect(t.writes.map((w) => `${w.method} ${w.path}`)).toEqual([`PUT /api/v1/roles/${ROLE}`]);
  });

  it('confirm-time after-read guard (tampered, re-signed request) → 403 action_not_allowed, row failed', async () => {
    const t = identity();
    const out = await t.propose('roles_update', {
      key: ROLE,
      body: { name: 'IT custom', permissions: ['policy:read', 'assistant:configure'] },
    });
    expect(out.status).toBe('pending_confirmation');
    const stored = t.row(out);
    (stored.request as { body: { permissions: string[] } }).body.permissions = ['policy:read'];
    const digest = resign(t, out);
    expect(await coded(t.confirm(out, { actionDigest: digest, ...REAUTH }))).toMatchObject({
      status: 403,
      code: 'assistant_action_not_allowed',
    });
    expect(stored).toMatchObject({ status: 'failed', errorCode: 'assistant_action_not_allowed' });
    expect(t.writes).toHaveLength(0);
    const refused = t.h.audit.entries.find((e) => e.action === 'assistant.confirmation_refused');
    expect(refused!.metadata).toMatchObject({ reason: 'guard', guard: 'deny_permission_change' });
    expect(t.h.audit.entries.some((e) => e.action === 'assistant.confirmation_failed')).toBe(true);
    expect(await metricOf(t, 'refused_guard')).toBe(1);
  });

  it('confirm-time before-read guard: a row re-targeted at the caller → 403, row failed, nothing read', async () => {
    const t = identity();
    const out = await t.propose('users_update', { id: OTHER, body: { displayName: 'Renamed' } });
    expect(out.confirmation!.view).toMatchObject({ risk: 'low', requiresReauth: false });
    const stored = t.row(out);
    const request = stored.request as { path: string; params: Record<string, unknown> };
    request.path = `/api/v1/users/${SELF}`;
    request.params.id = SELF;
    const digest = resign(t, out);
    const reads = t.h.loopback.calls.length;
    expect(await coded(t.confirm(out, { actionDigest: digest }))).toMatchObject({
      status: 403,
      code: 'assistant_action_not_allowed',
    });
    expect(stored).toMatchObject({ status: 'failed', errorCode: 'assistant_action_not_allowed' });
    expect(t.h.loopback.calls).toHaveLength(reads);
    expect(t.writes).toHaveLength(0);
    expect(
      t.h.audit.entries.find((e) => e.action === 'assistant.confirmation_refused')!.metadata,
    ).toMatchObject({ reason: 'guard', guard: 'not_self_user' });
  });

  it('effective risk: webhooks_update with body.url is high (re-auth, warning); a rename stays low', async () => {
    const t = identity();
    const moved = await t.propose('webhooks_update', {
      webhookId: WEBHOOK,
      body: { url: 'https://hooks.example.test/new' },
    });
    expect(moved.envelope).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(t.row(moved)).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(moved.confirmation!.view.summary!.warnings).toContain(ESCALATION_WARNINGS.webhookUrl);
    // CAS injected from the read; the digest binds the stored (effective) risk.
    expect((t.row(moved).request as { body: unknown }).body).toEqual({
      url: 'https://hooks.example.test/new',
      expectedRowVersion: 2,
    });
    const requested = t.h.audit.entries.filter(
      (e) => e.action === 'assistant.confirmation_requested',
    );
    expect(requested[0]!.metadata).toMatchObject({ risk: 'high', baseRisk: 'low' });
    expect((await coded(t.confirm(moved))).code).toBe('assistant_reauth_required');

    const renamed = await t.propose('webhooks_update', {
      webhookId: WEBHOOK,
      body: { name: 'SIEM (EU)' },
    });
    expect(t.row(renamed)).toMatchObject({ risk: 'low', requiresReauth: false });
    expect(renamed.confirmation!.view.summary!.warnings ?? []).not.toContain(
      ESCALATION_WARNINGS.webhookUrl,
    );
    expect(
      t.h.audit.entries.filter((e) => e.action === 'assistant.confirmation_requested')[1]!.metadata,
    ).toMatchObject({ risk: 'low', baseRisk: 'low' });
    expect((await t.confirm(renamed)).confirmation.status).toBe('executed');
    expect(t.writes).toHaveLength(1);
  });

  it('a stored risk that differs from the recomputed effective risk → 409 tool_changed, row failed', async () => {
    const t = identity();
    const out = await t.propose('webhooks_update', {
      webhookId: WEBHOOK,
      body: { url: 'https://hooks.example.test/new' },
    });
    const stored = t.row(out);
    stored.risk = 'low';
    stored.requiresReauth = false;
    const digest = resign(t, out);
    expect(await coded(t.confirm(out, { actionDigest: digest }))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_tool_changed',
    });
    expect(stored).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_tool_changed',
    });
    expect(t.writes).toHaveLength(0);
  });

  it('select: users_revoke_session reads the session list; a missing session fails the proposal 404', async () => {
    const t = identity();
    const out = await t.propose('users_revoke_session', { id: OTHER, sessionId: SESSION });
    expect(out.status).toBe('pending_confirmation');
    const pre = t.row(out).preconditions as { snapshot: Record<string, unknown> };
    expect(pre.snapshot).toMatchObject({
      authenticatedAt: '2026-11-21T08:00:00.000Z',
      expiresAt: '2026-11-22T08:00:00.000Z',
      ipAddress: '198.51.100.20',
      userAgent: 'IT browser',
    });
    expect(t.row(out).stateDigest).toBe(
      stateDigest(t.sessions[0], ['authenticatedAt', 'expiresAt']),
    );
    // The raw target stays in memory: never in rows, executions or audit.
    expect(
      serialized({ c: t.h.world.confirmations, e: t.h.world.executions, a: t.h.audit.entries }),
    ).not.toContain('raw-only-marker-1');

    const missing = await t.propose('users_revoke_session', {
      id: OTHER,
      sessionId: '0193c000-0000-7000-8000-0000000005e9',
    });
    expect(missing).toMatchObject({
      decision: 'allowed',
      status: 'failed',
      httpStatus: 404,
      errorCode: 'not_found',
    });
    expect(t.h.world.confirmations).toHaveLength(1);

    // The session changed (refreshed) before the confirm → 409 state_changed, nothing revoked.
    t.sessions[0]!.expiresAt = '2026-11-23T08:00:00.000Z';
    expect(await coded(t.confirm(out, REAUTH))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.row(out).status).toBe('failed');
    // Gone at confirm: the selected item is missing → refused as changed with the 404.
    const next = await t.propose('users_revoke_session', { id: OTHER, sessionId: SESSION });
    t.sessions.length = 0;
    expect(await coded(t.confirm(next))).toMatchObject({
      code: 'assistant_confirmation_state_changed',
      details: { httpStatus: 404 },
    });
    expect(t.writes).toHaveLength(0);
  });

  it('select: the unchanged session confirms and revokes', async () => {
    const t = identity();
    const out = await t.propose('users_revoke_session', { id: OTHER, sessionId: SESSION });
    expect((await t.confirm(out, REAUTH)).confirmation.status).toBe('executed');
    expect(t.writes.map((w) => `${w.method} ${w.path}`)).toEqual([
      `DELETE /api/v1/users/${OTHER}/sessions/${SESSION}`,
    ]);
  });

  it('select (optional): a feature without a stored value has a null snapshot and the digest of {}', async () => {
    const operator = defaultUser({
      organizationKind: 'platform',
      permissions: new Set(['assistant:use', 'platform:organizations']),
    });
    const t = setup({}, operator);
    t.h.loopback.on(`GET /api/v1/organizations/${ORG}/features`, () => ({
      kind: 'response',
      status: 200,
      body: { data: [{ key: 'webhooks', enabled: true, config: null, source: 'plan' }] },
    }));
    const out = await t.propose('organization_configuration_override_feature', {
      id: ORG,
      featureKey: 'dlp',
      body: { enabled: true },
    });
    expect(out.status).toBe('pending_confirmation');
    const stored = t.row(out);
    expect((stored.preconditions as { snapshot: unknown }).snapshot).toEqual({
      enabled: null,
      config: null,
      source: null,
    });
    expect(stored.stateDigest).toBe(stateDigest({}, ['enabled', 'config', 'source']));
    expect(stored).toMatchObject({ risk: 'high', requiresReauth: true });
  });

  it('select (required) with CAS: the scan engine’s version is injected as expectedVersion', async () => {
    const t = identity();
    const replace = await t.propose('scan_settings_replace', {
      engine: 'rspamd',
      body: { settings: { spamScore: 9 } },
    });
    expect(replace.status).toBe('pending_confirmation');
    expect(t.row(replace).request).toMatchObject({
      method: 'PUT',
      path: '/api/v1/scan-settings/rspamd',
      body: { settings: { spamScore: 9 }, expectedVersion: 4 },
    });
    expect((t.row(replace).preconditions as { rowVersion: number }).rowVersion).toBe(4);
    const reset = await t.propose('scan_settings_reset', { engine: 'rspamd' });
    expect(t.row(reset).request).toMatchObject({
      method: 'DELETE',
      path: '/api/v1/scan-settings/rspamd?expectedVersion=4',
    });
    // An engine the list does not have: 404, no row.
    const unknown = await t.propose('scan_settings_reset', { engine: 'sandbox' });
    expect(unknown).toMatchObject({ status: 'failed', httpStatus: 404, errorCode: 'not_found' });
    expect(serialized({ c: t.h.world.confirmations, a: t.h.audit.entries })).not.toContain(
      'raw-only-marker-2',
    );
    // The engine's version moved before the confirm → 409 state_changed.
    t.engines[0]!.version = 5;
    expect(await coded(t.confirm(replace, REAUTH))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.writes).toHaveLength(0);
  });
});
