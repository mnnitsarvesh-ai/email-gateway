/**
 * Step AI-2 policy write tools through chat (docs/plan/steps/29-ai-chat-confirmations-mail-
 * writes.md D1, D2, D4, §9 item 4; the `testedBy` of the 11 policy writes in
 * docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): each write is proposed through a directive
 * turn (`/tool <name> <json>`, the deterministic fake provider; never a real LLM), confirmed
 * through `POST /assistant/confirmations/{id}/confirm` (password + TOTP for the high-risk ones
 * unless the session's re-authentication window is open) and the api's own state is asserted on
 * the writer. The api listens on its ephemeral loopback port, so the precondition reads,
 * `POST /policies/validate` and the confirmed write go through the real pipeline.
 *
 * Also: `expectedRowVersion` is injected from the precondition snapshot even when the model sent
 * a stale one; `publish` and `activate` (legacy idempotency) carry `Idempotency-Key` = the
 * confirmation id and a replay with that key answers the stored response; the other policy
 * writes carry none; a refusal of the route (`409 policy_name_taken`) is a `200` with the
 * confirmation `failed` and the execution's error card; an invalid definition never becomes a
 * proposal (`assistant_definition_invalid`).
 *
 * Synthetic `it-*` organizations only.
 */
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/policies
// @covers patch /api/v1/policies/:policyId
// @covers delete /api/v1/policies/:policyId
// @covers post /api/v1/policies/:policyId/enable
// @covers post /api/v1/policies/:policyId/disable
// @covers post /api/v1/policies/:policyId/versions
// @covers put /api/v1/policies/:policyId/versions/:versionNo
// @covers delete /api/v1/policies/:policyId/versions/:versionNo
// @covers post /api/v1/policies/:policyId/versions/:versionNo/publish
// @covers post /api/v1/policies/:policyId/versions/:versionNo/activate
// @covers put /api/v1/policy-settings
import { randomUUID } from 'node:crypto';
import { FAKE_EXECUTABLES_DEFINITION } from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  ALL_TENANT_PERMISSIONS,
  call,
  clearAssistantCounters,
  confirm,
  confirmationRow,
  createAssistantApp,
  directive,
  enableAssistant,
  executionRow,
  member,
  type Member,
  platformMember,
  propose,
  type Proposal,
  reauthOf,
  recordLoopback,
  type RecordedCall,
  turn,
  newConversation,
  waitForRead,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { idem } from './support/http';

const P = '/api/v1/policies';
/** A stale row version the model "remembers"; the executor must replace it. */
const STALE = 999;

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: Member;

const tag = (): string => randomUUID().slice(0, 8);
const definition = (priority: number) => ({ ...FAKE_EXECUTABLES_DEFINITION, priority });

interface Confirmed {
  proposal: Proposal;
  res: Awaited<ReturnType<typeof confirm>>;
  /** Loopback requests of the confirm (the precondition re-read and the write). */
  calls: RecordedCall[];
}

/** Proposes `tool` through a directive turn and confirms it (re-authenticating when needed). */
async function chat(tool: string, args: Record<string, unknown>): Promise<Confirmed> {
  const proposal = await propose(ctx, admin, directive(tool, args));
  expect(proposal.confirmation.tool).toBe(tool);
  const recorder = recordLoopback(ctx);
  try {
    const reauth =
      proposal.confirmation.requiresReauth && !proposal.confirmation.reauthFresh
        ? await reauthOf(fx, admin)
        : undefined;
    const res = await confirm(ctx, admin, proposal, reauth ? { reauth } : {});
    return { proposal, res, calls: [...recorder.calls] };
  } finally {
    recorder.restore();
  }
}

/** Asserts an executed confirmation with this HTTP status; returns the write's loopback call. */
function executed(result: Confirmed, httpStatus: number): RecordedCall {
  expect(result.res.status, JSON.stringify(result.res.body)).toBe(200);
  expect(result.res.body.confirmation).toMatchObject({
    status: 'executed',
    result: { httpStatus, error: null },
  });
  expect(result.res.body.execution).toMatchObject({
    tool: result.proposal.confirmation.tool,
    decision: 'allowed',
    status: 'succeeded',
    httpStatus,
    turnId: null,
  });
  const writes = result.calls.filter((c) => c.method !== 'GET');
  expect(writes).toHaveLength(1);
  return writes[0]!;
}

/** The stored request of a confirmation (method, path with the query, body). */
async function storedRequest(confirmationId: string) {
  const row = await confirmationRow(ctx, confirmationId);
  return row.request as { method: string; path: string; body: Record<string, unknown> | null };
}

/** Waits until the replica serves the policy at its writer `rowVersion`. */
async function settled(policyId: string): Promise<void> {
  const row = await ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });
  await waitForRead(ctx, admin, `${P}/${policyId}`, (b) => b.rowVersion === row.rowVersion);
}

/** Waits until the replica serves the version at its writer `rowVersion`. */
async function versionSettled(policyId: string, versionNo: number): Promise<void> {
  const policy = await ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });
  const row = await ctx.prisma.policyVersion.findFirstOrThrow({
    where: { organizationId: org.id, policyId: policy.id, version: versionNo },
  });
  await waitForRead(
    ctx,
    admin,
    `${P}/${policyId}/versions/${versionNo}`,
    (b) => b.rowVersion === row.rowVersion && b.status === row.status,
  );
}

const policyRow = (policyId: string) =>
  ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });

const versionsOf = async (policyId: string) => {
  const policy = await policyRow(policyId);
  return ctx.prisma.policyVersion.findMany({
    where: { organizationId: org.id, policyId: policy.id },
    orderBy: { version: 'asc' },
  });
};

/** Audit rows of the operation's own action carrying the result execution's correlation id. */
async function operationAudited(result: Confirmed, action: string): Promise<void> {
  const execution = await executionRow(ctx, result.res.body.execution.id as string);
  const rows = await ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action, correlationId: execution.correlationId },
  });
  expect(rows, action).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(admin.user.publicId);
}

beforeAll(async () => {
  const assistant = await createAssistantApp();
  ctx = assistant.ctx;
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization();
  fx.registerCleanup(() =>
    ctx.get(PolicyTenantDataRepository).purgeOrganization(systemScope(org.id)),
  );
  admin = await member(ctx, fx, org, [await fx.createCustomRole(org, [...ALL_TENANT_PERMISSIONS])]);
  await enableAssistant(ctx, operator, org, admin);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
});

describe('the policy lifecycle through chat (11 policy writes)', () => {
  let policyId: string;
  const name = `it chat policy ${tag()}`;

  it('policy_management_create (low): validated first, then a draft', async () => {
    const result = await chat('policy_management_create', {
      body: {
        name,
        description: 'Created in the chat suite',
        definition: definition(100),
        changeNote: 'first version',
      },
    });
    const write = executed(result, 201);
    expect(write).toMatchObject({ method: 'POST', path: P, idempotencyKey: null });
    expect(result.proposal.confirmation.risk).toBe('low');
    const row = await ctx.prisma.emailPolicy.findFirstOrThrow({
      where: { organizationId: org.id, name },
    });
    policyId = row.publicId;
    expect(row.status).toBe('draft');
    await operationAudited(result, 'policy.created');
    await versionSettled(policyId, 1);
  });

  it('policy_management_update (low): the stale expectedRowVersion is replaced', async () => {
    const before = await policyRow(policyId);
    const result = await chat('policy_management_update', {
      policyId,
      body: { description: 'Updated through chat', expectedRowVersion: STALE },
    });
    executed(result, 200);
    const request = await storedRequest(result.proposal.confirmation.id);
    expect(request).toMatchObject({ method: 'PATCH', path: `${P}/${policyId}` });
    expect(request.body!.expectedRowVersion).toBe(before.rowVersion);
    const after = await policyRow(policyId);
    expect(after.description).toBe('Updated through chat');
    expect(after.rowVersion).toBe(before.rowVersion + 1);
    await operationAudited(result, 'policy.updated');
    await settled(policyId);
  });

  it('policy_management_publish (medium, legacy idempotency): Idempotency-Key = confirmation id', async () => {
    const result = await chat('policy_management_publish', {
      policyId,
      versionNo: 1,
      body: { activate: true, expectedRowVersion: STALE },
    });
    expect(result.proposal.confirmation.risk).toBe('medium');
    expect(result.proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    const write = executed(result, 200);
    expect(write).toMatchObject({
      path: `${P}/${policyId}/versions/1/publish`,
      idempotencyKey: result.proposal.confirmation.id,
    });
    const request = await storedRequest(result.proposal.confirmation.id);
    expect(request.body!.expectedRowVersion).not.toBe(STALE);
    const policy = await policyRow(policyId);
    expect(policy.status).toBe('active');
    const [v1] = await versionsOf(policyId);
    expect(v1).toMatchObject({ status: 'published' });
    expect(policy.activeVersionId).toBe(v1!.id);
    await operationAudited(result, 'policy.version_published');

    // The key is stored per principal; the same request with it replays the stored answer.
    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: org.id, idempotencyKey: result.proposal.confirmation.id },
    });
    expect(stored.statusCode).toBe(200);
    const replay = await call(ctx, admin.headers, 'post', request.path, request.body!).set(
      idem(result.proposal.confirmation.id),
    );
    expect(replay.status).toBe(200);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(await versionsOf(policyId)).toHaveLength(1);
    await settled(policyId);
  });

  it('policy_management_disable and policy_management_enable (medium)', async () => {
    const disabled = await chat('policy_management_disable', {
      policyId,
      body: { expectedRowVersion: STALE },
    });
    expect(executed(disabled, 200).idempotencyKey).toBeNull();
    expect((await policyRow(policyId)).status).toBe('disabled');
    await operationAudited(disabled, 'policy.disabled');
    await settled(policyId);

    const enabled = await chat('policy_management_enable', { policyId });
    executed(enabled, 200);
    const request = await storedRequest(enabled.proposal.confirmation.id);
    // The body was absent: the executor adds the CAS field from the snapshot.
    expect(request.body).toEqual({
      expectedRowVersion: (await policyRow(policyId)).rowVersion - 1,
    });
    expect((await policyRow(policyId)).status).toBe('active');
    await operationAudited(enabled, 'policy.enabled');
    await settled(policyId);
  });

  it('policy_management_create_draft (low) and policy_management_update_draft (medium)', async () => {
    const created = await chat('policy_management_create_draft', {
      policyId,
      body: { definition: definition(90), changeNote: 'second version' },
    });
    executed(created, 201);
    let versions = await versionsOf(policyId);
    expect(versions.map((v) => [v.version, v.status])).toEqual([
      [1, 'published'],
      [2, 'draft'],
    ]);
    await operationAudited(created, 'policy.version_draft_created');
    await versionSettled(policyId, 2);

    const before = versions[1]!;
    const updated = await chat('policy_management_update_draft', {
      policyId,
      versionNo: 2,
      body: { definition: definition(80), changeNote: 'edited', expectedRowVersion: STALE },
    });
    expect(updated.proposal.confirmation.risk).toBe('medium');
    executed(updated, 200);
    const request = await storedRequest(updated.proposal.confirmation.id);
    expect(request.body!.expectedRowVersion).toBe(before.rowVersion);
    versions = await versionsOf(policyId);
    expect(versions[1]).toMatchObject({ status: 'draft', rowVersion: before.rowVersion + 1 });
    expect((versions[1]!.definition as { priority: number }).priority).toBe(80);
    await operationAudited(updated, 'policy.version_draft_updated');
  });

  it('policy_management_activate (medium, legacy idempotency): rolls back to version 1', async () => {
    // Version 2 published and active through the api (portal path), then chat rolls back.
    const v2 = (await versionsOf(policyId))[1]!;
    const published = await call(
      ctx,
      admin.headers,
      'post',
      `${P}/${policyId}/versions/2/publish`,
      {
        expectedRowVersion: v2.rowVersion,
      },
    ).set(idem());
    expect(published.status, JSON.stringify(published.body)).toBe(200);
    await settled(policyId);
    const result = await chat('policy_management_activate', {
      policyId,
      versionNo: 1,
      body: { expectedRowVersion: STALE },
    });
    const write = executed(result, 200);
    expect(write).toMatchObject({
      path: `${P}/${policyId}/versions/1/activate`,
      idempotencyKey: result.proposal.confirmation.id,
    });
    const versions = await versionsOf(policyId);
    expect((await policyRow(policyId)).activeVersionId).toBe(versions[0]!.id);
    await operationAudited(result, 'policy.version_activated');
    expect(
      await ctx.prisma.apiIdempotencyKey.count({
        where: { organizationId: org.id, idempotencyKey: result.proposal.confirmation.id },
      }),
    ).toBe(1);
    await settled(policyId);
  });

  it('policy_management_delete_draft (high): re-authenticated, the draft is gone', async () => {
    const draft = await call(ctx, admin.headers, 'post', `${P}/${policyId}/versions`, {
      definition: definition(70),
    });
    expect(draft.status, JSON.stringify(draft.body)).toBe(201);
    await versionSettled(policyId, 3);
    const v3 = (await versionsOf(policyId))[2]!;
    const result = await chat('policy_management_delete_draft', {
      policyId,
      versionNo: 3,
      expectedRowVersion: STALE,
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const write = executed(result, 204);
    expect(write.path).toBe(`${P}/${policyId}/versions/3?expectedRowVersion=${v3.rowVersion}`);
    expect((await versionsOf(policyId)).map((v) => v.version)).toEqual([1, 2]);
    expect((await confirmationRow(ctx, result.proposal.confirmation.id)).reauthUsed).toBe(true);
    await operationAudited(result, 'policy.version_draft_deleted');
    await settled(policyId);
  });

  it('policy_settings_put (high): the settings document changes', async () => {
    const result = await chat('policy_settings_put', {
      body: { settings: { recipientSplit: false }, expectedRowVersion: STALE },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    executed(result, 200);
    const settings = await ctx.prisma.policySettings.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    expect(settings.settings).toMatchObject({ recipientSplit: false });
    await operationAudited(result, 'policy.settings_updated');
  });

  it('policy_management_remove (high): the policy is archived', async () => {
    const before = await policyRow(policyId);
    const result = await chat('policy_management_remove', { policyId, expectedRowVersion: STALE });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const write = executed(result, 204);
    expect(write).toMatchObject({
      method: 'DELETE',
      path: `${P}/${policyId}?expectedRowVersion=${before.rowVersion}`,
      idempotencyKey: null,
    });
    const after = await policyRow(policyId);
    expect(after.deletedAt).not.toBeNull();
    expect(after.status).toBe('archived');
    await operationAudited(result, 'policy.deleted');
  });
});

describe('refusals of the route and of the proposal', () => {
  it('a 409 of the route surfaces as a failed confirmation (200, status failed)', async () => {
    const name = `it taken ${tag()}`;
    const proposal = await propose(
      ctx,
      admin,
      directive('policy_management_create', { body: { name, definition: definition(60) } }),
    );
    // The name is taken through the api between the proposal and the confirm.
    const taken = await call(ctx, admin.headers, 'post', P, { name, definition: definition(60) });
    expect(taken.status).toBe(201);
    const res = await confirm(ctx, admin, proposal);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 409, error: 'policy_name_taken' },
    });
    expect(res.body.execution).toMatchObject({
      status: 'failed',
      httpStatus: 409,
      errorCode: 'policy_name_taken',
    });
    expect(res.body.execution.card).toMatchObject({ kind: 'error', status: 'error' });
    expect(await ctx.prisma.emailPolicy.count({ where: { organizationId: org.id, name } })).toBe(1);
    // The model learns it at the start of the next turn.
    const next = await turn(ctx, admin.headers, proposal.conversation, '/text ok');
    const row = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: next.body.turn.id as string },
    });
    expect(row.providerTranscript).toMatch(
      /- policy_management_create \(call r1\): the user confirmed it; it failed \(HTTP 409, policy_name_taken\)\./,
    );
  });

  it('an invalid definition never becomes a proposal (assistant_definition_invalid)', async () => {
    const conversation = await newConversation(ctx, admin);
    const res = await turn(
      ctx,
      admin.headers,
      conversation,
      directive('policy_management_create', {
        body: { name: `it invalid ${tag()}`, definition: { dslVersion: 'policy-dsl/1' } },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.body.executions[0]).toMatchObject({
      tool: 'policy_management_create',
      decision: 'allowed',
      status: 'failed',
      httpStatus: 422,
      errorCode: 'assistant_definition_invalid',
    });
    expect(res.body.confirmations).toEqual([]);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: { conversation: { publicId: conversation } },
      }),
    ).toBe(0);
  });

  it('a precondition read of an unknown policy fails the proposal with the read’s 404', async () => {
    const conversation = await newConversation(ctx, admin);
    const res = await turn(
      ctx,
      admin.headers,
      conversation,
      directive('policy_management_disable', { policyId: randomUUID() }),
    );
    expect(res.body.executions[0]).toMatchObject({
      tool: 'policy_management_disable',
      status: 'failed',
      httpStatus: 404,
      errorCode: 'policy_not_found',
    });
    expect(res.body.confirmations).toEqual([]);
  });
});
