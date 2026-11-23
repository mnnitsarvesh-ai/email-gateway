/**
 * Step AI-3 identity administration tools through chat (docs/plan/steps/30-ai-chat-identity-
 * tenant-admin.md D2–D6, D10, I12–I14, §9 item 4; the `testedBy` of the 18 users, roles,
 * departments and API key writes in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): each write
 * is proposed through a directive turn (`/tool <name> <json>`, the deterministic fake provider;
 * never a real LLM) by an MFA-enrolled `organization_admin`, confirmed through `POST
 * /assistant/confirmations/{id}/confirm` (password + TOTP for the high-risk ones unless the
 * session's re-authentication window is open: the very first high confirm without it answers
 * `401 assistant_reauth_required`) and the api's own state is asserted on the writer, with the
 * operation's own audit row carrying the result execution's correlation id. The api listens on
 * its ephemeral loopback port, so the precondition reads and the confirmed writes go through the
 * real pipeline.
 *
 * Also: legacy idempotency (`Idempotency-Key` = the confirmation id) of `users_invite`,
 * `users_resend_invitation` and `users_reset_mfa`, a replay with that key answering the stored
 * response; the invitation mail captured by the test mail sink; conditional escalation of
 * `users_update` (`body.email` → `high`, a display-name change stays `low`); the selected-session
 * precondition of `users_revoke_session` (an unknown session id fails the proposal with `404`);
 * the department CAS injection and the changed-state refusal; the API key revocation card (name
 * and prefix, never the key); the api's last-administrator rule (`409`) surfacing as a failed
 * confirmation; no credential-pattern key in any confirmation, card or stored snapshot.
 *
 * Synthetic `it-*` organizations only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/users/invitations
// @covers patch /api/v1/users/:id
// @covers patch /api/v1/users/:id/status
// @covers put /api/v1/users/:id/roles
// @covers post /api/v1/users/:id/mfa/reset
// @covers delete /api/v1/users/:id
// @covers post /api/v1/users/:id/invitation
// @covers delete /api/v1/users/:id/sessions
// @covers delete /api/v1/users/:id/sessions/:sessionId
// @covers get /api/v1/users/:id
// @covers get /api/v1/users/:id/sessions
// @covers post /api/v1/roles
// @covers put /api/v1/roles/:key
// @covers delete /api/v1/roles/:key
// @covers get /api/v1/roles/:key
// @covers post /api/v1/departments
// @covers patch /api/v1/departments/:departmentId
// @covers delete /api/v1/departments/:departmentId
// @covers get /api/v1/departments/:departmentId
// @covers post /api/v1/departments/:departmentId/members
// @covers delete /api/v1/departments/:departmentId/members/:memberId
// @covers get /api/v1/api-keys/:id
// @covers delete /api/v1/api-keys/:id
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  auditByCorrelation,
  call,
  type ChatWrite,
  clearAssistantCounters,
  confirm,
  confirmationRow,
  createAssistantApp,
  credentialKeys,
  credentialKeysInResult,
  directive,
  enableAssistant,
  member,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  propose,
  proposeAndConfirm,
  reauthOf,
  type RecordedCall,
  resultCorrelationId,
  turn,
} from './support/assistant';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  uniqueSuffix,
} from './support/fixtures';
import { bearer, idem, login, type TokenResponseBody, uniqueIp } from './support/http';

const POLL = { timeout: 15_000, interval: 200 };
/** A stale row version the model "remembers"; the executor replaces it from the snapshot. */
const STALE = 999;

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let org: FixtureOrganization;
let admin: Member;

const tag = (): string => randomUUID().slice(0, 8);
const newEmail = (): string => `chat-${uniqueSuffix()}@example.test`;

const chat = (tool: string, args: Record<string, unknown>): Promise<ChatWrite> =>
  proposeAndConfirm(ctx, fx, admin, tool, args);

/** Asserts an executed confirmation with this HTTP status; returns the write's loopback call. */
function executed(result: ChatWrite, httpStatus: number): RecordedCall {
  expect(result.res.status, JSON.stringify(result.res.body)).toBe(200);
  expect(result.res.body.confirmation, JSON.stringify(result.res.body.confirmation)).toMatchObject({
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

/** The operation's own audit row carries the result execution's correlation id. */
async function operationAudited(result: ChatWrite, action: string) {
  const correlationId = await resultCorrelationId(ctx, result.res);
  const rows = (await auditByCorrelation(ctx, org.id, correlationId)).filter(
    (r) => r.action === action,
  );
  expect(rows, action).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(admin.user.publicId);
  return rows[0]!;
}

/** No credential-pattern key in the card, the summary or the stored snapshot (I14). */
async function credentialFree(result: ChatWrite): Promise<void> {
  expect(credentialKeys(result.proposal.confirmation)).toEqual([]);
  // The card's record parts (the execution view's own `errorCode` is part of its contract).
  expect(
    credentialKeysInResult(null, result.res.body.execution.card as Record<string, unknown> | null),
  ).toEqual([]);
  expect(credentialKeys(result.res.body.confirmation)).toEqual([]);
  const row = await confirmationRow(ctx, result.proposal.confirmation.id);
  // `roles[].key` is the snapshot's display field of the user's role keys (D6 "roles"): the
  // credential pattern (`key$`) matches its name, never a credential (reported, design §11).
  expect(
    credentialKeys(row.preconditions).filter((path) => !path.endsWith('.roles[].key')),
  ).toEqual([]);
  expect(credentialKeys(row.summary)).toEqual([]);
}

/** The stored request of a confirmation (method, path with the query, body). */
async function storedRequest(confirmationId: string) {
  const row = await confirmationRow(ctx, confirmationId);
  return row.request as { method: string; path: string; body: Record<string, unknown> | null };
}

const summaryText = (result: ChatWrite): string =>
  JSON.stringify(result.proposal.confirmation.summary);

const userRow = (user: { id: bigint }) =>
  ctx.prisma.user.findUniqueOrThrow({
    where: { id: user.id },
    include: { userRoles: { include: { role: { select: { key: true } } } } },
  });
const roleKeysOf = async (user: { id: bigint }): Promise<string[]> =>
  (await userRow(user)).userRoles.map((r) => r.role.key).sort();

async function sessionOf(user: FixtureUser): Promise<TokenResponseBody> {
  const res = await login(
    ctx,
    { email: user.email, password: user.password, organization: user.organization.slug },
    uniqueIp(),
  );
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body as TokenResponseBody;
}
const me = (accessToken: string) =>
  ctx.http.get('/api/v1/auth/me').set(bearer(accessToken)).set('X-Forwarded-For', uniqueIp());

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  org = await fx.createOrganization();
  fx.registerCleanup(() =>
    ctx.get(PolicyTenantDataRepository).purgeOrganization(systemScope(org.id)),
  );
  admin = await member(ctx, fx, org, ['organization_admin']);
  await enableAssistant(ctx, operator, org, admin);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
});

describe('users through chat (9 writes)', () => {
  let invitedEmail: string;
  let invitedId: string;

  it('users_invite (high, legacy idempotency): 401 without re-authentication, then invited', async () => {
    invitedEmail = newEmail();
    const proposal = await propose(
      ctx,
      admin,
      directive('users_invite', {
        body: {
          email: invitedEmail,
          displayName: 'Invited Through Chat',
          // Not security_analyst: it holds archive:search, which organization_admin lacks, so
          // the api accepts the invitation but refuses to manage the user afterwards (resend).
          roleKeys: ['domain_admin'],
        },
      }),
    );
    expect(proposal.confirmation).toMatchObject({
      tool: 'users_invite',
      risk: 'high',
      requiresReauth: true,
      reauthFresh: false,
      status: 'pending',
    });
    const summary = proposal.confirmation.summary!;
    expect(summary.title).toBe('Invite user');
    expect(JSON.stringify(summary.target)).toContain(invitedEmail);
    expect(JSON.stringify(summary.target)).toContain('domain_admin');
    expect(summary.warnings).toContain(
      'An invitation email is sent; the person gets these roles when they accept.',
    );
    expect(summary.reversible).toBe(false);

    // The first high-risk confirm of the session without re-authentication is refused; the
    // confirmation stays pending and nothing is sent.
    const refused = await confirm(ctx, admin, proposal);
    expect(refused.status).toBe(401);
    expect(refused.body.code).toBe('assistant_reauth_required');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
    expect(
      await ctx.prisma.user.count({ where: { organizationId: org.id, email: invitedEmail } }),
    ).toBe(0);

    const res = await confirm(ctx, admin, proposal, { reauth: await reauthOf(fx, admin) });
    const result: ChatWrite = { proposal, res, calls: [] };
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 201, error: null },
    });
    expect((await confirmationRow(ctx, proposal.confirmation.id)).reauthUsed).toBe(true);
    const invited = await ctx.prisma.user.findFirstOrThrow({
      where: { organizationId: org.id, email: invitedEmail },
      include: { userRoles: { include: { role: { select: { key: true } } } } },
    });
    invitedId = invited.publicId;
    expect(invited.status).toBe('invited');
    expect(invited.userRoles.map((r) => r.role.key)).toEqual(['domain_admin']);
    await expect.poll(() => ctx.emails.tokenFor(invitedEmail, 'invitation'), POLL).toBeDefined();
    const audit = await operationAudited(result, 'user.invited');
    expect(audit.resourceId).toBe(invitedId);
    await credentialFree(result);

    // Legacy idempotency: the confirmation id was the key; a replay answers the stored response.
    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: org.id, idempotencyKey: proposal.confirmation.id },
    });
    expect(stored.statusCode).toBe(201);
    const request = await storedRequest(proposal.confirmation.id);
    const replay = await call(ctx, admin.headers, 'post', request.path, request.body!).set(
      idem(proposal.confirmation.id),
    );
    expect(replay.status).toBe(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body.id).toBe(invitedId);
    expect(
      await ctx.prisma.user.count({ where: { organizationId: org.id, email: invitedEmail } }),
    ).toBe(1);
  });

  it('users_resend_invitation (medium, legacy idempotency): a new link is mailed', async () => {
    const first = ctx.emails.tokenFor(invitedEmail, 'invitation');
    const result = await chat('users_resend_invitation', { id: invitedId });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(result.proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    expect(result.res.body.confirmation, JSON.stringify(result.res.body)).toBeDefined();
    const write = executed(result, 202);
    expect(write).toMatchObject({
      method: 'POST',
      path: `/api/v1/users/${invitedId}/invitation`,
      idempotencyKey: result.proposal.confirmation.id,
    });
    await expect.poll(() => ctx.emails.tokenFor(invitedEmail, 'invitation'), POLL).not.toBe(first);
    await operationAudited(result, 'user.invitation_resent');
    await credentialFree(result);
    const replay = await call(ctx, admin.headers, 'post', write.path).set(
      idem(result.proposal.confirmation.id),
    );
    expect(replay.status).toBe(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
  });

  it('users_update: a display-name change is low; an email change escalates to high', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const renamed = await chat('users_update', {
      id: target.publicId,
      body: { displayName: 'Renamed In Chat' },
    });
    expect(renamed.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expect(executed(renamed, 200).idempotencyKey).toBeNull();
    expect((await userRow(target)).displayName).toBe('Renamed In Chat');
    await operationAudited(renamed, 'user.updated');
    // The display name (attacker-influenced) is marked untrusted in the card's target.
    const nameTarget = renamed.proposal.confirmation.summary!.target.find(
      (t) => t.value === target.displayName,
    );
    expect(nameTarget?.untrusted).toBe(true);

    const email = newEmail();
    const moved = await chat('users_update', { id: target.publicId, body: { email } });
    expect(moved.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(moved.proposal.confirmation.summary!.warnings).toContain(
      'Changing the email address sends sign-in, invitation and password-reset mail to the new address.',
    );
    executed(moved, 200);
    expect((await userRow(target)).email).toBe(email);
    await expect.poll(() => ctx.emails.tokenFor(email, 'email_verification'), POLL).toBeDefined();
    await operationAudited(moved, 'user.updated');
    // The stored risk is the effective risk; the audit row names the registry's base risk.
    expect((await confirmationRow(ctx, moved.proposal.confirmation.id)).risk).toBe('high');
    const requested = await ctx.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: org.id,
        action: 'assistant.confirmation_requested',
        resourceId: moved.proposal.confirmation.id,
      },
    });
    expect(requested.metadata).toMatchObject({ risk: 'high', baseRisk: 'low' });
    await credentialFree(moved);
  });

  it('users_replace_roles (high): added and removed roles on the card; audited from → to', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const result = await chat('users_replace_roles', {
      id: target.publicId,
      body: { roleKeys: ['compliance_auditor', 'read_only_user'] },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const changes = result.proposal.confirmation.summary!.changes;
    expect(changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: 'Roles added', after: 'compliance_auditor' }),
      ]),
    );
    executed(result, 200);
    expect(await roleKeysOf(target)).toEqual(['compliance_auditor', 'read_only_user']);
    const audit = await operationAudited(result, 'user.roles_changed');
    expect(audit.metadata).toMatchObject({
      from: ['read_only_user'],
      to: ['compliance_auditor', 'read_only_user'],
    });
    await credentialFree(result);
  });

  it('users_change_status (high): disabled, the user’s sessions stop working', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = await sessionOf(target);
    await me(session.accessToken).expect(200);
    const result = await chat('users_change_status', {
      id: target.publicId,
      body: { status: 'disabled', reason: 'Disabled in the chat suite' },
    });
    expect(result.proposal.confirmation.risk).toBe('high');
    expect(result.proposal.confirmation.summary!.title).toBe('Disable user');
    executed(result, 200);
    expect((await userRow(target)).status).toBe('disabled');
    await me(session.accessToken).expect(401);
    await operationAudited(result, 'user.status_changed');
    await credentialFree(result);
  });

  it('users_reset_mfa (high, legacy idempotency): MFA cleared, a replay answers the stored 204', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'], mfa: true });
    const result = await chat('users_reset_mfa', { id: target.publicId });
    expect(result.proposal.confirmation.risk).toBe('high');
    const write = executed(result, 204);
    expect(write).toMatchObject({
      path: `/api/v1/users/${target.publicId}/mfa/reset`,
      idempotencyKey: result.proposal.confirmation.id,
    });
    expect(await userRow(target)).toMatchObject({ mfaEnabled: false, mfaSecretCiphertext: null });
    await operationAudited(result, 'user.mfa_reset');
    await credentialFree(result);
    const replay = await call(ctx, admin.headers, 'post', write.path).set(
      idem(result.proposal.confirmation.id),
    );
    expect(replay.status).toBe(204);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: org.id, action: 'user.mfa_reset', resourceId: target.publicId },
      }),
    ).toBe(1);
  });

  it('users_revoke_session (high): the selected live session of another user; unknown id → 404', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const kept = await sessionOf(target);
    const revoked = await sessionOf(target);
    const result = await chat('users_revoke_session', {
      id: target.publicId,
      sessionId: revoked.sessionId,
    });
    expect(result.proposal.confirmation.risk).toBe('high');
    executed(result, 204);
    await me(revoked.accessToken).expect(401);
    await me(kept.accessToken).expect(200);
    const audit = await operationAudited(result, 'session.revoked');
    expect(audit.resourceId).toBe(revoked.sessionId);
    await credentialFree(result);

    // A session id the selected-item read does not list: the proposal fails like a 404 read.
    const conversation = await newConversation(ctx, admin);
    const res = await turn(
      ctx,
      admin.headers,
      conversation,
      directive('users_revoke_session', { id: target.publicId, sessionId: randomUUID() }),
    );
    expect(res.status).toBe(200);
    expect(res.body.executions[0]).toMatchObject({
      tool: 'users_revoke_session',
      decision: 'allowed',
      status: 'failed',
      httpStatus: 404,
    });
    expect(res.body.confirmations).toEqual([]);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: { conversation: { publicId: conversation } },
      }),
    ).toBe(0);
    await me(kept.accessToken).expect(200);
  });

  it('users_revoke_all_sessions (high): every session of the user ends', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const a = await sessionOf(target);
    const b = await sessionOf(target);
    const result = await chat('users_revoke_all_sessions', { id: target.publicId });
    expect(result.proposal.confirmation.risk).toBe('high');
    executed(result, 204);
    await me(a.accessToken).expect(401);
    await me(b.accessToken).expect(401);
    await operationAudited(result, 'session.revoked_all');
    await credentialFree(result);
  });

  it('users_remove (high): soft-deleted, sessions revoked', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = await sessionOf(target);
    const result = await chat('users_remove', { id: target.publicId });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(result.proposal.confirmation.summary!.reversible).toBe(false);
    executed(result, 204);
    expect((await userRow(target)).deletedAt).not.toBeNull();
    await me(session.accessToken).expect(401);
    await operationAudited(result, 'user.deleted');
    await credentialFree(result);
  });
});

describe('roles through chat (3 writes)', () => {
  const key = `it_chat_role_${tag()}`;

  it('roles_create (high): the custom role exists', async () => {
    const result = await chat('roles_create', {
      body: { key, name: 'Chat reviewer', permissions: ['message:read'] },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    executed(result, 201);
    const role = await ctx.prisma.role.findFirstOrThrow({
      where: { organizationId: org.id, key },
      include: { permissions: { include: { permission: { select: { key: true } } } } },
    });
    expect(role.isSystem).toBe(false);
    expect(role.permissions.map((p) => p.permission.key)).toEqual(['message:read']);
    await operationAudited(result, 'role.created');
    await credentialFree(result);
  });

  it('roles_update (high): the card lists the permission diff; holders get it', async () => {
    const result = await chat('roles_update', {
      key,
      body: { name: 'Chat reviewer', permissions: ['message:read', 'audit:read'] },
    });
    expect(result.proposal.confirmation.risk).toBe('high');
    expect(summaryText(result)).toContain('audit:read');
    expect(summaryText(result)).not.toContain('quarantine:release');
    executed(result, 200);
    const audit = await operationAudited(result, 'role.updated');
    expect(audit.metadata).toMatchObject({ added: ['audit:read'], removed: [] });
    await credentialFree(result);
  });

  it('roles_remove (high): the unassigned custom role is deleted', async () => {
    const result = await chat('roles_remove', { key });
    expect(result.proposal.confirmation.risk).toBe('high');
    executed(result, 204);
    expect(await ctx.prisma.role.count({ where: { organizationId: org.id, key } })).toBe(0);
    await operationAudited(result, 'role.deleted');
    await credentialFree(result);
  });
});

describe('departments through chat (5 writes)', () => {
  let departmentId: string;
  let memberId: string;
  let holder: FixtureUser;

  const departmentRow = () =>
    ctx.prisma.tenantDepartment.findFirstOrThrow({ where: { publicId: departmentId } });

  beforeAll(async () => {
    holder = await fx.createUser(org, { roles: ['read_only_user'] });
  });

  it('departments_create (low)', async () => {
    const name = `Chat Finance ${tag()}`;
    const result = await chat('departments_create', { body: { name } });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    executed(result, 201);
    const row = await ctx.prisma.tenantDepartment.findFirstOrThrow({
      where: { organizationId: org.id, name },
    });
    departmentId = row.publicId;
    expect(row.rowVersion).toBeGreaterThanOrEqual(1);
    await operationAudited(result, 'department.created');
  });

  it('departments_update (low): the stale expectedRowVersion is replaced from the snapshot', async () => {
    const before = await departmentRow();
    const result = await chat('departments_update', {
      departmentId,
      body: { description: 'Updated through chat', expectedRowVersion: STALE },
    });
    executed(result, 200);
    const request = await storedRequest(result.proposal.confirmation.id);
    expect(request.body!.expectedRowVersion).toBe(before.rowVersion);
    const after = await departmentRow();
    expect(after.description).toBe('Updated through chat');
    expect(after.rowVersion).toBe(before.rowVersion + 1);
    await operationAudited(result, 'department.updated');
  });

  it('departments_add_member (low) and departments_remove_member (medium)', async () => {
    const added = await chat('departments_add_member', {
      departmentId,
      body: { userId: holder.publicId },
    });
    expect(added.proposal.confirmation.risk).toBe('low');
    executed(added, 201);
    const row = await ctx.prisma.tenantDepartmentMember.findFirstOrThrow({
      where: { organizationId: org.id, userId: holder.id },
    });
    memberId = row.publicId;
    await operationAudited(added, 'department.member_added');

    const removed = await chat('departments_remove_member', { departmentId, memberId });
    expect(removed.proposal.confirmation.risk).toBe('medium');
    expect(removed.proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    executed(removed, 204);
    expect(await ctx.prisma.tenantDepartmentMember.count({ where: { publicId: memberId } })).toBe(
      0,
    );
    await operationAudited(removed, 'department.member_removed');
  });

  it('a department renamed through the api after the proposal is refused (state changed)', async () => {
    const before = await departmentRow();
    const proposal = await propose(
      ctx,
      admin,
      directive('departments_update', { departmentId, body: { name: `Chat Legal ${tag()}` } }),
    );
    const renamed = await call(ctx, admin.headers, 'patch', `/api/v1/departments/${departmentId}`, {
      name: `Renamed In Portal ${tag()}`,
      expectedRowVersion: before.rowVersion,
    });
    expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
    const res = await confirm(ctx, admin, proposal);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_state_changed');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('failed');
    expect((await departmentRow()).name).toMatch(/^Renamed In Portal /);
  });

  it('departments_remove (high): expectedRowVersion injected in the query', async () => {
    const before = await departmentRow();
    const result = await chat('departments_remove', { departmentId, expectedRowVersion: STALE });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const write = executed(result, 204);
    expect(write).toMatchObject({
      method: 'DELETE',
      path: `/api/v1/departments/${departmentId}?expectedRowVersion=${before.rowVersion}`,
    });
    expect(await ctx.prisma.tenantDepartment.count({ where: { publicId: departmentId } })).toBe(0);
    await operationAudited(result, 'department.deleted');
  });
});

describe('API keys through chat (1 write)', () => {
  it('api_keys_revoke (high): the card shows the key name and prefix, never the key', async () => {
    const name = `it chat key ${tag()}`;
    const created = await call(ctx, admin.headers, 'post', '/api/v1/api-keys', {
      name,
      scopes: ['user:read'],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const { apiKey, key } = created.body as {
      apiKey: { id: string; prefix: string };
      key: string;
    };
    const { id, prefix } = apiKey;
    const result = await chat('api_keys_revoke', { id });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const target = result.proposal.confirmation.summary!.target;
    expect(target).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: 'API key', value: name }),
        expect.objectContaining({ label: 'Prefix', value: prefix }),
      ]),
    );
    const traces = JSON.stringify(
      {
        proposal: result.proposal.res.body,
        confirm: result.res.body,
        row: await confirmationRow(ctx, result.proposal.confirmation.id),
      },
      (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    );
    expect(traces).not.toContain(key);
    executed(result, 204);
    const row = await ctx.prisma.apiKey.findFirstOrThrow({ where: { publicId: id } });
    expect(row.revokedAt).not.toBeNull();
    await operationAudited(result, 'apikey.revoked');
    await credentialFree(result);
    const refused = await ctx.http
      .get('/api/v1/users')
      .set({ 'X-API-Key': key })
      .set('X-Forwarded-For', uniqueIp());
    expect(refused.status).toBe(401);
  });
});

describe('the api’s last-administrator rule surfaces as a failed confirmation (R4)', () => {
  it('removing user:manage from the only administrating role → 409, nothing changes', async () => {
    const lone = await fx.createOrganization();
    fx.registerCleanup(() => clearAssistantCounters(ctx, [lone.id]));
    const permissions = [
      'assistant:use',
      'assistant:configure',
      'organization:read',
      'user:read',
      'user:manage',
      'role:read',
      'role:manage',
    ];
    const keeper = await memberWith(ctx, fx, lone, { permissions });
    await enableAssistant(ctx, operator, lone, keeper);
    const roleRow = await ctx.prisma.role.findFirstOrThrow({
      where: { organizationId: lone.id, isSystem: false },
    });
    const proposal = await propose(
      ctx,
      keeper,
      directive('roles_update', {
        key: roleRow.key,
        body: {
          name: roleRow.name,
          permissions: permissions.filter((p) => p !== 'user:manage'),
        },
      }),
    );
    expect(proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const res = await confirm(ctx, keeper, proposal, { reauth: await reauthOf(fx, keeper) });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 409 },
    });
    expect(res.body.execution).toMatchObject({ status: 'failed', httpStatus: 409 });
    const after = await ctx.prisma.role.findUniqueOrThrow({
      where: { id: roleRow.id },
      include: { permissions: { include: { permission: { select: { key: true } } } } },
    });
    expect(after.permissions.map((p) => p.permission.key)).toContain('user:manage');
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: lone.id, action: 'role.updated', resourceId: roleRow.key },
      }),
    ).toBe(0);
  });
});
