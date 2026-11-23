/**
 * Step AI-3 separation of duties in chat (docs/plan/steps/30-ai-chat-identity-tenant-admin.md
 * I12, I13, D2–D4, D10, §9 item 4 "separation of duties", items a–g) on the real stack: the api
 * on its ephemeral loopback port, real MySQL and Redis, the deterministic fake provider (never a
 * real LLM).
 *
 * (a) Every self-guarded tool called with the caller's own user id is `denied_guard` before any
 *     loopback request (not even the precondition read): no confirmation row, no operation audit
 *     row, an `assistant.tool_denied` audit row with metadata `guard`.
 * (b) The api refuses self-escalation: a user holding `user:manage` through a custom role (but
 *     not every permission of `organization_admin`) calls `PUT /users/{self}/roles` directly with
 *     `organization_admin` → `403`, roles unchanged.
 * (c) Through chat, that user proposes `users_replace_roles` on ANOTHER user to
 *     `organization_admin` (and `users_invite` with it) and confirms with re-authentication →
 *     the api's `403` surfaces as a failed confirmation; nothing changes.
 * (d) `roles_update` of a custom role the caller holds, adding a permission the caller lacks, and
 *     `roles_create` with such a permission → the api's `403`, failed confirmations.
 * (e) `roles_create` / `roles_update` adding or removing `assistant:configure` → `denied_guard`
 *     (an update that keeps it unchanged is a normal proposal).
 * (f) Every role and permission change needs re-authentication (`401
 *     assistant_reauth_required` without it); the session's window then applies.
 * (g) An escalated proposal (`webhooks_update` with `url`) cannot be confirmed without
 *     re-authentication, and a stored confirmation whose risk was lowered in the database is
 *     refused (`409`: the digest binds the risk, the confirm recomputes the effective risk).
 *
 * Synthetic `it-*` organizations only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers put /api/v1/users/:id/roles
// @covers post /api/v1/users/invitations
// @covers patch /api/v1/users/:id
// @covers patch /api/v1/users/:id/status
// @covers post /api/v1/users/:id/mfa/reset
// @covers delete /api/v1/users/:id
// @covers post /api/v1/users/:id/invitation
// @covers delete /api/v1/users/:id/sessions
// @covers delete /api/v1/users/:id/sessions/:sessionId
// @covers post /api/v1/roles
// @covers put /api/v1/roles/:key
// @covers delete /api/v1/roles/:key
// @covers patch /api/v1/webhooks/:webhookId
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  A,
  actionsByCorrelation,
  call,
  clearAssistantCounters,
  closeReauthWindow,
  confirm,
  confirmationRow,
  createAssistantApp,
  directive,
  enableAssistant,
  envelopesOf,
  executionRow,
  member,
  type Member,
  newConversation,
  operationAudit,
  platformMember,
  principalOf,
  propose,
  type Proposal,
  reauthOf,
  recordLoopback,
  requestsTo,
  secondSession,
  turn,
  writesTo,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { idem } from './support/http';
import { createBody, subscriptionRow, WEBHOOKS } from './support/webhooks';

const SELF_MESSAGE =
  'Changes to your own account, roles, status, MFA or sessions are not available in chat. Ask another administrator, or use your account pages in the portal.';
const CONFIGURE_MESSAGE =
  'The assistant cannot change who may configure it. Change roles that grant assistant:configure in the portal.';

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let org: FixtureOrganization;
let admin: Member;
/** `user:manage` through a custom role, without every permission of `organization_admin`. */
let manager: Member;
let managerRole: string;

const tag = (): string => randomUUID().slice(0, 8);

const roleKeysOf = async (userId: bigint): Promise<string[]> =>
  (
    await ctx.prisma.userRole.findMany({
      where: { userId },
      include: { role: { select: { key: true } } },
    })
  )
    .map((r) => r.role.key)
    .sort();

const rolePermissions = async (key: string): Promise<string[]> =>
  (
    await ctx.prisma.role.findFirstOrThrow({
      where: { organizationId: org.id, key },
      include: { permissions: { include: { permission: { select: { key: true } } } } },
    })
  ).permissions
    .map((p) => p.permission.key)
    .sort();

/** One directive turn of `who` in a new conversation: its only execution and the turn body. */
async function single(who: Member, tool: string, args: Record<string, unknown>) {
  const conversation = await newConversation(ctx, who);
  const res = await turn(ctx, who.headers, conversation, directive(tool, args));
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  expect(res.body.executions).toHaveLength(1);
  return { res, conversation, who, execution: res.body.executions[0] as Record<string, unknown> };
}

/** A `denied_guard` refusal: refused execution, no confirmation, the denial audited. */
async function expectGuardDenied(
  outcome: Awaited<ReturnType<typeof single>>,
  tool: string,
  guard: string,
  message: string,
): Promise<void> {
  expect(outcome.execution).toMatchObject({
    tool,
    access: 'write',
    decision: 'denied_guard',
    status: 'refused',
    httpStatus: null,
    errorCode: 'denied_guard',
    message,
    card: null,
  });
  // The stored conversation (reload, refetch) carries the same guard message and the tool's
  // display title, never the decision code alone (design 30 D12).
  const stored = await call(
    ctx,
    outcome.who.headers,
    'get',
    `${A}/conversations/${outcome.conversation}/messages`,
  );
  expect(stored.status).toBe(200);
  const storedExecution = (
    stored.body.data as Array<{ executions: Array<Record<string, unknown>> }>
  )
    .flatMap((m) => m.executions)
    .find((e) => e.id === outcome.execution.id);
  expect(storedExecution).toMatchObject({
    decision: 'denied_guard',
    errorCode: 'denied_guard',
    message,
    title: outcome.execution.title,
    card: null,
  });
  expect(storedExecution!.title).not.toBe(tool);
  expect(outcome.res.body.confirmations).toEqual([]);
  expect(
    await ctx.prisma.aiChatActionConfirmation.count({
      where: { conversation: { publicId: outcome.conversation } },
    }),
  ).toBe(0);
  const [envelope] = await envelopesOf(ctx, outcome.res.body.turn.id as string);
  expect(envelope!.parsed).toMatchObject({
    status: 'denied',
    decision: 'denied_guard',
    code: 'denied_guard',
    message,
  });
  const row = await executionRow(ctx, outcome.execution.id as string);
  expect(row.decision).toBe('denied_guard');
  const denied = await ctx.prisma.auditLog.findMany({
    where: { action: 'assistant.tool_denied', resourceId: outcome.execution.id as string },
  });
  expect(denied).toHaveLength(1);
  expect(denied[0]!.metadata).toMatchObject({ guard });
  expect(
    operationAudit(
      await ctx.prisma.auditLog.findMany({ where: { correlationId: row.correlationId } }),
    ),
  ).toEqual([]);
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ features: { webhooks: true } });
  admin = await member(ctx, fx, org, ['organization_admin']);
  await enableAssistant(ctx, operator, org, admin);
  managerRole = await fx.createCustomRole(org, [
    'assistant:use',
    'user:read',
    'user:manage',
    'role:read',
    'role:manage',
  ]);
  // read_only_user too: the manager holds every permission of a read-only target (target side).
  manager = await member(ctx, fx, org, [managerRole, 'read_only_user']);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
});

describe('(a) self-guarded tools with the caller’s own id are denied_guard (I12)', () => {
  it('refuses all 8 before any loopback request; nothing stored or changed', async () => {
    const self = admin.user.publicId;
    const sessionId = (await principalOf(ctx, admin.token)).sessionId;
    const cases: Array<[string, string, Record<string, unknown>]> = [
      ['users_update', '/api/v1/users/{id}', { id: self, body: { displayName: 'Me again' } }],
      [
        'users_change_status',
        '/api/v1/users/{id}/status',
        { id: self, body: { status: 'disabled', reason: 'Self service' } },
      ],
      [
        'users_replace_roles',
        '/api/v1/users/{id}/roles',
        // The caller's id in upper case: the compare is case-insensitive.
        { id: self.toUpperCase(), body: { roleKeys: ['organization_admin', 'read_only_user'] } },
      ],
      ['users_reset_mfa', '/api/v1/users/{id}/mfa/reset', { id: self }],
      ['users_remove', '/api/v1/users/{id}', { id: self }],
      ['users_revoke_all_sessions', '/api/v1/users/{id}/sessions', { id: self }],
      ['users_revoke_session', '/api/v1/users/{id}/sessions/{sessionId}', { id: self, sessionId }],
      ['users_resend_invitation', '/api/v1/users/{id}/invitation', { id: self }],
    ];
    const before = await ctx.prisma.user.findUniqueOrThrow({ where: { id: admin.user.id } });
    const rolesBefore = await roleKeysOf(admin.user.id);
    for (const [tool, template, args] of cases) {
      const recorder = recordLoopback(ctx);
      let outcome: Awaited<ReturnType<typeof single>>;
      try {
        outcome = await single(admin, tool, args);
      } finally {
        recorder.restore();
      }
      await expectGuardDenied(outcome, tool, 'not_self_user', SELF_MESSAGE);
      // Not even the precondition read (`GET /users/{id}`, `/sessions`): the turn's own
      // context read is the only loopback request.
      expect(requestsTo(recorder, template), tool).toEqual([]);
      expect(requestsTo(recorder, '/api/v1/users/{id}'), tool).toEqual([]);
      expect(
        recorder.calls.map((c) => c.path),
        tool,
      ).toEqual(['/api/v1/auth/me']);
    }
    const after = await ctx.prisma.user.findUniqueOrThrow({ where: { id: admin.user.id } });
    expect(after).toMatchObject({
      status: before.status,
      displayName: before.displayName,
      mfaEnabled: true,
      deletedAt: null,
    });
    expect(await roleKeysOf(admin.user.id)).toEqual(rolesBefore);
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: org.id,
          resourceId: admin.user.publicId,
          action: { startsWith: 'user.' },
        },
      }),
    ).toBe(0);
    // The caller's session is alive.
    expect((await call(ctx, admin.headers, 'get', '/api/v1/auth/me')).status).toBe(200);
  });
});

describe('(b)–(d) the api’s no-escalation rules stay the authority (I13)', () => {
  it('(b) refuses a direct self-escalation to organization_admin (403, roles unchanged)', async () => {
    const before = await roleKeysOf(manager.user.id);
    const res = await call(
      ctx,
      manager.headers,
      'put',
      `/api/v1/users/${manager.user.publicId}/roles`,
      { roleKeys: ['organization_admin'] },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(await roleKeysOf(manager.user.id)).toEqual(before);
  });

  it('(c) users_replace_roles and users_invite with organization_admin fail with the api’s 403', async () => {
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const promote = await propose(
      ctx,
      manager,
      directive('users_replace_roles', {
        id: target.publicId,
        body: { roleKeys: ['organization_admin'] },
      }),
    );
    expect(promote.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const refused = await confirm(ctx, manager, promote, { reauth: await reauthOf(fx, manager) });
    expect(refused.status, JSON.stringify(refused.body)).toBe(200);
    expect(refused.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 403 },
    });
    expect(refused.body.execution).toMatchObject({ status: 'failed', httpStatus: 403 });
    expect(await roleKeysOf(target.id)).toEqual(['read_only_user']);

    const email = `chat-escalation-${tag()}@example.test`;
    const invite = await propose(
      ctx,
      manager,
      directive('users_invite', {
        body: { email, displayName: 'Escalation', roleKeys: ['organization_admin'] },
      }),
    );
    const invited = await confirm(ctx, manager, invite);
    expect(invited.status, JSON.stringify(invited.body)).toBe(200);
    expect(invited.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 403 },
    });
    expect(await ctx.prisma.user.count({ where: { organizationId: org.id, email } })).toBe(0);
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: org.id,
          action: { in: ['user.roles_changed', 'user.invited'] },
          actorId: manager.user.publicId,
        },
      }),
    ).toBe(0);
  });

  it('(d) roles_update / roles_create with a permission the caller lacks fail with 403', async () => {
    const before = await rolePermissions(managerRole);
    const widen = await propose(
      ctx,
      manager,
      directive('roles_update', {
        key: managerRole,
        body: { name: 'Widened', permissions: [...before, 'policy:publish'] },
      }),
    );
    const widened = await confirm(ctx, manager, widen);
    expect(widened.status, JSON.stringify(widened.body)).toBe(200);
    expect(widened.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 403 },
    });
    expect(await rolePermissions(managerRole)).toEqual(before);

    const key = `it_sod_${tag()}`;
    const create = await propose(
      ctx,
      manager,
      directive('roles_create', {
        body: { key, name: 'Sneaky', permissions: ['user:read', 'policy:publish'] },
      }),
    );
    const created = await confirm(ctx, manager, create);
    expect(created.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 403 },
    });
    expect(await ctx.prisma.role.count({ where: { organizationId: org.id, key } })).toBe(0);
  });
});

describe('(e) the assistant cannot change who may configure it (A3-4)', () => {
  it('roles_create / roles_update adding or removing assistant:configure → denied_guard', async () => {
    const recorder = recordLoopback(ctx);
    try {
      const key = `it_cfg_${tag()}`;
      const created = await single(admin, 'roles_create', {
        body: { key, name: 'Configurers', permissions: ['assistant:configure', 'message:read'] },
      });
      await expectGuardDenied(created, 'roles_create', 'deny_permission_change', CONFIGURE_MESSAGE);
      expect(writesTo(recorder, '/api/v1/roles')).toEqual([]);
      expect(await ctx.prisma.role.count({ where: { organizationId: org.id, key } })).toBe(0);

      // Adding it to an existing role: the guard needs the role's current permissions (read).
      const plain = await fx.createCustomRole(org, ['message:read']);
      const added = await single(admin, 'roles_update', {
        key: plain,
        body: { name: 'Plain', permissions: ['message:read', 'assistant:configure'] },
      });
      await expectGuardDenied(added, 'roles_update', 'deny_permission_change', CONFIGURE_MESSAGE);
      // Removing it.
      const holding = await fx.createCustomRole(org, ['message:read', 'assistant:configure']);
      const removed = await single(admin, 'roles_update', {
        key: holding,
        body: { name: 'Holding', permissions: ['message:read'] },
      });
      await expectGuardDenied(removed, 'roles_update', 'deny_permission_change', CONFIGURE_MESSAGE);
      expect(writesTo(recorder, '/api/v1/roles/{key}')).toEqual([]);
      expect(await rolePermissions(plain)).toEqual(['message:read']);
      expect(await rolePermissions(holding)).toEqual(['assistant:configure', 'message:read']);

      // Keeping it unchanged is an ordinary (high) proposal.
      const kept = await propose(
        ctx,
        admin,
        directive('roles_update', {
          key: holding,
          body: {
            name: 'Holding',
            permissions: ['assistant:configure', 'audit:read', 'message:read'],
          },
        }),
      );
      expect(kept.confirmation).toMatchObject({ tool: 'roles_update', risk: 'high' });
      expect(writesTo(recorder, '/api/v1/roles/{key}')).toEqual([]);
    } finally {
      recorder.restore();
    }
  });
});

describe('(f) every role and permission change needs re-authentication', () => {
  it('401 assistant_reauth_required without it; the session’s window then applies', async () => {
    // A fresh sign-in: a new session family whose window is closed.
    const session = await secondSession(ctx, fx, admin);
    const target = await fx.createUser(org, { roles: ['read_only_user'] });
    const key = `it_reauth_${tag()}`;
    const proposals: Array<[string, Record<string, unknown>]> = [
      ['roles_create', { body: { key, name: 'Reauth', permissions: ['message:read'] } }],
      [
        'roles_update',
        { key, body: { name: 'Reauth', permissions: ['message:read', 'audit:read'] } },
      ],
      ['users_replace_roles', { id: target.publicId, body: { roleKeys: [key] } }],
      [
        'users_invite',
        {
          body: {
            email: `chat-reauth-${tag()}@example.test`,
            displayName: 'Reauth',
            roleKeys: ['read_only_user'],
          },
        },
      ],
    ];
    const pending: Proposal[] = [];
    let windowOpen = false;
    for (const [tool, args] of proposals) {
      const proposal = await propose(ctx, session, directive(tool, args));
      pending.push(proposal);
      expect(proposal.confirmation, tool).toMatchObject({
        tool,
        risk: 'high',
        requiresReauth: true,
        reauthFresh: windowOpen,
      });
      if (!windowOpen) {
        const refused = await confirm(ctx, session, proposal);
        expect(refused.status, tool).toBe(401);
        expect(refused.body.code).toBe('assistant_reauth_required');
        expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
        const done = await confirm(ctx, session, proposal, { reauth: await reauthOf(fx, session) });
        expect(done.status, JSON.stringify(done.body)).toBe(200);
        expect(done.body.confirmation.status, tool).toBe('executed');
        expect((await confirmationRow(ctx, proposal.confirmation.id)).reauthUsed).toBe(true);
        windowOpen = true;
      } else {
        // Within the window: no fields needed.
        const done = await confirm(ctx, session, proposal);
        expect(done.status, JSON.stringify(done.body)).toBe(200);
        expect(done.body.confirmation.status, tool).toBe('executed');
        expect((await confirmationRow(ctx, proposal.confirmation.id)).reauthUsed).toBe(false);
      }
    }
    expect(await roleKeysOf(target.id)).toEqual([key]);
    // The window is per session family: the admin's first session never re-authenticated here.
    await closeReauthWindow(ctx, admin);
    const other = await propose(
      ctx,
      admin,
      directive('roles_remove', { key: await fx.createCustomRole(org, ['message:read']) }),
    );
    expect(other.confirmation).toMatchObject({ risk: 'high', reauthFresh: false });
    const refused = await confirm(ctx, admin, other);
    expect(refused.status).toBe(401);
    expect(refused.body.code).toBe('assistant_reauth_required');
  });
});

describe('(g) escalated proposals and tampered risk', () => {
  let webhookId: string;

  beforeAll(async () => {
    const created = await call(ctx, admin.headers, 'post', WEBHOOKS, createBody()).set(idem());
    expect(created.status, JSON.stringify(created.body?.code)).toBe(201);
    webhookId = created.body.id as string;
  });

  it('webhooks_update with url is high: 401 without re-authentication; a lowered stored risk is refused', async () => {
    await closeReauthWindow(ctx, admin);
    const before = await subscriptionRow(ctx, webhookId);
    const rename = await propose(
      ctx,
      admin,
      directive('webhooks_update', {
        webhookId,
        body: { name: 'renamed only', expectedRowVersion: 1 },
      }),
    );
    expect(rename.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });

    const redirect = await propose(
      ctx,
      admin,
      directive('webhooks_update', {
        webhookId,
        body: { url: `https://elsewhere-${tag()}.webhooks-it.test/in`, expectedRowVersion: 1 },
      }),
    );
    expect(redirect.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(redirect.confirmation.summary!.warnings).toContain(
      "Sends this webhook's event data to a new address.",
    );
    const refused = await confirm(ctx, admin, redirect);
    expect(refused.status).toBe(401);
    expect(refused.body.code).toBe('assistant_reauth_required');

    // The stored risk lowered by SQL (a tampered row): the confirm refuses it, nothing is sent.
    await ctx.prisma.aiChatActionConfirmation.update({
      where: { publicId: redirect.confirmation.id },
      data: { risk: 'low', requiresReauth: false },
    });
    const recorder = recordLoopback(ctx);
    let tampered;
    try {
      tampered = await confirm(ctx, admin, redirect);
    } finally {
      recorder.restore();
    }
    expect(tampered.status, JSON.stringify(tampered.body)).toBe(409);
    expect([
      'assistant_confirmation_digest_mismatch',
      'assistant_confirmation_tool_changed',
    ]).toContain(tampered.body.code);
    expect(writesTo(recorder, '/api/v1/webhooks/{webhookId}')).toEqual([]);
    expect((await confirmationRow(ctx, redirect.confirmation.id)).status).toBe('failed');
    const after = await subscriptionRow(ctx, webhookId);
    expect(after).toMatchObject({
      url: before.url,
      rowVersion: before.rowVersion,
      name: before.name,
    });
    const correlated = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'webhook.updated', resourceId: webhookId },
    });
    expect(correlated).toHaveLength(0);
    // The rename (low) still confirms without re-authentication.
    const renamed = await confirm(ctx, admin, rename);
    expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
    expect(renamed.body.confirmation.status).toBe('executed');
    expect((await subscriptionRow(ctx, webhookId)).name).toBe('renamed only');
    expect(
      await actionsByCorrelation(
        ctx,
        (await executionRow(ctx, renamed.body.execution.id as string)).correlationId,
      ),
    ).toContain('webhook.updated');
  });
});
