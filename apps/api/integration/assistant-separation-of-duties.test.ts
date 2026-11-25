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
 * Step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md I18, D3, §9 item 3 points a–f),
 * ATO responses on an `it-ato-*` organization: (a) the requester asks to approve (the fake's
 * "approve the pending ato response" plan) or reject through chat → `denied_guard`
 * (`not_self_field`), no confirmation row, no request to the decision routes, no decision audit
 * row; (b) the api refuses the requester's direct approve / reject with an MFA session (`403
 * ato_approval_self`), status unchanged; (c) the requester's second session is refused the same
 * way; (d) a response requested by an API key the requester created → the creator is
 * `denied_guard` (`require_read_value` on the api's `canDecide`) and refused directly, another
 * responder approves through chat and it executes; (e) the response decided elsewhere between
 * the approver's proposal and confirm → the confirm is refused (`409` state changed or `403`),
 * nothing executes; (f) approve and rollback need re-authentication; (g) with the assistant's
 * four-eyes guards removed from the approve / reject specs (a simulated guard regression), the
 * requester's chat-confirmed decision reaches the api, which refuses it (`403
 * ato_approval_self`): the confirmation fails, the response stays `pending_approval`, no decision
 * audit row (I18: the api's refusal is the authority through chat as well as directly).
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
// @covers post /api/v1/ato/incidents/:incidentId/responses
// @covers post /api/v1/ato/responses/:responseId/approve
// @covers post /api/v1/ato/responses/:responseId/reject
// @covers post /api/v1/ato/responses/:responseId/cancel
// @covers post /api/v1/ato/responses/:responseId/rollback
import { randomUUID } from 'node:crypto';
import { confirmationSpecOf, GUARD_MESSAGES } from '@email-gateway/assistant';
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
  expectExecuted,
  member,
  type Member,
  newConversation,
  operationActionsOf,
  operationAudit,
  platformMember,
  principalOf,
  propose,
  proposeAndConfirm,
  type Proposal,
  reauthOf,
  recordLoopback,
  requestsTo,
  secondSession,
  turn,
  waitForRead,
  writesTo,
} from './support/assistant';
import {
  type AtoChat,
  atoChatTenant,
  decideDirectly,
  mailboxLabel,
  requestResponse,
  responseRow,
  responseVisible,
} from './support/assistant-ato';
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

// ---------------------------------------------------------------------------------------------
// Step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md I18, D3, R2, §9 item 3 points
// a–f): ATO responses keep four eyes in chat. The api's refusal (`ato_approval_self`) stays the
// authority; the assistant's guards refuse a requester's (or an API-key creator's) decision
// before anything is stored.
// ---------------------------------------------------------------------------------------------

describe('step AI-4: ATO responses keep four eyes in chat (I18)', () => {
  const FOUR_EYES = GUARD_MESSAGES.ato_four_eyes;
  const APPROVE = '/api/v1/ato/responses/{responseId}/approve';
  const REJECT = '/api/v1/ato/responses/{responseId}/reject';
  let ato: AtoChat;
  let requester: Member;
  let approver: Member;

  beforeAll(async () => {
    ato = await atoChatTenant(ctx, fx, operator);
    requester = ato.analystA;
    approver = ato.analystB;
  }, 240_000);

  afterAll(async () => {
    if (ctx && ato) await clearAssistantCounters(ctx, [ato.org.id]);
  });

  /** An open incident on a fresh synthetic mailbox account. */
  async function openIncident(): Promise<string> {
    const { incident } = await ato.seed.compromised(ato.org.id, mailboxLabel('sod'));
    await waitForRead(ctx, requester, `/api/v1/incidents/${incident.publicId}`);
    return incident.publicId;
  }

  /** The requester asks for `restrict_smtp_sending` through chat: the pending response id. */
  async function requestedThroughChat(): Promise<string> {
    const incidentId = await openIncident();
    const requested = await proposeAndConfirm(ctx, fx, requester, 'ato_responses_request', {
      incidentId,
      body: {
        actionType: 'restrict_smtp_sending',
        durationMinutes: 60,
        reason: 'Outbound burst after impossible travel',
      },
    });
    expectExecuted(requested, 201);
    const row = await ctx.prisma.atoResponseAction.findFirstOrThrow({
      where: { organizationId: ato.org.id, incident: { publicId: incidentId } },
    });
    expect(row.status).toBe('pending_approval');
    await responseVisible(ctx, approver, row.publicId, 'pending_approval');
    return row.publicId;
  }

  const decisionAudits = (responseId: string) =>
    ctx.prisma.auditLog.count({
      where: {
        organizationId: ato.org.id,
        resourceId: responseId,
        action: { in: ['ato.response_approved', 'ato.response_rejected'] },
      },
    });

  it('(a) the requester asks to approve (the fake plan) or reject (directive): denied_guard, nothing reaches the decision routes', async () => {
    const responseId = await requestedThroughChat();
    await waitForRead(
      ctx,
      requester,
      '/api/v1/ato/responses?status=pending_approval&limit=1',
      (b) => (b.data as Array<{ id: string }>)[0]?.id === responseId,
    );
    const recorder = recordLoopback(ctx);
    let planned;
    let rejected;
    try {
      const conversation = await newConversation(ctx, requester);
      planned = await turn(
        ctx,
        requester.headers,
        conversation,
        'approve the pending ato response',
      );
      rejected = await single(requester, 'ato_responses_reject', {
        responseId,
        body: { reason: 'I asked for it, so I reject it' },
      });
    } finally {
      recorder.restore();
    }
    expect(planned.status, JSON.stringify(planned.body)).toBe(200);
    const [list, approve] = planned.body.executions as Array<Record<string, unknown>>;
    expect(list).toMatchObject({ tool: 'ato_responses_list', status: 'succeeded' });
    expect(approve).toMatchObject({
      tool: 'ato_responses_approve',
      decision: 'denied_guard',
      status: 'refused',
      errorCode: 'denied_guard',
      message: FOUR_EYES,
      card: null,
    });
    expect(planned.body.confirmations).toEqual([]);
    const denied = await ctx.prisma.auditLog.findMany({
      where: { action: 'assistant.tool_denied', resourceId: approve!.id as string },
    });
    expect(denied[0]!.metadata).toMatchObject({ guard: 'not_self_field' });
    await expectGuardDenied(rejected, 'ato_responses_reject', 'not_self_field', FOUR_EYES);
    // Only the precondition reads ran (after-read guards); no decision request was sent.
    expect(requestsTo(recorder, APPROVE)).toEqual([]);
    expect(requestsTo(recorder, REJECT)).toEqual([]);
    expect(await decisionAudits(responseId)).toBe(0);
    expect((await responseRow(ctx, responseId)).status).toBe('pending_approval');
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: {
          organizationId: ato.org.id,
          userId: requester.user.id,
          toolName: { in: ['ato_responses_approve', 'ato_responses_reject'] },
        },
      }),
    ).toBe(0);
  });

  it('(b) the api refuses a direct self-approval with an MFA session (403), status unchanged', async () => {
    const responseId = await requestedThroughChat();
    for (const verb of ['approve', 'reject'] as const) {
      const res = await decideDirectly(ctx, requester.headers, responseId, verb, {
        reason: 'Deciding my own request',
      });
      expect(res.status, JSON.stringify(res.body)).toBe(403);
      expect(res.body.code).toBe('ato_approval_self');
    }
    expect((await responseRow(ctx, responseId)).status).toBe('pending_approval');
    expect(await decisionAudits(responseId)).toBe(0);
  });

  it('(c) the requester’s second session is refused the same way (the guard is by user, not session)', async () => {
    const responseId = await requestedThroughChat();
    const other = await secondSession(ctx, fx, requester);
    const outcome = await single(other, 'ato_responses_approve', {
      responseId,
      body: { reason: 'From my other browser' },
    });
    await expectGuardDenied(outcome, 'ato_responses_approve', 'not_self_field', FOUR_EYES);
    expect((await responseRow(ctx, responseId)).status).toBe('pending_approval');
  });

  it('(d) a response requested by an API key the requester created: the creator is refused in chat and directly; another responder approves', async () => {
    const incidentId = await openIncident();
    const key = {
      'X-API-Key': await fx.createApiKey(ato.org, ['ato:read', 'ato:respond'], {
        createdBy: requester.user,
      }),
    };
    const requested = await requestResponse(ctx, key, incidentId, {
      actionType: 'restrict_smtp_sending',
      durationMinutes: 60,
      reason: 'Requested by automation',
    });
    expect(requested.status, JSON.stringify(requested.body)).toBe(201);
    expect(requested.body).toMatchObject({
      status: 'pending_approval',
      requestedBy: { type: 'api_key' },
    });
    const responseId = requested.body.id as string;
    await responseVisible(ctx, requester, responseId, 'pending_approval');

    const outcome = await single(requester, 'ato_responses_approve', {
      responseId,
      body: { reason: 'My key asked for it' },
    });
    await expectGuardDenied(outcome, 'ato_responses_approve', 'require_read_value', FOUR_EYES);
    const direct = await decideDirectly(ctx, requester.headers, responseId, 'approve', {
      reason: 'My key asked for it',
    });
    expect(direct.status).toBe(403);
    expect(direct.body.code).toBe('ato_approval_self');

    const approved = await proposeAndConfirm(ctx, fx, approver, 'ato_responses_approve', {
      responseId,
      body: { reason: 'Second pair of eyes' },
    });
    expectExecuted(approved, 200);
    expect(await responseRow(ctx, responseId)).toMatchObject({ status: 'succeeded' });
    expect(await operationActionsOf(ctx, approved.res)).toContain('ato.response_approved');
    // Lifted again (the restriction must not outlive the test).
    const lifted = await decideDirectly(ctx, approver.headers, responseId, 'rollback', {
      reason: 'Test cleanup: lift it',
    });
    expect(lifted.status, JSON.stringify(lifted.body)).toBe(200);
  });

  it('(e) decided elsewhere between proposal and confirm: the approver’s confirm is refused, nothing executes', async () => {
    const responseId = await requestedThroughChat();
    const proposal = await propose(
      ctx,
      approver,
      directive('ato_responses_approve', { responseId, body: { reason: 'Looks right' } }),
    );
    expect(proposal.confirmation).toMatchObject({ risk: 'high', status: 'pending' });
    const cancelled = await decideDirectly(ctx, requester.headers, responseId, 'cancel', {
      reason: 'Handled by phone instead',
    });
    expect(cancelled.status, JSON.stringify(cancelled.body)).toBe(200);
    await responseVisible(ctx, approver, responseId, 'cancelled');
    const recorder = recordLoopback(ctx);
    let res;
    try {
      res = await confirm(ctx, approver, proposal, { reauth: await reauthOf(fx, approver) });
    } finally {
      recorder.restore();
    }
    expect([403, 409]).toContain(res.status);
    expect(['assistant_action_not_allowed', 'assistant_confirmation_state_changed']).toContain(
      res.body.code,
    );
    expect(writesTo(recorder, APPROVE)).toEqual([]);
    expect((await responseRow(ctx, responseId)).status).toBe('cancelled');
    expect(await decisionAudits(responseId)).toBe(0);
  });

  it('(f) approve and rollback need re-authentication (401 assistant_reauth_required without it)', async () => {
    const responseId = await requestedThroughChat();
    await closeReauthWindow(ctx, approver);
    const approve = await propose(
      ctx,
      approver,
      directive('ato_responses_approve', { responseId, body: { reason: 'Confirmed by phone' } }),
    );
    expect(approve.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const refused = await confirm(ctx, approver, approve);
    expect(refused.status).toBe(401);
    expect(refused.body.code).toBe('assistant_reauth_required');
    expect((await responseRow(ctx, responseId)).status).toBe('pending_approval');
    const approved = await confirm(ctx, approver, approve, {
      reauth: await reauthOf(fx, approver),
    });
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body.confirmation.status).toBe('executed');
    expect((await responseRow(ctx, responseId)).status).toBe('succeeded');

    await closeReauthWindow(ctx, approver);
    await responseVisible(ctx, approver, responseId, 'succeeded');
    const rollback = await propose(
      ctx,
      approver,
      directive('ato_responses_rollback', { responseId, body: { reason: 'Lift it again' } }),
    );
    expect(rollback.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const unauthenticated = await confirm(ctx, approver, rollback);
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.body.code).toBe('assistant_reauth_required');
    expect((await responseRow(ctx, responseId)).status).toBe('succeeded');
    const lifted = await confirm(ctx, approver, rollback, { reauth: await reauthOf(fx, approver) });
    expect(lifted.status, JSON.stringify(lifted.body)).toBe(200);
    expect((await responseRow(ctx, responseId)).status).toBe('rolled_back');
  });
  it('(g) guards regressed: the requester’s chat-confirmed approve / reject reaches the api and is refused (403 ato_approval_self)', async () => {
    const responseId = await requestedThroughChat();
    // Simulate a regression of the assistant's guards (both are registry-driven): the api and
    // this suite share the package's spec objects, so removing `guards` disables them for the
    // proposal and for the confirm-time re-check. Restored in `finally`.
    const specs = ['AtoResponsesController_approve_v1', 'AtoResponsesController_reject_v1'].map(
      (operationId) => confirmationSpecOf(operationId) as { guards?: unknown },
    );
    const saved = specs.map((spec) => spec.guards);
    expect(saved.every((guards) => Array.isArray(guards) && guards.length > 0)).toBe(true);
    const recorder = recordLoopback(ctx);
    const outcomes: Array<{ verb: string; res: Awaited<ReturnType<typeof confirm>> }> = [];
    try {
      for (const spec of specs) delete spec.guards;
      for (const [tool, verb] of [
        ['ato_responses_approve', 'approve'],
        ['ato_responses_reject', 'reject'],
      ] as const) {
        const proposal = await propose(
          ctx,
          requester,
          directive(tool, { responseId, body: { reason: 'Deciding my own request' } }),
        );
        expect(proposal.confirmation).toMatchObject({ tool, status: 'pending' });
        outcomes.push({
          verb,
          res: await confirm(ctx, requester, proposal, {
            reauth: await reauthOf(fx, requester),
          }),
        });
      }
    } finally {
      specs.forEach((spec, i) => (spec.guards = saved[i]));
      recorder.restore();
    }
    for (const { verb, res } of outcomes) {
      expect(res.status, `${verb}: ${JSON.stringify(res.body)}`).toBe(200);
      expect(res.body.confirmation).toMatchObject({
        status: 'failed',
        result: { httpStatus: 403, error: 'ato_approval_self' },
      });
      expect(res.body.execution).toMatchObject({ status: 'failed', httpStatus: 403 });
      const row = await confirmationRow(ctx, res.body.confirmation.id as string);
      expect(row.status).toBe('failed');
    }
    // The requests really reached the api's decision routes (one each), and it refused them.
    expect(writesTo(recorder, APPROVE)).toHaveLength(1);
    expect(writesTo(recorder, REJECT)).toHaveLength(1);
    expect((await responseRow(ctx, responseId)).status).toBe('pending_approval');
    expect(await decisionAudits(responseId)).toBe(0);
    // The guards are back: the same request is denied before anything is stored.
    const after = await single(requester, 'ato_responses_approve', {
      responseId,
      body: { reason: 'Deciding my own request' },
    });
    await expectGuardDenied(after, 'ato_responses_approve', 'not_self_field', FOUR_EYES);
  });
});
