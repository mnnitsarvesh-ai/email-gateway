import {
  actionDigest,
  AI5_ESCALATION_WARNINGS,
  buildActionUpdates,
  type ConfirmationSpec,
  confirmationSpecOf,
  findTool,
  GUARD_MESSAGES,
  IMPACT_TOKEN_PLACEHOLDER,
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
import {
  digestInputOf,
  parseStoredPreconditions,
  parseStoredRequest,
} from '../domain/confirmation-binding';
import { ownerOf } from './conversation.service';
import type { ReadCall } from './confirmation-proposer.service';
import type { LoopbackCall, LoopbackResult } from './loopback-client';
import { actionUpdatesOf } from './turn-engine.service';
import type { ExecutionContext, ExecutionOutcome } from './tool-executor.service';

/**
 * Step AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md §9 item 2, WP4) at the service
 * level: snapshot-aware effective risk at proposal and confirm (D3), the server-filled impact
 * token from an allow-listed preview (D5), omitted inputs (D7), the new guards and the queued
 * outcome wording (D4, D11). In-memory doubles, the fake loopback, synthetic ids only.
 */

const POLICY = '0193c500-0000-7000-8000-000000000001';
const CONNECTION = '0193c500-0000-7000-8000-000000000002';
const DOMAIN = '0193c500-0000-7000-8000-000000000003';
const SOURCE = '0193c500-0000-7000-8000-000000000004';
const CASE = '0193c500-0000-7000-8000-000000000005';
const SEARCH = '0193c500-0000-7000-8000-000000000006';
const EXPORT = '0193c500-0000-7000-8000-000000000007';
const CONNECTOR = '0193c500-0000-7000-8000-000000000008';
const AUTH = { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' };
const REAUTH = { reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } };
/** Synthetic impact tokens of the fake preview (never secret-shaped). */
const TOKEN_A = 'it-impact-token-a-0001';
const TOKEN_B = 'it-impact-token-b-0002';
const MODEL_TOKEN = 'it-model-chosen-token';

const TOOLS = [
  'archive_retention_get',
  'archive_retention_update',
  'archive_retention_delete',
  'provider_connections_get',
  'provider_mail_flow_preview',
  'provider_mail_flow_apply',
  'provider_connections_disconnect',
  'provider_grants_verify',
  'intake_sources_get',
  'ediscovery_searches_get',
  'ediscovery_exports_create',
] as const;

const permissionsOf = (names: readonly string[]): string[] => [
  'assistant:use',
  ...new Set(
    names.flatMap((name) => {
      const requirement = findTool(name)!.requirement;
      return requirement.mode === 'authenticated' ? [] : requirement.permissions;
    }),
  ),
];

const admin = (overrides: Partial<UserPrincipal> = {}): UserPrincipal =>
  testUser({ permissions: new Set(permissionsOf(TOOLS)), ...overrides });

const routeOf = (name: string, params: Record<string, string> = {}): string => {
  const tool = findTool(name)!;
  return `${tool.method} ${tool.pathTemplate.replace(/\{(\w+)\}/g, (_m, key: string) => params[key]!)}`;
};

const ok = (body: unknown, status = 200): LoopbackResult => ({
  kind: 'response',
  status,
  body: structuredClone(body),
});

const json = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

const CRITERIA = { directions: ['inbound', 'outbound'], categories: ['delivered'] };

/** The change set of a mail-flow preview (`host` varies it). */
const changeSetOf = (host: string) => ({
  kind: 'inbound',
  domains: [
    {
      domainId: DOMAIN,
      name: 'contoso.example',
      current: { provider: 'custom', servers: [] },
      proposed: {
        provider: 'microsoft_365',
        servers: [{ host, port: 25, priority: 0, tlsMode: 'required' }],
      },
      changed: true,
    },
  ],
  connector: null,
  connection: [],
  grantsRevoked: 0,
});

function setup(user: UserPrincipal = admin()) {
  const h = createAssistantHarness({}, undefined, user);
  h.world.enable(user.organizationId);
  const scope = scopeFromPrincipal(user);
  const owner = ownerOf(user, scope);
  const conversation = h.world.addConversation(owner);
  const writes: LoopbackCall[] = [];
  const previews: LoopbackCall[] = [];
  const policy = {
    id: POLICY,
    name: 'Finance mail',
    retentionDays: 365,
    onExpiry: 'review',
    priority: 50,
    criteria: structuredClone(CRITERIA),
    isDefault: false,
    rowVersion: 4,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
  h.loopback.on(routeOf('archive_retention_get', { policyId: POLICY }), () => ok(policy));
  for (const name of ['archive_retention_update', 'archive_retention_delete']) {
    h.loopback.on(routeOf(name, { policyId: POLICY }), (call) => {
      writes.push(call);
      return name === 'archive_retention_delete' ? ok(null, 204) : ok({ ...policy, rowVersion: 5 });
    });
  }
  const connection = {
    id: CONNECTION,
    provider: 'microsoft_365',
    displayName: 'Contoso',
    status: 'active',
    outboundMode: 'active',
    internalRouting: true,
    health: 'healthy',
    grants: [{ id: CONNECTOR, profile: 'mail_flow', status: 'active', authMethod: 'platform_app' }],
    domains: [{ id: DOMAIN, name: 'contoso.example', providerVerification: 'verified' }],
    rowVersion: 5,
  };
  h.loopback.on(routeOf('provider_connections_get', { id: CONNECTION }), () => ok(connection));
  /** The preview's answer (per test); every call is recorded. */
  let preview: (call: LoopbackCall) => LoopbackResult = (call) => {
    const change = (call.body as { change: { kind: string } }).change;
    return ok({
      change,
      changeSet:
        change.kind === 'disable'
          ? {
              kind: 'disable',
              domains: [],
              connector: { action: 'disable', id: CONNECTOR },
              connection: [{ field: 'status', from: 'active', to: 'disabled' }],
              grantsRevoked: 1,
            }
          : changeSetOf('contoso-example.mail.protection.example'),
      impactToken: previews.length === 1 ? TOKEN_A : TOKEN_B,
      expiresAt: '2026-11-25T12:15:00.000Z',
      warnings: [],
    });
  };
  h.loopback.on(routeOf('provider_mail_flow_preview', { id: CONNECTION }), (call) => {
    previews.push(call);
    return preview(call);
  });
  h.loopback.on(routeOf('provider_mail_flow_apply', { id: CONNECTION }), (call) => {
    writes.push(call);
    return ok({ id: CONNECTION, status: 'active', rowVersion: 6 });
  });
  h.loopback.on(routeOf('provider_connections_disconnect', { id: CONNECTION }), (call) => {
    writes.push(call);
    return ok({ ...connection, status: 'disabled', rowVersion: 6 });
  });
  const search = {
    id: SEARCH,
    caseId: CASE,
    status: 'completed',
    hitCount: 12,
    truncated: false,
    indexComplete: true,
    incompleteReason: null,
  };
  h.loopback.on(routeOf('ediscovery_searches_get', { caseId: CASE, searchId: SEARCH }), () =>
    ok(search),
  );
  h.loopback.on(routeOf('ediscovery_exports_create', { caseId: CASE }), (call) => {
    writes.push(call);
    return ok({ id: EXPORT, caseId: CASE, searchId: SEARCH, status: 'queued' }, 202);
  });
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
    correlationBase: 'it-corr-ai5',
    signal: new AbortController().signal,
    allocateSeq: nextSeq,
  });
  const call = (name: string, args: Record<string, unknown>) =>
    h.executor.execute(ctx(), { name, arguments: args }, 0);
  const confirm = (
    outcome: ExecutionOutcome,
    extra: Partial<{ reauth: { password: string; totpCode?: string }; actionDigest: string }> = {},
  ) =>
    h.confirmations.confirm(
      user,
      scope,
      outcome.confirmation!.view.id,
      {
        token: outcome.confirmation!.token,
        actionDigest: outcome.confirmation!.view.actionDigest,
        ...extra,
      },
      AUTH,
    );
  const row = (outcome: ExecutionOutcome): StoredConfirmation =>
    h.world.confirmations.find((k) => k.publicId === outcome.confirmation!.view.id)!;
  /** Re-signs a (tampered) row so that only the later checks can catch the change. */
  const resign = (outcome: ExecutionOutcome): string => {
    const stored = row(outcome);
    stored.actionDigest = actionDigest(
      digestInputOf({
        confirmationId: stored.publicId,
        organizationPublicId: user.organizationPublicId,
        userPublicId: user.userPublicId,
        sessionFamilyId: stored.sessionFamilyId,
        overrideId: null,
        conversationId: conversation.publicId,
        executionId: outcome.executionId,
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
  return {
    h,
    user,
    scope,
    owner,
    conversation,
    writes,
    previews,
    policy,
    connection,
    setPreview: (fn: (call: LoopbackCall) => LoopbackResult) => {
      preview = fn;
    },
    call,
    confirm,
    row,
    resign,
  };
}

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

function captureLogs(): string[] {
  const lines: string[] = [];
  for (const level of ['log', 'warn', 'error', 'debug', 'verbose'] as const) {
    vi.spyOn(Logger.prototype, level).mockImplementation((...args: unknown[]) => {
      lines.push(json(args));
    });
  }
  return lines;
}

afterEach(() => {
  vi.restoreAllMocks();
});

const retentionArgs = (body: Record<string, unknown>) => ({
  policyId: POLICY,
  body: { name: 'Finance mail', onExpiry: 'review', priority: 50, criteria: CRITERIA, ...body },
});

describe('snapshot-aware effective risk (D3): archive_retention_update', () => {
  it('shortening retention at proposal → high with the warning and re-authentication', async () => {
    const t = setup();
    const out = await t.call('archive_retention_update', retentionArgs({ retentionDays: 30 }));
    expect(out.status).toBe('pending_confirmation');
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(out.confirmation!.view.summary!.warnings).toContain(
      AI5_ESCALATION_WARNINGS.retentionShortened,
    );
    // The CAS field is the read's row version; the stored snapshot holds the compared fields.
    const stored = t.row(out);
    expect((stored.request as { body: Record<string, unknown> }).body).toMatchObject({
      retentionDays: 30,
      expectedRowVersion: 4,
    });
    expect((stored.preconditions as { snapshot: Record<string, unknown> }).snapshot).toMatchObject({
      retentionDays: 365,
      onExpiry: 'review',
      priority: 50,
      isDefault: false,
    });
    expect(
      t.h.audit.entries.find((e) => e.action === 'assistant.confirmation_requested')!.metadata,
    ).toMatchObject({ risk: 'high', baseRisk: 'medium' });
    expect(t.writes).toHaveLength(0);
    // Confirm: re-authentication required, then executed.
    expect((await coded(t.confirm(out))).code).toBe('assistant_reauth_required');
    const done = await t.confirm(out, REAUTH);
    expect(done.confirmation).toMatchObject({ status: 'executed', result: { httpStatus: 200 } });
    expect(t.writes).toHaveLength(1);
  });

  it('a longer retention with the read’s other fields stays medium (the snapshot is compared, not ignored)', async () => {
    const t = setup();
    const out = await t.call('archive_retention_update', retentionArgs({ retentionDays: 400 }));
    expect(out.confirmation!.view).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(out.confirmation!.view.summary!.warnings ?? []).not.toContain(
      AI5_ESCALATION_WARNINGS.retentionShortened,
    );
    // Confirm recomputes from the STORED snapshot: equal risk → executed without re-auth.
    const done = await t.confirm(out);
    expect(done.confirmation).toMatchObject({ status: 'executed' });
    expect(t.writes).toHaveLength(1);
  });

  it('onExpiry review → delete and a criteria change escalate; omitted fields count as the PUT defaults', async () => {
    const t = setup();
    const toDelete = await t.call(
      'archive_retention_update',
      retentionArgs({ retentionDays: 365, onExpiry: 'delete' }),
    );
    expect(toDelete.confirmation!.view.risk).toBe('high');
    expect(toDelete.confirmation!.view.summary!.warnings).toContain(
      AI5_ESCALATION_WARNINGS.expiryDelete,
    );
    // Only name and days: onExpiry → delete (default), criteria → {} (default), priority → 100.
    const bare = await t.call('archive_retention_update', {
      policyId: POLICY,
      body: { name: 'Finance mail', retentionDays: 365 },
    });
    expect(bare.confirmation!.view.risk).toBe('high');
    expect(bare.confirmation!.view.summary!.warnings).toEqual(
      expect.arrayContaining([
        AI5_ESCALATION_WARNINGS.expiryDelete,
        AI5_ESCALATION_WARNINGS.retentionScope,
      ]),
    );
  });

  it('a tampered stored risk (re-signed) → 409 tool_changed at confirm, nothing written', async () => {
    const t = setup();
    const out = await t.call('archive_retention_update', retentionArgs({ retentionDays: 30 }));
    const stored = t.row(out);
    stored.risk = 'medium';
    stored.requiresReauth = false;
    const digest = t.resign(out);
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

  it('confirm recomputes from the stored snapshot: a re-signed snapshot that no longer shortens → 409 tool_changed', async () => {
    const t = setup();
    const out = await t.call('archive_retention_update', retentionArgs({ retentionDays: 30 }));
    const stored = t.row(out);
    // The stored risk stays high; with the stored snapshot at 10 days, 30 days is no shortening.
    (stored.preconditions as { snapshot: Record<string, unknown> }).snapshot.retentionDays = 10;
    const digest = t.resign(out);
    expect(await coded(t.confirm(out, { actionDigest: digest, ...REAUTH }))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_tool_changed',
    });
    expect(t.writes).toHaveLength(0);
  });

  it('a retention change between proposal and confirm → 409 state_changed (the compared field is a state field)', async () => {
    const t = setup();
    const out = await t.call('archive_retention_update', retentionArgs({ retentionDays: 400 }));
    expect(out.confirmation!.view.risk).toBe('medium');
    // Another administrator raised the retention to 500 days: 400 now shortens it.
    t.policy.retentionDays = 500;
    expect(await coded(t.confirm(out))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.writes).toHaveLength(0);
  });

  it('the default policy cannot be deleted: denied_guard with the D4 message, no confirmation', async () => {
    const t = setup();
    t.policy.isDefault = true;
    const out = await t.call('archive_retention_delete', { policyId: POLICY });
    expect(out).toMatchObject({
      decision: 'denied_guard',
      confirmation: null,
      denialMessage: GUARD_MESSAGES.retention_default_policy,
    });
    expect((await t.h.executions.get(t.user, t.scope, out.executionId)).message).toBe(
      GUARD_MESSAGES.retention_default_policy,
    );
    expect(t.h.world.confirmations).toHaveLength(0);
    expect(t.writes).toHaveLength(0);
  });
});

describe('server-filled impact token (D5): provider_mail_flow_apply and disconnect', () => {
  const CHANGE = { kind: 'inbound', domainIds: [DOMAIN] };

  it('proposal: GET read, then POST preview { change } with the caller’s credential; token injected over the model’s', async () => {
    const logs = captureLogs();
    const t = setup();
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE, impactToken: MODEL_TOKEN, confirm: true },
    });
    expect(out.status).toBe('pending_confirmation');
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    // The read, then the preview: internal calls (no execution id), the proposing user's token.
    const sent = t.h.loopback.calls
      .filter((c) => c.path.startsWith('/api/v1/provider-connections'))
      .map((c) => `${c.method} ${c.path}`);
    expect(sent).toEqual([
      routeOf('provider_connections_get', { id: CONNECTION }),
      routeOf('provider_mail_flow_preview', { id: CONNECTION }),
    ]);
    expect(t.previews).toHaveLength(1);
    const preview = t.previews[0]!;
    expect(preview.body).toEqual({ change: CHANGE });
    expect(preview).toMatchObject({
      method: 'POST',
      authorization: AUTH.authorization,
      clientIp: AUTH.clientIp,
      executionId: null,
    });
    expect(preview.correlationId).toMatch(/^it-corr-ai5/);
    expect(preview.readPrimary).toBeUndefined();
    // The stored request carries the server's token and `confirm: true`, never the model's.
    const stored = t.row(out);
    expect((stored.request as { body: unknown }).body).toEqual({
      change: CHANGE,
      impactToken: TOKEN_A,
      confirm: true,
    });
    // The snapshot holds the change set (merged under `preview`), never the token.
    const snapshot = (stored.preconditions as { snapshot: Record<string, unknown> }).snapshot;
    expect(snapshot['preview.changeSet.kind']).toBe('inbound');
    expect(snapshot['preview.changeSet.domains[].name']).toBe('["contoso.example"]');
    expect(t.writes).toHaveLength(0);
    // The token is nowhere but in the stored request.
    const { request: _request, ...rest } = stored;
    for (const token of [TOKEN_A, MODEL_TOKEN]) {
      expect(json(rest), token).not.toContain(token);
      expect(json(t.h.world.executions), token).not.toContain(token);
      expect(json(t.h.audit.entries), token).not.toContain(token);
      expect(json(out.view), token).not.toContain(token);
      expect(json(out.envelope), token).not.toContain(token);
      expect(json(out.card), token).not.toContain(token);
      expect(json(out.confirmation!.view), token).not.toContain(token);
      expect(logs.join('\n'), token).not.toContain(token);
      expect(json(await t.h.executions.get(t.user, t.scope, out.executionId)), token).not.toContain(
        token,
      );
    }
    expect(json(stored.request)).not.toContain(MODEL_TOKEN);
  });

  it('the model may omit impactToken and confirm (placeholder before the schema check, never sent)', async () => {
    const t = setup();
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    expect(out.status).toBe('pending_confirmation');
    expect((t.row(out).request as { body: unknown }).body).toEqual({
      change: CHANGE,
      impactToken: TOKEN_A,
      confirm: true,
    });
    expect(json(t.h.loopback.calls)).not.toContain(IMPACT_TOKEN_PLACEHOLDER);
  });

  it('confirm: the same read and preview again; the stored (proposal) token is applied once', async () => {
    const logs = captureLogs();
    const t = setup();
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    expect((await coded(t.confirm(out))).code).toBe('assistant_reauth_required');
    const done = await t.confirm(out, REAUTH);
    expect(done.confirmation).toMatchObject({ status: 'executed', result: { httpStatus: 200 } });
    expect(t.previews).toHaveLength(2);
    expect(t.previews[1]!.body).toEqual({ change: CHANGE });
    expect(t.writes).toHaveLength(1);
    expect(t.writes[0]!.body).toEqual({ change: CHANGE, impactToken: TOKEN_A, confirm: true });
    // The confirm-time preview's token is used for the comparison only, never sent or kept.
    for (const token of [TOKEN_A, TOKEN_B]) {
      expect(json(done), token).not.toContain(token);
      expect(json(t.h.world.executions), token).not.toContain(token);
      expect(json(t.h.audit.entries), token).not.toContain(token);
      expect(logs.join('\n'), token).not.toContain(token);
    }
    expect(json(t.row(out).request)).not.toContain(TOKEN_B);
  });

  it('a changed change set at confirm → 409 state_changed; nothing applied', async () => {
    const t = setup();
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    t.setPreview(() =>
      ok({
        change: CHANGE,
        changeSet: changeSetOf('other-host.mail.protection.example'),
        impactToken: TOKEN_B,
        expiresAt: '2026-11-25T12:15:00.000Z',
        warnings: [],
      }),
    );
    expect(await coded(t.confirm(out, REAUTH))).toMatchObject({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.row(out)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_state_changed',
    });
    expect(t.writes).toHaveLength(0);
  });

  it('a new token alone (same change set) is not a state change', async () => {
    const t = setup();
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    // The default preview already answers TOKEN_B at confirm; the change set is the same.
    expect((await t.confirm(out, REAUTH)).confirmation.status).toBe('executed');
  });

  it('a non-2xx preview fails the proposal with its code; no confirmation, no write', async () => {
    const t = setup();
    t.setPreview(() =>
      ok({ statusCode: 409, code: 'outbound_active', message: 'Outbound routing is active' }, 409),
    );
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    expect(out).toMatchObject({
      decision: 'allowed',
      status: 'failed',
      httpStatus: 409,
      errorCode: 'outbound_active',
      confirmation: null,
    });
    expect(t.h.world.confirmations).toHaveLength(0);
    expect(t.writes).toHaveLength(0);
  });

  it('a 2xx preview without a usable token fails the proposal (502 precondition unavailable)', async () => {
    const t = setup();
    t.setPreview(() => ok({ change: CHANGE, changeSet: changeSetOf('x.example'), warnings: [] }));
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    expect(out).toMatchObject({ status: 'failed', httpStatus: 502, confirmation: null });
    expect(t.h.world.confirmations).toHaveLength(0);
  });

  it('a failed read stops before the preview', async () => {
    const t = setup();
    t.h.loopback.on(routeOf('provider_connections_get', { id: CONNECTION }), () =>
      ok({ statusCode: 404, code: 'not_found', message: 'Not found' }, 404),
    );
    const out = await t.call('provider_mail_flow_apply', {
      id: CONNECTION,
      body: { change: CHANGE },
    });
    expect(out).toMatchObject({ status: 'failed', httpStatus: 404 });
    expect(t.previews).toHaveLength(0);
  });

  it('disconnect: the model passes only the id; the preview gets the constant { kind: disable }', async () => {
    const t = setup();
    const out = await t.call('provider_connections_disconnect', { id: CONNECTION });
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(t.previews[0]!.body).toEqual({ change: { kind: 'disable' } });
    expect(t.row(out).request as { method: string; body: unknown }).toMatchObject({
      method: 'DELETE',
      body: { impactToken: TOKEN_A, confirm: true },
    });
    const done = await t.confirm(out, REAUTH);
    expect(done.confirmation.status).toBe('executed');
    expect(t.writes.map((w) => `${w.method} ${json(w.body)}`)).toEqual([
      `DELETE ${json({ impactToken: TOKEN_A, confirm: true })}`,
    ]);
  });

  it('preview(): only IMPACT_PREVIEW_TOOLS; get() keeps refusing non-GET tools', async () => {
    const t = setup();
    const call: ReadCall = {
      ...AUTH,
      correlationId: 'it-corr-ai5-x',
      signal: new AbortController().signal,
    };
    const apply = confirmationSpecOf('ProviderMailFlowController_apply_v1')!;
    const args = { id: CONNECTION, body: { change: CHANGE } };
    // An allow-listed tool: sent.
    expect(await t.h.proposer.preview(call, apply.impactToken!, args)).toMatchObject({ ok: true });
    expect(t.previews).toHaveLength(1);
    // Any other tool (a side-effect-free POST read or a write): refused without a request.
    const before = t.h.loopback.calls.length;
    for (const previewTool of ['policy_tools_validate', 'provider_mail_flow_apply']) {
      const injection = {
        ...apply.impactToken!,
        previewTool,
      } as unknown as NonNullable<ConfirmationSpec['impactToken']>;
      expect(await t.h.proposer.preview(call, injection, args)).toEqual({
        ok: false,
        result: { kind: 'unavailable' },
      });
    }
    // A precondition naming the POST preview as its read is refused by get().
    const viaGet: ConfirmationSpec = {
      operationId: 'it-synthetic',
      precondition: {
        kind: 'single',
        tool: 'provider_mail_flow_preview',
        params: { id: 'id' },
        stateFields: ['changeSet'],
      },
    };
    expect(await t.h.proposer.readPreconditions(call, viaGet, args)).toEqual({
      ok: false,
      result: { kind: 'unavailable' },
    });
    // An impact token without a single precondition fails closed.
    expect(
      await t.h.proposer.readPreconditions(call, { ...apply, precondition: null }, args),
    ).toEqual({ ok: false, result: { kind: 'unavailable' } });
    expect(t.h.loopback.calls.length).toBe(before);
  });
});

describe('omitted inputs (D7)', () => {
  it('intake_sources_get with a forced reveal → denied_schema, no loopback call', async () => {
    const t = setup();
    const out = await t.call('intake_sources_get', { sourceId: SOURCE, reveal: 'true' });
    expect(out).toMatchObject({ decision: 'denied_schema', status: 'refused' });
    expect(t.h.loopback.toolCalls).toHaveLength(0);
    expect(t.h.loopback.calls.filter((c) => c.path.includes('intake-sources'))).toHaveLength(0);
  });

  it('provider_grants_verify with body.subjectEmail → denied_schema, no read, no confirmation', async () => {
    const t = setup();
    const out = await t.call('provider_grants_verify', {
      id: CONNECTION,
      profile: 'mail_flow',
      body: { subjectEmail: 'admin@contoso.example' },
    });
    expect(out).toMatchObject({ decision: 'denied_schema', status: 'refused', confirmation: null });
    expect(t.h.loopback.calls.filter((c) => c.path.startsWith('/api/v1/provider'))).toHaveLength(0);
    expect(t.h.world.confirmations).toHaveLength(0);
  });
});

describe('outcome wording (D11): queued 202 writes', () => {
  it('an executed eDiscovery export gets its queued line in the next turn', async () => {
    const t = setup();
    const out = await t.call('ediscovery_exports_create', {
      caseId: CASE,
      body: { searchId: SEARCH },
    });
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    const done = await t.confirm(out, REAUTH);
    expect(done.confirmation).toMatchObject({ status: 'executed', result: { httpStatus: 202 } });
    const updates = actionUpdatesOf(
      await t.h.world.confirmationsDouble().unreported(t.owner, t.conversation.id, 20),
    );
    expect(updates.map((u) => u.tool)).toEqual(['ediscovery_exports_create']);
    expect(buildActionUpdates(updates)).toContain(
      'the user confirmed it; the export was queued (HTTP 202). It is downloaded only on the case page in the portal.',
    );
  });
});
