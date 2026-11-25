import {
  buildActionUpdates,
  findTool,
  GUARD_MESSAGES,
  OPERATION_TOOLS,
  REDACTED_PARAM,
} from '@email-gateway/assistant';
import { PLATFORM_PERMISSIONS, TENANT_PERMISSIONS } from '@email-gateway/database';
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
import { availableTools } from '../domain/tool-catalog';
import { ownerOf } from './conversation.service';
import type { LoopbackCall, LoopbackResult } from './loopback-client';
import { actionUpdatesOf } from './turn-engine.service';
import {
  type ExecutionContext,
  type ExecutionOutcome,
  redactParams,
} from './tool-executor.service';

/**
 * Step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md §9 item 2, WP4) at the service
 * level: redacted read inputs (D9), the ATO four-eyes guards at proposal and confirm (D3, I18),
 * platform hiding (D11, I19), escalated risks (D2/D4, I20) and the outcome wording of queued
 * work and response requests (D10). In-memory doubles, the fake loopback, synthetic ids only.
 */

const SELF = testUser().userPublicId;
const OTHER_USER = '0193b000-0000-7000-8000-000000000502';
const API_KEY = '0193b000-0000-7000-8000-0000000a0001';
const RESPONSE = '0193c400-0000-7000-8000-000000000001';
const ACCOUNT = '0193c400-0000-7000-8000-000000000002';
const INCIDENT = '0193c400-0000-7000-8000-000000000003';
const DLP_POLICY = '0193c400-0000-7000-8000-000000000004';
const AUTH = { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' };
/** The same user's refreshed access token at confirm time (same session). */
const AUTH_AT_CONFIRM = { authorization: 'Bearer it-access-token-2', clientIp: '198.51.100.7' };
const REAUTH = { reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } };

/** Synthetic DLP pattern-test inputs (never stored, audited or logged, D9). */
const SAMPLE = 'Synthetic sample: order ref ZQX-48151623 for the it-dlp test';
const PATTERN = 'ZQX-[0-9]{8}';

/** The tools this suite calls (their permissions form the analyst's grant). */
const TOOLS = [
  'ato_responses_get',
  'ato_responses_approve',
  'ato_responses_reject',
  'ato_responses_request',
  'ato_accounts_get',
  'ato_accounts_set_override',
  'ato_account_mailbox_refresh',
  'incidents_get',
  'dlp_policies_get',
  'dlp_policies_update',
  'dlp_patterns_test',
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

const analyst = (overrides: Partial<UserPrincipal> = {}): UserPrincipal =>
  testUser({ permissions: new Set(permissionsOf(TOOLS)), ...overrides });

/** `METHOD /api/v1/...` of a tool with its path parameters filled. */
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

function setup(user: UserPrincipal = analyst()) {
  const h = createAssistantHarness({}, undefined, user);
  h.world.enable(user.override?.targetOrganizationId ?? user.organizationId);
  const scope = scopeFromPrincipal(user);
  const owner = ownerOf(user, scope);
  const conversation = h.world.addConversation(owner);
  /** Write requests that reached the (fake) api. */
  const writes: LoopbackCall[] = [];
  /** The ATO response as `GET /ato/responses/{id}` shows it (`canDecide` per caller below). */
  const response = {
    id: RESPONSE,
    actionType: 'restrict_smtp_sending',
    provider: 'gateway',
    impact: 'high',
    status: 'pending_approval',
    account: { id: ACCOUNT, kind: 'mailbox' },
    target: { scope: 'mailbox', connectorId: null, cidr: null },
    params: { durationMinutes: 60, mode: 'reject', description: null },
    requestedBy: { type: 'user', id: OTHER_USER },
    requestReason: 'Outbound spam from the mailbox',
    approvalExpiresAt: '2026-11-26T18:00:00.000Z',
    executedAt: null,
    effectiveUntil: null,
  };
  /** The api's own `canDecide` for the caller of the read (by its credential). */
  let canDecide: (call: LoopbackCall) => boolean = () => true;
  h.loopback.on(routeOf('ato_responses_get', { responseId: RESPONSE }), (call) =>
    ok({ ...response, canDecide: canDecide(call) }),
  );
  for (const name of ['ato_responses_approve', 'ato_responses_reject']) {
    h.loopback.on(routeOf(name, { responseId: RESPONSE }), (call) => {
      writes.push(call);
      response.status = name === 'ato_responses_approve' ? 'succeeded' : 'rejected';
      return ok({ ...response, canDecide: false });
    });
  }
  const account = {
    id: ACCOUNT,
    kind: 'mailbox',
    address: 'alex@it-ato.example',
    displayName: 'Alex',
    status: 'active',
    riskScore: 72,
    riskLevel: 'high',
    rowVersion: 14,
    overrideDetail: null,
    protection: { protected: false, reason: null, at: null },
    trustedContexts: [],
  };
  h.loopback.on(routeOf('ato_accounts_get', { accountId: ACCOUNT }), () => ok(account));
  h.loopback.on(routeOf('ato_accounts_set_override', { accountId: ACCOUNT }), (call) => {
    writes.push(call);
    return ok(account);
  });
  h.loopback.on(routeOf('ato_account_mailbox_refresh', { accountId: ACCOUNT }), (call) => {
    writes.push(call);
    return ok({ accountId: ACCOUNT, status: 'queued' }, 202);
  });
  h.loopback.on(routeOf('incidents_get', { incidentId: INCIDENT }), () =>
    ok({
      id: INCIDENT,
      category: 'account_takeover',
      subject: { type: 'ato_account', id: ACCOUNT, display: 'alex@it-ato.example' },
      status: 'open',
      severity: 'high',
      assigneeId: null,
      rowVersion: 3,
    }),
  );
  h.loopback.on(routeOf('ato_responses_request', { incidentId: INCIDENT }), (call) => {
    writes.push(call);
    return ok({ ...response, requestedBy: { type: 'user', id: SELF }, canDecide: false }, 201);
  });
  const policy = {
    id: DLP_POLICY,
    name: 'Outbound financial data',
    enabled: true,
    mode: 'enforce',
    priority: 100,
    ruleCount: 2,
    version: 7,
    rules: [],
  };
  h.loopback.on(routeOf('dlp_policies_get', { id: DLP_POLICY }), () => ok(policy));
  h.loopback.on(routeOf('dlp_policies_update', { id: DLP_POLICY }), (call) => {
    writes.push(call);
    return ok({ ...policy, version: 8 });
  });
  h.loopback.on(routeOf('dlp_patterns_test'), () =>
    ok({
      valid: true,
      matches: [{ start: 24, end: 36, masked: '********1623', validator: null, context: false }],
      truncated: false,
    }),
  );
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
    correlationBase: 'it-corr-ai4',
    signal: new AbortController().signal,
    allocateSeq: nextSeq,
    ...overrides,
  });
  const call = (name: string, args: Record<string, unknown>) =>
    h.executor.execute(ctx(), { name, arguments: args }, 0);
  const confirm = (
    outcome: ExecutionOutcome,
    extra: Partial<{ reauth: { password: string; totpCode?: string } }> = {},
    request = AUTH,
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
      request,
    );
  const row = (outcome: ExecutionOutcome): StoredConfirmation =>
    h.world.confirmations.find((k) => k.publicId === outcome.confirmation!.view.id)!;
  return {
    h,
    user,
    scope,
    owner,
    conversation,
    writes,
    response,
    setCanDecide: (fn: (call: LoopbackCall) => boolean) => {
      canDecide = fn;
    },
    call,
    confirm,
    row,
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

/** Every Nest `Logger` line of the test (the services log through it). */
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

describe('redacted read inputs (D9): dlp_patterns_test', () => {
  const ARGS = {
    body: { pattern: PATTERN, sample: SAMPLE, caseInsensitive: false, maskStyle: 'last4' },
  };

  it('executed: neither sample nor pattern in params_redacted, audit params or logs; the loopback body keeps them', async () => {
    const logs = captureLogs();
    const t = setup();
    const out = await t.call('dlp_patterns_test', structuredClone(ARGS));
    expect(out).toMatchObject({ decision: 'allowed', status: 'succeeded', httpStatus: 200 });
    // The operation needs the real values.
    const sent = t.h.loopback.toolCalls;
    expect(sent).toHaveLength(1);
    expect(sent[0]!.body).toEqual(ARGS.body);
    // The stored and audited copies carry the placeholder.
    const redacted = {
      body: {
        pattern: REDACTED_PARAM,
        sample: REDACTED_PARAM,
        caseInsensitive: false,
        maskStyle: 'last4',
      },
    };
    expect(t.h.world.executions).toHaveLength(1);
    expect(t.h.world.executions[0]!.paramsRedacted).toEqual(redacted);
    const audited = t.h.audit.entries.find((e) => e.action === 'assistant.tool_executed')!;
    expect((audited.metadata as { params: unknown }).params).toEqual(redacted);
    // A successful read logs nothing at all; the refusal case below logs and is checked too.
    for (const value of [SAMPLE, PATTERN, 'ZQX-48151623']) {
      expect(json(t.h.world.executions), value).not.toContain(value);
      expect(json(t.h.audit.entries), value).not.toContain(value);
      expect(logs.join('\n'), value).not.toContain(value);
      expect(json(out.view), value).not.toContain(value);
      expect(json(await t.h.executions.get(t.user, t.scope, out.executionId)), value).not.toContain(
        value,
      );
    }
  });

  it('denied (schema, permission): neither value is stored, audited or logged; nothing is sent', async () => {
    const logs = captureLogs();
    const t = setup();
    const schema = await t.call('dlp_patterns_test', {
      body: { ...ARGS.body, validator: 'not-a-validator' },
    });
    expect(schema).toMatchObject({ decision: 'denied_schema', status: 'refused' });
    expect(t.h.world.executions[0]!.paramsRedacted).toMatchObject({
      body: { pattern: REDACTED_PARAM, sample: REDACTED_PARAM, validator: 'not-a-validator' },
    });
    const reader = setup(analyst({ permissions: new Set(['assistant:use', 'dlp:read']) }));
    const permission = await reader.call('dlp_patterns_test', structuredClone(ARGS));
    expect(permission.decision).toBe('denied_permission');
    for (const s of [t, reader]) {
      expect(s.h.loopback.toolCalls).toHaveLength(0);
      expect(s.h.audit.entries.map((e) => e.action)).toEqual(['assistant.tool_denied']);
      for (const value of [SAMPLE, PATTERN]) {
        expect(json(s.h.world.executions), value).not.toContain(value);
        expect(json(s.h.audit.entries), value).not.toContain(value);
      }
    }
    expect(logs.length).toBeGreaterThan(0);
    for (const value of [SAMPLE, PATTERN]) expect(logs.join('\n')).not.toContain(value);
    expect(schema.denialMessage).not.toContain(SAMPLE);
  });

  it('redactParams: the listed paths first, then the credential scrub; exact is false', () => {
    const tool = findTool('dlp_patterns_test')!;
    expect(tool.redactParams).toEqual(['body.sample', 'body.pattern']);
    const args = { body: { pattern: PATTERN, sample: SAMPLE, maskStyle: 'full', apiKey: 'x' } };
    expect(redactParams(args, 4096, tool)).toEqual({
      value: { body: { pattern: REDACTED_PARAM, sample: REDACTED_PARAM, maskStyle: 'full' } },
      exact: false,
    });
    // The arguments themselves are untouched (the loopback sends them).
    expect(args.body.sample).toBe(SAMPLE);
    // An absent path is not invented; nothing redacted and nothing scrubbed stays exact.
    expect(redactParams({ body: { maskStyle: 'full' } }, 4096, tool)).toEqual({
      value: { body: { maskStyle: 'full' } },
      exact: true,
    });
    // Tools without the override (and refusals without a tool) only scrub.
    expect(redactParams({ q: SAMPLE }, 4096, null)).toEqual({ value: { q: SAMPLE }, exact: true });
    expect(redactParams({ q: SAMPLE }, 4096, findTool('dlp_policies_list')!).exact).toBe(true);
  });
});

describe('ATO four-eyes guards (D3, I18)', () => {
  const APPROVE = { responseId: RESPONSE, body: { reason: 'Checked by a second analyst' } };

  it('the requester → denied_guard (not_self_field) after the read: no confirmation, no write', async () => {
    for (const name of ['ato_responses_approve', 'ato_responses_reject']) {
      const t = setup();
      t.response.requestedBy = { type: 'user', id: SELF.toUpperCase() };
      // Even a regressed view that says the requester may decide is refused (defence in depth).
      t.setCanDecide(() => true);
      const out = await t.call(name, APPROVE);
      expect(out, name).toMatchObject({
        decision: 'denied_guard',
        status: 'refused',
        errorCode: 'denied_guard',
        confirmation: null,
        denialMessage: GUARD_MESSAGES.ato_four_eyes,
      });
      expect(out.view.message).toBe(GUARD_MESSAGES.ato_four_eyes);
      expect((await t.h.executions.get(t.user, t.scope, out.executionId)).message).toBe(
        GUARD_MESSAGES.ato_four_eyes,
      );
      // Only the precondition read, with the proposing user's own credential.
      expect(t.h.loopback.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
        routeOf('ato_responses_get', { responseId: RESPONSE }),
      ]);
      expect(t.h.loopback.calls[0]!.authorization).toBe(AUTH.authorization);
      expect(t.writes).toHaveLength(0);
      expect(t.h.world.confirmations).toHaveLength(0);
      expect(t.h.audit.entries.map((e) => e.action)).toEqual(['assistant.tool_denied']);
      expect(t.h.audit.entries[0]!.metadata).toMatchObject({
        decision: 'denied_guard',
        guard: 'not_self_field',
      });
    }
  });

  it('a response requested by an API key the caller created (canDecide false) → denied_guard (require_read_value)', async () => {
    const t = setup();
    t.response.requestedBy = { type: 'api_key', id: API_KEY };
    t.setCanDecide(() => false);
    const out = await t.call('ato_responses_approve', APPROVE);
    expect(out).toMatchObject({
      decision: 'denied_guard',
      confirmation: null,
      denialMessage: GUARD_MESSAGES.ato_four_eyes,
    });
    expect(t.h.world.confirmations).toHaveLength(0);
    expect(t.writes).toHaveLength(0);
    expect(t.h.audit.entries[0]!.metadata).toMatchObject({
      decision: 'denied_guard',
      guard: 'require_read_value',
    });
  });

  it('canDecide is the api’s answer for the caller of the read (the proposing user)', async () => {
    const t = setup();
    // The api computes canDecide per credential: only the proposing user's token is used.
    t.setCanDecide((call) => call.authorization !== AUTH.authorization);
    const out = await t.call('ato_responses_approve', APPROVE);
    expect(out.decision).toBe('denied_guard');
    expect(t.h.loopback.calls.every((c) => c.authorization === AUTH.authorization)).toBe(true);
  });

  it('another responder → pending high confirmation with re-auth; confirm re-reads with the confirming credential and approves once', async () => {
    const t = setup();
    t.setCanDecide(() => true);
    const out = await t.call('ato_responses_approve', APPROVE);
    expect(out).toMatchObject({ decision: 'allowed', status: 'pending_confirmation' });
    expect(out.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(t.row(out)).toMatchObject({ risk: 'high', requiresReauth: true, status: 'pending' });
    expect(t.writes).toHaveLength(0);
    expect((await coded(t.confirm(out))).code).toBe('assistant_reauth_required');
    const reads = t.h.loopback.calls.length;
    const done = await t.confirm(out, REAUTH, AUTH_AT_CONFIRM);
    expect(done.confirmation).toMatchObject({ status: 'executed', result: { httpStatus: 200 } });
    const confirmCalls = t.h.loopback.calls.slice(reads);
    expect(confirmCalls.map((c) => `${c.method} ${c.path}`)).toEqual([
      routeOf('ato_responses_get', { responseId: RESPONSE }),
      routeOf('ato_responses_approve', { responseId: RESPONSE }),
    ]);
    expect(confirmCalls.every((c) => c.authorization === AUTH_AT_CONFIRM.authorization)).toBe(true);
    expect(t.writes).toHaveLength(1);
    expect(t.writes[0]).toMatchObject({
      body: APPROVE.body,
      idempotencyKey: out.confirmation!.view.id,
    });
  });

  it('canDecide false since the proposal → confirm 403 assistant_action_not_allowed, row failed, nothing executed', async () => {
    const t = setup();
    t.setCanDecide(() => true);
    const out = await t.call('ato_responses_approve', APPROVE);
    expect(out.status).toBe('pending_confirmation');
    // E.g. the confirming session lost its MFA or `ato:respond` as the api sees it.
    t.setCanDecide(() => false);
    expect(await coded(t.confirm(out, REAUTH))).toEqual({
      status: 403,
      code: 'assistant_action_not_allowed',
    });
    expect(t.row(out)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_action_not_allowed',
    });
    expect(t.writes).toHaveLength(0);
    expect(
      t.h.audit.entries.find((e) => e.action === 'assistant.confirmation_refused')!.metadata,
    ).toMatchObject({ reason: 'guard', guard: 'require_read_value' });
    expect(t.h.audit.entries.some((e) => e.action === 'assistant.confirmation_executed')).toBe(
      false,
    );
  });

  it('a response that is no longer pending passes the guards (the api answers 409); a status change before confirm is 409 state_changed', async () => {
    const t = setup();
    t.response.status = 'expired';
    t.setCanDecide(() => false);
    const stale = await t.call('ato_responses_reject', {
      responseId: RESPONSE,
      body: { reason: 'Not needed' },
    });
    expect(stale.status).toBe('pending_confirmation');
    t.response.status = 'pending_approval';
    t.setCanDecide(() => true);
    const out = await t.call('ato_responses_approve', APPROVE);
    t.response.status = 'rejected';
    expect(await coded(t.confirm(out, REAUTH))).toEqual({
      status: 409,
      code: 'assistant_confirmation_state_changed',
    });
    expect(t.writes).toHaveLength(0);
  });
});

describe('platform hiding (D11, I19)', () => {
  const PLATFORM_TOOLS = OPERATION_TOOLS.filter((tool) => tool.enabled && tool.platformOnly);
  const TARGET = { id: 7002n, publicId: '0193b000-0000-7000-8000-000000007002' };
  const customer = testUser({ permissions: new Set(TENANT_PERMISSIONS) });
  const tenantSet = new Set<string>(TENANT_PERMISSIONS);
  const operatorPermissions = [...TENANT_PERMISSIONS, ...PLATFORM_PERMISSIONS];
  const operator = testUser({
    userId: 601n,
    userPublicId: '0193b000-0000-7000-8000-000000000601',
    organizationId: 1n,
    organizationPublicId: '0193b000-0000-7000-8000-000000000001',
    organizationKind: 'platform',
    permissions: new Set(operatorPermissions),
  });
  // As the auth guard builds it under an override token: platform permissions stripped.
  const overridden: UserPrincipal = {
    ...operator,
    permissions: new Set(operatorPermissions.filter((p) => tenantSet.has(p))),
    override: {
      id: '0193b000-0000-7000-8000-0000000000f1',
      reason: 'Investigating a ticket',
      targetOrganizationId: TARGET.id,
      targetOrganizationPublicId: TARGET.publicId,
      expiresAt: new Date('2099-01-01T00:00:00.000Z'),
    },
  };

  it('the registry has the AI-4 platform tools (reads and writes)', () => {
    const names = PLATFORM_TOOLS.map((tool) => tool.name);
    for (const name of [
      'threat_hashes_add',
      'threat_hashes_remove',
      'threat_indicators_add',
      'threat_indicators_remove',
      'threat_indicators_get',
      'attachment_rescans_request',
      'attachment_rescans_cancel',
      'dead_letters_replay',
      'scan_training_train',
    ]) {
      expect(names, name).toContain(name);
    }
  });

  it.each([
    ['a customer user with every tenant permission', customer],
    ['a platform user under an override (platform:* stripped)', overridden],
  ])(
    '%s: no platformOnly tool in the catalogue or GET /tools; forced calls denied_permission without a request',
    async (_label, principal) => {
      expect(availableTools(principal).filter((tool) => tool.platformOnly)).toEqual([]);
      const t = setup(principal);
      const listed = new Set(t.h.conversations.tools(principal).tools.map((tool) => tool.name));
      for (const tool of PLATFORM_TOOLS) expect(listed.has(tool.name), tool.name).toBe(false);
      // The tenant tools stay available (the filter is not "nothing at all").
      expect(listed.has('dlp_patterns_test')).toBe(true);
      for (const tool of PLATFORM_TOOLS) {
        const out = await t.call(tool.name, {});
        expect(out.decision, tool.name).toBe('denied_permission');
      }
      expect(t.h.loopback.calls).toHaveLength(0);
      expect(t.h.world.confirmations).toHaveLength(0);
      expect(new Set(t.h.audit.entries.map((e) => e.action))).toEqual(
        new Set(['assistant.tool_denied']),
      );
    },
  );

  it('a platform user without an override sees them', () => {
    const offered = new Set(availableTools(operator).map((tool) => tool.name));
    for (const tool of PLATFORM_TOOLS) expect(offered.has(tool.name), tool.name).toBe(true);
    const t = setup(operator);
    const listed = new Set(t.h.conversations.tools(operator).tools.map((tool) => tool.name));
    for (const tool of PLATFORM_TOOLS) expect(listed.has(tool.name), tool.name).toBe(true);
  });
});

describe('escalated risks (D2, D4, I20)', () => {
  const OVERRIDE = (verdict: string) => ({
    accountId: ACCOUNT,
    body: { verdict, reason: 'Checked with the account owner', expiresInHours: 24 },
  });

  it('ato_accounts_set_override: benign is high with re-auth; compromised stays medium', async () => {
    const t = setup();
    const benign = await t.call('ato_accounts_set_override', OVERRIDE('benign'));
    expect(benign.envelope).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(t.row(benign)).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(benign.confirmation!.view.summary!.warnings.length).toBeGreaterThan(0);
    expect((await coded(t.confirm(benign))).code).toBe('assistant_reauth_required');
    const compromised = await t.call('ato_accounts_set_override', OVERRIDE('compromised'));
    expect(t.row(compromised)).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(
      t.h.audit.entries
        .filter((e) => e.action === 'assistant.confirmation_requested')
        .map((e) => [
          (e.metadata as { risk: string }).risk,
          (e.metadata as { baseRisk: string }).baseRisk,
        ]),
    ).toEqual([
      ['high', 'medium'],
      ['medium', 'medium'],
    ]);
    expect(t.writes).toHaveLength(0);
  });

  it('dlp_policies_update: disabling is high with re-auth (CAS version injected); a rename stays low and confirms', async () => {
    const t = setup();
    const disabled = await t.call('dlp_policies_update', {
      id: DLP_POLICY,
      body: { enabled: false },
    });
    expect(t.row(disabled)).toMatchObject({ risk: 'high', requiresReauth: true });
    expect((t.row(disabled).request as { body: unknown }).body).toEqual({
      enabled: false,
      version: 7,
    });
    const renamed = await t.call('dlp_policies_update', {
      id: DLP_POLICY,
      body: { name: 'Outbound finance data' },
    });
    expect(t.row(renamed)).toMatchObject({ risk: 'low', requiresReauth: false });
    expect((await t.confirm(renamed)).confirmation.status).toBe('executed');
    expect(t.writes.map((w) => w.body)).toEqual([{ name: 'Outbound finance data', version: 7 }]);
  });
});

describe('outcome wording (D10): the tool name reaches buildActionUpdates', () => {
  it('a queued 202 and a requested response get their own lines in the next turn', async () => {
    const t = setup();
    const refresh = await t.call('ato_account_mailbox_refresh', { accountId: ACCOUNT });
    expect(refresh.confirmation!.view).toMatchObject({ risk: 'low' });
    const queued = await t.confirm(refresh);
    expect(queued.confirmation).toMatchObject({ status: 'executed', result: { httpStatus: 202 } });
    const request = await t.call('ato_responses_request', {
      incidentId: INCIDENT,
      body: {
        actionType: 'restrict_smtp_sending',
        target: { scope: 'mailbox' },
        durationMinutes: 60,
        mode: 'reject',
        reason: 'Outbound spam from the mailbox',
      },
    });
    expect(request.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    const requested = await t.confirm(request, REAUTH);
    expect(requested.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 201 },
    });
    const updates = actionUpdatesOf(
      await t.h.world.confirmationsDouble().unreported(t.owner, t.conversation.id, 20),
    );
    expect(updates.map((u) => u.tool)).toEqual([
      'ato_account_mailbox_refresh',
      'ato_responses_request',
    ]);
    const text = buildActionUpdates(updates);
    expect(text).toContain(
      `- ato_account_mailbox_refresh (call r${refresh.seq}): the user confirmed it; it was queued (HTTP 202).`,
    );
    expect(text).toContain(
      `- ato_responses_request (call r${request.seq}): the user confirmed it; the response was requested (HTTP 201). If it needs approval, another responder must approve it; the requester cannot.`,
    );
    expect(text).not.toContain('waiting for approval by another person');
  });
});
