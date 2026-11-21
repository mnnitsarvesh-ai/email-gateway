/**
 * Step AI-1 tool sweep (docs/plan/steps/28-ai-chat-management.md D3, D5, D8, §9 item 4; the
 * `testedBy` of every enabled tool in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): EVERY
 * enabled tool of the registry is called through the real executor and the api's own pipeline
 * (the api listens on its ephemeral loopback port; the provider is the deterministic fake, never a
 * real LLM).
 *
 * - Tenant tools: one turn per tool with the fake's directive `/tool <name> <json>` as synthetic
 *   users holding every tenant permission (a custom role in a synthetic organization with every
 *   feature on); minimal valid arguments from the tool's input schema (required parameters only,
 *   synthetic UUIDs for ids, the first enum value, the last day for date ranges). Each call ends
 *   `ok` or with an expected coded 4xx (synthetic ids → 404, filter combinations → 400/409/422),
 *   never a 5xx, a 401 or an unexpected 403; no envelope or card carries a credential-pattern key.
 * - Platform-only tools: a platform `super_admin` through the executor directly (a turn of a
 *   platform user would need the assistant enabled in the platform organization, which the suites
 *   never change); the same pre-filter, schema check, loopback, card, envelope, execution and audit
 *   rows as in a turn.
 * - Without the permission: for a user holding only `assistant:use` (and for `read_only_user`),
 *   every tool it lacks is absent from `GET /assistant/tools`, and a forced directive call is
 *   `denied_permission` with no loopback request for the operation (only the turn's own `/auth/me`
 *   context read), an execution row with that decision, an `assistant.tool_denied` audit row and
 *   no audit row of the operation.
 *
 * - Step AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md §9 item 4): the read sweep
 *   now covers 178 enabled reads (the side-effect-free policy POSTs `policy_tools_validate`,
 *   `policy_tools_test`, `policy_tools_sample_dry_run` and `policy_messages_dry_run` included),
 *   and the "no write without confirmation" sweep calls every enabled WRITE (31) through a turn:
 *   each ends `pending_confirmation` or as a coded proposal failure (the precondition read's 4xx,
 *   an invalid definition), never a 5xx; the only loopback requests are GETs and `POST
 *   /policies/validate` (no request reaches a write route), no audit row of an operation carries
 *   the executions' correlation ids and the organization's mail-operation tables are unchanged.
 *
 * Synthetic `it-*` organizations only.
 */
// @covers get /api/v1/assistant/tools
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
import { createHash, randomUUID } from 'node:crypto';
import { FAKE_EXECUTABLES_DEFINITION } from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  ALL_TENANT_PERMISSIONS,
  allFeatures,
  A,
  call,
  clearAssistantCounters,
  createAssistantApp,
  credentialKeysInResult,
  DirectExecutor,
  directive,
  ENABLED_READS,
  ENABLED_TOOLS,
  ENABLED_WRITES,
  enableAssistant,
  envelopesOf,
  member,
  type Member,
  minimalArguments,
  newConversation,
  platformMember,
  principalOf,
  recordLoopback,
  turn,
  withheldColumns,
} from './support/assistant';
import { deleteAtoRows } from './support/ato';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';

/** Turns per conversation (keeps each replayed segment small). */
const TURNS_PER_CONVERSATION = 5;
/** Coded client errors a minimal call may legitimately get. */
const EXPECTED_4XX = new Set([400, 404, 409, 422]);

interface SweepResult {
  tool: string;
  decision: string;
  status: string;
  httpStatus: number | null;
  errorCode: string | null;
  credentialKeys: string[];
  withheld: string[];
}

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let org: FixtureOrganization;
let sweepers: Member[];
let bare: Member[];
let reader: Member;

/** Round-robin over users and conversations (per-user turn window of the suite: 120/minute). */
class TurnRunner {
  private index = 0;
  private readonly conversations = new Map<string, { id: string; turns: number }>();

  constructor(private readonly users: Member[]) {}

  async run(message: string) {
    const user = this.users[this.index % this.users.length]!;
    this.index += 1;
    let conversation = this.conversations.get(user.user.publicId);
    if (!conversation || conversation.turns >= TURNS_PER_CONVERSATION) {
      conversation = { id: await newConversation(ctx, user), turns: 0 };
      this.conversations.set(user.user.publicId, conversation);
    }
    conversation.turns += 1;
    return { user, res: await turn(ctx, user.headers, conversation.id, message) };
  }
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ features: allFeatures() });
  // ato_detection is on: the ATO reads and the live ato-worker (sign-ins) write ATO rows.
  fx.registerCleanup(() => deleteAtoRows(ctx.prisma, [org.id]), { rerunOnConflict: true });
  const all = await fx.createCustomRole(org, [...ALL_TENANT_PERMISSIONS]);
  const useOnly = await fx.createCustomRole(org, ['assistant:use']);
  sweepers = [];
  for (let i = 0; i < 4; i += 1) sweepers.push(await member(ctx, fx, org, [all]));
  bare = [];
  for (let i = 0; i < 4; i += 1) bare.push(await member(ctx, fx, org, [useOnly]));
  reader = await member(ctx, fx, org, ['read_only_user']);
  await enableAssistant(ctx, operator, org, sweepers[0]!);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
});

function assertSwept(results: SweepResult[]): void {
  const problems = results.filter(
    (r) =>
      r.decision !== 'allowed' ||
      r.credentialKeys.length > 0 ||
      !(
        (r.status === 'succeeded' && r.httpStatus !== null && r.httpStatus < 300) ||
        (r.status === 'failed' &&
          r.httpStatus !== null &&
          EXPECTED_4XX.has(r.httpStatus) &&
          r.errorCode !== null)
      ),
  );
  expect(problems, JSON.stringify(problems, null, 1)).toEqual([]);
}

describe('tool sweep over every enabled read (§9 item 4)', () => {
  const tenantTools = ENABLED_READS.filter((t) => !t.platformOnly);
  const platformTools = ENABLED_READS.filter((t) => t.platformOnly);
  const swept: SweepResult[] = [];

  it('offers exactly the enabled tenant tools to a user with every tenant permission', async () => {
    // Step AI-2: 209 enabled tools = 178 reads + 31 confirmable writes.
    expect(ENABLED_READS).toHaveLength(178);
    expect(ENABLED_WRITES).toHaveLength(31);
    expect(ENABLED_TOOLS).toHaveLength(209);
    for (const name of [
      'policy_tools_validate',
      'policy_tools_test',
      'policy_tools_sample_dry_run',
      'policy_messages_dry_run',
    ]) {
      expect(
        ENABLED_READS.map((t) => t.name),
        name,
      ).toContain(name);
    }
    const res = await call(ctx, sweepers[0]!.headers, 'get', `${A}/tools`);
    expect(res.status).toBe(200);
    const names = (res.body.tools as Array<{ name: string }>).map((t) => t.name).sort();
    expect(names).toEqual(
      ENABLED_TOOLS.filter((t) => !t.platformOnly)
        .map((t) => t.name)
        .sort(),
    );
  });

  it('calls every enabled tenant read through a turn: ok or a coded 4xx', async () => {
    const runner = new TurnRunner(sweepers);
    for (const tool of tenantTools) {
      const args = minimalArguments(tool);
      const { res } = await runner.run(directive(tool.name, args));
      expect(res.status, `${tool.name}: turn ${JSON.stringify(res.body)}`).toBe(200);
      expect(res.body.turn.status, tool.name).toBe('completed');
      const execution = res.body.executions[0];
      expect(execution?.tool, tool.name).toBe(tool.name);
      const envelope = (await envelopesOf(ctx, res.body.turn.id as string))[0]?.parsed ?? null;
      expect(envelope, tool.name).not.toBeNull();
      swept.push({
        tool: tool.name,
        decision: execution.decision,
        status: execution.status,
        httpStatus: execution.httpStatus,
        errorCode: execution.errorCode,
        credentialKeys: credentialKeysInResult(envelope, execution.card),
        withheld: withheldColumns(execution.card),
      });
    }
    expect(swept).toHaveLength(tenantTools.length);
    assertSwept(swept);
  }, 600_000);

  it('calls every platform-only tool as a platform super_admin through the executor', async () => {
    const admin = await platformMember(ctx, fx, ['super_admin']);
    const listed = await call(ctx, admin.headers, 'get', `${A}/tools`);
    expect(listed.status).toBe(200);
    const names = new Set((listed.body.tools as Array<{ name: string }>).map((t) => t.name));
    for (const tool of platformTools) expect(names.has(tool.name), tool.name).toBe(true);

    const executor = new DirectExecutor(ctx, admin, await principalOf(ctx, admin.token), org);
    const results: SweepResult[] = [];
    for (const tool of platformTools) {
      const outcome = await executor.execute(tool.name, minimalArguments(tool, { bound: false }));
      results.push({
        tool: tool.name,
        decision: outcome.decision,
        status: outcome.status,
        httpStatus: outcome.httpStatus,
        errorCode: outcome.errorCode,
        credentialKeys: credentialKeysInResult(
          outcome.envelope as unknown as Record<string, unknown>,
          outcome.card as unknown as Record<string, unknown> | null,
        ),
        withheld: withheldColumns(outcome.card as unknown as Record<string, unknown> | null),
      });
    }
    assertSwept(results);
    swept.push(...results);
    // Every execution is recorded and audited (I6).
    const rows = await ctx.prisma.aiChatToolExecution.count({
      where: { organizationId: org.id, userId: admin.user.id },
    });
    expect(rows).toBe(platformTools.length);
  }, 120_000);

  it('swept every enabled read once', () => {
    expect(new Set(swept.map((r) => r.tool)).size).toBe(ENABLED_READS.length);
    const byOutcome = swept.reduce<Record<string, number>>((acc, r) => {
      const key = r.status === 'succeeded' ? 'ok' : `${r.httpStatus} ${r.errorCode}`;
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
    const withheld = swept
      .filter((r) => r.withheld.length > 0)
      .map((r) => `${r.tool}: ${r.withheld.join(', ')}`);
    // eslint-disable-next-line no-console -- the sweep reports its count and outcomes (§9 item 4)
    console.info(
      `[assistant-tools] swept ${swept.length} enabled reads ` +
        `(${tenantTools.length} tenant, ${platformTools.length} platform): ` +
        `${JSON.stringify(byOutcome)}; card columns withheld by the credential pattern: ` +
        `${withheld.length > 0 ? withheld.join('; ') : 'none'}; validation refusals: ` +
        swept
          .filter((r) => r.httpStatus !== null && r.httpStatus !== 404 && r.httpStatus >= 400)
          .map((r) => `${r.tool} ${r.httpStatus} ${r.errorCode}`)
          .join(', '),
    );
  });
});

/** A synthetic id that matches no record. */
const unknown = (): string => randomUUID();
const sweepReason = 'requested by the tool sweep';
const viewDefinition = {
  version: 1,
  filters: {},
  sort: '-receivedAt',
  range: { kind: 'relative', preset: '24h' },
  columns: null,
};

/**
 * Schema-valid arguments of every enabled write: synthetic ids (the precondition read answers
 * 404) or, for the writes without a precondition read on a record, a complete request that
 * becomes a pending proposal.
 */
const WRITE_SAMPLES: Readonly<Record<string, () => Record<string, unknown>>> = {
  policy_management_create: () => ({
    body: { name: `it sweep ${randomUUID().slice(0, 8)}`, definition: FAKE_EXECUTABLES_DEFINITION },
  }),
  policy_management_update: () => ({
    policyId: unknown(),
    body: { name: 'it sweep', expectedRowVersion: 1 },
  }),
  policy_management_enable: () => ({ policyId: unknown() }),
  policy_management_disable: () => ({ policyId: unknown() }),
  policy_management_remove: () => ({ policyId: unknown() }),
  policy_management_create_draft: () => ({
    policyId: unknown(),
    body: { definition: FAKE_EXECUTABLES_DEFINITION },
  }),
  policy_management_update_draft: () => ({
    policyId: unknown(),
    versionNo: 1,
    body: { definition: FAKE_EXECUTABLES_DEFINITION, expectedRowVersion: 1 },
  }),
  policy_management_delete_draft: () => ({ policyId: unknown(), versionNo: 1 }),
  policy_management_publish: () => ({
    policyId: unknown(),
    versionNo: 1,
    body: { expectedRowVersion: 1 },
  }),
  policy_management_activate: () => ({ policyId: unknown(), versionNo: 1 }),
  policy_settings_put: () => ({ body: { settings: {}, expectedRowVersion: 0 } }),
  quarantine_entries_release: () => ({ entryId: unknown(), body: { reason: sweepReason } }),
  quarantine_entries_reject: () => ({ entryId: unknown(), body: { reason: sweepReason } }),
  quarantine_entries_delete: () => ({ entryId: unknown(), body: { reason: sweepReason } }),
  quarantine_entries_request_release: () => ({
    entryId: unknown(),
    body: { reason: sweepReason },
  }),
  quarantine_entries_manual: () => ({ body: { messageId: unknown(), reason: sweepReason } }),
  quarantine_self_release: () => ({ entryId: unknown(), body: { reason: sweepReason } }),
  quarantine_self_request_release: () => ({ entryId: unknown(), body: { reason: sweepReason } }),
  quarantine_self_put_preferences: () => ({ body: { digestOptOut: true } }),
  quarantine_tools_put_settings: () => ({ body: { settings: {}, expectedRowVersion: 0 } }),
  quarantine_tools_bulk: () => ({
    body: { action: 'reject', ids: [unknown(), unknown()], reason: sweepReason },
  }),
  quarantine_approvals_approve: () => ({ approvalId: unknown(), body: { reason: sweepReason } }),
  quarantine_approvals_deny: () => ({ approvalId: unknown(), body: { reason: sweepReason } }),
  quarantine_approvals_cancel: () => ({ approvalId: unknown(), body: { reason: sweepReason } }),
  message_lifecycle_release: () => ({
    messageId: unknown(),
    body: { expectedVersion: 0, reason: sweepReason },
  }),
  message_lifecycle_rescan: () => ({
    messageId: unknown(),
    body: { expectedVersion: 0, reason: sweepReason },
  }),
  recipient_suppressions_create: () => ({
    body: { address: `sweep-${randomUUID().slice(0, 8)}@example.org` },
  }),
  recipient_suppressions_delete: () => ({ suppressionId: '999999999999' }),
  saved_views_create: () => ({
    body: {
      kind: 'message_explorer',
      name: `it sweep ${randomUUID().slice(0, 8)}`,
      definition: viewDefinition,
    },
  }),
  saved_views_update: () => ({
    viewId: unknown(),
    body: { name: 'it sweep', definition: viewDefinition, expectedRowVersion: 1 },
  }),
  saved_views_remove: () => ({ viewId: unknown() }),
};

/** Checksums of the tables an enabled write could change, for the sweep's organization. */
async function writeTargets(): Promise<Record<string, string>> {
  const where = { organizationId: org.id };
  const orderBy = { id: 'asc' as const };
  const sha = (rows: unknown) =>
    createHash('sha256')
      .update(JSON.stringify(rows, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)))
      .digest('hex');
  const p = ctx.prisma;
  return {
    policies: sha(await p.emailPolicy.findMany({ where, orderBy })),
    versions: sha(await p.policyVersion.findMany({ where, orderBy })),
    policySettings: sha(await p.policySettings.findMany({ where, orderBy })),
    quarantine: sha(await p.quarantineMessage.findMany({ where, orderBy })),
    approvals: sha(await p.quarantineApprovalRequest.findMany({ where, orderBy })),
    quarantineSettings: sha(await p.quarantineSettings.findMany({ where, orderBy })),
    messages: sha(await p.emailMessage.findMany({ where, orderBy: { id: 'asc' } })),
    suppressions: sha(await p.deliverySuppression.findMany({ where, orderBy })),
    views: sha(await p.savedView.findMany({ where, orderBy })),
    idempotency: sha(await p.apiIdempotencyKey.findMany({ where, orderBy })),
    outbox: String(await p.messageOutbox.count({ where })),
  };
}

describe('no write without confirmation: every enabled write through a turn (§9 item 4)', () => {
  it('ends pending_confirmation or as a coded proposal failure; nothing reaches a write route', async () => {
    expect(Object.keys(WRITE_SAMPLES).sort()).toEqual(ENABLED_WRITES.map((t) => t.name).sort());
    const before = await writeTargets();
    const runner = new TurnRunner(sweepers);
    const recorder = recordLoopback(ctx);
    const results: Array<{
      tool: string;
      decision: string;
      status: string;
      httpStatus: number | null;
      errorCode: string | null;
      correlationId: string;
    }> = [];
    try {
      for (const tool of ENABLED_WRITES) {
        const { res } = await runner.run(directive(tool.name, WRITE_SAMPLES[tool.name]!()));
        expect(res.status, `${tool.name}: turn ${JSON.stringify(res.body)}`).toBe(200);
        expect(res.body.turn.status, tool.name).toBe('completed');
        const execution = res.body.executions[0];
        expect(execution?.tool, tool.name).toBe(tool.name);
        const row = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
          where: { publicId: execution.id as string },
        });
        results.push({
          tool: tool.name,
          decision: execution.decision,
          status: execution.status,
          httpStatus: execution.httpStatus,
          errorCode: execution.errorCode,
          correlationId: row.correlationId,
        });
        const pending = (
          res.body.confirmations as Array<{ confirmation: { executionId: string } }>
        ).map((c) => c.confirmation.executionId);
        expect(pending, tool.name).toEqual(
          execution.status === 'pending_confirmation' ? [execution.id] : [],
        );
      }
    } finally {
      recorder.restore();
    }
    const problems = results.filter(
      (r) =>
        r.decision !== 'allowed' ||
        !(
          (r.status === 'pending_confirmation' && r.httpStatus === null) ||
          (r.status === 'failed' &&
            r.httpStatus !== null &&
            r.httpStatus >= 400 &&
            r.httpStatus < 500 &&
            r.errorCode !== null)
        ),
    );
    expect(problems, JSON.stringify(problems, null, 1)).toEqual([]);
    // Only side-effect-free requests were sent: reads and the definition validation.
    const sent = recorder.calls.filter(
      (c) =>
        !(c.method === 'GET' || (c.method === 'POST' && c.path === '/api/v1/policies/validate')),
    );
    expect(sent, JSON.stringify(sent)).toEqual([]);
    expect(recorder.calls.every((c) => c.idempotencyKey === null)).toBe(true);
    // No operation audited anything under the executions' correlation ids.
    for (const r of results) {
      const audited = await ctx.prisma.auditLog.findMany({
        where: { organizationId: org.id, correlationId: r.correlationId },
        select: { action: true },
      });
      expect(
        audited.map((a) => a.action).filter((action) => !action.startsWith('assistant.')),
        r.tool,
      ).toEqual([]);
    }
    expect(await writeTargets()).toEqual(before);
    const pending = results.filter((r) => r.status === 'pending_confirmation').map((r) => r.tool);
    expect(pending).toEqual(
      expect.arrayContaining([
        'policy_management_create',
        'policy_settings_put',
        'quarantine_tools_put_settings',
        'recipient_suppressions_create',
        'saved_views_create',
      ]),
    );
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: { organizationId: org.id, status: 'pending' },
      }),
    ).toBe(pending.length);
    // eslint-disable-next-line no-console -- the sweep reports its count and outcomes (§9 item 4)
    console.info(
      `[assistant-tools] swept ${results.length} enabled writes: ${pending.length} pending ` +
        `confirmation (${pending.join(', ')}); refused proposals: ` +
        results
          .filter((r) => r.status !== 'pending_confirmation')
          .map((r) => `${r.tool} ${r.httpStatus} ${r.errorCode}`)
          .join(', '),
    );
  }, 600_000);
});

describe('tools without the permission (D5 step 3)', () => {
  it('hides them and refuses a forced call with denied_permission and no loopback request', async () => {
    const listed = await call(ctx, bare[0]!.headers, 'get', `${A}/tools`);
    expect(listed.status).toBe(200);
    const offered = new Set((listed.body.tools as Array<{ name: string }>).map((t) => t.name));
    // Only requirement-free reads (`authenticated`) stay for a user holding assistant:use alone.
    for (const name of offered) {
      expect(ENABLED_TOOLS.find((t) => t.name === name)?.requirement.mode, name).toBe(
        'authenticated',
      );
    }
    const missing = ENABLED_TOOLS.filter((t) => !offered.has(t.name));
    expect(missing.length).toBeGreaterThan(ENABLED_TOOLS.length - 5);
    // No write tool is offered without its permission (step AI-2).
    expect(ENABLED_WRITES.every((t) => !offered.has(t.name))).toBe(true);

    const runner = new TurnRunner(bare);
    const recorder = recordLoopback(ctx);
    try {
      for (const tool of missing) {
        recorder.calls.length = 0;
        const { res } = await runner.run(directive(tool.name, minimalArguments(tool)));
        expect(res.status, tool.name).toBe(200);
        const execution = res.body.executions[0];
        expect(execution, tool.name).toMatchObject({
          tool: tool.name,
          decision: 'denied_permission',
          status: 'refused',
          httpStatus: null,
          errorCode: 'denied_permission',
          card: null,
        });
        // The turn's only loopback request is its own context read.
        expect(
          recorder.calls.map((c) => c.path),
          tool.name,
        ).toEqual(['/api/v1/auth/me']);
        const row = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
          where: { publicId: execution.id as string },
        });
        expect(row.decision).toBe('denied_permission');
        const audit = await ctx.prisma.auditLog.findMany({
          where: { organizationId: org.id, resourceId: execution.id as string },
          select: { action: true },
        });
        expect(audit.map((a) => a.action)).toEqual(['assistant.tool_denied']);
        expect(
          await ctx.prisma.auditLog.count({ where: { correlationId: row.correlationId } }),
          tool.name,
        ).toBe(0);
      }
    } finally {
      recorder.restore();
    }
  }, 600_000);

  it('refuses tools a read_only_user lacks (session management, platform)', async () => {
    const listed = await call(ctx, reader.headers, 'get', `${A}/tools`);
    const names = new Set((listed.body.tools as Array<{ name: string }>).map((t) => t.name));
    expect(names.has('users_list')).toBe(true);
    for (const name of ['users_list_sessions', 'dead_letters_stats', 'ato_providers_connections']) {
      expect(names.has(name), name).toBe(false);
      const conversation = await newConversation(ctx, reader);
      const tool = ENABLED_TOOLS.find((t) => t.name === name)!;
      const res = await turn(
        ctx,
        reader.headers,
        conversation,
        directive(name, minimalArguments(tool)),
      );
      expect(res.status).toBe(200);
      expect(res.body.executions[0]).toMatchObject({ tool: name, decision: 'denied_permission' });
      expect(res.body.message.content).toBe('The request was not allowed: denied_permission.');
    }
  });
});
