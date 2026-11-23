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
 * - Step AI-3 (docs/plan/steps/30-ai-chat-identity-tenant-admin.md D1, §9 item 4): the read sweep
 *   covers 179 enabled reads (`api_keys_get` added; `webhooks_test` became a write), and the "no
 *   write without confirmation" sweep covers all 78 enabled writes: the tenant writes through
 *   turns, the platform-only organization writes (create, deletion cancel, feature and limit
 *   override/reset) through the executor as a platform `super_admin` with explicit `it-*`
 *   organization ids. Each ends `pending_confirmation`, a coded proposal failure or
 *   `denied_guard` (the assistant's own feature), no request reaches a write route, no operation
 *   audit row carries the executions' correlation ids and the identity and tenant administration
 *   tables of the organization are unchanged.
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
    // Step AI-3: 257 enabled tools = 179 reads + 78 confirmable writes.
    expect(ENABLED_READS).toHaveLength(179);
    expect(ENABLED_WRITES).toHaveLength(78);
    expect(ENABLED_TOOLS).toHaveLength(257);
    expect(ENABLED_WRITES.map((t) => t.name)).toContain('webhooks_test');
    for (const name of [
      'policy_tools_validate',
      'policy_tools_test',
      'policy_tools_sample_dry_run',
      'policy_messages_dry_run',
      'api_keys_get',
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
  // --- step AI-3 (design 30 D1): identity and tenant administration ---
  users_invite: () => ({
    body: {
      email: `sweep-${randomUUID().slice(0, 8)}@example.test`,
      displayName: 'Sweep invitee',
      roleKeys: ['read_only_user'],
    },
  }),
  users_update: () => ({ id: unknown(), body: { displayName: 'it sweep' } }),
  users_change_status: () => ({
    id: unknown(),
    body: { status: 'disabled', reason: sweepReason },
  }),
  users_replace_roles: () => ({ id: unknown(), body: { roleKeys: ['read_only_user'] } }),
  users_reset_mfa: () => ({ id: unknown() }),
  users_remove: () => ({ id: unknown() }),
  users_resend_invitation: () => ({ id: unknown() }),
  users_revoke_all_sessions: () => ({ id: unknown() }),
  users_revoke_session: () => ({ id: unknown(), sessionId: unknown() }),
  roles_create: () => ({
    body: {
      key: `it_sweep_${randomUUID().slice(0, 8)}`,
      name: 'Sweep role',
      permissions: ['message:read'],
    },
  }),
  roles_update: () => ({
    key: 'it_unknown_role',
    body: { name: 'it sweep', permissions: ['message:read'] },
  }),
  roles_remove: () => ({ key: 'it_unknown_role' }),
  departments_create: () => ({ body: { name: `it sweep ${randomUUID().slice(0, 8)}` } }),
  departments_update: () => ({
    departmentId: unknown(),
    body: { name: 'it sweep', expectedRowVersion: 1 },
  }),
  departments_remove: () => ({ departmentId: unknown() }),
  departments_add_member: () => ({ departmentId: unknown(), body: { userId: unknown() } }),
  departments_remove_member: () => ({ departmentId: unknown(), memberId: unknown() }),
  api_keys_revoke: () => ({ id: unknown() }),
  domains_create: () => ({ body: { name: `sweep-${randomUUID().slice(0, 8)}.domains-it.test` } }),
  domains_remove: () => ({ id: unknown() }),
  domains_change_status: () => ({ id: unknown(), body: { status: 'active' } }),
  domain_dns_verify: () => ({ id: unknown() }),
  domain_dns_rotate: () => ({ id: unknown() }),
  domain_destinations_replace: () => ({ id: unknown(), body: { provider: 'google_workspace' } }),
  domain_destinations_remove: () => ({ id: unknown() }),
  domain_recipients_set: () => ({ id: unknown(), body: { mode: 'accept_all' } }),
  domain_recipients_add: () => ({ id: unknown(), body: { localParts: ['sweep'] } }),
  domain_recipients_remove: () => ({ id: unknown(), body: { localParts: ['sweep'] } }),
  notifications_put_preferences: () => ({ body: { optOut: [], quarantineDigestOptOut: false } }),
  notifications_put_settings: () => ({ body: { settings: {}, expectedRowVersion: 0 } }),
  organizations_update: () => ({ body: { name: 'it sweep organization' } }),
  organization_configuration_update_settings: () => ({ body: { timezone: 'UTC' } }),
  scan_settings_replace: () => ({
    engine: 'rspamd',
    body: { expectedVersion: 0, settings: { spamScore: 8 } },
  }),
  scan_settings_reset: () => ({ engine: 'rspamd' }),
  smtp_connectors_update: () => ({ id: unknown(), body: { name: 'it sweep' } }),
  smtp_connectors_remove: () => ({ id: unknown() }),
  webhooks_update: () => ({
    webhookId: unknown(),
    body: { name: 'it sweep', expectedRowVersion: 1 },
  }),
  webhooks_delete: () => ({ webhookId: unknown() }),
  webhooks_test: () => ({ webhookId: unknown() }),
  webhook_deliveries_replay: () => ({ webhookId: unknown(), deliveryId: unknown() }),
  webhook_deliveries_create_replay: () => ({
    webhookId: unknown(),
    body: { from: new Date(Date.now() - 3_600_000).toISOString(), to: new Date().toISOString() },
  }),
  // Platform-only (the executor as a platform super_admin; always an explicit it-* id).
  organizations_create: () => ({
    body: {
      name: 'it sweep organization',
      slug: `it-sweep-${randomUUID().slice(0, 8)}`,
      planCode: 'standard',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
    },
  }),
  organization_deletion_cancel: () => ({ id: org.publicId, body: { reason: sweepReason } }),
  organization_configuration_override_feature: () => ({
    id: org.publicId,
    featureKey: 'dlp',
    body: { enabled: false },
  }),
  // The assistant's own feature: a proposal guard refuses it (denied_guard).
  organization_configuration_reset_feature: () => ({
    id: org.publicId,
    featureKey: 'ai_assistant',
  }),
  organization_configuration_override_limit: () => ({
    id: org.publicId,
    limitKey: 'max_users',
    body: { value: 100 },
  }),
  // An organization that does not exist: the selected-item read's 404.
  organization_configuration_reset_limit: () => ({ id: unknown(), limitKey: 'max_users' }),
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
    // Sign-in bookkeeping of the suite's own logins (`auth.login.recorded.v1`, and the live
    // ato-worker's `ato.*` events about them: ato_detection is on) can land at any time; neither
    // is a write of a tool (the correlation check below covers the tools' own events).
    outbox: String(
      await p.messageOutbox.count({
        where: {
          ...where,
          NOT: [{ eventType: { startsWith: 'auth.' } }, { eventType: { startsWith: 'ato.' } }],
        },
      }),
    ),
    // Step AI-3: identity and tenant administration (stable columns only: sign-ins of the
    // suite's users update session and last-login bookkeeping).
    users: sha(
      await p.user.findMany({
        where,
        orderBy,
        select: {
          id: true,
          email: true,
          displayName: true,
          status: true,
          mfaEnabled: true,
          deletedAt: true,
          lockedUntil: true,
        },
      }),
    ),
    userRoles: sha(await p.userRole.findMany({ where, orderBy: { userId: 'asc' } })),
    roles: sha(await p.role.findMany({ where, orderBy, include: { permissions: true } })),
    departments: sha(await p.tenantDepartment.findMany({ where, orderBy })),
    departmentMembers: sha(await p.tenantDepartmentMember.findMany({ where, orderBy })),
    apiKeys: sha(await p.apiKey.findMany({ where, orderBy })),
    domains: sha(await p.domain.findMany({ where, orderBy })),
    notificationSettings: sha(await p.notificationSettings.findMany({ where })),
    notificationPreferences: sha(await p.notificationUserPreference.findMany({ where })),
    organization: sha(
      await p.organization.findUniqueOrThrow({
        where: { id: org.id },
        select: { name: true, status: true, planId: true, deletionRequestedAt: true },
      }),
    ),
    organizationSettings: sha(await p.organizationSetting.findMany({ where })),
    features: sha(await p.organizationFeature.findMany({ where, orderBy: { featureKey: 'asc' } })),
    limits: sha(await p.organizationLimit.findMany({ where, orderBy: { limitKey: 'asc' } })),
    scanSettings: sha(await p.scanEngineSetting.findMany({ where, orderBy })),
    connectors: sha(await p.smtpConnector.findMany({ where, orderBy })),
    webhooks: sha(await p.webhookSubscription.findMany({ where, orderBy })),
    webhookDeliveries: String(await p.webhookDelivery.count({ where })),
    sweepOrganizations: String(
      await p.organization.count({ where: { slug: { startsWith: 'it-sweep-' } } }),
    ),
  };
}

describe('no write without confirmation: every enabled write (§9 item 4)', () => {
  it('ends pending_confirmation, a coded proposal failure or denied_guard; nothing reaches a write route', async () => {
    expect(Object.keys(WRITE_SAMPLES).sort()).toEqual(ENABLED_WRITES.map((t) => t.name).sort());
    const tenantWrites = ENABLED_WRITES.filter((t) => !t.platformOnly);
    const platformWrites = ENABLED_WRITES.filter((t) => t.platformOnly);
    // Step AI-3: the platform-only organization writes (D6).
    expect(platformWrites.map((t) => t.name).sort()).toEqual([
      'organization_configuration_override_feature',
      'organization_configuration_override_limit',
      'organization_configuration_reset_feature',
      'organization_configuration_reset_limit',
      'organization_deletion_cancel',
      'organizations_create',
    ]);
    const platformAdmin = await platformMember(ctx, fx, ['super_admin']);
    const executor = new DirectExecutor(
      ctx,
      platformAdmin,
      await principalOf(ctx, platformAdmin.token),
      org,
    );
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
      for (const tool of tenantWrites) {
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
      for (const tool of platformWrites) {
        const outcome = await executor.execute(tool.name, WRITE_SAMPLES[tool.name]!());
        const row = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
          where: { publicId: outcome.executionId },
        });
        results.push({
          tool: tool.name,
          decision: outcome.decision,
          status: outcome.status,
          httpStatus: outcome.httpStatus,
          errorCode: outcome.errorCode,
          correlationId: row.correlationId,
        });
        expect(outcome.confirmation !== null, tool.name).toBe(
          outcome.status === 'pending_confirmation',
        );
      }
    } finally {
      recorder.restore();
    }
    const problems = results.filter(
      (r) =>
        !(
          (r.decision === 'allowed' &&
            r.status === 'pending_confirmation' &&
            r.httpStatus === null) ||
          (r.decision === 'allowed' &&
            r.status === 'failed' &&
            r.httpStatus !== null &&
            r.httpStatus >= 400 &&
            r.httpStatus < 500 &&
            r.errorCode !== null) ||
          (r.decision === 'denied_guard' && r.status === 'refused')
        ),
    );
    expect(problems, JSON.stringify(problems, null, 1)).toEqual([]);
    expect(results).toHaveLength(ENABLED_WRITES.length);
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
        where: { correlationId: r.correlationId },
        select: { action: true },
      });
      expect(
        audited.map((a) => a.action).filter((action) => !action.startsWith('assistant.')),
        r.tool,
      ).toEqual([]);
    }
    // No event of any operation carries the executions' correlation ids either.
    expect(
      await ctx.prisma.messageOutbox.count({
        where: { correlationId: { in: results.map((r) => r.correlationId) } },
      }),
    ).toBe(0);
    expect(await writeTargets()).toEqual(before);
    const pending = results.filter((r) => r.status === 'pending_confirmation').map((r) => r.tool);
    expect(pending).toEqual(
      expect.arrayContaining([
        'policy_management_create',
        'policy_settings_put',
        'quarantine_tools_put_settings',
        'recipient_suppressions_create',
        'saved_views_create',
        // Step AI-3: writes without a record to read, or whose read is the organization's own.
        'users_invite',
        'roles_create',
        'departments_create',
        'domains_create',
        'notifications_put_preferences',
        'notifications_put_settings',
        'organizations_update',
        'organization_configuration_update_settings',
        'scan_settings_replace',
        'scan_settings_reset',
        'organizations_create',
        'organization_configuration_override_feature',
        'organization_configuration_override_limit',
      ]),
    );
    expect(results.filter((r) => r.decision === 'denied_guard').map((r) => r.tool)).toEqual([
      'organization_configuration_reset_feature',
    ]);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: { organizationId: org.id, status: 'pending' },
      }),
    ).toBe(pending.length);
    // eslint-disable-next-line no-console -- the sweep reports its count and outcomes (§9 item 4)
    console.info(
      `[assistant-tools] swept ${results.length} enabled writes ` +
        `(${tenantWrites.length} tenant, ${platformWrites.length} platform): ${pending.length} ` +
        `pending confirmation (${pending.join(', ')}); refused proposals: ` +
        results
          .filter((r) => r.status !== 'pending_confirmation')
          .map(
            (r) =>
              `${r.tool} ${r.decision === 'allowed' ? `${r.httpStatus} ${r.errorCode}` : r.decision}`,
          )
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
    // No write tool is offered without its permission (step AI-2); step AI-3: the caller's own
    // notification preferences need no permission (requirement `authenticated`).
    expect(ENABLED_WRITES.filter((t) => offered.has(t.name)).map((t) => t.name)).toEqual([
      'notifications_put_preferences',
    ]);

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
