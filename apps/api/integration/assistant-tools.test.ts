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
 * - Step AI-R (docs/plan/steps/31-ai-chat-reports.md D1, §9 item 5): the registry adds two
 *   NATIVE tools (not OpenAPI operations): the read sweep covers 180 enabled reads
 *   (`report_generate` builds a real report from the report APIs, stored in MinIO; this suite
 *   removes the objects), the catalogue of a `report:read` holder lists both native tools, and
 *   the write sweep covers 79 writes: `report_send_email` (in a conversation with a report) ends
 *   `pending_confirmation` with no delivery row and no outbox event.
 *
 * - Step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md D1, D11, I19, §9 item 3): the
 *   read sweep covers 186 enabled reads (the four new single reads `bec_trusted_senders_get`,
 *   `bec_feedback_get_suppression`, `dlp_exceptions_get`, `threat_indicators_get` and the two
 *   side-effect-free AI-4 reads `dlp_patterns_test`, `risk_dry_run_dry_run`), the write sweep all
 *   143 enabled writes (the 56 tenant AI-4 writes through turns, the eight platform operations
 *   through the executor, each platform write in its own conversation so the per-conversation
 *   pending cap never applies), and the platform-only tools are proven hidden (I19): a customer
 *   user holding every tenant permission is never offered one and a forced call is
 *   `denied_permission` with no loopback request for the operation and no operation audit row; a
 *   platform `super_admin` under an override into an `it-*` organization gets the same; the same
 *   user without an override is offered every one of them.
 *
 * - Step AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md D1, D7, §9 item 3): every
 *   planned tool of the program is enabled. The read sweep covers 188 enabled reads (the new
 *   single read `archive_admin_capture_issue` and the side-effect-free POST read
 *   `provider_mail_flow_preview`; `intake_sources_get` without its omitted `reveal` input), the
 *   write sweep all 168 enabled writes (the 25 archive, journaling, eDiscovery and
 *   provider-connection writes through turns; the impact preview POST is the only other
 *   side-effect-free request allowed), and a forced `intake_sources_get { reveal: 'true' }` is
 *   `denied_schema` with no loopback request and no `journal_intake.address_revealed` audit row.
 *
 * - Step API-1 (docs/plan/steps/35-api-mode-protection.md D15): the read sweep covers 197 enabled
 *   reads (the 9 API-mode reads, asserted by name; the sweep organization has an API-mode
 *   connection with a mailbox and a copy, so the lists answer rows); the 5 API-mode writes are
 *   not applicable until API-3, so the write sweep is unchanged (168).
 *
 * Synthetic `it-*` organizations only.
 */
// @covers get /api/v1/assistant/tools
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
import { createHash, randomUUID } from 'node:crypto';
import type { Response } from 'supertest';
import { FAKE_EXECUTABLES_DEFINITION } from '@email-gateway/assistant';
import { defaultBindingSettings } from '@email-gateway/idp-adapters';
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
  isImpactPreview,
  member,
  type Member,
  minimalArguments,
  newConversation,
  PLATFORM_ONLY_TOOLS,
  platformMember,
  principalOf,
  recordLoopback,
  trackReports,
  turn,
  withheldColumns,
} from './support/assistant';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { ApiModeTenantDataRepository } from '../src/modules/tenant-data/api-mode-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { deleteAtoRows } from './support/ato';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, uniqueIp } from './support/http';

/** Step API-1 (design 35 D15): the nine enabled API-mode read tools. */
const API_MODE_READS = [
  'protection_mode_get_organization',
  'api_mode_overview',
  'api_mode_list_connections',
  'api_mode_get_connection',
  'api_mode_setup_guide',
  'api_mode_list_mailboxes',
  'api_mode_get_mailbox',
  'api_mode_list_detections',
  'api_mode_get_detection',
];

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
  // Step AI-R: report_generate (read sweep) and the report of the write sweep (rows, objects).
  trackReports(ctx, fx, [org.id]);
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
  await seedApiMode(org);
}, 180_000);

/**
 * Step API-1: one bound Microsoft 365 connection with an API-mode row and a mailbox (the
 * mailbox-worker's rows), so the API-mode list reads of the sweep answer rows. Purged (API-mode
 * tables before the provider connections they reference) before the organization.
 */
async function seedApiMode(organization: FixtureOrganization): Promise<void> {
  const p = ctx.prisma;
  const connection = await p.providerConnection.create({
    data: {
      organizationId: organization.id,
      provider: 'microsoft_365',
      displayName: `Sweep ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b',
      activeTenantKey: `microsoft_365:${randomUUID()}`,
    },
    select: { id: true },
  });
  const api = await p.apiModeConnection.create({
    data: {
      publicId: randomUUID(),
      organizationId: organization.id,
      providerConnectionId: connection.id,
      provider: 'microsoft_365',
    },
    select: { id: true },
  });
  const mailbox = await p.apiMailbox.create({
    data: {
      publicId: randomUUID(),
      organizationId: organization.id,
      apiConnectionId: api.id,
      providerUserId: `sweep-${randomUUID()}`,
      primaryAddress: `sweep-${randomUUID().slice(0, 8)}@tools-it.test`,
      status: 'active',
    },
    select: { id: true, primaryAddress: true },
  });
  await p.apiMailboxAddress.create({
    data: {
      organizationId: organization.id,
      mailboxId: mailbox.id,
      address: mailbox.primaryAddress,
      kind: 'primary',
    },
  });
  fx.registerCleanup(async () => {
    await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(organization.id));
    await ctx.get(ProviderTenantDataRepository).purgeOrganization(systemScope(organization.id));
  });
}

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
    // Step AI-3: 257 enabled tools = 179 reads + 78 confirmable writes; step AI-R: 259 = 180
    // reads + 79 writes with the native `report_generate` and `report_send_email` (design 31 D1).
    // Step AI-4 (design 32 D1): 329 = 186 reads + 143 writes; step AI-5 (design 33 D1): 356 =
    // 188 reads + 168 writes (every planned tool of the program); step API-1 (design 35 D15):
    // 365 = 197 reads (the 9 API-mode reads) + 168 writes (its 5 writes are deferred to API-3).
    expect(ENABLED_READS).toHaveLength(197);
    expect(ENABLED_WRITES).toHaveLength(168);
    expect(ENABLED_TOOLS).toHaveLength(365);
    expect(ENABLED_TOOLS.filter((t) => t.native).map((t) => [t.name, t.access])).toEqual([
      ['report_generate', 'read'],
      ['report_send_email', 'write'],
    ]);
    expect(ENABLED_WRITES.map((t) => t.name)).toContain('webhooks_test');
    for (const name of [
      'policy_tools_validate',
      'policy_tools_test',
      'policy_tools_sample_dry_run',
      'policy_messages_dry_run',
      'api_keys_get',
      'report_generate',
      // Step AI-4: the four new single reads and the two side-effect-free AI-4 reads.
      'bec_trusted_senders_get',
      'bec_feedback_get_suppression',
      'dlp_exceptions_get',
      'threat_indicators_get',
      'dlp_patterns_test',
      'risk_dry_run_dry_run',
      // Step AI-5: the new single read and the side-effect-free mail-flow preview.
      'archive_admin_capture_issue',
      'provider_mail_flow_preview',
      // Step API-1 (D15): the API-mode reads.
      ...API_MODE_READS,
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
    // Step AI-R: a `report:read` holder is offered both native tools.
    expect(names).toEqual(expect.arrayContaining(['report_generate', 'report_send_email']));
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
    // Step API-1: every API-mode read ran through the api (the seeded rows of the sweep
    // organization answer the lists; unknown ids answer their coded 404).
    for (const name of API_MODE_READS) {
      const result = swept.find((r) => r.tool === name);
      expect(result, name).toBeDefined();
      expect(
        result!.status === 'succeeded' || result!.httpStatus === 404,
        `${name} ${JSON.stringify(result)}`,
      ).toBe(true);
    }
    for (const name of [
      'api_mode_overview',
      'api_mode_list_connections',
      'api_mode_list_mailboxes',
      'api_mode_list_detections',
      'protection_mode_get_organization',
    ]) {
      expect(swept.find((r) => r.tool === name)?.status, name).toBe('succeeded');
    }
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
const tag = (): string => randomUUID().slice(0, 8);
const inDays = (days: number): string => new Date(Date.now() + days * 86_400_000).toISOString();
/** Step AI-4: the synthetic platform catalog values of the write sweep (never stored). */
const SWEEP_HASH = createHash('sha256').update(`it-sweep-${randomUUID()}`).digest('hex');
const SWEEP_INDICATOR = `sweep-${randomUUID().slice(0, 8)}.tools-it.test`;
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
  // Step AI-R (design 31 D5): the native write, in a conversation that holds a report (the
  // latest report and the user's own address by default).
  report_send_email: () => ({}),
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
  // --- step AI-4 (design 32 D5): ATO, incidents, BEC, DLP, risk scoring (tenant) ---
  ato_accounts_update: () => ({
    accountId: unknown(),
    body: { protected: true, reason: sweepReason, expectedRowVersion: 1 },
  }),
  ato_account_mailbox_refresh: () => ({ accountId: unknown() }),
  ato_accounts_set_override: () => ({
    accountId: unknown(),
    body: { verdict: 'benign', reason: sweepReason, expiresInHours: 24 },
  }),
  ato_accounts_clear_override: () => ({ accountId: unknown(), body: { reason: sweepReason } }),
  ato_accounts_add_trusted_context: () => ({
    accountId: unknown(),
    body: { kind: 'country', value: 'DE', reason: sweepReason, expiresInDays: 30 },
  }),
  ato_accounts_remove_trusted_context: () => ({ accountId: unknown(), contextId: unknown() }),
  ato_responses_request: () => ({
    incidentId: unknown(),
    body: { actionType: 'restrict_smtp_sending', reason: sweepReason },
  }),
  ato_responses_approve: () => ({ responseId: unknown(), body: { reason: sweepReason } }),
  ato_responses_reject: () => ({ responseId: unknown(), body: { reason: sweepReason } }),
  ato_responses_cancel: () => ({ responseId: unknown(), body: { reason: sweepReason } }),
  ato_responses_rollback: () => ({ responseId: unknown(), body: { reason: sweepReason } }),
  ato_settings_update: () => ({ body: { expectedRowVersion: 0, settings: {} } }),
  // The selected connection of the connections list is required: not found → 404.
  ato_providers_create: () => ({ body: { connectionId: unknown() } }),
  ato_providers_update: () => ({
    integrationId: unknown(),
    body: { rowVersion: 1, settings: defaultBindingSettings() },
  }),
  ato_providers_remove: () => ({ integrationId: unknown(), body: { reason: sweepReason } }),
  ato_providers_backfill: () => ({ integrationId: unknown(), body: { from: inDays(-1) } }),
  ato_providers_health_check: () => ({ integrationId: unknown() }),
  ato_providers_pause: () => ({ integrationId: unknown(), body: { reason: sweepReason } }),
  ato_providers_resume: () => ({ integrationId: unknown() }),
  incidents_create: () => ({
    body: {
      category: 'account_takeover',
      subject: { type: 'ato_account', id: unknown() },
      reason: sweepReason,
    },
  }),
  incidents_update: () => ({
    incidentId: unknown(),
    body: { status: 'investigating', expectedRowVersion: 1 },
  }),
  incidents_add_note: () => ({ incidentId: unknown(), body: { note: sweepReason } }),
  bec_executives_create: () => ({ body: { displayName: `Sweep Executive ${tag()}` } }),
  bec_executives_update: () => ({ id: unknown(), body: { version: 1, title: 'CFO' } }),
  bec_executives_remove: () => ({ id: unknown() }),
  bec_trusted_senders_create: () => ({
    body: { kind: 'address', value: `sweep-${tag()}@partner.example`, reason: sweepReason },
  }),
  bec_trusted_senders_update: () => ({ id: unknown(), body: { version: 1, reason: sweepReason } }),
  bec_trusted_senders_remove: () => ({ id: unknown() }),
  bec_vendors_create: () => ({
    body: { name: `Sweep Vendor ${tag()}`, domains: [`sweep-${tag()}.example`] },
  }),
  bec_vendors_update: () => ({ id: unknown(), body: { version: 1, name: 'it sweep' } }),
  bec_vendors_remove: () => ({ id: unknown() }),
  bec_feedback_delete_suppression: () => ({ id: unknown() }),
  bec_message_feedback_record: () => ({
    messageId: unknown(),
    scanId: '1',
    body: { kind: 'false_negative' },
  }),
  dlp_compliance_enable: () => ({
    body: {
      expectedVersion: 0,
      basis: 'uidai_authorised_entity',
      reference: 'Sweep reference',
      attested: true,
      reviewDueAt: inDays(200),
    },
  }),
  dlp_compliance_disable: () => ({}),
  dlp_dictionaries_create: () => ({
    body: { name: `Sweep ${tag()}`, category: 'custom', terms: ['sweepterm'], severity: 'low' },
  }),
  dlp_dictionaries_update: () => ({ id: unknown(), body: { version: 1, name: 'it sweep' } }),
  dlp_dictionaries_remove: () => ({ id: unknown() }),
  dlp_exceptions_create: () => ({
    body: {
      scope: 'sender_address',
      value: `sweep-${tag()}@partner.example`,
      reason: sweepReason,
      expiresAt: inDays(30),
    },
  }),
  dlp_exceptions_update: () => ({ id: unknown(), body: { version: 1, reason: sweepReason } }),
  dlp_exceptions_remove: () => ({ id: unknown() }),
  dlp_patterns_create: () => ({
    body: { name: `Sweep ${tag()}`, pattern: `SWEEP${tag()}-[0-9]{6}`, severity: 'low' },
  }),
  dlp_patterns_update: () => ({ id: unknown(), body: { version: 1, name: 'it sweep' } }),
  dlp_patterns_remove: () => ({ id: unknown() }),
  dlp_policies_create: () => ({ body: { name: `Sweep ${tag()}` } }),
  dlp_policies_update: () => ({ id: unknown(), body: { version: 1, name: 'it sweep' } }),
  dlp_policies_remove: () => ({ id: unknown() }),
  dlp_policies_create_rule: () => ({
    id: unknown(),
    body: {
      name: 'it sweep',
      conditions: { selectors: { categories: ['payment_card'] } },
      action: 'alert',
    },
  }),
  dlp_policies_update_rule: () => ({
    id: unknown(),
    ruleId: unknown(),
    body: { version: 1, name: 'it sweep' },
  }),
  dlp_policies_remove_rule: () => ({ id: unknown(), ruleId: unknown() }),
  risk_profiles_create_draft: () => ({ body: { overrides: {} } }),
  risk_profiles_update_draft: () => ({
    versionId: unknown(),
    body: { overrides: {}, expectedRowVersion: 1 },
  }),
  risk_profiles_delete_draft: () => ({ versionId: unknown() }),
  risk_profiles_publish: () => ({ versionId: unknown(), body: { expectedRowVersion: 1 } }),
  // The precondition is the organization's profile (not the version): a pending proposal.
  risk_profiles_activate: () => ({ versionId: unknown() }),
  risk_profiles_reset: () => ({}),
  // Step AI-4 platform-only operations (an it-* organization; dry runs; synthetic values).
  attachment_rescans_request: () => ({
    body: { windowHours: 1, organizationId: org.publicId, reason: sweepReason, dryRun: true },
  }),
  attachment_rescans_cancel: () => ({ jobId: unknown(), body: { reason: sweepReason } }),
  dead_letters_replay: () => ({
    body: { sourceQueue: 'email.received', limit: 1, reason: sweepReason, dryRun: true },
  }),
  scan_training_train: () => ({
    organizationId: org.publicId,
    messageId: unknown(),
    body: { operation: 'fuzzy_add', fuzzyFlag: 'spam', reason: sweepReason },
  }),
  threat_hashes_add: () => ({ body: { sha256: SWEEP_HASH, severity: 'low', reason: sweepReason } }),
  // The selected hash of the exact-filter list is required: not found → 404.
  threat_hashes_remove: () => ({ sha256: SWEEP_HASH, reason: sweepReason }),
  threat_indicators_add: () => ({
    body: {
      type: 'domain',
      value: SWEEP_INDICATOR,
      severity: 'low',
      category: 'spam',
      reason: sweepReason,
    },
  }),
  threat_indicators_remove: () => ({ id: '999999999999', reason: sweepReason }),
  // --- step AI-5 (design 33 D1, D6): archive, journaling, eDiscovery, provider connections ---
  archive_retention_create: () => ({ body: { name: `it sweep ${tag()}`, retentionDays: 30 } }),
  archive_retention_update: () => ({
    policyId: unknown(),
    body: { expectedRowVersion: 1, name: 'it sweep', retentionDays: 30 },
  }),
  archive_retention_delete: () => ({ policyId: unknown() }),
  archive_admin_retry: () => ({ messageId: unknown() }),
  // The organization's own settings (no row yet: rowVersion 0): a pending proposal.
  archive_admin_update: () => ({ body: { expectedRowVersion: 0, enabled: true } }),
  journaling_update: () => ({ body: { expectedRowVersion: 0, enabled: true } }),
  intake_sources_update: () => ({
    sourceId: unknown(),
    body: { expectedRowVersion: 1, displayName: 'it sweep' },
  }),
  intake_sources_disable: () => ({ sourceId: unknown() }),
  intake_sources_attest: () => ({
    sourceId: unknown(),
    body: { code: 'journal.onprem.journal_recipient_created', attested: true },
  }),
  ediscovery_cases_create: () => ({ body: { name: `it sweep ${tag()}` } }),
  ediscovery_cases_update: () => ({
    caseId: unknown(),
    body: { expectedRowVersion: 1, name: 'it sweep' },
  }),
  ediscovery_cases_close: () => ({ caseId: unknown() }),
  ediscovery_cases_create_hold: () => ({
    caseId: unknown(),
    body: { name: 'it sweep', reason: sweepReason },
  }),
  ediscovery_searches_create: () => ({
    caseId: unknown(),
    body: { criteria: { from: inDays(-1), to: inDays(0) } },
  }),
  ediscovery_searches_review: () => ({
    caseId: unknown(),
    searchId: unknown(),
    body: { tag: 'relevant', messageIds: [unknown()] },
  }),
  ediscovery_exports_create: () => ({ caseId: unknown(), body: { searchId: unknown() } }),
  provider_connections_create: () => ({
    body: { provider: 'microsoft_365', displayName: `it sweep ${tag()}` },
  }),
  provider_connections_update: () => ({
    id: unknown(),
    body: { displayName: 'it sweep', rowVersion: 1 },
  }),
  // The impact token and `confirm` are server-filled (D5): only the id.
  provider_connections_disconnect: () => ({ id: unknown() }),
  provider_attestations_record: () => ({
    id: unknown(),
    body: { code: 'm365.inbound_connector_created', attested: true },
  }),
  provider_domains_replace: () => ({ id: unknown(), body: { domainIds: [] } }),
  provider_grants_revoke: () => ({ id: unknown(), profile: 'm365.mail_flow' }),
  provider_grants_verify: () => ({ id: unknown(), profile: 'm365.mail_flow', body: {} }),
  provider_health_check_now: () => ({ id: unknown() }),
  provider_mail_flow_apply: () => ({ id: unknown(), body: { change: { kind: 'suspend' } } }),
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
    // Step AI-4: ATO, incidents, BEC, DLP, risk scoring and the platform catalogs (counts and
    // rows; the live ato-worker may add sign-in accounts and settings, which no tool writes).
    incidents: sha(await p.securityIncident.findMany({ where, orderBy })),
    atoResponses: sha(await p.atoResponseAction.findMany({ where, orderBy })),
    atoContexts: sha(await p.atoTrustedContext.findMany({ where, orderBy })),
    atoOverrides: sha(await p.atoRiskOverride.findMany({ where, orderBy })),
    atoProviders: sha(await p.atoProviderIntegration.findMany({ where, orderBy })),
    atoSettingsVersions: String(await p.atoSettingsVersion.count({ where })),
    becExecutives: sha(await p.becExecutiveProfile.findMany({ where, orderBy })),
    becVendors: sha(await p.becVendorProfile.findMany({ where, orderBy })),
    becTrusted: sha(await p.becTrustedSender.findMany({ where, orderBy })),
    becFeedback: sha(await p.becFeedback.findMany({ where, orderBy })),
    becSuppressions: sha(await p.becSuppressionRule.findMany({ where, orderBy })),
    dlpPolicies: sha(await p.dlpPolicy.findMany({ where, orderBy })),
    dlpRules: sha(await p.dlpPolicyRule.findMany({ where, orderBy })),
    dlpExceptions: sha(await p.dlpException.findMany({ where, orderBy })),
    dlpPatterns: sha(await p.dlpCustomPattern.findMany({ where, orderBy })),
    dlpDictionaries: sha(await p.dlpKeywordDictionary.findMany({ where, orderBy })),
    dlpCompliance: sha(await p.dlpComplianceSettings.findMany({ where })),
    riskVersions: sha(await p.riskScoringProfileVersion.findMany({ where, orderBy })),
    riskProfile: sha(await p.riskScoringProfile.findMany({ where })),
    rescanJobs: String(await p.attachmentRescanJob.count({ where })),
    sweepHash: String(await p.malwareSignature.count({ where: { sha256: SWEEP_HASH } })),
    sweepIndicator: String(await p.threatIndicator.count({ where: { value: SWEEP_INDICATOR } })),
    sweepOrganizations: String(
      await p.organization.count({ where: { slug: { startsWith: 'it-sweep-' } } }),
    ),
    // Step AI-5: archive, journaling, eDiscovery and provider connections.
    retentionPolicies: sha(await p.archiveRetentionPolicy.findMany({ where, orderBy })),
    archiveSettings: sha(await p.archiveSetting.findMany({ where })),
    captureIntents: sha(await p.archiveCaptureIntent.findMany({ where, orderBy })),
    intakeSources: sha(await p.journalIntakeSource.findMany({ where, orderBy })),
    cases: sha(await p.ediscoveryCase.findMany({ where, orderBy })),
    legalHolds: sha(await p.archiveLegalHold.findMany({ where, orderBy })),
    searches: sha(await p.ediscoverySearch.findMany({ where, orderBy })),
    exports: sha(await p.ediscoveryExport.findMany({ where, orderBy })),
    providerConnections: sha(await p.providerConnection.findMany({ where, orderBy })),
    providerGrants: sha(await p.providerConnectionGrant.findMany({ where, orderBy })),
    providerDomains: sha(await p.providerConnectionDomain.findMany({ where, orderBy })),
  };
}

describe('no write without confirmation: every enabled write (§9 item 4)', () => {
  it('ends pending_confirmation, a coded proposal failure or denied_guard; nothing reaches a write route', async () => {
    expect(Object.keys(WRITE_SAMPLES).sort()).toEqual(ENABLED_WRITES.map((t) => t.name).sort());
    const tenantWrites = ENABLED_WRITES.filter((t) => !t.platformOnly);
    const platformWrites = ENABLED_WRITES.filter((t) => t.platformOnly);
    // Step AI-3: the platform-only organization writes (D6); step AI-4: the eight platform
    // operations (design 32 D5 #57–64).
    expect(platformWrites.map((t) => t.name).sort()).toEqual([
      'attachment_rescans_cancel',
      'attachment_rescans_request',
      'dead_letters_replay',
      'organization_configuration_override_feature',
      'organization_configuration_override_limit',
      'organization_configuration_reset_feature',
      'organization_configuration_reset_limit',
      'organization_deletion_cancel',
      'organizations_create',
      'scan_training_train',
      'threat_hashes_add',
      'threat_hashes_remove',
      'threat_indicators_add',
      'threat_indicators_remove',
    ]);
    const platformAdmin = await platformMember(ctx, fx, ['super_admin']);
    const platformPrincipal = await principalOf(ctx, platformAdmin.token);
    // Step AI-R: report_send_email needs a report of its conversation (generated before the
    // snapshot: a report is not a write target of the sweep; its delivery would be).
    const reportConversation = await newConversation(ctx, sweepers[0]!);
    const generated = await turn(
      ctx,
      sweepers[0]!.headers,
      reportConversation,
      directive('report_generate', { sections: ['traffic'] }),
    );
    expect(generated.body.executions[0]).toMatchObject({ status: 'succeeded', httpStatus: 201 });
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
        const message = directive(tool.name, WRITE_SAMPLES[tool.name]!());
        const { res } =
          tool.name === 'report_send_email'
            ? { res: await turn(ctx, sweepers[0]!.headers, reportConversation, message) }
            : await runner.run(message);
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
        // One conversation per platform write: the pending cap is per conversation.
        const executor = new DirectExecutor(ctx, platformAdmin, platformPrincipal, org);
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
    // Only side-effect-free requests were sent: reads, the definition validation and (step AI-5
    // D5) the impact preview of a mail-flow apply or disconnect.
    const sent = recorder.calls.filter(
      (c) =>
        !(
          c.method === 'GET' ||
          (c.method === 'POST' && c.path === '/api/v1/policies/validate') ||
          isImpactPreview(c)
        ),
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
    // Step AI-R: the proposed report email queued nothing.
    expect(await ctx.prisma.aiChatReportDelivery.count({ where: { organizationId: org.id } })).toBe(
      0,
    );
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
        // Step AI-R: the native report email (the conversation's report, the own address).
        'report_send_email',
        // Step AI-4: creates without a record to read, reads of the organization's own
        // settings / compliance / profile, and the platform operations without a precondition.
        'bec_executives_create',
        'bec_trusted_senders_create',
        'bec_vendors_create',
        'dlp_dictionaries_create',
        'dlp_exceptions_create',
        'dlp_patterns_create',
        'dlp_policies_create',
        'dlp_compliance_enable',
        'dlp_compliance_disable',
        'risk_profiles_create_draft',
        'risk_profiles_activate',
        'risk_profiles_reset',
        'ato_settings_update',
        'attachment_rescans_request',
        'dead_letters_replay',
        'scan_training_train',
        'threat_hashes_add',
        'threat_indicators_add',
        // Step AI-5: creates without a record to read and the organization's own settings.
        'archive_retention_create',
        'archive_admin_update',
        'journaling_update',
        'ediscovery_cases_create',
        'provider_connections_create',
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

describe('step AI-4: platform-only tools never reach tenant principals (D11, I19)', () => {
  /**
   * Forces every platform-only tool by directive through `runner`: each is `denied_permission`
   * with the turn's own context read as the only loopback request, no card, the denial audited
   * and no operation audit row under the execution's correlation id.
   */
  async function expectAllDenied(
    run: (message: string) => Promise<{ res: Response }>,
    organizationId: bigint,
  ): Promise<void> {
    const recorder = recordLoopback(ctx);
    try {
      for (const tool of PLATFORM_ONLY_TOOLS) {
        recorder.calls.length = 0;
        const { res } = await run(directive(tool.name, minimalArguments(tool, { bound: false })));
        expect(res.status, tool.name).toBe(200);
        const execution = res.body.executions[0];
        expect(execution, tool.name).toMatchObject({
          tool: tool.name,
          decision: 'denied_permission',
          status: 'refused',
          httpStatus: null,
          card: null,
        });
        expect(res.body.confirmations, tool.name).toEqual([]);
        expect(
          recorder.calls.map((c) => c.path),
          tool.name,
        ).toEqual(['/api/v1/auth/me']);
        const row = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
          where: { publicId: execution.id as string },
        });
        expect(row.organizationId).toBe(organizationId);
        const audit = await ctx.prisma.auditLog.findMany({
          where: { organizationId, resourceId: execution.id as string },
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
  }

  it('a customer user holding every tenant permission is offered none; forced calls are denied_permission', async () => {
    // Step AI-4: eight platform writes and the platform reads (design 32 D11).
    expect(PLATFORM_ONLY_TOOLS.map((t) => t.name)).toEqual(
      expect.arrayContaining([
        'attachment_rescans_request',
        'attachment_rescans_cancel',
        'attachment_rescans_list',
        'attachment_rescans_get',
        'dead_letters_replay',
        'dead_letters_stats',
        'scan_training_train',
        'threat_hashes_add',
        'threat_hashes_remove',
        'threat_hashes_list',
        'threat_indicators_add',
        'threat_indicators_remove',
        'threat_indicators_list',
        'threat_indicators_get',
        'platform_audit_logs_search',
      ]),
    );
    const listed = await call(ctx, sweepers[0]!.headers, 'get', `${A}/tools`);
    expect(listed.status).toBe(200);
    const names = (listed.body.tools as Array<{ name: string }>).map((t) => t.name);
    expect(names.filter((n) => PLATFORM_ONLY_TOOLS.some((t) => t.name === n))).toEqual([]);
    const runner = new TurnRunner(sweepers);
    await expectAllDenied((message) => runner.run(message), org.id);
  }, 300_000);

  it('a platform super_admin under an override into an it-* organization: none offered, every forced call denied', async () => {
    const admin = await platformMember(ctx, fx, ['super_admin']);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(admin.headers)
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: org.publicId, reason: 'Assistant platform-tool hiding check' });
    expect(started.status, JSON.stringify(started.body)).toBe(201);
    const overrideId = started.body.overrideId as string;
    const override = bearer(started.body.accessToken as string);
    try {
      const listed = await call(ctx, override, 'get', `${A}/tools`);
      expect(listed.status).toBe(200);
      const names = (listed.body.tools as Array<{ name: string }>).map((t) => t.name);
      expect(names).toContain('users_list');
      expect(names.filter((n) => PLATFORM_ONLY_TOOLS.some((t) => t.name === n))).toEqual([]);
      let conversation = '';
      let turns = 0;
      await expectAllDenied(async (message) => {
        if (turns++ % TURNS_PER_CONVERSATION === 0) {
          conversation = await newConversation(ctx, override);
        }
        return { res: await turn(ctx, override, conversation, message) };
      }, org.id);
    } finally {
      await ctx.http
        .delete(`/api/v1/platform/overrides/${overrideId}`)
        .set(admin.headers)
        .set('X-Forwarded-For', uniqueIp());
    }
    // Without the override the same user is offered every platform-only tool.
    const home = await call(ctx, admin.headers, 'get', `${A}/tools`);
    const offered = new Set((home.body.tools as Array<{ name: string }>).map((t) => t.name));
    for (const tool of PLATFORM_ONLY_TOOLS) expect(offered.has(tool.name), tool.name).toBe(true);
  }, 300_000);
});

describe('step AI-5: omitted inputs (D7, I23)', () => {
  it('a forced intake_sources_get { reveal: "true" } is denied_schema: no loopback request, no reveal audited', async () => {
    const tool = ENABLED_READS.find((t) => t.name === 'intake_sources_get')!;
    expect(Object.keys((tool.inputSchema as { properties: object }).properties)).toEqual([
      'sourceId',
    ]);
    const sourceId = unknown();
    const conversation = await newConversation(ctx, sweepers[0]!);
    const recorder = recordLoopback(ctx);
    let forced: Response;
    let plain: Response;
    try {
      forced = await turn(
        ctx,
        sweepers[0]!.headers,
        conversation,
        directive('intake_sources_get', { sourceId, reveal: 'true' }),
      );
      expect(recorder.calls.filter((c) => c.path.startsWith('/api/v1/journaling/'))).toEqual([]);
      // Without the omitted input the same tool reaches the api (an unknown source: 404).
      plain = await turn(
        ctx,
        sweepers[0]!.headers,
        conversation,
        directive('intake_sources_get', { sourceId }),
      );
    } finally {
      recorder.restore();
    }
    expect(forced.body.executions[0]).toMatchObject({
      tool: 'intake_sources_get',
      decision: 'denied_schema',
      status: 'refused',
    });
    expect(plain.body.executions[0]).toMatchObject({
      tool: 'intake_sources_get',
      decision: 'allowed',
      status: 'failed',
      httpStatus: 404,
    });
    expect(
      recorder.calls
        .filter((c) => c.path.startsWith('/api/v1/journaling/'))
        .map((c) => `${c.method} ${c.path}`),
    ).toEqual([`GET /api/v1/journaling/intake-sources/${sourceId}`]);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: org.id, action: 'journal_intake.address_revealed' },
      }),
    ).toBe(0);
  });
});
