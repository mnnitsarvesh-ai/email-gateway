/**
 * Step AI-3 tenant administration tools through chat (docs/plan/steps/30-ai-chat-identity-
 * tenant-admin.md D2–D6, D10, §9 item 4; the `testedBy` of the 19 notification, organization,
 * scan-settings, SMTP connector and webhook writes in docs/assistant/UI_TO_CHAT_CAPABILITY_
 * MATRIX.md). The deterministic fake provider proposes every write (never a real LLM); the api
 * listens on its ephemeral loopback port, so precondition reads, confirm-time re-reads and the
 * confirmed writes go through the real `/api/v1` pipeline; the api's state and the operation's
 * own audit row (correlated to the result execution) are asserted on the writer.
 *
 * - As a customer `organization_admin` (directive turns + the confirm route): notification
 *   preferences (low) and settings (medium, `expectedRowVersion` injected with minimum 0);
 *   `organizations_update` bound to the own `it-*` organization (a rename is medium; `planCode`
 *   escalates to high and the api's `403` for a customer surfaces as a failed confirmation);
 *   organization settings (a timezone change stays medium; `mfaRequired: false` and a new
 *   `notificationEmail` escalate to high); scan settings replace / reset (high, `expectedVersion`
 *   injected from the selected engine's `version`); SMTP connector update (a rename is medium;
 *   `networks` and `requireTls: false` on a `source_ip` connector escalate to high) and delete;
 *   webhooks update (a rename is low; `url` escalates to high; `expectedRowVersion` injected),
 *   test (a low write: a `test` delivery is queued), delivery replay and range replay (medium,
 *   required idempotency), delete (high, `Idempotency-Key` = the confirmation id).
 * - As a platform `super_admin` through `DirectExecutor` + `DirectConfirmer` (the executor and
 *   the confirm service called directly, storing under a synthetic organization; a turn of a
 *   platform user would need the assistant enabled in the platform organization, which the suites
 *   never change), always naming an `it-*` organization: create (medium; with `initialAdmin`
 *   high), cancel a pending deletion, feature override / reset (selected-item precondition;
 *   `ai_assistant` is `denied_guard`), limit override / reset.
 *
 * The live webhook-worker (when the apps profile runs) is paused while the webhook writes run,
 * so the queued test and replay deliveries are never sent; endpoints are `.test` names.
 * Synthetic `it-*` organizations only; nothing of the platform organization changes.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers put /api/v1/notifications/preferences
// @covers put /api/v1/notifications/settings
// @covers post /api/v1/organizations
// @covers put /api/v1/organizations/:id
// @covers post /api/v1/organizations/:id/deletion/cancel
// @covers put /api/v1/organizations/:id/features/:featureKey
// @covers delete /api/v1/organizations/:id/features/:featureKey
// @covers put /api/v1/organizations/:id/limits/:limitKey
// @covers delete /api/v1/organizations/:id/limits/:limitKey
// @covers put /api/v1/organizations/:id/settings
// @covers put /api/v1/scan-settings/:engine
// @covers delete /api/v1/scan-settings/:engine
// @covers patch /api/v1/smtp-connectors/:id
// @covers delete /api/v1/smtp-connectors/:id
// @covers patch /api/v1/webhooks/:webhookId
// @covers delete /api/v1/webhooks/:webhookId
// @covers post /api/v1/webhooks/:webhookId/test
// @covers post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay
// @covers post /api/v1/webhooks/:webhookId/replays
import { PLANS } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  actionsByCorrelation,
  auditByCorrelation,
  call,
  type ChatWrite,
  clearAssistantCounters,
  confirmationRow,
  createAssistantApp,
  credentialKeys,
  type DirectAnswer,
  directPlatform,
  type DirectPlatform,
  enableAssistant,
  executionRow,
  member,
  type Member,
  platformMember,
  proposeAndConfirm,
  type RecordedCall,
  recordLoopback,
  resultCorrelationId,
} from './support/assistant';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  uniqueSuffix,
} from './support/fixtures';
import { idem } from './support/http';
import { pauseLiveService } from './support/live-archive-worker';
import { randomV4Network } from './support/smtp';
import { createBody, endpoint, seedDelivery, subscriptionRow, WEBHOOKS } from './support/webhooks';

/** A stale row version the model "remembers"; the executor replaces it from the snapshot. */
const STALE = 999;
const standard = PLANS.find((p) => p.code === 'standard')!;

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let org: FixtureOrganization;
let admin: Member;

const chat = (tool: string, args: Record<string, unknown>): Promise<ChatWrite> =>
  proposeAndConfirm(ctx, fx, admin, tool, args);

/** Asserts an executed confirmation with this HTTP status; returns the write's loopback call. */
function executed(result: ChatWrite, httpStatus: number): RecordedCall {
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

async function credentialFree(result: ChatWrite): Promise<void> {
  expect(credentialKeys(result.proposal.confirmation)).toEqual([]);
  expect(credentialKeys(result.res.body.confirmation)).toEqual([]);
  const row = await confirmationRow(ctx, result.proposal.confirmation.id);
  // `plan.code` is the snapshot's state field of the plan (D6 "plan.code"): the credential
  // pattern (`code`) matches its name, never a credential (reported, design §11).
  expect(credentialKeys(row.preconditions).filter((path) => !path.endsWith('.plan.code'))).toEqual(
    [],
  );
}

async function storedRequest(confirmationId: string) {
  const row = await confirmationRow(ctx, confirmationId);
  return row.request as { method: string; path: string; body: Record<string, unknown> | null };
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ features: { webhooks: true } });
  fx.registerCleanup(() =>
    ctx.prisma.scanEngineSetting.deleteMany({ where: { organizationId: org.id } }),
  );
  admin = await member(ctx, fx, org, ['organization_admin']);
  await enableAssistant(ctx, operator, org, admin);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
});

describe('notifications through chat (2 writes)', () => {
  it('notifications_put_preferences (low): the caller’s own opt-outs', async () => {
    const result = await chat('notifications_put_preferences', {
      body: { optOut: ['threat_detected'], quarantineDigestOptOut: false },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    executed(result, 200);
    const row = await ctx.prisma.notificationUserPreference.findUniqueOrThrow({
      where: { userId: admin.user.id },
    });
    expect(row.preferences).toMatchObject({ optOut: ['threat_detected'] });
    await operationAudited(result, 'notification.preferences_updated');
    await credentialFree(result);
  });

  it('notifications_put_settings (medium): expectedRowVersion injected (minimum 0)', async () => {
    const result = await chat('notifications_put_settings', {
      body: {
        settings: { alerts: { threatDetected: { throttleMinutes: 30 } } },
        expectedRowVersion: STALE,
      },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(result.proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    executed(result, 200);
    // Nothing stored yet: the snapshot's row version is 0, the schema's minimum.
    expect((await storedRequest(result.proposal.confirmation.id)).body!.expectedRowVersion).toBe(0);
    const row = await ctx.prisma.notificationSettings.findUniqueOrThrow({
      where: { organizationId: org.id },
    });
    expect(row.rowVersion).toBe(1);
    await operationAudited(result, 'notification.settings_updated');
  });
});

describe('the own organization as a customer admin (2 writes)', () => {
  it('organizations_update: bound to the own organization; a rename is medium', async () => {
    const name = `Renamed through chat ${uniqueSuffix()}`;
    const result = await chat('organizations_update', { body: { name } });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    const write = executed(result, 200);
    expect(write).toMatchObject({ method: 'PUT', path: `/api/v1/organizations/${org.publicId}` });
    expect((await ctx.prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).name).toBe(
      name,
    );
    await operationAudited(result, 'organization.updated');
    await credentialFree(result);
  });

  it('organizations_update with planCode escalates to high; the api refuses a customer (403)', async () => {
    const result = await chat('organizations_update', {
      body: { name: 'Plan change attempt', planCode: 'enterprise' },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(result.proposal.confirmation.summary!.warnings).toContain(
      "Changes the plan, and with it the organization's features and limits.",
    );
    expect(result.res.status, JSON.stringify(result.res.body)).toBe(200);
    expect(result.res.body.confirmation).toMatchObject({
      status: 'failed',
      result: { httpStatus: 403 },
    });
    const row = await ctx.prisma.organization.findUniqueOrThrow({
      where: { id: org.id },
      include: { plan: { select: { code: true } } },
    });
    expect(row.plan.code).toBe('standard');
    expect(row.name).not.toBe('Plan change attempt');
  });

  it('organization_configuration_update_settings: timezone medium; MFA off and a new notification email high', async () => {
    const timezone = await chat('organization_configuration_update_settings', {
      body: { timezone: 'Europe/Berlin' },
    });
    expect(timezone.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    executed(timezone, 200);
    await operationAudited(timezone, 'organization.settings_updated');

    const mfa = await chat('organization_configuration_update_settings', {
      body: { mfaRequired: false },
    });
    expect(mfa.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(mfa.proposal.confirmation.summary!.warnings).toContain(
      'Users of the organization will no longer have to use MFA.',
    );
    executed(mfa, 200);

    const email = await chat('organization_configuration_update_settings', {
      body: { notificationEmail: 'soc-chat@example.test' },
    });
    expect(email.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(email.proposal.confirmation.summary!.warnings).toContain(
      'Organization notifications go to a new address.',
    );
    executed(email, 200);
    const settings = await ctx.prisma.organizationSetting.findUniqueOrThrow({
      where: { organizationId: org.id },
    });
    expect(settings).toMatchObject({
      timezone: 'Europe/Berlin',
      mfaRequired: false,
      notificationEmail: 'soc-chat@example.test',
    });
    await credentialFree(email);
  });
});

describe('scan settings through chat (2 writes)', () => {
  const settingRow = () =>
    ctx.prisma.scanEngineSetting.findFirstOrThrow({
      where: { organizationId: org.id, engine: 'rspamd' },
    });

  it('scan_settings_replace (high): expectedVersion injected from the selected engine', async () => {
    const result = await chat('scan_settings_replace', {
      engine: 'rspamd',
      body: { expectedVersion: STALE, settings: { spamScore: 8 } },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    executed(result, 200);
    expect((await storedRequest(result.proposal.confirmation.id)).body!.expectedVersion).toBe(0);
    expect(await settingRow()).toMatchObject({ version: 1, settings: { spamScore: 8 } });
    await operationAudited(result, 'scan_settings.updated');
  });

  it('scan_settings_reset (high): the query expectedVersion is the current version', async () => {
    const result = await chat('scan_settings_reset', { engine: 'rspamd' });
    expect(result.proposal.confirmation.risk).toBe('high');
    const write = executed(result, 200);
    expect(write).toMatchObject({
      method: 'DELETE',
      path: '/api/v1/scan-settings/rspamd?expectedVersion=1',
    });
    expect(await settingRow()).toMatchObject({ version: 2 });
    await operationAudited(result, 'scan_settings.reset');
  });
});

describe('SMTP connectors through chat (2 writes)', () => {
  let connectorId: string;
  const connectorRow = () =>
    ctx.prisma.smtpConnector.findUniqueOrThrow({
      where: { publicId: connectorId },
      include: { networks: true },
    });

  beforeAll(async () => {
    const created = await call(ctx, admin.headers, 'post', '/api/v1/smtp-connectors', {
      name: `chat relay ${uniqueSuffix()}`,
      authType: 'source_ip',
      networks: [randomV4Network()],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    connectorId = created.body.id as string;
  });

  it('smtp_connectors_update: a rename stays medium', async () => {
    const result = await chat('smtp_connectors_update', {
      id: connectorId,
      body: { name: 'renamed through chat' },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    executed(result, 200);
    expect((await connectorRow()).name).toBe('renamed through chat');
    await operationAudited(result, 'smtp_connector.updated');
  });

  it('smtp_connectors_update: new networks and requireTls false escalate to high', async () => {
    const network = randomV4Network();
    const networks = await chat('smtp_connectors_update', {
      id: connectorId,
      body: { networks: [network] },
    });
    expect(networks.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(networks.proposal.confirmation.summary!.warnings).toContain(
      'Changes which networks may relay mail through the gateway.',
    );
    executed(networks, 200);
    expect((await connectorRow()).networks.map((n) => n.cidr)).toEqual([network]);

    const tls = await chat('smtp_connectors_update', {
      id: connectorId,
      body: { requireTls: false },
    });
    expect(tls.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(tls.proposal.confirmation.summary!.warnings).toContain(
      'Allows sessions without TLS on this connector.',
    );
    executed(tls, 200);
    expect((await connectorRow()).requireTls).toBe(false);
    await credentialFree(tls);
  });

  it('smtp_connectors_remove (high)', async () => {
    const result = await chat('smtp_connectors_remove', { id: connectorId });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    executed(result, 204);
    expect(await ctx.prisma.smtpConnector.count({ where: { publicId: connectorId } })).toBe(0);
    await operationAudited(result, 'smtp_connector.deleted');
  });
});

describe('webhooks through chat (5 writes)', () => {
  let webhookId: string;
  let resume: () => Promise<void> = () => Promise.resolve();
  const hook = () => subscriptionRow(ctx, webhookId);

  beforeAll(async () => {
    resume = await pauseLiveService('webhook-worker');
    const created = await call(ctx, admin.headers, 'post', WEBHOOKS, createBody()).set(idem());
    expect(created.status, JSON.stringify(created.body?.code)).toBe(201);
    webhookId = created.body.id as string;
  }, 60_000);

  afterAll(async () => {
    await resume();
  }, 60_000);

  it('webhooks_update: a rename is low; expectedRowVersion injected', async () => {
    const before = await hook();
    const result = await chat('webhooks_update', {
      webhookId,
      body: { name: 'renamed through chat', expectedRowVersion: STALE },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    executed(result, 200);
    expect((await storedRequest(result.proposal.confirmation.id)).body!.expectedRowVersion).toBe(
      before.rowVersion,
    );
    expect(await hook()).toMatchObject({
      name: 'renamed through chat',
      rowVersion: before.rowVersion + 1,
    });
    await operationAudited(result, 'webhook.updated');
  });

  it('webhooks_update with url escalates to high', async () => {
    const url = endpoint('moved');
    const result = await chat('webhooks_update', {
      webhookId,
      body: { url, expectedRowVersion: STALE },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(result.proposal.confirmation.summary!.warnings).toContain(
      "Sends this webhook's event data to a new address.",
    );
    executed(result, 200);
    expect((await hook()).url).toBe(url);
    await credentialFree(result);
  });

  it('webhooks_test (a low write): a test delivery is queued, nothing is sent', async () => {
    const result = await chat('webhooks_test', { webhookId });
    expect(result.proposal.confirmation).toMatchObject({
      tool: 'webhooks_test',
      risk: 'low',
      requiresReauth: false,
    });
    expect(result.proposal.confirmation.summary!.reversible).toBe(false);
    executed(result, 202);
    const sub = await hook();
    const deliveries = await ctx.prisma.webhookDelivery.findMany({
      where: { subscriptionId: sub.id, trigger: 'test' },
    });
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0]).toMatchObject({ status: 'pending', attemptCount: 0 });
    expect(
      await ctx.prisma.webhookDeliveryAttempt.count({ where: { deliveryId: deliveries[0]!.id } }),
    ).toBe(0);
    await operationAudited(result, 'webhook.test_requested');
  });

  it('webhook_deliveries_replay (medium, required idempotency): one replay delivery', async () => {
    const sub = await hook();
    const seeded = await seedDelivery(ctx, sub, {
      occurredAt: new Date(Date.now() - 10 * 60_000),
      organizationPublicId: org.publicId,
      status: 'dead',
      attempts: 2,
    });
    const result = await chat('webhook_deliveries_replay', {
      webhookId,
      deliveryId: seeded.publicId,
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    const write = executed(result, 202);
    expect(write.idempotencyKey).toBe(result.proposal.confirmation.id);
    const replays = await ctx.prisma.webhookDelivery.findMany({
      where: { subscriptionId: sub.id, eventId: seeded.eventId, trigger: 'replay' },
    });
    expect(replays).toHaveLength(1);
    expect(replays[0]).toMatchObject({ deliverySeq: 1, status: 'pending' });
    await operationAudited(result, 'webhook.delivery_replayed');
  });

  it('webhook_deliveries_create_replay (medium, required idempotency): a queued range replay', async () => {
    const result = await chat('webhook_deliveries_create_replay', {
      webhookId,
      body: {
        from: new Date(Date.now() - 60 * 60_000).toISOString(),
        to: new Date().toISOString(),
      },
    });
    expect(result.proposal.confirmation.risk).toBe('medium');
    const write = executed(result, 202);
    expect(write.idempotencyKey).toBe(result.proposal.confirmation.id);
    const sub = await hook();
    const replays = await ctx.prisma.webhookReplay.findMany({ where: { subscriptionId: sub.id } });
    expect(replays).toHaveLength(1);
    expect(replays[0]).toMatchObject({ status: 'queued', requestedByType: 'user' });
    await operationAudited(result, 'webhook.replay_requested');
    // Completed by hand so the delete below is not blocked by a running replay.
    await ctx.prisma.webhookReplay.update({
      where: { id: replays[0]!.id },
      data: { status: 'completed', completedAt: new Date() },
    });
  });

  it('webhooks_delete (high): Idempotency-Key = the confirmation id', async () => {
    const result = await chat('webhooks_delete', { webhookId });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const write = executed(result, 204);
    expect(write).toMatchObject({
      method: 'DELETE',
      path: `${WEBHOOKS}/${webhookId}`,
      idempotencyKey: result.proposal.confirmation.id,
    });
    expect((await hook()).deletedAt).not.toBeNull();
    await operationAudited(result, 'webhook.deleted');
  });
});

describe('platform organization tools through DirectExecutor + DirectConfirmer (8 writes)', () => {
  let platform: DirectPlatform;
  let target: FixtureOrganization;

  /** A confirmed platform write: executed with this status; returns its audit actions. */
  async function platformExecuted(answer: DirectAnswer, httpStatus: number): Promise<string[]> {
    expect(answer.status, JSON.stringify(answer.body)).toBe(200);
    expect(answer.body.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus, error: null },
    });
    expect(answer.body.execution).toMatchObject({ status: 'succeeded', httpStatus });
    const row = await executionRow(ctx, answer.body.execution.id as string);
    return actionsByCorrelation(ctx, row.correlationId);
  }

  const featureRow = (key: string) =>
    ctx.prisma.organizationFeature.findUniqueOrThrow({
      where: { organizationId_featureKey: { organizationId: target.id, featureKey: key } },
    });
  const limitRow = (key: string) =>
    ctx.prisma.organizationLimit.findUniqueOrThrow({
      where: { organizationId_limitKey: { organizationId: target.id, limitKey: key } },
    });

  beforeAll(async () => {
    // Proposals of the platform user are stored under `org` (an it-* organization whose
    // assistant is on); the writes name `target`, another it-* organization.
    platform = await directPlatform(ctx, fx, org);
    target = await fx.createOrganization();
  });

  it('organizations_create (medium): an it-* organization; with initialAdmin it is high', async () => {
    const slug = `it-chat-${uniqueSuffix()}`;
    const pending = await platform.propose('organizations_create', {
      body: {
        name: `Chat created ${slug}`,
        slug,
        planCode: 'standard',
        deploymentMode: 'saas',
        dataRegion: 'ap-south-1',
      },
    });
    expect(pending.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    const answer = await platform.confirm(pending);
    const actions = await platformExecuted(answer, 201);
    const created = await ctx.prisma.organization.findUniqueOrThrow({ where: { slug } });
    fx.trackOrganization(created.id);
    expect(created.kind).toBe('customer');
    expect(actions).toContain('organization.created');

    const owned = `it-chat-${uniqueSuffix()}`;
    const ownerEmail = `owner-${uniqueSuffix()}@example.test`;
    const withAdmin = await platform.propose('organizations_create', {
      body: {
        name: `Chat created ${owned}`,
        slug: owned,
        planCode: 'standard',
        deploymentMode: 'saas',
        dataRegion: 'ap-south-1',
        initialAdmin: { email: ownerEmail, displayName: 'Chat Owner' },
      },
    });
    expect(withAdmin.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(withAdmin.confirmation.summary!.warnings).toContain(
      'Invites an administrator with full access to the new organization.',
    );
    // The platform session's first high confirm without re-authentication: refused, nothing
    // created; the confirmation stays pending.
    const refused = await platform.confirm(withAdmin, { reauth: false });
    expect(refused.status).toBe(401);
    expect(refused.body.code).toBe('assistant_reauth_required');
    expect(await ctx.prisma.organization.count({ where: { slug: owned } })).toBe(0);
    await platformExecuted(await platform.confirm(withAdmin), 201);
    const ownedRow = await ctx.prisma.organization.findUniqueOrThrow({ where: { slug: owned } });
    fx.trackOrganization(ownedRow.id);
    expect(
      await ctx.prisma.user.findFirstOrThrow({
        where: { organizationId: ownedRow.id, email: ownerEmail },
      }),
    ).toMatchObject({ status: 'invited' });
  });

  it('organization_configuration_override_feature / reset_feature (high, selected item)', async () => {
    const before = await featureRow('dlp');
    const override = await platform.propose('organization_configuration_override_feature', {
      id: target.publicId,
      featureKey: 'dlp',
      body: { enabled: !before.enabled },
    });
    expect(override.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const overridden = await platformExecuted(await platform.confirm(override), 200);
    expect(overridden).toContain('organization.feature_overridden');
    expect(await featureRow('dlp')).toMatchObject({ enabled: !before.enabled, source: 'override' });

    const reset = await platform.propose('organization_configuration_reset_feature', {
      id: target.publicId,
      featureKey: 'dlp',
    });
    const resetActions = await platformExecuted(await platform.confirm(reset), 204);
    expect(resetActions).toContain('organization.feature_reset');
    expect(await featureRow('dlp')).toMatchObject({ enabled: before.enabled, source: 'plan' });
  });

  it('the assistant’s own feature is denied_guard (A3-4), before any request', async () => {
    const before = await featureRow('ai_assistant');
    const recorder = recordLoopback(ctx);
    try {
      for (const [tool, args] of [
        [
          'organization_configuration_override_feature',
          { id: target.publicId, featureKey: 'ai_assistant', body: { enabled: true } },
        ],
        [
          'organization_configuration_reset_feature',
          { id: target.publicId, featureKey: 'ai_assistant' },
        ],
      ] as const) {
        const outcome = await platform.executor.execute(tool, { ...args });
        expect(outcome, tool).toMatchObject({
          decision: 'denied_guard',
          status: 'refused',
          confirmation: null,
        });
        expect(outcome.envelope).toMatchObject({
          status: 'denied',
          message:
            'The assistant cannot turn itself on or off for an organization. Use the Organizations page in the portal.',
        });
      }
    } finally {
      recorder.restore();
    }
    expect(recorder.calls).toEqual([]);
    expect(await featureRow('ai_assistant')).toEqual(before);
  });

  it('organization_configuration_override_limit / reset_limit (high, selected item)', async () => {
    const override = await platform.propose('organization_configuration_override_limit', {
      id: target.publicId,
      limitKey: 'max_users',
      body: { value: 7 },
    });
    expect(override.confirmation.risk).toBe('high');
    expect(await platformExecuted(await platform.confirm(override), 200)).toContain(
      'organization.limit_overridden',
    );
    expect(await limitRow('max_users')).toMatchObject({ limitValue: 7n, source: 'override' });

    const reset = await platform.propose('organization_configuration_reset_limit', {
      id: target.publicId,
      limitKey: 'max_users',
    });
    expect(await platformExecuted(await platform.confirm(reset), 204)).toContain(
      'organization.limit_reset',
    );
    expect(await limitRow('max_users')).toMatchObject({
      limitValue: BigInt(standard.limits.max_users),
      source: 'plan',
    });
  });

  it('organization_deletion_cancel (medium): a pending deletion of an it-* organization', async () => {
    const doomed = await fx.createOrganization({ status: 'suspended' });
    const requested = await call(
      ctx,
      platform.member.headers,
      'post',
      `/api/v1/organizations/${doomed.publicId}/deletion`,
      { reason: 'Offboarding in the chat suite', confirmSlug: doomed.slug },
    ).set(idem());
    expect(requested.status, JSON.stringify(requested.body)).toBe(200);
    expect(requested.body.state).toBe('pending_deletion');

    const pending = await platform.propose('organization_deletion_cancel', {
      id: doomed.publicId,
      body: { reason: 'Customer stays' },
    });
    expect(pending.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    const actions = await platformExecuted(await platform.confirm(pending), 200);
    expect(actions).toContain('organization.deletion_cancelled');
    expect(
      await ctx.prisma.organization.findUniqueOrThrow({ where: { id: doomed.id } }),
    ).toMatchObject({ status: 'suspended', deletionRequestedAt: null, deletedAt: null });
  });

  it('a platform-only write without an organization id is denied_schema (no binding)', async () => {
    const outcome = await platform.executor.execute('organization_deletion_cancel', {
      body: { reason: 'No organization named' },
    });
    expect(outcome).toMatchObject({ decision: 'denied_schema', status: 'refused' });
  });
});
