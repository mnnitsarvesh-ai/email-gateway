/**
 * Step AI-5 provider-connection tools through chat (docs/plan/steps/33-ai-chat-compliance-
 * integrations.md D2, D5, D6 #17–#25, D7, D12, I23, §9 item 3; the `testedBy` of the 9
 * provider-connection writes in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md). The
 * deterministic fake provider proposes every write from a directive turn (never a real LLM); the
 * api listens on its ephemeral loopback port, so precondition reads, the impact previews,
 * confirm-time re-reads and the confirmed writes go through the real `/api/v1` pipeline with the
 * user's own token, MFA session and permissions. The integration-worker's writes (tenant and
 * grant verification, provider domain checks) are simulated with SQL as in
 * `provider-connections.test.ts`; no provider endpoint and no internet is reached by the api.
 *
 * - create (low), rename (CAS `rowVersion` injected), domains replace (medium), attestation
 *   (medium), grant verify of an active customer grant (medium; a forced `body.subjectEmail` →
 *   `denied_schema` without a loopback request), grant revoke (high), health check now (low,
 *   queued 202);
 * - the mail-flow preview read: neither the envelope nor the card carries the impact token;
 * - mail-flow apply (`inbound` on a linked active domain): the card shows the preview's change
 *   set, the stored request carries the server's token (the model's token is ignored), confirm
 *   with re-authentication applies the destinations and audits `integration.mail_flow_applied`
 *   (two previews audited: proposal and confirm); a routing change between proposal and confirm
 *   → `409 assistant_confirmation_state_changed` with nothing applied by the confirmation;
 * - disconnect (high; the server previews `disable`): grants revoked and their credentials
 *   wiped, inbound destinations kept;
 * - credentials upload, grant create, consent completion and validation runs →
 *   `denied_not_applicable` without a loopback request;
 * - no impact token in any transcript, envelope, execution row (`params_redacted`), confirmation
 *   view or audit row (only the confirmation's stored request holds it).
 *
 * Synthetic `it-*` organizations, `.test` domains and random tenant ids only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers get /api/v1/assistant/confirmations/:confirmationId
// @covers post /api/v1/provider-connections
// @covers get /api/v1/provider-connections/:id
// @covers patch /api/v1/provider-connections/:id
// @covers delete /api/v1/provider-connections/:id
// @covers put /api/v1/provider-connections/:id/domains
// @covers post /api/v1/provider-connections/:id/attestations
// @covers post /api/v1/provider-connections/:id/grants/:profile/verify
// @covers delete /api/v1/provider-connections/:id/grants/:profile
// @covers post /api/v1/provider-connections/:id/health/check
// @covers post /api/v1/provider-connections/:id/mail-flow/preview
// @covers post /api/v1/provider-connections/:id/mail-flow/apply
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  auditByCorrelation,
  call,
  type ChatWrite,
  clearAssistantCounters,
  closeReauthWindow,
  confirm,
  createAssistantApp,
  credentialKeys,
  credentialKeysInResult,
  directive,
  envelopesOf,
  executionRow,
  expectExecuted,
  getConfirmation,
  type Member,
  newConversation,
  operationActionsOf,
  platformMember,
  propose,
  proposeAndConfirm,
  reauthOf,
  recordLoopback,
  type RecordedCall,
  requestsTo,
  resultCorrelationId,
  storedRequestOf,
  turn,
} from './support/assistant';
import {
  chatUser,
  type ComplianceTenant,
  complianceTenant,
  INTEGRATION_PERMISSIONS,
  PROVIDERS,
} from './support/assistant-compliance';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { idem } from './support/http';
import { insertDomain, type InsertedDomain } from './support/smtp';

const P = PROVIDERS;
const PROFILE = 'm365.mail_flow';
const STALE = 999;
/** A synthetic client secret (never a real credential; never in a stored assistant row). */
const CLIENT_SECRET = `it-chat-client-secret-${randomUUID().replace(/-/g, '')}`;
/** The impact token the model "remembers" (ignored: the server injects its own). */
const MODEL_TOKEN = `it-model-impact-${randomUUID().slice(0, 8)}`;

let ctx: IntegrationApp;
let fx: Fixtures;
let tenant: ComplianceTenant;
let org: FixtureOrganization;
let admin: Member;
/** Every server-issued impact token the suite saw (stored requests and portal previews). */
const tokens = new Set<string>();

const chat = (
  tool: string,
  args: Record<string, unknown>,
  options: { conversation?: string; reauth?: boolean } = {},
): Promise<ChatWrite> => proposeAndConfirm(ctx, fx, admin, tool, args, options);

/** The operation's own audit row (this organization, the result execution's correlation id). */
async function audited(result: ChatWrite, action: string) {
  const correlationId = await resultCorrelationId(ctx, result.res);
  const rows = (await auditByCorrelation(ctx, org.id, correlationId)).filter(
    (r) => r.action === action,
  );
  expect(
    rows,
    `${action}: ${JSON.stringify(await operationActionsOf(ctx, result.res))}`,
  ).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(admin.user.publicId);
  return rows[0]!;
}

const connectionRow = (publicId: string) =>
  ctx.prisma.providerConnection.findUniqueOrThrow({
    where: { publicId },
    include: { grants: true },
  });

/** A draft Microsoft 365 connection created through the api (the portal's path). */
async function draftConnection(label: string): Promise<string> {
  const res = await call(ctx, tenant.owner.headers, 'post', P, {
    provider: 'microsoft_365',
    displayName: `${label} ${randomUUID().slice(0, 8)}`,
  }).set(idem());
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.id as string;
}

/**
 * A customer-owned app grant with its credential uploaded through the api (both N/A in chat:
 * portal only), as the owner.
 */
async function customerGrant(connectionId: string): Promise<void> {
  const created = await call(ctx, tenant.owner.headers, 'post', `${P}/${connectionId}/grants`, {
    profile: PROFILE,
    authMethod: 'customer_app_secret',
  }).set(idem());
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  const put = await call(
    ctx,
    tenant.owner.headers,
    'put',
    `${P}/${connectionId}/grants/${PROFILE}/credentials`,
    {
      tenantId: randomUUID(),
      clientId: randomUUID(),
      clientSecret: CLIENT_SECRET,
    },
  ).set(idem());
  expect(put.status, JSON.stringify(put.body)).toBe(200);
}

/**
 * What the integration-worker writes when the tenant, the grant and the linked domains verify
 * (`provider-connections.test.ts` `workerBinds`): grants active, domains provider-verified with
 * their MX host, the connection active and bound to a (random) tenant.
 */
async function workerBinds(connectionId: string, domains: InsertedDomain[] = []): Promise<void> {
  const tenantId = randomUUID();
  const c = await connectionRow(connectionId);
  await ctx.prisma.providerConnectionGrant.updateMany({
    where: { connectionId: c.id, status: { not: 'revoked' } },
    data: {
      status: 'active',
      verifiedAt: new Date(),
      observedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
      missingPermissions: [],
      excessPermissions: [],
      rowVersion: { increment: 1 },
    },
  });
  for (const domain of domains) {
    await ctx.prisma.providerConnectionDomain.updateMany({
      where: { connectionId: c.id, domainId: domain.id },
      data: {
        providerVerification: 'verified',
        providerCheckedAt: new Date(),
        providerMxHost: `${domain.name.replace(/\./g, '-')}.mail.protection.outlook.com`,
      },
    });
  }
  await ctx.prisma.providerConnection.update({
    where: { id: c.id },
    data: {
      status: 'active',
      externalTenantId: tenantId,
      externalTenantName: 'Contoso IT (test)',
      tenantVerifiedAt: new Date(),
      activeTenantKey: `microsoft_365:${tenantId}`,
      rowVersion: { increment: 1 },
    },
  });
}

interface Refusal {
  conversation: string;
  execution: Record<string, unknown>;
  calls: RecordedCall[];
}

async function refusedTurn(tool: string, args: Record<string, unknown>): Promise<Refusal> {
  const conversation = await newConversation(ctx, admin);
  const recorder = recordLoopback(ctx);
  try {
    const res = await turn(ctx, admin.headers, conversation, directive(tool, args));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmations, tool).toEqual([]);
    const execution = (res.body.executions as Array<Record<string, unknown>>)[0]!;
    expect(execution.tool).toBe(tool);
    return { conversation, execution, calls: [...recorder.calls] };
  } finally {
    recorder.restore();
  }
}

/**
 * The stored rows of the organization, as text: every row except the confirmations' stored
 * requests (the only place the server's impact token is kept, D12). With `userText: false` the
 * user's own messages and the provider transcripts (which replay the user's directive text, the
 * test's synthetic model token and client secret included) are left out.
 */
async function storedText(options: { userText: boolean }): Promise<string> {
  const where = { organizationId: org.id };
  const [turns, messages, executions, confirmations, audit] = await Promise.all([
    ctx.prisma.aiChatTurn.findMany({ where }),
    ctx.prisma.aiChatMessage.findMany({ where }),
    ctx.prisma.aiChatToolExecution.findMany({ where }),
    ctx.prisma.aiChatActionConfirmation.findMany({ where }),
    ctx.prisma.auditLog.findMany({ where }),
  ]);
  return JSON.stringify(
    {
      turns: options.userText ? turns : [],
      messages: options.userText ? messages : messages.filter((m) => m.role !== 'user'),
      executions,
      confirmations: confirmations.map((c) => ({ ...c, request: undefined })),
      audit,
    },
    (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
  );
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  tenant = await complianceTenant(ctx, fx, operator);
  org = tenant.org;
  admin = await chatUser(ctx, fx, org, INTEGRATION_PERMISSIONS, 'Integration admin');
}, 240_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('the connection wizard through chat (D6 #17–#21, #24)', () => {
  let connectionId: string;
  let domainA: InsertedDomain;
  let domainB: InsertedDomain;

  it('provider_connections_create (low): a draft connection, integration.connection_created', async () => {
    const displayName = `Contoso chat ${randomUUID().slice(0, 8)}`;
    const created = await chat('provider_connections_create', {
      body: { provider: 'microsoft_365', displayName },
    });
    expect(created.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(created, 201);
    const row = await ctx.prisma.providerConnection.findFirstOrThrow({
      where: { organizationId: org.id, displayName },
    });
    connectionId = row.publicId;
    expect(row).toMatchObject({ status: 'draft', outboundMode: 'off' });
    const audit = await audited(created, 'integration.connection_created');
    expect(audit.resourceId).toBe(connectionId);
  });

  it('provider_connections_update (low): the rowVersion CAS is injected from the read', async () => {
    const before = await connectionRow(connectionId);
    const renamed = await chat('provider_connections_update', {
      id: connectionId,
      body: { displayName: 'Contoso chat (renamed)', rowVersion: STALE },
    });
    expect(renamed.proposal.confirmation).toMatchObject({ risk: 'low' });
    expectExecuted(renamed, 200);
    expect((await storedRequestOf(ctx, renamed.proposal.confirmation.id)).body!.rowVersion).toBe(
      before.rowVersion,
    );
    expect(await connectionRow(connectionId)).toMatchObject({
      displayName: 'Contoso chat (renamed)',
      rowVersion: before.rowVersion + 1,
    });
    await audited(renamed, 'integration.connection_updated');
  });

  it('provider_domains_replace (medium): links active domains of the organization', async () => {
    domainA = await insertDomain(ctx, org, { label: 'prov-a' });
    domainB = await insertDomain(ctx, org, { label: 'prov-b' });
    const linked = await chat('provider_domains_replace', {
      id: connectionId,
      body: { domainIds: [domainA.publicId, domainB.publicId] },
    });
    expect(linked.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(linked.proposal.confirmation.summary!.impact.length).toBeGreaterThan(0);
    expectExecuted(linked, 200);
    const links = await ctx.prisma.providerConnectionDomain.findMany({
      where: { organizationId: org.id, connection: { publicId: connectionId } },
    });
    expect(links.map((l) => l.domainId).sort()).toEqual([domainA.id, domainB.id].sort());
    await audited(linked, 'integration.domains_linked');
  });

  it('provider_attestations_record (medium): integration.attestation_recorded', async () => {
    const attested = await chat('provider_attestations_record', {
      id: connectionId,
      body: { code: 'm365.inbound_connector_created', attested: true },
    });
    expect(attested.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(attested, 200);
    await audited(attested, 'integration.attestation_recorded');
  });

  it('provider_health_check_now (low): queued 202, integration.health_check_requested', async () => {
    await customerGrant(connectionId);
    await workerBinds(connectionId, [domainA, domainB]);
    const checked = await chat('provider_health_check_now', { id: connectionId });
    expect(checked.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    expectExecuted(checked, 202);
    await audited(checked, 'integration.health_check_requested');
  });

  describe('mail flow (D5): the server previews, injects the impact token and binds the change set', () => {
    it('provider_mail_flow_preview (read): neither the envelope nor the card carries the impact token', async () => {
      const conversation = await newConversation(ctx, admin);
      const res = await turn(
        ctx,
        admin.headers,
        conversation,
        directive('provider_mail_flow_preview', {
          id: connectionId,
          body: { change: { kind: 'inbound', domainIds: [domainA.publicId] } },
        }),
      );
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      const execution = res.body.executions[0];
      expect(execution).toMatchObject({
        tool: 'provider_mail_flow_preview',
        status: 'succeeded',
        httpStatus: 200,
      });
      const [envelope] = await envelopesOf(ctx, res.body.turn.id as string);
      expect(envelope!.raw).not.toMatch(/impactToken/i);
      expect(JSON.stringify(execution.card ?? null)).not.toMatch(/impactToken/i);
      expect(credentialKeysInResult(envelope!.parsed, execution.card)).toEqual([]);
      expect(envelope!.raw).toContain(domainA.name);
      expect(
        await ctx.prisma.auditLog.count({
          where: {
            organizationId: org.id,
            action: 'integration.mail_flow_previewed',
            resourceId: connectionId,
          },
        }),
      ).toBeGreaterThanOrEqual(1);
    });

    it('provider_mail_flow_apply (high): the preview’s change set in the card, the server’s token stored, applied with re-auth', async () => {
      const previewed = () =>
        ctx.prisma.auditLog.count({
          where: {
            organizationId: org.id,
            action: 'integration.mail_flow_previewed',
            resourceId: connectionId,
          },
        });
      const previewsBefore = await previewed();
      await closeReauthWindow(ctx, admin);
      const change = { kind: 'inbound', domainIds: [domainA.publicId] };
      const proposal = await propose(
        ctx,
        admin,
        directive('provider_mail_flow_apply', {
          id: connectionId,
          body: { change, impactToken: MODEL_TOKEN, confirm: true },
        }),
      );
      expect(proposal.confirmation).toMatchObject({
        tool: 'provider_mail_flow_apply',
        risk: 'high',
        requiresReauth: true,
      });
      const summary = JSON.stringify(proposal.confirmation.summary);
      expect(summary).toContain(domainA.name);
      expect(summary).toContain('mail.protection.outlook.com');
      expect(summary).not.toContain(MODEL_TOKEN);
      expect(credentialKeys(proposal.confirmation.summary)).toEqual([]);
      const stored = await storedRequestOf(ctx, proposal.confirmation.id);
      const serverToken = stored.body!.impactToken as string;
      tokens.add(serverToken);
      expect(serverToken).toEqual(expect.any(String));
      expect(serverToken).not.toBe(MODEL_TOKEN);
      expect(serverToken).not.toBe('pending-preview');
      expect(stored.body).toMatchObject({ change, confirm: true });
      expect(await previewed()).toBe(previewsBefore + 1);
      // The confirmation view never carries the token.
      const view = await getConfirmation(ctx, admin, proposal.confirmation.id);
      expect(JSON.stringify(view.body)).not.toContain(serverToken);

      const recorder = recordLoopback(ctx);
      let res;
      try {
        res = await confirm(ctx, admin, proposal, { reauth: await reauthOf(fx, admin) });
      } finally {
        recorder.restore();
      }
      const result: ChatWrite = { proposal, res, calls: [...recorder.calls] };
      const write = expectExecuted(result, 200);
      expect(write).toMatchObject({ method: 'POST', path: `${P}/${connectionId}/mail-flow/apply` });
      // The confirm re-ran the read and the preview (two previews audited in all).
      expect(result.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
        `GET ${P}/${connectionId}`,
        `POST ${P}/${connectionId}/mail-flow/preview`,
        `POST ${P}/${connectionId}/mail-flow/apply`,
      ]);
      expect(await previewed()).toBe(previewsBefore + 2);
      const servers = await ctx.prisma.domainMailServer.findMany({
        where: { domainId: domainA.id, role: 'inbound_destination' },
      });
      expect(servers).toEqual([
        expect.objectContaining({
          provider: 'microsoft_365',
          host: `${domainA.name.replace(/\./g, '-')}.mail.protection.outlook.com`,
        }),
      ]);
      const audit = await audited(result, 'integration.mail_flow_applied');
      expect(audit.resourceId).toBe(connectionId);
      const execution = await executionRow(ctx, res.body.execution.id as string);
      expect(JSON.stringify(execution.paramsRedacted)).not.toContain(serverToken);
    });

    it('a routing change between proposal and confirm → 409 state_changed; the confirmation applies nothing', async () => {
      const change = { kind: 'inbound', domainIds: [domainB.publicId] };
      const proposal = await propose(
        ctx,
        admin,
        directive('provider_mail_flow_apply', { id: connectionId, body: { change } }),
      );
      tokens.add(
        (await storedRequestOf(ctx, proposal.confirmation.id)).body!.impactToken as string,
      );
      // Another administrator applies the same change in the portal (preview + apply).
      const pre = await call(
        ctx,
        tenant.owner.headers,
        'post',
        `${P}/${connectionId}/mail-flow/preview`,
        {
          change,
        },
      );
      expect(pre.status, JSON.stringify(pre.body)).toBe(200);
      tokens.add(pre.body.impactToken as string);
      const applied = await call(
        ctx,
        tenant.owner.headers,
        'post',
        `${P}/${connectionId}/mail-flow/apply`,
        {
          change,
          impactToken: pre.body.impactToken,
          confirm: true,
        },
      ).set(idem());
      expect(applied.status, JSON.stringify(applied.body)).toBe(200);
      const appliedBefore = await ctx.prisma.auditLog.count({
        where: { organizationId: org.id, action: 'integration.mail_flow_applied' },
      });

      const recorder = recordLoopback(ctx);
      let res;
      try {
        res = await confirm(ctx, admin, proposal, { reauth: await reauthOf(fx, admin) });
      } finally {
        recorder.restore();
      }
      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body.code).toBe('assistant_confirmation_state_changed');
      expect(recorder.calls.filter((c) => c.path.endsWith('/mail-flow/apply'))).toEqual([]);
      expect(
        await ctx.prisma.auditLog.count({
          where: { organizationId: org.id, action: 'integration.mail_flow_applied' },
        }),
      ).toBe(appliedBefore);
      expect(
        await ctx.prisma.domainMailServer.count({
          where: { domainId: domainB.id, role: 'inbound_destination' },
        }),
      ).toBe(1);
    });

    it('provider_connections_disconnect (high): preview disable; grants revoked, credentials wiped, destinations kept', async () => {
      const disconnected = await chat('provider_connections_disconnect', { id: connectionId });
      expect(disconnected.proposal.confirmation).toMatchObject({
        risk: 'high',
        requiresReauth: true,
      });
      expect(JSON.stringify(disconnected.proposal.confirmation.summary)).toMatch(/disable/i);
      expect(disconnected.proposal.confirmation.summary!.reversible).toBe(false);
      const stored = await storedRequestOf(ctx, disconnected.proposal.confirmation.id);
      tokens.add(stored.body!.impactToken as string);
      expect(stored).toMatchObject({ method: 'DELETE', body: { confirm: true } });
      const write = expectExecuted(disconnected, 200);
      expect(write).toMatchObject({ method: 'DELETE', path: `${P}/${connectionId}` });
      const row = await connectionRow(connectionId);
      expect(row).toMatchObject({ status: 'disabled', outboundMode: 'off', activeTenantKey: null });
      expect(row.grants.length).toBeGreaterThan(0);
      expect(
        row.grants.every((g) => g.status === 'revoked' && g.credentialCiphertext === null),
      ).toBe(true);
      expect(
        await ctx.prisma.domainMailServer.count({
          where: { domainId: { in: [domainA.id, domainB.id] }, role: 'inbound_destination' },
        }),
      ).toBe(2);
      await audited(disconnected, 'integration.connection_disconnected');
    });
  });
});

describe('grants through chat (D6 #22–#23, D7)', () => {
  it('provider_grants_verify (medium) re-verifies an active customer grant; a forced subjectEmail → denied_schema', async () => {
    const connectionId = await draftConnection('Verify');
    await customerGrant(connectionId);
    await workerBinds(connectionId);
    const forced = await refusedTurn('provider_grants_verify', {
      id: connectionId,
      profile: PROFILE,
      body: { subjectEmail: 'admin@contoso.example' },
    });
    expect(forced.execution).toMatchObject({ decision: 'denied_schema', status: 'refused' });
    expect(requestsTo({ calls: forced.calls }, `${P}/{id}`)).toEqual([]);
    expect(requestsTo({ calls: forced.calls }, `${P}/{id}/grants/{p}/verify`)).toEqual([]);

    const verified = await chat('provider_grants_verify', {
      id: connectionId,
      profile: PROFILE,
      body: {},
    });
    expect(verified.proposal.confirmation).toMatchObject({ risk: 'medium' });
    expectExecuted(verified, 200);
    expect(verified.res.body.execution).toMatchObject({ httpStatus: 200 });
    await audited(verified, 'integration.grant_verification_requested');
  });

  it('provider_grants_revoke (high): the grant is revoked and its credential wiped', async () => {
    const connectionId = await draftConnection('Revoke');
    await customerGrant(connectionId);
    await workerBinds(connectionId);
    const revoked = await chat('provider_grants_revoke', { id: connectionId, profile: PROFILE });
    expect(revoked.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(revoked.proposal.confirmation.summary!.reversible).toBe(false);
    expectExecuted(revoked, 200);
    const grant = (await connectionRow(connectionId)).grants.find((g) => g.profile === PROFILE)!;
    expect(grant).toMatchObject({
      status: 'revoked',
      credentialCiphertext: null,
      credentialKeyId: null,
    });
    await audited(revoked, 'integration.grant_revoked');
  });
});

describe('credentials, consent and validation stay in the portal (D7, I23)', () => {
  it('set credentials, grant create, consent completion and validation runs → denied_not_applicable without a loopback request', async () => {
    const connectionId = await draftConnection('Not applicable');
    for (const [tool, args, template] of [
      [
        'provider_grants_set_credentials',
        {
          id: connectionId,
          profile: PROFILE,
          body: { tenantId: randomUUID(), clientId: randomUUID(), clientSecret: CLIENT_SECRET },
        },
        `${P}/{id}/grants/{p}/credentials`,
      ],
      [
        'provider_grants_create',
        { id: connectionId, body: { profile: PROFILE, authMethod: 'platform_app' } },
        `${P}/{id}/grants`,
      ],
      [
        'provider_grants_complete_consent',
        { body: { state: 'it-state', tenant: randomUUID(), adminConsent: true } },
        `${P}/consent/complete`,
      ],
      [
        'provider_validations_create',
        { id: connectionId, body: { kind: 'full' } },
        `${P}/{id}/validations`,
      ],
    ] as const) {
      const refusal = await refusedTurn(tool, args);
      expect(refusal.execution, tool).toMatchObject({
        decision: 'denied_not_applicable',
        status: 'refused',
      });
      expect(requestsTo({ calls: refusal.calls }, template), tool).toEqual([]);
    }
    expect(
      await ctx.prisma.providerConnectionGrant.count({
        where: { connection: { publicId: connectionId } },
      }),
    ).toBe(0);
    expect(
      await ctx.prisma.providerValidationRun.count({
        where: { connection: { publicId: connectionId } },
      }),
    ).toBe(0);
  });
});

describe('no impact token or credential outside the stored request (I23, R3)', () => {
  it('transcripts, envelopes, executions, confirmation views, audit rows and logs carry none', async () => {
    expect(tokens.size).toBeGreaterThanOrEqual(4);
    const everything = await storedText({ userText: true });
    const logs = ctx.logs.join('\n');
    for (const token of tokens) {
      expect(everything).not.toContain(token);
      expect(logs).not.toContain(token);
    }
    // The model's token and the client secret were typed into the user's directive text only:
    // no execution, confirmation, assistant message, audit row or log line holds them.
    const derived = await storedText({ userText: false });
    for (const value of [MODEL_TOKEN, CLIENT_SECRET]) {
      expect(derived).not.toContain(value);
      expect(logs).not.toContain(value);
    }
  });
});
