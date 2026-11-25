/**
 * Step AI-4 detection tools through chat (docs/plan/steps/32-ai-chat-security-operations.md D2,
 * D4, D5, D9, I20, §9 item 3; the `testedBy` of the 34 BEC, DLP and risk-scoring writes, D5
 * #20–47 and #51–56, in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md). The deterministic fake
 * provider proposes every write from a directive turn (never a real LLM); the api listens on its
 * ephemeral loopback port, so precondition reads, confirm-time re-reads and the confirmed writes
 * go through the real `/api/v1` pipeline. Each write asserts the api's state and the operation's
 * own audit row carrying the result execution's correlation id.
 *
 * - BEC: executives, vendors and trusted senders create / update (CAS `version` injected; the D4
 *   escalations: disabled, known addresses / senders / domains, payment-change sensitivity off,
 *   trusted-sender expiry; the create escalations of known addresses / senders / domains and
 *   payment-change sensitivity off) / delete (query `version` injected); per-message feedback on a seeded
 *   synthetic message with a BEC scan result (without a suppression low, with one escalated to
 *   high) and the suppression's delete (medium, the new single read as precondition).
 * - DLP: policies, rules (the selected rule's `version`), exceptions (create high; widening
 *   escalates), patterns (a pattern change is medium, disable high), dictionaries, the Aadhaar
 *   compliance basis enable / disable (high, `expectedVersion` injected, minimum 0); the
 *   side-effect-free `dlp_patterns_test` whose sample and pattern never reach the execution row
 *   or an audit row (D9); a changed-state refusal (the policy updated through the api between
 *   proposal and confirm → `409 assistant_confirmation_state_changed`, nothing written).
 * - Risk scoring: draft create (low) → update (medium, CAS) → publish (medium) → a second draft
 *   deleted (high) → activate (medium, `expectedProfileVersion` injected) → reset (high).
 *
 * Synthetic `it-*` organizations and `.example` values only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/bec/executives
// @covers patch /api/v1/bec/executives/:id
// @covers delete /api/v1/bec/executives/:id
// @covers post /api/v1/bec/trusted-senders
// @covers patch /api/v1/bec/trusted-senders/:id
// @covers delete /api/v1/bec/trusted-senders/:id
// @covers post /api/v1/bec/vendors
// @covers patch /api/v1/bec/vendors/:id
// @covers delete /api/v1/bec/vendors/:id
// @covers delete /api/v1/bec/suppressions/:id
// @covers post /api/v1/messages/:messageId/scans/:scanId/bec-feedback
// @covers put /api/v1/dlp/compliance/aadhaar
// @covers delete /api/v1/dlp/compliance/aadhaar
// @covers post /api/v1/dlp/dictionaries
// @covers patch /api/v1/dlp/dictionaries/:id
// @covers delete /api/v1/dlp/dictionaries/:id
// @covers post /api/v1/dlp/exceptions
// @covers patch /api/v1/dlp/exceptions/:id
// @covers delete /api/v1/dlp/exceptions/:id
// @covers post /api/v1/dlp/patterns
// @covers patch /api/v1/dlp/patterns/:id
// @covers delete /api/v1/dlp/patterns/:id
// @covers post /api/v1/dlp/patterns/test
// @covers post /api/v1/dlp/policies
// @covers patch /api/v1/dlp/policies/:id
// @covers delete /api/v1/dlp/policies/:id
// @covers post /api/v1/dlp/policies/:id/rules
// @covers patch /api/v1/dlp/policies/:id/rules/:ruleId
// @covers delete /api/v1/dlp/policies/:id/rules/:ruleId
// @covers post /api/v1/risk-scoring/profile/versions
// @covers put /api/v1/risk-scoring/profile/versions/:versionId
// @covers delete /api/v1/risk-scoring/profile/versions/:versionId
// @covers post /api/v1/risk-scoring/profile/versions/:versionId/publish
// @covers post /api/v1/risk-scoring/profile/versions/:versionId/activate
// @covers post /api/v1/risk-scoring/profile/reset
import { randomBytes } from 'node:crypto';
import { AI4_ESCALATION_WARNINGS as W } from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { BecTenantDataRepository } from '../src/modules/tenant-data/bec-tenant-data.repository';
import { DlpTenantDataRepository } from '../src/modules/tenant-data/dlp-tenant-data.repository';
import { RiskTenantDataRepository } from '../src/modules/tenant-data/risk-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  ALL_TENANT_PERMISSIONS,
  allFeatures,
  auditByCorrelation,
  call,
  type ChatWrite,
  clearAssistantCounters,
  confirm,
  createAssistantApp,
  credentialKeys,
  directive,
  enableAssistant,
  executionRow,
  expectExecuted,
  type Member,
  memberWith,
  newConversation,
  operationActionsOf,
  platformMember,
  propose,
  proposeAndConfirm,
  recordLoopback,
  resultCorrelationId,
  storedRequestOf,
  turn,
  waitForRead,
  writesTo,
} from './support/assistant';
import { deleteAtoRows } from './support/ato';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';

/** A stale version the model "remembers"; the executor replaces it from the snapshot. */
const STALE = 999;
const DAY_MS = 86_400_000;
const run = randomBytes(4).toString('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let analyst: Member;

const chat = (tool: string, args: Record<string, unknown>): Promise<ChatWrite> =>
  proposeAndConfirm(ctx, fx, analyst, tool, args);

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
  expect(rows[0]!.actorId).toBe(analyst.user.publicId);
  return rows[0]!;
}

/** The query or body `version` the confirmed request carried. */
async function sentVersion(result: ChatWrite): Promise<number> {
  const request = await storedRequestOf(ctx, result.proposal.confirmation.id);
  const query = /[?&](?:version|expectedRowVersion|expectedVersion)=(\d+)/.exec(request.path);
  if (query) return Number(query[1]);
  const body = request.body ?? {};
  return (body.version ?? body.expectedRowVersion ?? body.expectedVersion) as number;
}

const expectRisk = (result: ChatWrite, risk: 'low' | 'medium' | 'high', warning?: string) => {
  expect(result.proposal.confirmation.risk, result.proposal.confirmation.tool).toBe(risk);
  if (warning) expect(result.proposal.confirmation.summary!.warnings).toContain(warning);
  expect(credentialKeys(result.proposal.confirmation.summary)).toEqual([]);
};

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ features: allFeatures() });
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [org.id]));
  fx.registerCleanup(async () => {
    const scope = systemScope(org.id);
    await ctx.get(BecTenantDataRepository).purgeOrganization(scope);
    await ctx.get(DlpTenantDataRepository).purgeOrganization(scope);
    await ctx.get(RiskTenantDataRepository).purgeOrganization(scope);
    const where = { organizationId: org.id };
    await ctx.prisma.scanEngineResult.deleteMany({ where });
    await ctx.prisma.emailScan.deleteMany({ where });
  });
  // ato_detection is on (every feature): the live ato-worker records the suite's sign-ins.
  fx.registerCleanup(() => deleteAtoRows(ctx.prisma, [org.id]), { rerunOnConflict: true });
  analyst = await memberWith(ctx, fx, org, { permissions: [...ALL_TENANT_PERMISSIONS] });
  await enableAssistant(ctx, operator, org, analyst);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('BEC executives, vendors and trusted senders (D5 #20–#28)', () => {
  it('bec_executives_create (low) / update (low; disabled and known addresses escalate) / remove (high)', async () => {
    const created = await chat('bec_executives_create', {
      body: { displayName: `Anita Sharma ${run}`, title: 'CEO' },
    });
    expectRisk(created, 'low');
    expectExecuted(created, 201);
    const id = (
      await ctx.prisma.becExecutiveProfile.findFirstOrThrow({
        where: { organizationId: org.id },
        orderBy: { id: 'desc' },
      })
    ).publicId;
    await audited(created, 'bec_executive.created');
    const row = () => ctx.prisma.becExecutiveProfile.findUniqueOrThrow({ where: { publicId: id } });

    await waitForRead(ctx, analyst, `/api/v1/bec/executives/${id}`);
    const renamed = await chat('bec_executives_update', {
      id,
      body: { version: STALE, title: 'CFO' },
    });
    expectRisk(renamed, 'low');
    expectExecuted(renamed, 200);
    expect(await sentVersion(renamed)).toBe(1);
    expect(await row()).toMatchObject({ title: 'CFO', version: 2 });
    await audited(renamed, 'bec_executive.updated');

    await waitForRead(ctx, analyst, `/api/v1/bec/executives/${id}`, (b) => b.version === 2);
    const widened = await chat('bec_executives_update', {
      id,
      body: { version: STALE, enabled: false, knownAddresses: ['anita@acme.example'] },
    });
    expectRisk(widened, 'high', W.executiveDisabled);
    expect(widened.proposal.confirmation.summary!.warnings).toContain(W.executiveAddresses);
    expectExecuted(widened, 200);
    expect(await row()).toMatchObject({ enabled: false, version: 3 });

    await waitForRead(ctx, analyst, `/api/v1/bec/executives/${id}`, (b) => b.version === 3);
    const removed = await chat('bec_executives_remove', { id });
    expectRisk(removed, 'high');
    const write = expectExecuted(removed, 204);
    expect(write.path).toBe(`/api/v1/bec/executives/${id}?version=3`);
    expect(await ctx.prisma.becExecutiveProfile.count({ where: { publicId: id } })).toBe(0);
    await audited(removed, 'bec_executive.deleted');
  });

  it('bec_vendors_create (domains → high) / update (payment change off, known senders, disabled → high) / remove (high)', async () => {
    const created = await chat('bec_vendors_create', {
      body: { name: `Globex ${run}`, domains: [`globex-${run}.example`] },
    });
    expectRisk(created, 'high', W.vendorSenders);
    expect(created.proposal.confirmation.requiresReauth).toBe(true);
    expectExecuted(created, 201);
    const id = (
      await ctx.prisma.becVendorProfile.findFirstOrThrow({
        where: { organizationId: org.id },
        orderBy: { id: 'desc' },
      })
    ).publicId;
    await audited(created, 'bec_vendor.created');

    await waitForRead(ctx, analyst, `/api/v1/bec/vendors/${id}`);
    const renamed = await chat('bec_vendors_update', {
      id,
      body: { version: STALE, name: `Globex Supplies ${run}` },
    });
    expectRisk(renamed, 'low');
    expectExecuted(renamed, 200);
    await audited(renamed, 'bec_vendor.updated');

    await waitForRead(ctx, analyst, `/api/v1/bec/vendors/${id}`, (b) => b.version === 2);
    const weakened = await chat('bec_vendors_update', {
      id,
      body: {
        version: STALE,
        paymentChangeSensitive: false,
        knownSenders: [`ar@globex-${run}.example`],
      },
    });
    expectRisk(weakened, 'high', W.vendorPaymentChange);
    expect(weakened.proposal.confirmation.summary!.warnings).toContain(W.vendorSenders);
    expectExecuted(weakened, 200);
    expect(await sentVersion(weakened)).toBe(2);
    expect(
      await ctx.prisma.becVendorProfile.findUniqueOrThrow({ where: { publicId: id } }),
    ).toMatchObject({ paymentChangeSensitive: false, version: 3 });

    await waitForRead(ctx, analyst, `/api/v1/bec/vendors/${id}`, (b) => b.version === 3);
    const disabled = await chat('bec_vendors_update', {
      id,
      body: { version: STALE, enabled: false },
    });
    expectRisk(disabled, 'high', W.vendorDisabled);
    expectExecuted(disabled, 200);

    await waitForRead(ctx, analyst, `/api/v1/bec/vendors/${id}`, (b) => b.version === 4);
    const removed = await chat('bec_vendors_remove', { id });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(`/api/v1/bec/vendors/${id}?version=4`);
    await audited(removed, 'bec_vendor.deleted');
  });

  it('creates escalate like updates (I20, A4-2): known addresses → high, a plain executive stays low; every vendor create is high (domains are required)', async () => {
    // An executive with known addresses suppresses impersonation findings for mail from them.
    const exec = await chat('bec_executives_create', {
      body: {
        displayName: `Rahul Mehta ${run}`,
        title: 'CEO',
        knownAddresses: [`rahul-${run}@freemail.example`],
      },
    });
    expectRisk(exec, 'high', W.executiveAddresses);
    expect(exec.proposal.confirmation.requiresReauth).toBe(true);
    expectExecuted(exec, 201);
    await audited(exec, 'bec_executive.created');
    expect(
      await ctx.prisma.becExecutiveProfile.findFirstOrThrow({
        where: { organizationId: org.id, displayName: `Rahul Mehta ${run}` },
      }),
    ).toMatchObject({ enabled: true });

    // A disabled new profile is not loaded by detection: nothing is weakened, it stays low.
    const disabledExec = await chat('bec_executives_create', {
      body: { displayName: `Disabled Exec ${run}`, enabled: false },
    });
    expectRisk(disabledExec, 'low');
    expect(disabledExec.proposal.confirmation.summary!.warnings).toEqual([]);
    expectExecuted(disabledExec, 201);

    const senders = await chat('bec_vendors_create', {
      body: {
        name: `Initech ${run}`,
        domains: [`initech-${run}.example`],
        knownSenders: [`billing@initech-${run}.example`],
        paymentChangeSensitive: false,
      },
    });
    expectRisk(senders, 'high', W.vendorSenders);
    expect(senders.proposal.confirmation.summary!.warnings).toContain(W.vendorPaymentChange);
    expectExecuted(senders, 201);
    await audited(senders, 'bec_vendor.created');

    // `domains` is required on a vendor create (1–20), and mail from a vendor domain is
    // recognized as the vendor (V1 and the Reply-To rule R1 do not fire for it), so every vendor
    // create is high; payment-change sensitivity off adds its own warning.
    const plainVendor = await chat('bec_vendors_create', {
      body: {
        name: `Hooli ${run}`,
        domains: [`hooli-${run}.example`],
        paymentChangeSensitive: true,
      },
    });
    expectRisk(plainVendor, 'high', W.vendorSenders);
    expect(plainVendor.proposal.confirmation.summary!.warnings).not.toContain(
      W.vendorPaymentChange,
    );
    expectExecuted(plainVendor, 201);

    const paymentOff = await chat('bec_vendors_create', {
      body: {
        name: `Umbrella ${run}`,
        domains: [`umbrella-${run}.example`],
        paymentChangeSensitive: false,
      },
    });
    expectRisk(paymentOff, 'high', W.vendorSenders);
    expect(paymentOff.proposal.confirmation.summary!.warnings).toContain(W.vendorPaymentChange);
    expectExecuted(paymentOff, 201);

    // A plain executive (no known addresses) stays low.
    const plainExec = await chat('bec_executives_create', {
      body: { displayName: `Plain Exec ${run}`, title: 'COO' },
    });
    expectRisk(plainExec, 'low');
    expect(plainExec.proposal.confirmation.requiresReauth).toBe(false);
    expectExecuted(plainExec, 201);
  });

  it('bec_trusted_senders_create (high) / update (low; expiresAt → high) / remove (high)', async () => {
    const created = await chat('bec_trusted_senders_create', {
      body: { kind: 'address', value: `Ops.${run}@Partner.Example`, reason: 'Payroll partner' },
    });
    expectRisk(created, 'high');
    expectExecuted(created, 201);
    const row = await ctx.prisma.becTrustedSender.findFirstOrThrow({
      where: { organizationId: org.id },
      orderBy: { id: 'desc' },
    });
    expect(row.value).toBe(`ops.${run}@partner.example`);
    const id = row.publicId;
    await audited(created, 'bec_trusted_sender.created');

    await waitForRead(ctx, analyst, `/api/v1/bec/trusted-senders/${id}`);
    const reason = await chat('bec_trusted_senders_update', {
      id,
      body: { version: STALE, reason: 'Payroll partner (renewed)' },
    });
    expectRisk(reason, 'low');
    expectExecuted(reason, 200);
    await audited(reason, 'bec_trusted_sender.updated');

    await waitForRead(ctx, analyst, `/api/v1/bec/trusted-senders/${id}`, (b) => b.version === 2);
    const expiry = await chat('bec_trusted_senders_update', {
      id,
      body: { version: STALE, expiresAt: new Date(Date.now() + 60 * DAY_MS).toISOString() },
    });
    expectRisk(expiry, 'high', W.trustedSenderExpiry);
    expectExecuted(expiry, 200);
    expect(await sentVersion(expiry)).toBe(2);

    await waitForRead(ctx, analyst, `/api/v1/bec/trusted-senders/${id}`, (b) => b.version === 3);
    const removed = await chat('bec_trusted_senders_remove', { id });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(`/api/v1/bec/trusted-senders/${id}?version=3`);
    expect(await ctx.prisma.becTrustedSender.count({ where: { publicId: id } })).toBe(0);
    await audited(removed, 'bec_trusted_sender.deleted');
  });
});

/** A completed round with a bec final and its `bec_scan_results` row (as the email-worker writes). */
async function insertBecRound(message: LifecycleMessage): Promise<bigint> {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const completedAt = new Date(startedAt.getTime() + 1_234);
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const rules = [
    {
      id: 'R2',
      code: 'bec.reply_to.freemail',
      category: 'identity',
      severity: 'medium',
      weight: 20,
      suppressed: null,
      evidence: [{ header: 'Reply-To', domain: 'gmail.com' }],
    },
  ];
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: 'suspicious',
      requiredEngines: ['bec'],
      reasonCodes: rules.map((r) => r.code),
      startedAt,
      completedAt,
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'bec',
      engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
      outcome: 'suspicious',
      score: 45,
      requiredScore: 40,
      durationMs: 321,
      attempt: 1,
      isFinal: true,
      reasonCodes: rules.map((r) => r.code),
      settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
      evidence: { signals: [], thresholds: { suspicious: 40, malicious: 80 } },
      completedAt,
    },
  });
  await ctx.prisma.becScanResult.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
      rulesVersion: 'bec-map/1',
      settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
      lexiconVersion: '2876a3ab',
      textVersion: 'bec-text/1',
      deterministicScore: 45,
      score: 45,
      deterministicVerdict: 'suspicious',
      verdict: 'suspicious',
      inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      rules,
      features: { rule_r2: 1 },
      identity: {
        from: {
          displayName: 'Billing',
          address: `billing-${run}@partner-co.example`,
          domain: 'partner-co.example',
          registrableDomain: 'partner-co.example',
          kind: 'external',
        },
        fromCount: 1,
        replyTo: [],
        sender: null,
        returnPath: null,
        envelopeFrom: `billing-${run}@partner-co.example`,
        isReply: false,
        flags: [],
      },
      ai: [],
      aiShadow: [],
      durationMs: 321,
    },
  });
  return scan.id;
}

describe('BEC per-message feedback and suppressions (D5 #29–#30)', () => {
  it('bec_message_feedback_record: without suppress low; with suppress high; the suppression deleted (medium)', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'scanned' });
    const scanId = (await insertBecRound(message)).toString();
    await waitForRead(ctx, analyst, `/api/v1/messages/${message.publicId}`);

    const negative = await chat('bec_message_feedback_record', {
      messageId: message.publicId,
      scanId,
      body: { kind: 'false_negative' },
    });
    expectRisk(negative, 'low');
    expectExecuted(negative, 201);
    await audited(negative, 'bec_feedback.recorded');

    const suppress = await chat('bec_message_feedback_record', {
      messageId: message.publicId,
      scanId,
      body: {
        kind: 'false_positive',
        reasonCodes: ['bec.reply_to.freemail'],
        suppress: { codes: ['bec.reply_to.freemail'], scope: 'domain', days: 30 },
      },
    });
    expectRisk(suppress, 'high', W.becSuppress);
    expectExecuted(suppress, 201);
    const rule = await ctx.prisma.becSuppressionRule.findFirstOrThrow({
      where: { organizationId: org.id, reasonCode: 'bec.reply_to.freemail' },
    });
    expect(rule.senderValue).toBe('partner-co.example');

    await waitForRead(ctx, analyst, `/api/v1/bec/suppressions/${rule.publicId}`);
    const removed = await chat('bec_feedback_delete_suppression', { id: rule.publicId });
    expectRisk(removed, 'medium');
    expectExecuted(removed, 204);
    expect(await ctx.prisma.becSuppressionRule.count({ where: { id: rule.id } })).toBe(0);
    await audited(removed, 'bec_suppression.deleted');
  });
});

describe('DLP policies and rules (D5 #42–#47)', () => {
  let policyId: string;
  let ruleId: string;
  const policyRow = () => ctx.prisma.dlpPolicy.findUniqueOrThrow({ where: { publicId: policyId } });
  const ruleRow = () => ctx.prisma.dlpPolicyRule.findUniqueOrThrow({ where: { publicId: ruleId } });
  const policyUrl = () => `/api/v1/dlp/policies/${policyId}`;

  it('dlp_policies_create (low) / update (rename low; disabled and monitor → high)', async () => {
    const created = await chat('dlp_policies_create', { body: { name: `Cards ${run}` } });
    expectRisk(created, 'low');
    expectExecuted(created, 201);
    policyId = (
      await ctx.prisma.dlpPolicy.findFirstOrThrow({
        where: { organizationId: org.id, name: `Cards ${run}` },
      })
    ).publicId;
    await audited(created, 'dlp_policy.created');

    await waitForRead(ctx, analyst, policyUrl());
    const renamed = await chat('dlp_policies_update', {
      id: policyId,
      body: { version: STALE, name: `Card numbers ${run}` },
    });
    expectRisk(renamed, 'low');
    expectExecuted(renamed, 200);
    expect(await sentVersion(renamed)).toBe(1);
    await audited(renamed, 'dlp_policy.updated');

    await waitForRead(ctx, analyst, policyUrl(), (b) => b.version === 2);
    const monitor = await chat('dlp_policies_update', {
      id: policyId,
      body: { version: STALE, mode: 'monitor' },
    });
    expectRisk(monitor, 'high', W.dlpPolicyMonitor);
    expectExecuted(monitor, 200);

    await waitForRead(ctx, analyst, policyUrl(), (b) => b.version === 3);
    const disabled = await chat('dlp_policies_update', {
      id: policyId,
      body: { version: STALE, enabled: false },
    });
    expectRisk(disabled, 'high', W.dlpPolicyDisabled);
    expectExecuted(disabled, 200);
    expect(await policyRow()).toMatchObject({ enabled: false, mode: 'monitor', version: 4 });
  });

  it('a policy changed through the api between proposal and confirm → 409 state changed, nothing written', async () => {
    await waitForRead(ctx, analyst, policyUrl(), (b) => b.version === 4);
    const proposal = await propose(
      ctx,
      analyst,
      directive('dlp_policies_update', {
        id: policyId,
        body: { version: STALE, name: 'stale rename' },
      }),
    );
    const direct = await call(ctx, analyst.headers, 'patch', policyUrl(), {
      version: 4,
      description: 'Changed on the policies page',
    });
    expect(direct.status, JSON.stringify(direct.body)).toBe(200);
    await waitForRead(ctx, analyst, policyUrl(), (b) => b.version === 5);
    const recorder = recordLoopback(ctx);
    let res;
    try {
      res = await confirm(ctx, analyst, proposal);
    } finally {
      recorder.restore();
    }
    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_state_changed');
    expect(writesTo(recorder, '/api/v1/dlp/policies/{id}')).toEqual([]);
    expect(await policyRow()).toMatchObject({ version: 5, name: `Card numbers ${run}` });
  });

  it('dlp_policies_create_rule (low; allow → high) / update_rule (rule version injected; disabled → high) / remove_rule (high)', async () => {
    const block = await chat('dlp_policies_create_rule', {
      id: policyId,
      body: {
        name: 'Cards out',
        conditions: { selectors: { categories: ['payment_card'] } },
        action: 'block',
      },
    });
    expectRisk(block, 'low');
    expectExecuted(block, 201);
    ruleId = (
      await ctx.prisma.dlpPolicyRule.findFirstOrThrow({
        where: { organizationId: org.id, name: 'Cards out' },
      })
    ).publicId;
    await audited(block, 'dlp_rule.created');

    await waitForRead(
      ctx,
      analyst,
      policyUrl(),
      (b) => (b.rules as unknown[] | undefined)?.length === 1,
    );
    const allow = await chat('dlp_policies_create_rule', {
      id: policyId,
      body: {
        name: 'Auditors in',
        conditions: { selectors: { categories: ['national_id'] } },
        action: 'allow',
      },
    });
    expectRisk(allow, 'high', W.dlpAllowRule);
    expectExecuted(allow, 201);

    await waitForRead(
      ctx,
      analyst,
      policyUrl(),
      (b) => (b.rules as unknown[] | undefined)?.length === 2,
    );
    const renamed = await chat('dlp_policies_update_rule', {
      id: policyId,
      ruleId,
      body: { version: STALE, name: 'Cards outbound' },
    });
    expectRisk(renamed, 'low');
    expectExecuted(renamed, 200);
    expect(await sentVersion(renamed)).toBe(1);
    expect(await ruleRow()).toMatchObject({ name: 'Cards outbound', version: 2 });
    await audited(renamed, 'dlp_rule.updated');

    await waitForRead(ctx, analyst, policyUrl(), (b) =>
      ((b.rules as Array<{ id: string; version: number }> | undefined) ?? []).some(
        (r) => r.id === ruleId && r.version === 2,
      ),
    );
    const disabled = await chat('dlp_policies_update_rule', {
      id: policyId,
      ruleId,
      body: { version: STALE, enabled: false },
    });
    expectRisk(disabled, 'high', W.dlpRuleDisabled);
    expectExecuted(disabled, 200);

    await waitForRead(ctx, analyst, policyUrl(), (b) =>
      ((b.rules as Array<{ id: string; version: number }> | undefined) ?? []).some(
        (r) => r.id === ruleId && r.version === 3,
      ),
    );
    const removed = await chat('dlp_policies_remove_rule', { id: policyId, ruleId });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(
      `/api/v1/dlp/policies/${policyId}/rules/${ruleId}?version=3`,
    );
    await audited(removed, 'dlp_rule.deleted');
  });

  it('dlp_policies_remove (high): query version injected', async () => {
    const current = await waitForRead(
      ctx,
      analyst,
      policyUrl(),
      (b) => (b.rules as unknown[]).length === 1,
    );
    const removed = await chat('dlp_policies_remove', { id: policyId });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(
      `${policyUrl()}?version=${current.version as number}`,
    );
    expect(await ctx.prisma.dlpPolicy.count({ where: { publicId: policyId } })).toBe(0);
    await audited(removed, 'dlp_policy.deleted');
  });
});

describe('DLP exceptions, patterns and dictionaries (D5 #33–#41)', () => {
  it('dlp_exceptions_create (high) / update (reason low; enabled, expiresAt, filters → high) / remove (high)', async () => {
    const created = await chat('dlp_exceptions_create', {
      body: {
        scope: 'recipient_domain',
        value: `auditor-${run}.example`,
        reason: 'Statutory auditor receives card reconciliations',
        expiresAt: new Date(Date.now() + 30 * DAY_MS).toISOString(),
      },
    });
    expectRisk(created, 'high');
    expectExecuted(created, 201);
    const id = (
      await ctx.prisma.dlpException.findFirstOrThrow({
        where: { organizationId: org.id, value: `auditor-${run}.example` },
      })
    ).publicId;
    await audited(created, 'dlp_exception.created');
    const url = `/api/v1/dlp/exceptions/${id}`;

    await waitForRead(ctx, analyst, url);
    const reason = await chat('dlp_exceptions_update', {
      id,
      body: { version: STALE, reason: 'Statutory auditor (2026 engagement)' },
    });
    expectRisk(reason, 'low');
    expectExecuted(reason, 200);
    expect(await sentVersion(reason)).toBe(1);
    await audited(reason, 'dlp_exception.updated');

    await waitForRead(ctx, analyst, url, (b) => b.version === 2);
    const widened = await chat('dlp_exceptions_update', {
      id,
      body: {
        version: STALE,
        expiresAt: new Date(Date.now() + 80 * DAY_MS).toISOString(),
        filters: null,
      },
    });
    expectRisk(widened, 'high', W.dlpExceptionWidened);
    expectExecuted(widened, 200);

    await waitForRead(ctx, analyst, url, (b) => b.version === 3);
    const removed = await chat('dlp_exceptions_remove', { id });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(`${url}?version=3`);
    expect(await ctx.prisma.dlpException.count({ where: { publicId: id } })).toBe(0);
    await audited(removed, 'dlp_exception.deleted');
  });

  it('dlp_patterns_create (low) / update (name low; pattern medium; disabled high) / remove (high); never the pattern in warnings', async () => {
    const pattern = `EMP${run}-[0-9]{6}`;
    const created = await chat('dlp_patterns_create', {
      body: {
        name: `Employee id ${run}`,
        pattern,
        severity: 'medium',
        contextKeywords: ['employee'],
      },
    });
    expectRisk(created, 'low');
    expectExecuted(created, 201);
    const id = (
      await ctx.prisma.dlpCustomPattern.findFirstOrThrow({
        where: { organizationId: org.id, name: `Employee id ${run}` },
      })
    ).publicId;
    await audited(created, 'dlp_pattern.created');
    const url = `/api/v1/dlp/patterns/${id}`;

    await waitForRead(ctx, analyst, url);
    const renamed = await chat('dlp_patterns_update', {
      id,
      body: { version: STALE, name: `Employee number ${run}` },
    });
    expectRisk(renamed, 'low');
    expectExecuted(renamed, 200);

    await waitForRead(ctx, analyst, url, (b) => b.version === 2);
    const changed = await chat('dlp_patterns_update', {
      id,
      body: { version: STALE, pattern: `EMP${run}-[0-9]{7}` },
    });
    expectRisk(changed, 'medium', W.dlpPatternChanged);
    const summary = changed.proposal.confirmation.summary!;
    expect(
      JSON.stringify([summary.impact, summary.warnings, summary.title, summary.action]),
    ).not.toContain(`EMP${run}`);
    expectExecuted(changed, 200);
    await audited(changed, 'dlp_pattern.updated');

    await waitForRead(ctx, analyst, url, (b) => b.version === 3);
    const disabled = await chat('dlp_patterns_update', {
      id,
      body: { version: STALE, enabled: false },
    });
    expectRisk(disabled, 'high', W.dlpDetectorDisabled);
    expectExecuted(disabled, 200);

    await waitForRead(ctx, analyst, url, (b) => b.version === 4);
    const removed = await chat('dlp_patterns_remove', { id });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(`${url}?version=4`);
    await audited(removed, 'dlp_pattern.deleted');
  });

  it('dlp_dictionaries_create (low) / update (terms low; disabled high) / remove (high)', async () => {
    const created = await chat('dlp_dictionaries_create', {
      body: {
        name: `Projects ${run}`,
        category: 'confidential',
        severity: 'high',
        terms: [`Falcon${run}`, 'Board Pack Q3'],
      },
    });
    expectRisk(created, 'low');
    expectExecuted(created, 201);
    const id = (
      await ctx.prisma.dlpKeywordDictionary.findFirstOrThrow({
        where: { organizationId: org.id, name: `Projects ${run}` },
      })
    ).publicId;
    await audited(created, 'dlp_dictionary.created');
    const url = `/api/v1/dlp/dictionaries/${id}`;

    await waitForRead(ctx, analyst, url);
    const terms = await chat('dlp_dictionaries_update', {
      id,
      body: { version: STALE, terms: [`Falcon${run}`, 'Board Pack Q4', 'Merger Memo'] },
    });
    expectRisk(terms, 'low');
    expectExecuted(terms, 200);
    await audited(terms, 'dlp_dictionary.updated');

    await waitForRead(ctx, analyst, url, (b) => b.version === 2);
    const disabled = await chat('dlp_dictionaries_update', {
      id,
      body: { version: STALE, enabled: false },
    });
    expectRisk(disabled, 'high', W.dlpDetectorDisabled);
    expectExecuted(disabled, 200);

    await waitForRead(ctx, analyst, url, (b) => b.version === 3);
    const removed = await chat('dlp_dictionaries_remove', { id });
    expectRisk(removed, 'high');
    expect(expectExecuted(removed, 204).path).toBe(`${url}?version=3`);
    await audited(removed, 'dlp_dictionary.deleted');
  });
});

describe('DLP Aadhaar compliance (D5 #31–#32)', () => {
  it('dlp_compliance_enable (high, expectedVersion injected, minimum 0) / dlp_compliance_disable (high, query)', async () => {
    await waitForRead(ctx, analyst, '/api/v1/dlp/compliance');
    const enabled = await chat('dlp_compliance_enable', {
      body: {
        expectedVersion: STALE,
        basis: 'uidai_authorised_entity',
        reference: 'UIDAI AUA licence 2026-01',
        attested: true,
        reviewDueAt: new Date(Date.now() + 200 * DAY_MS).toISOString(),
      },
    });
    expectRisk(enabled, 'high');
    const write = expectExecuted(enabled, 200);
    // Legacy idempotency: the confirmation id is the key.
    expect(write.idempotencyKey).toBe(enabled.proposal.confirmation.id);
    expect(await sentVersion(enabled)).toBe(0);
    await audited(enabled, 'dlp_compliance.aadhaar_enabled');

    await waitForRead(ctx, analyst, '/api/v1/dlp/compliance', (b) => b.version === 1);
    const disabled = await chat('dlp_compliance_disable', {});
    expectRisk(disabled, 'high');
    expect(expectExecuted(disabled, 200).path).toBe(
      '/api/v1/dlp/compliance/aadhaar?expectedVersion=1',
    );
    expect(
      await ctx.prisma.dlpComplianceSettings.findFirstOrThrow({
        where: { organizationId: org.id },
      }),
    ).toMatchObject({ version: 2 });
    await audited(disabled, 'dlp_compliance.aadhaar_disabled');
  });
});

describe('dlp_patterns_test: the sample and the pattern are never stored (D9)', () => {
  it('the loopback carries them; params_redacted and every audit row do not', async () => {
    const sampleMarker = `SAMPLEMARK${run}`;
    const patternMarker = `PATMARK${run}`;
    const conversation = await newConversation(ctx, analyst);
    const res = await turn(
      ctx,
      analyst.headers,
      conversation,
      directive('dlp_patterns_test', {
        body: {
          pattern: `${patternMarker}-[0-9]{6}`,
          sample: `${sampleMarker} employee ${patternMarker}-123456`,
        },
      }),
    );
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.executions[0]).toMatchObject({
      tool: 'dlp_patterns_test',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 200,
    });
    const row = await executionRow(ctx, res.body.executions[0].id as string);
    const stored = JSON.stringify(row.paramsRedacted);
    expect(stored).toContain('[redacted]');
    expect(stored).not.toContain(sampleMarker);
    expect(stored).not.toContain(patternMarker);
    const audit = await ctx.prisma.auditLog.findMany({ where: { organizationId: org.id } });
    const text = JSON.stringify(audit.map((a) => a.metadata));
    expect(text).not.toContain(sampleMarker);
    expect(text).not.toContain(patternMarker);
    expect(
      audit.some(
        (a) => a.correlationId === row.correlationId && !a.action.startsWith('assistant.'),
      ),
    ).toBe(false);
  });
});

describe('risk scoring profiles (D5 #51–#56)', () => {
  const VERSIONS = '/api/v1/risk-scoring/profile/versions';
  let v1: string;

  it('create_draft (low) → update_draft (medium, CAS) → publish (medium); a second draft deleted (high)', async () => {
    const created = await chat('risk_profiles_create_draft', {
      body: { overrides: { actions: { medium: 'quarantine' } }, changeNote: 'hold medium' },
    });
    expectRisk(created, 'low');
    expectExecuted(created, 201);
    v1 = (
      await ctx.prisma.riskScoringProfileVersion.findFirstOrThrow({
        where: { organizationId: org.id, versionNo: 1 },
      })
    ).publicId;
    await audited(created, 'risk_profile.draft_created');

    await waitForRead(ctx, analyst, `${VERSIONS}/${v1}`);
    const updated = await chat('risk_profiles_update_draft', {
      versionId: v1,
      body: { overrides: { actions: { medium: 'require_approval' } }, expectedRowVersion: STALE },
    });
    expectRisk(updated, 'medium');
    expectExecuted(updated, 200);
    expect(await sentVersion(updated)).toBe(1);
    await audited(updated, 'risk_profile.draft_updated');

    await waitForRead(ctx, analyst, `${VERSIONS}/${v1}`, (b) => b.rowVersion === 2);
    const published = await chat('risk_profiles_publish', {
      versionId: v1,
      body: { expectedRowVersion: STALE },
    });
    expectRisk(published, 'medium');
    expectExecuted(published, 200);
    expect(await sentVersion(published)).toBe(2);
    expect(await operationActionsOf(ctx, published.res)).toEqual(
      expect.arrayContaining(['risk_profile.published']),
    );

    const draft = await chat('risk_profiles_create_draft', { body: { overrides: {} } });
    expectExecuted(draft, 201);
    const v2 = (
      await ctx.prisma.riskScoringProfileVersion.findFirstOrThrow({
        where: { organizationId: org.id, versionNo: 2 },
      })
    ).publicId;
    await waitForRead(ctx, analyst, `${VERSIONS}/${v2}`);
    const deleted = await chat('risk_profiles_delete_draft', { versionId: v2 });
    expectRisk(deleted, 'high');
    expect(expectExecuted(deleted, 204).path).toBe(`${VERSIONS}/${v2}?expectedRowVersion=1`);
    expect(await ctx.prisma.riskScoringProfileVersion.count({ where: { publicId: v2 } })).toBe(0);
    await audited(deleted, 'risk_profile.draft_deleted');
  });

  it('reset (high) then activate (medium): expectedProfileVersion injected from the profile read', async () => {
    const before = await waitForRead(
      ctx,
      analyst,
      '/api/v1/risk-scoring/profile',
      (b) => (b.active as { versionId?: string } | undefined)?.versionId === v1,
    );
    const reset = await chat('risk_profiles_reset', {});
    expectRisk(reset, 'high');
    expectExecuted(reset, 200);
    const resetBody = (await storedRequestOf(ctx, reset.proposal.confirmation.id)).body!;
    expect(resetBody.expectedProfileVersion).toBe(before.profileVersion);
    await audited(reset, 'risk_profile.reset');
    expect(
      (await ctx.prisma.riskScoringProfile.findFirstOrThrow({ where: { organizationId: org.id } }))
        .activeVersionId,
    ).toBeNull();

    const after = await waitForRead(
      ctx,
      analyst,
      '/api/v1/risk-scoring/profile',
      (b) => (b.active as { source?: string } | undefined)?.source === 'platform',
    );
    const activated = await chat('risk_profiles_activate', { versionId: v1 });
    expectRisk(activated, 'medium');
    const write = expectExecuted(activated, 200);
    expect(write.idempotencyKey).toBe(activated.proposal.confirmation.id);
    expect(
      (await storedRequestOf(ctx, activated.proposal.confirmation.id)).body!.expectedProfileVersion,
    ).toBe(after.profileVersion);
    await audited(activated, 'risk_profile.activated');
  });
});
