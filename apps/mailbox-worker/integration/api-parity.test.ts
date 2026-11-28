import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import {
  EventTypes,
  messageCopyDetectedV1,
  policyNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import {
  messageLocation,
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import {
  copyMessageIdHash,
  ingestKeyForCopy,
  remediationDecisionRecordSchema,
} from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import { mailboxRestoreApprovalReasons } from '@email-gateway/quarantine';
import type { MailboxComponents } from '../src/components';
import { COPIES_CONSUMER } from '../src/copies/copies.handler';
import { CounterStore, hourOf } from '../src/runtime/redis-stores';
import { adminClawback, clawbackConfig, user } from './support/clawback';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import {
  CLEAN_RISK,
  clearPolicies,
  policyDoc,
  publishPolicy,
  ruleFor,
  scanRound,
  type RiskShape,
} from './support/parity';
import { actionsOfCopy, cancelOpenActions, copiesOf, drain } from './support/remediation';

/**
 * Design note 38 §10.3 (mailbox-worker, step API-4): detect-mode policy evaluation of API-mode
 * copies with the policy-engine's runtime on the real writer (A1–A3), the policy lane of the
 * remediation decision executed on the Graph simulator with the A5 mailbox entries, outbound
 * detections (A6), the ALERT request (A7), the `mail.message.copy_detected.v1` outbox row (A8),
 * the feed copy path, mailbox scope (B6: evaluation, new mailboxes, feeds, decisions, clawback,
 * coverage), the detect-only expiry (B7), first-copy tracking (B8), the `policy.errors_1h` health
 * check (A11) and idempotent redelivery. Injected clock; synthetic `it-apiparity-*`
 * organizations only; nothing reaches a real provider.
 */
const fx = new Fixtures('it-apiparity');
const clock = new Clock();
let sims: RunningSimulators;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const ALEX = `alex@${MS_DOMAIN}`;
const BLAKE = `blake@${MS_DOMAIN}`;
const CASEY = `casey@${MS_DOMAIN}`;
const EXTERNAL = 'partner@partner-org.example';
let firstCopyId: bigint | null = null;

const MALWARE: RiskShape = {
  verdict: 'malware',
  level: 'critical',
  score: 990,
  recommendedAction: 'block',
  hardBlocks: ['hb.malware_attachment'],
};

interface Sent {
  message: { id: bigint; publicId: string; receivedAt: Date };
  event: ReturnType<Fixtures['copyScanned']>;
  delivered: Map<string, string>;
  messageId: string;
}

/** A journal copy (delivered to the simulator mailboxes of `MS_DOMAIN` recipients) + its round. */
async function journal(
  target: { org: TestOrg; sourceId: bigint },
  input: {
    to: string[];
    from?: string;
    direction?: 'inbound' | 'outbound' | 'internal';
    risk?: RiskShape;
    dlp?: { action: 'alert' | 'require_approval' | 'quarantine' | 'block'; category: string };
    messageId?: string;
    deliver?: boolean;
    breakScan?: boolean;
  },
): Promise<Sent> {
  const messageId = input.messageId ?? `${randomUUID()}@sender.example`;
  const from = input.from ?? 'sender@sender.example';
  const eml = syntheticEml({ messageId, from, to: input.to });
  const delivered = new Map<string, string>();
  if (input.deliver !== false) {
    for (const to of input.to.filter((r) => r.endsWith(`@${MS_DOMAIN}`))) {
      delivered.set(to, (await sims.deliver({ user: to, eml })).messageId);
    }
  }
  const message = await fx.journalCopy(target.org, target.sourceId, {
    eml,
    recipients: input.to,
    messageId,
    from,
    receivedAt: clock.now(),
    direction: input.direction ?? 'inbound',
  });
  const risk = input.risk ?? CLEAN_RISK;
  const scanId = await scanRound(fx, target.org.id, message, {
    risk,
    direction: input.direction ?? 'inbound',
    ...(input.dlp ? { dlp: input.dlp } : {}),
  });
  if (input.breakScan) {
    // A malformed round row (PolicyInputError: a final scan without its completion time).
    await fx.prisma.emailScan.updateMany({
      where: { id: scanId, receivedAt: message.receivedAt },
      data: { completedAt: null },
    });
  }
  const event = fx.copyScanned(target.org.id, message, {
    completedAt: clock.now(),
    verdict: risk.verdict,
    riskScore: risk.score,
    scanId: scanId.toString(),
  });
  expect(await comps.copies.handle(event)).toBe('handled');
  return { message, event, delivered, messageId };
}

const main = () => ({ org, sourceId });
const detectRows = (messageId: bigint) =>
  fx.prisma.policyExecutionLog.findMany({
    where: { messageId },
    orderBy: { evaluationSeq: 'asc' },
  });
const outboxOf = (eventType: string, aggregateId?: string) =>
  fx.prisma.messageOutbox.findMany({
    where: {
      organizationId: { in: fx.organizationIds },
      eventType,
      ...(aggregateId ? { aggregateId } : {}),
    },
    orderBy: { id: 'asc' },
  });
const recordOf = (decision: unknown) => {
  const record = remediationDecisionRecordSchema.parse(decision);
  if (record.v !== 2) throw new Error('expected api-remediation-decision/2');
  return record;
};
const counter = async (field: string): Promise<number> =>
  Number(
    (await fx.redis.hget(CounterStore.key(conn.apiConnectionId, hourOf(clock.now())), field)) ?? 0,
  );

beforeAll(async () => {
  sims = await startSimulators({
    dataset: { microsoft: { directories: [microsoftDirectory(clock.now())] } },
    now: clock.ms,
  });
  sims.tokens.setGrant(
    MS_TENANT_ID,
    M365_MAILBOX_REMEDIATION_PROFILE.key,
    M365_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  const tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(clawbackConfig(fx, sims, { API_MODE_POLICY_EVALUATION_ENABLED: 'true' }), {
    clock,
    tokens,
  });
  org = await fx.organization('main');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
  expect((await comps.inventory!.run(conn.apiConnectionId)).result).toBe('ok');
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
  await clearPolicies(fx, org.id);
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('detect evaluation of journal copies and the policy lane (A1–A5)', () => {
  it('tenant REJECT on a clean copy → detect row, copy columns, policy-lane move, entry reason policy, detection event', async () => {
    const pub = await publishPolicy(
      fx,
      org.id,
      'block sender',
      policyDoc('inbound', [ruleFor('inbound', 'block-sender', [{ type: 'REJECT' }])]),
    );
    const sent = await journal(main(), { to: [ALEX] });
    const [row] = await detectRows(sent.message.id);
    expect(row).toMatchObject({
      evaluationMode: 'detect',
      evaluationSeq: 0,
      disposition: 'reject',
      decisionSource: 'tenant_rule',
      decisivePolicyPublicId: pub.publicId,
      decisiveRuleId: 'block-sender',
      deliveredObject: 'none',
      delivery: null,
      objectKey: null,
    });
    expect((row!.actions as Array<{ type: string; status: string }>)[0]).toMatchObject({
      type: 'REJECT',
      status: 'requested',
    });
    const [copy] = await copiesOf(fx, sent.message.id);
    firstCopyId = copy!.id;
    expect(copy).toMatchObject({
      policyState: 'evaluated',
      policyDisposition: 'reject',
      policyTagged: false,
      dlpAction: null,
      remediationState: 'pending',
      remediationAction: 'move_quarantine',
    });
    const [action] = await actionsOfCopy(fx, copy!.id);
    expect(action).toMatchObject({
      action: 'move_quarantine',
      trigger: 'policy',
      status: 'pending',
    });
    const record = recordOf(action!.decision);
    expect(record).toMatchObject({
      v: 2,
      ruleId: 'policy-mapping:reject',
      lanes: { verdict: null, policy: { key: 'reject' }, winner: 'policy' },
      policyOutcome: {
        disposition: 'reject',
        decisiveRuleRef: `${pub.publicId}#${pub.versionNo}/block-sender`,
      },
    });
    await drain(comps);
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: copy!.id },
    });
    expect(entry).toMatchObject({
      kind: 'quarantine',
      reason: 'policy',
      location: 'mailbox',
      explanationText: `Removed from the mailbox by the tenant policy (API mode; rule ${pub.publicId}#${pub.versionNo}/block-sender)`,
    });
    const location = messageLocation(sims.script, ALEX, sent.delivered.get(ALEX)!)!;
    expect(location.folder!.displayName).toBe('Email Gateway Quarantine');
    // P-I1: no lifecycle edge, verdict, delivery or policy decision event for a copy.
    const message = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: sent.message.id },
    });
    expect(message).toMatchObject({ status: 'journaled', finalVerdict: null, finalAction: null });
    expect(await outboxOf(EventTypes.PolicyDecided)).toEqual([]);
    expect(await outboxOf('mail.delivery.approved.v1')).toEqual([]);
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId);
    expect(detected).toMatchObject({
      aggregateType: 'message',
      correlationId: sent.event.correlationId,
    });
    expect(messageCopyDetectedV1.parse(detected!.payload)).toMatchObject({
      messageId: sent.message.id.toString(),
      ingestSource: 'journal_intake',
      copySource: 'journal',
      direction: 'inbound',
      protectionMode: 'api',
      verdict: 'clean',
      policy: { state: 'evaluated', disposition: 'reject', decisionSource: 'tenant_rule' },
      dlp: null,
      copies: { counted: 1, remediation: { pending: 1, simulated: 0, skipped: 0, none: 0 } },
      detectionIds: [copy!.publicId],
    });
    expect(await counter('policy_evaluations')).toBeGreaterThanOrEqual(1);
  });

  it('first-copy tracking: the domain row keeps its first in-scope copy (B8)', async () => {
    await journal(main(), { to: [BLAKE] });
    const settings = await fx.prisma.apiModeDomainSetting.findUniqueOrThrow({
      where: { domainId: org.domains.get(MS_DOMAIN)! },
    });
    expect(settings).toMatchObject({ organizationId: org.id, scopeKind: 'all' });
    expect(settings.firstCopyId).toBe(firstCopyId);
    expect(settings.firstCopyAt).not.toBeNull();
  });

  it('REQUIRE_APPROVAL → a review entry whose restore needs an approver', async () => {
    await publishPolicy(
      fx,
      org.id,
      'hold',
      policyDoc('inbound', [ruleFor('inbound', 'hold', [{ type: 'REQUIRE_APPROVAL' }])]),
    );
    const sent = await journal(main(), { to: [CASEY] });
    const [copy] = await copiesOf(fx, sent.message.id);
    expect(copy).toMatchObject({ policyDisposition: 'require_approval' });
    await drain(comps);
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: copy!.id },
    });
    expect(entry).toMatchObject({ kind: 'review', reason: 'policy', status: 'held' });
    expect(
      mailboxRestoreApprovalReasons({
        entry: {
          kind: entry.kind,
          reason: entry.reason,
          state: entry.status,
          riskLevel: entry.riskLevel,
          hasHardBlock: entry.hasHardBlock,
        },
        copyStatus: 'scanned',
      }),
    ).toContain('review');
  });

  it('DLP block on an internal copy → reject floor → remediated, entry reason dlp (A6.1)', async () => {
    const sent = await journal(main(), {
      to: [ALEX],
      from: BLAKE,
      direction: 'internal',
      dlp: { action: 'block', category: 'payment_card' },
    });
    const [copy] = await copiesOf(fx, sent.message.id);
    expect(copy).toMatchObject({
      direction: 'internal',
      policyState: 'evaluated',
      policyDisposition: 'reject',
      dlpAction: 'block',
    });
    const [row] = await detectRows(sent.message.id);
    expect(row).toMatchObject({ direction: 'internal', decisionSource: 'floor' });
    await drain(comps);
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: copy!.id },
    });
    expect(entry).toMatchObject({ reason: 'dlp', kind: 'quarantine' });
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId);
    expect(messageCopyDetectedV1.parse(detected!.payload)).toMatchObject({
      direction: 'internal',
      dlp: { action: 'block', verdict: 'suspicious', categories: ['payment_card'] },
    });
  });

  it('tagged allow → tag; malware + tenant TAG → the malware action wins (verdict lane)', async () => {
    await publishPolicy(
      fx,
      org.id,
      'tag',
      policyDoc('inbound', [ruleFor('inbound', 'tag', [{ type: 'TAG', label: 'external' }])]),
    );
    const tagged = await journal(main(), { to: [BLAKE] });
    const [t] = await copiesOf(fx, tagged.message.id);
    expect(t).toMatchObject({ policyDisposition: 'allow', policyTagged: true });
    const [tagAction] = await actionsOfCopy(fx, t!.id);
    expect(tagAction).toMatchObject({ action: 'tag', status: 'pending' });
    expect(recordOf(tagAction!.decision).lanes).toMatchObject({
      policy: { key: 'allow_tagged', action: 'tag' },
      winner: 'policy',
    });
    const malware = await journal(main(), { to: [ALEX], risk: MALWARE });
    const [m] = await copiesOf(fx, malware.message.id);
    const [mAction] = await actionsOfCopy(fx, m!.id);
    expect(mAction).toMatchObject({ action: 'move_quarantine' });
    const record = recordOf(mAction!.decision);
    expect(record.lanes.winner).toBe('verdict');
    expect(record.ruleId).toBe('p1-high-confidence-malware-phishing-hb');
  });

  it('a tenant allow override on a level-only recommendation → skip policy_allow_override', async () => {
    await publishPolicy(
      fx,
      org.id,
      'trust',
      policyDoc('inbound', [ruleFor('inbound', 'trust', [{ type: 'ALLOW' }], { override: true })]),
      { allowRecommendationOverrides: true },
    );
    const sent = await journal(main(), {
      to: [CASEY],
      risk: { verdict: 'suspicious', level: 'high', score: 700, recommendedAction: 'quarantine' },
    });
    const [copy] = await copiesOf(fx, sent.message.id);
    expect(copy).toMatchObject({ policyDisposition: 'allow', verdict: 'suspicious' });
    const [action] = await actionsOfCopy(fx, copy!.id);
    expect(action).toMatchObject({ status: 'skipped', reasonCode: 'policy_allow_override' });
    expect(recordOf(action!.decision)).toMatchObject({
      lanes: { suppressedBy: 'policy_allow_override', winner: null },
      policyOutcome: { overrideApplied: true, decisionSource: 'tenant_rule' },
    });
  });

  it('organization setting off → disabled and the API-2 decision; clean + no policy → no event', async () => {
    await fx.prisma.apiModeOrgSetting.create({
      data: { organizationId: org.id, policyEvaluationEnabled: false },
    });
    try {
      await publishPolicy(
        fx,
        org.id,
        'block sender',
        policyDoc('inbound', [ruleFor('inbound', 'block-sender', [{ type: 'REJECT' }])]),
      );
      const sent = await journal(main(), { to: [ALEX] });
      const [copy] = await copiesOf(fx, sent.message.id);
      expect(copy).toMatchObject({ policyState: 'disabled', remediationState: 'none' });
      expect(await detectRows(sent.message.id)).toEqual([]);
      expect(await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId)).toEqual([]);
    } finally {
      await fx.prisma.apiModeOrgSetting.deleteMany({ where: { organizationId: org.id } });
    }
    await clearPolicies(fx, org.id);
    const clean = await journal(main(), { to: [BLAKE] });
    const [c] = await copiesOf(fx, clean.message.id);
    expect(c).toMatchObject({ policyState: 'evaluated', policyDisposition: 'allow' });
    expect(await outboxOf(EventTypes.MessageCopyDetected, clean.message.publicId)).toEqual([]);
  });

  it('PolicyInputError → failed, counted; the verdict lane still decides', async () => {
    const before = await counter('policy_errors');
    const sent = await journal(main(), { to: [BLAKE], risk: MALWARE, breakScan: true });
    const [copy] = await copiesOf(fx, sent.message.id);
    expect(copy).toMatchObject({ policyState: 'failed', policyDisposition: null });
    expect(await detectRows(sent.message.id)).toEqual([]);
    const [action] = await actionsOfCopy(fx, copy!.id);
    expect(action).toMatchObject({ action: 'move_quarantine', status: 'pending' });
    expect(recordOf(action!.decision).policyOutcome).toBeNull();
    expect(await counter('policy_errors')).toBe(before + 1);
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId);
    expect(messageCopyDetectedV1.parse(detected!.payload).policy).toEqual({
      state: 'failed',
      disposition: null,
      decisionSource: null,
      overrideApplied: false,
      actionTypes: [],
    });
  });

  it('ALERT rule → one detect-mode policy alert per message (A7)', async () => {
    await publishPolicy(
      fx,
      org.id,
      'alert',
      policyDoc('inbound', [
        ruleFor('inbound', 'alert', [
          { type: 'QUARANTINE' },
          { type: 'ALERT', severity: 'critical' },
        ]),
      ]),
    );
    const sent = await journal(main(), { to: [ALEX, BLAKE] });
    const alerts = await outboxOf(
      EventTypes.PolicyNotificationRequested,
      sent.message.id.toString(),
    );
    expect(alerts).toHaveLength(1);
    expect(policyNotificationRequestedV1.parse(alerts[0]!.payload)).toMatchObject({
      kind: 'policy_alert',
      severity: 'critical',
      disposition: 'quarantine',
      lifecycleRound: 0,
      evaluationMode: 'detect',
    });
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId);
    expect(messageCopyDetectedV1.parse(detected!.payload).copies.counted).toBe(2);
  });

  it('redelivery is a duplicate; a manual replay reuses the detect row (no second row, action or event)', async () => {
    await publishPolicy(
      fx,
      org.id,
      'block sender',
      policyDoc('inbound', [ruleFor('inbound', 'block-sender', [{ type: 'REJECT' }])]),
    );
    const sent = await journal(main(), { to: [CASEY] });
    expect(await comps.copies.handle(sent.event)).toBe('duplicate');
    await fx.prisma.messageIdempotency.deleteMany({
      where: { consumer: COPIES_CONSUMER, eventId: sent.event.eventId },
    });
    expect(await comps.copies.handle(sent.event)).toBe('handled');
    expect(await detectRows(sent.message.id)).toHaveLength(1);
    const [copy] = await copiesOf(fx, sent.message.id);
    expect(await actionsOfCopy(fx, copy!.id)).toHaveLength(1);
    expect(await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId)).toHaveLength(1);
  });
});

describe('outbound detections (A6)', () => {
  it('outbound DLP → an outbound copy on the sender mailbox, never remediated, not a coverage sighting', async () => {
    const alex = await fx.prisma.apiMailbox.findFirstOrThrow({
      where: { organizationId: org.id, primaryAddress: ALEX },
    });
    const sent = await journal(main(), {
      to: [EXTERNAL],
      from: ALEX,
      direction: 'outbound',
      dlp: { action: 'block', category: 'payment_card' },
      deliver: false,
    });
    const copies = await copiesOf(fx, sent.message.id);
    expect(copies).toHaveLength(1);
    expect(copies[0]).toMatchObject({
      mailboxId: alex.id,
      direction: 'outbound',
      source: 'journal',
      seenJournal: true,
      lagMs: null,
      providerDeliveredAt: null,
      policyState: 'evaluated',
      policyDisposition: 'reject',
      dlpAction: 'block',
      remediationState: 'skipped',
    });
    const [action] = await actionsOfCopy(fx, copies[0]!.id);
    expect(action).toMatchObject({ status: 'skipped', reasonCode: 'outbound_not_remediable' });
    const after = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: alex.id } });
    expect(after.journalLastSeenAt).toEqual(alex.journalLastSeenAt);
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId);
    expect(messageCopyDetectedV1.parse(detected!.payload)).toMatchObject({
      direction: 'outbound',
      dlp: { action: 'block' },
      copies: { counted: 1, remediation: { skipped: 1 } },
    });
    expect(await counter('outbound_detections')).toBeGreaterThanOrEqual(1);
    // A6.4: clawback criteria directions are inbound/internal, so an outbound copy is never a
    // target (the search filters `direction IN (…)`).
    const requester = await user(fx, org.id, `requester-${randomUUID().slice(0, 8)}@${MS_DOMAIN}`);
    const clawback = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: [copyMessageIdHash(org.id, `<${sent.messageId}>`)!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    clock.advance(comps.config.API_MODE_CLAWBACK_TICK_MS + 1);
    await comps.clawback.tick();
    expect(
      await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: clawback.id } }),
    ).toMatchObject({ status: 'no_match', targetsTotal: 0 });
    // A clean outbound message is evaluated but records nothing.
    const clean = await journal(main(), {
      to: [EXTERNAL],
      from: ALEX,
      direction: 'outbound',
      deliver: false,
    });
    expect(await copiesOf(fx, clean.message.id)).toEqual([]);
    expect(await detectRows(clean.message.id)).toHaveLength(1);
  });

  it('the sender was also a recipient of the same message → no outbound row', async () => {
    const messageId = `${randomUUID()}@${MS_DOMAIN}`;
    await journal(main(), { to: [BLAKE], from: BLAKE, direction: 'internal', messageId });
    const out = await journal(main(), {
      to: [EXTERNAL],
      from: BLAKE,
      direction: 'outbound',
      dlp: { action: 'block', category: 'payment_card' },
      messageId,
      deliver: false,
    });
    expect(await copiesOf(fx, out.message.id)).toEqual([]);
    expect(await outboxOf(EventTypes.MessageCopyDetected, out.message.publicId)).toEqual([]);
  });
});

describe('feed copies and hybrid (A3.2, P-I3)', () => {
  it('a feed copy is evaluated with its single recipient and decided', async () => {
    await publishPolicy(
      fx,
      org.id,
      'quarantine',
      policyDoc('inbound', [ruleFor('inbound', 'q', [{ type: 'QUARANTINE' }])]),
    );
    const mailbox = await fx.prisma.apiMailbox.findFirstOrThrow({
      where: { organizationId: org.id, primaryAddress: CASEY },
    });
    const providerMessageId = `feed-${randomUUID()}`;
    const eml = syntheticEml({ to: [CASEY] });
    const key = await fx.putEml(org.id, eml);
    const committed = await comps.feeds!.repository.commit({
      organizationId: org.id,
      apiConnection: {
        id: conn.apiConnectionId,
        publicId: conn.apiConnectionPublicId,
        provider: 'microsoft_365',
      },
      mailbox: {
        id: mailbox.id,
        publicId: mailbox.publicId,
        primaryAddress: CASEY,
        domainId: mailbox.domainId,
      },
      source: 'graph',
      providerMessageId,
      ingestKey: ingestKeyForCopy({
        connectionPublicId: conn.apiConnectionPublicId,
        mailboxPublicId: mailbox.publicId,
        providerMessageId,
      }),
      receivedAt: clock.now(),
      providerDeliveredAt: clock.now(),
      deliveredBasis: 'graph_received',
      direction: 'inbound',
      internetMessageId: null,
      headerFrom: 'Example Sender <sender@sender.example>',
      subject: 'Synthetic feed copy',
      envelopeFrom: 'sender@sender.example',
      sizeBytes: Buffer.byteLength(eml),
      emlObjectKey: key,
      emlSha256: 'e'.repeat(64),
      messageIdHash: null,
      dedupeClaimId: null,
    });
    const identity = await fx.prisma.messageIdentity.findUniqueOrThrow({
      where: { id: committed.messageId },
    });
    const message = {
      id: committed.messageId,
      publicId: identity.publicId,
      receivedAt: committed.receivedAt,
    };
    const scanId = await scanRound(fx, org.id, message);
    const event = fx.copyScanned(org.id, message, {
      completedAt: clock.now(),
      ingestSource: 'mailbox_api',
      verdict: 'clean',
      riskScore: 20,
      scanId: scanId.toString(),
    });
    expect(await comps.copies.handle(event)).toBe('handled');
    const [copy] = await copiesOf(fx, message.id);
    expect(copy).toMatchObject({
      status: 'scanned',
      policyState: 'evaluated',
      policyDisposition: 'quarantine',
      remediationAction: 'move_quarantine',
    });
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, message.publicId);
    expect(messageCopyDetectedV1.parse(detected!.payload)).toMatchObject({
      ingestSource: 'mailbox_api',
      copySource: 'graph',
    });
  });

  it('hybrid inline authority → no evaluation, no decision, no event', async () => {
    const hybrid = await fx.organization('hybrid');
    await fx.domain(hybrid, 'hybrid-parity.example', 'hybrid');
    const hc = await fx.connection(hybrid, 'microsoft_365', {
      tenantId: randomUUID(),
      domains: ['hybrid-parity.example'],
    });
    const hs = await fx.journalSource(hybrid, hc);
    await publishPolicy(
      fx,
      hybrid.id,
      'block',
      policyDoc('inbound', [ruleFor('inbound', 'block', [{ type: 'REJECT' }])]),
    );
    const messageId = `${randomUUID()}@sender.example`;
    const to = 'pat@hybrid-parity.example';
    await fx.gatewayMessage(hybrid, {
      messageId,
      recipient: to,
      receivedAt: clock.now(),
      finalVerdict: 'clean',
    });
    const sent = await journal(
      { org: hybrid, sourceId: hs },
      { to: [to], messageId, deliver: false, risk: MALWARE },
    );
    const [copy] = await copiesOf(fx, sent.message.id);
    expect(copy).toMatchObject({
      verdictAuthority: 'inline',
      policyState: 'inline',
      policyDisposition: null,
    });
    expect(await detectRows(sent.message.id)).toEqual([]);
    expect(await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId)).toEqual([]);
    const [action] = await actionsOfCopy(fx, copy!.id);
    expect(action?.reasonCode ?? 'none').not.toBe('policy_allow_override');
  });
});

describe('mailbox scope (B6)', () => {
  let s: TestOrg;
  let sc: TestConnection;
  let ss: bigint;
  const DOMAIN = 'scope-parity.example';
  const A = `ann@${DOMAIN}`;
  const B = `bob@${DOMAIN}`;
  const C = `cid@${DOMAIN}`;
  const box = (address: string) =>
    fx.prisma.apiMailbox.findFirstOrThrow({
      where: { organizationId: s.id, primaryAddress: address },
    });

  beforeAll(async () => {
    s = await fx.organization('scope');
    await fx.domain(s, DOMAIN, 'api');
    sc = await fx.connection(s, 'microsoft_365', {
      tenantId: randomUUID(),
      domains: [DOMAIN],
      feeds: { enabled: true, mode: 'poll' },
    });
    ss = await fx.journalSource(s, sc);
    for (const [i, address] of [A, B].entries()) {
      await fx.prisma.apiMailbox.create({
        data: {
          publicId: uuidv7(),
          organizationId: s.id,
          apiConnectionId: sc.apiConnectionId,
          providerUserId: `sim-user-${i}-${randomUUID()}`,
          primaryAddress: address,
          domainId: s.domains.get(DOMAIN)!,
          status: 'active',
          feedStatus: 'active',
          feedCursor: 'opaque-cursor',
          nextSyncAt: new Date(clock.ms() + 3_600_000),
          addresses: { create: { organizationId: s.id, address, kind: 'primary' } },
        },
      });
    }
  });

  it('mailboxes: selection evaluated, excluded feed stopped, decision out_of_scope, not counted, clawback skipped, coverage out_of_scope', async () => {
    await fx.prisma.apiModeDomainSetting.create({
      data: {
        organizationId: s.id,
        domainId: s.domains.get(DOMAIN)!,
        scopeKind: 'mailboxes',
        scopeRecomputeRequestedAt: clock.now(),
      },
    });
    await fx.prisma.apiMailbox.updateMany({
      where: { id: (await box(A)).id },
      data: { scopeSelected: true },
    });
    await comps.scope.runOnce();
    expect(await box(A)).toMatchObject({ scopeState: 'in_scope' });
    expect(await box(B)).toMatchObject({ scopeState: 'excluded' });
    expect(
      (
        await fx.prisma.apiModeDomainSetting.findUniqueOrThrow({
          where: { domainId: s.domains.get(DOMAIN)! },
        })
      ).scopeRecomputeRequestedAt,
    ).toBeNull();
    await comps.feeds!.tick();
    expect(await box(B)).toMatchObject({
      feedStatus: 'off',
      feedCursor: null,
      lastErrorCode: 'mailbox_out_of_scope',
    });
    expect(await box(A)).toMatchObject({ feedStatus: 'active' });

    const sent = await journal(
      { org: s, sourceId: ss },
      { to: [A, B, C], risk: MALWARE, deliver: false },
    );
    const copies = await copiesOf(fx, sent.message.id);
    const byMailbox = new Map(copies.map((c) => [c.mailboxId, c]));
    const bCopy = byMailbox.get((await box(B)).id)!;
    const [bAction] = await actionsOfCopy(fx, bCopy.id);
    expect(bAction).toMatchObject({ status: 'skipped', reasonCode: 'out_of_scope' });
    expect(await box(C)).toMatchObject({ status: 'discovered', scopeState: 'excluded' });
    const [detected] = await outboxOf(EventTypes.MessageCopyDetected, sent.message.publicId);
    const payload = messageCopyDetectedV1.parse(detected!.payload);
    expect(payload.copies.counted).toBe(1);
    expect(payload.detectionIds).toEqual([byMailbox.get((await box(A)).id)!.publicId]);

    const requester = await user(fx, s.id, `requester@${DOMAIN}`);
    const created = await adminClawback(fx, s.id, {
      keys: { messageIdHashes: [copyMessageIdHash(s.id, `<${sent.messageId}>`)!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    clock.advance(comps.config.API_MODE_CLAWBACK_TICK_MS + 1);
    await comps.clawback.tick();
    const targets = await fx.prisma.apiClawbackTarget.findMany({
      where: { clawbackId: created.id },
    });
    const bId = (await box(B)).id;
    const bTarget = targets.find((t) => t.mailboxId === bId);
    expect(bTarget).toMatchObject({ status: 'skipped', reasonCode: 'out_of_scope' });

    await comps.health.runOnce();
    expect(await box(B)).toMatchObject({ coverageState: 'out_of_scope' });
  });

  it('departments: members in scope (address or active user), refreshed every interval; back in scope resumes the feed', async () => {
    const dept = await fx.prisma.tenantDepartment.create({
      data: { organizationId: s.id, name: `it-dept-${randomUUID().slice(0, 8)}` },
    });
    await fx.prisma.tenantDepartmentMember.create({
      data: { organizationId: s.id, departmentId: dept.id, address: A },
    });
    await fx.prisma.apiModeDomainSetting.update({
      where: { domainId: s.domains.get(DOMAIN)! },
      data: {
        scopeKind: 'departments',
        scopeDepartmentIds: [dept.publicId],
        scopeRecomputeRequestedAt: clock.now(),
      },
    });
    await comps.scope.runOnce();
    expect(await box(A)).toMatchObject({ scopeState: 'in_scope' });
    expect(await box(B)).toMatchObject({ scopeState: 'excluded' });
    // A user member: B's address belongs to an active user of the department (P5).
    const bob = await user(fx, s.id, B);
    await fx.prisma.tenantDepartmentMember.create({
      data: { organizationId: s.id, departmentId: dept.id, userId: bob.id },
    });
    await comps.scope.runOnce();
    expect(await box(B)).toMatchObject({ scopeState: 'excluded' });
    clock.advance(comps.config.API_MODE_SCOPE_REFRESH_MINUTES * 60_000 + 1);
    await comps.scope.runOnce();
    expect(await box(B)).toMatchObject({ scopeState: 'in_scope' });
    await comps.maintenance.runOnce();
    expect(await box(B)).toMatchObject({ feedStatus: 'pending', feedCursor: null });
  });
});

describe('detect-only expiry (B7)', () => {
  it('remind: one alert, mode kept; enforce: mode switched with audit and alert', async () => {
    const d = await fx.organization('detect');
    const domainId = await fx.domain(d, 'detect-parity.example', 'api');
    const document = { v: 1, rules: [] };
    const past = new Date(clock.ms() - 60_000);
    const remind = await fx.prisma.apiRemediationPolicy.create({
      data: {
        organizationId: d.id,
        mode: 'detect_only',
        document,
        documentSha256: 'a'.repeat(64),
        detectOnlyUntil: past,
        detectOnlyThen: 'remind',
        detectOnlyStartedAt: new Date(clock.ms() - 7 * 86_400_000),
      },
    });
    const enforce = await fx.prisma.apiRemediationPolicy.create({
      data: {
        organizationId: d.id,
        domainId,
        mode: 'detect_only',
        document,
        documentSha256: 'b'.repeat(64),
        detectOnlyUntil: past,
        detectOnlyThen: 'enforce',
        detectOnlyStartedAt: new Date(clock.ms() - 7 * 86_400_000),
      },
    });
    const report = await comps.detectOnly.runOnce();
    expect(report).toMatchObject({ enforced: 1, reminded: 1, alerts: 2, failed: 0 });
    expect(
      await fx.prisma.apiRemediationPolicy.findUniqueOrThrow({ where: { id: remind.id } }),
    ).toMatchObject({
      mode: 'detect_only',
      rowVersion: 1,
      detectOnlyThen: 'remind',
      detectOnlyNotifiedAt: clock.now(),
    });
    expect(
      await fx.prisma.apiRemediationPolicy.findUniqueOrThrow({ where: { id: enforce.id } }),
    ).toMatchObject({
      mode: 'enforce',
      rowVersion: 2,
      detectOnlyUntil: null,
      detectOnlyThen: null,
      detectOnlyStartedAt: null,
      detectOnlyNotifiedAt: clock.now(),
    });
    const audits = await fx.prisma.auditLog.findMany({
      where: { organizationId: d.id },
      orderBy: { id: 'asc' },
    });
    expect(audits.map((a) => a.action).sort()).toEqual([
      'api_mode.detect_only_period_ended',
      'api_mode.remediation_policy_auto_enforced',
    ]);
    expect(
      audits.find((a) => a.action === 'api_mode.remediation_policy_auto_enforced')!.metadata,
    ).toEqual({
      policyId: enforce.publicId,
      scope: 'domain',
      simulatedSinceStart: 0,
    });
    const alerts = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: d.id, eventType: EventTypes.NotificationAlertRequested },
    });
    const bySeverity = Object.fromEntries(
      alerts.map((a) => {
        const p = a.payload as {
          kind: string;
          severity: string;
          refs: { remediationPolicyId: string };
        };
        expect(p.kind).toBe('api_mode_detect_only_ended');
        return [p.refs.remediationPolicyId, p.severity];
      }),
    );
    expect(bySeverity).toEqual({ [remind.publicId]: 'low', [enforce.publicId]: 'medium' });
    expect(await comps.detectOnly.runOnce()).toMatchObject({ enforced: 0, reminded: 0, alerts: 0 });
  });
});

describe('policy.errors_1h (A11)', () => {
  it('an error ratio above 50 % of the last hour fails the check', async () => {
    await fx.prisma.apiModeCounter.upsert({
      where: {
        apiConnectionId_hour: { apiConnectionId: conn.apiConnectionId, hour: hourOf(clock.now()) },
      },
      create: {
        organizationId: org.id,
        apiConnectionId: conn.apiConnectionId,
        hour: hourOf(clock.now()),
        policyEvaluations: 4,
        policyErrors: 20,
      },
      update: { policyEvaluations: 4, policyErrors: 20 },
    });
    await comps.health.runOnce();
    const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: conn.apiConnectionId },
    });
    const checks = (row.healthChecks as { checks: { code: string; status: string }[] }).checks;
    expect(checks.find((c) => c.code === 'policy.errors_1h')).toMatchObject({ status: 'fail' });
    expect(row.healthStatus).toBe('failing');
  });
});
