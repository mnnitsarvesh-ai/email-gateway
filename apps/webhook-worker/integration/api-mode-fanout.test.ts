/**
 * API-mode detections through the real fanout against the MySQL writer (step API-4 A8, A9, §10.3,
 * ADR-0106): `mail.message.copy_detected.v1` envelopes and `mail.attachment.sandbox_completed.v1`
 * of a copy message are handled by `FanoutService` (driven directly, as the consumer would) for
 * synthetic `it-wh-*` organizations. Covers: the two new public types (strict schemas, payload
 * guard, no subject, body, address or matched value), subscription filters (directions,
 * domainIds, minSeverity, verdicts), the `threat_detected` / `dlp_detected` alert requests with
 * the tenant settings and throttles, deterministic ids, the ledger, and the sandbox of a copy
 * message (`mailbox.threat.detected` stage sandbox, never `email.threat.detected`).
 */
import { randomUUID } from 'node:crypto';
import { MetricsService, uuidv7 } from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  EXAMPLE_EVENT_PAYLOADS,
  notificationAlertRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { parseStoredEnvelope, webhookEventId } from '@email-gateway/webhooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FanoutReads } from '../src/fanout/facts';
import { FanoutService, PendingCounts } from '../src/fanout/fanout.service';
import { SubscriptionIndex } from '../src/fanout/subscription-index';
import { WebhookMetrics } from '../src/metrics/webhook-metrics';
import { Fixtures } from './support/fixtures';

const fx = new Fixtures();
const logger = createLogger({ service: 'webhook-worker-it', level: 'silent' });
const CONSUMER = `it-api-fanout-${fx.suffix}`;
let service: FanoutService;
let metrics: MetricsService;

type Org = { id: bigint; publicId: string };
type Msg = Awaited<ReturnType<Fixtures['message']>>;

function envelope(
  eventType: string,
  organizationId: bigint,
  overrides: Record<string, unknown> = {},
): EventEnvelope<unknown> {
  return {
    eventId: fx.track(uuidv7()),
    eventType,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${fx.suffix}`,
    organizationId: organizationId.toString(),
    payload: { ...(EXAMPLE_EVENT_PAYLOADS as Record<string, object>)[eventType], ...overrides },
  };
}

/** A copy message (`ingest_source` journal_intake) of the organization on `domainId`. */
async function copyMessage(org: Org, domainId: bigint | null): Promise<Msg> {
  const m = await fx.message(org.id, { domainId });
  await fx.prisma.emailMessage.update({
    where: { id_receivedAt: { id: m.messageId, receivedAt: m.receivedAt } },
    data: { ingestSource: 'journal_intake' },
  });
  return m;
}

/** An API-mode connection (on a provider connection) of the organization. */
async function apiConnection(org: Org): Promise<bigint> {
  const provider = await fx.prisma.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `it-${randomUUID().slice(0, 8)}`,
      status: 'active',
    },
    select: { id: true },
  });
  const row = await fx.prisma.apiModeConnection.create({
    data: { organizationId: org.id, providerConnectionId: provider.id, provider: 'microsoft_365' },
    select: { id: true },
  });
  return row.id;
}

/** A copy of `m` in a new mailbox of `domainId` (synthetic address, never in any payload). */
async function copy(
  org: Org,
  connectionId: bigint,
  m: Msg,
  domainId: bigint | null,
  options: {
    authority?: 'copy' | 'inline';
    scope?: 'in_scope' | 'excluded';
    disposition?: 'allow' | 'quarantine' | 'reject' | null;
  } = {},
): Promise<string> {
  const mailbox = await fx.prisma.apiMailbox.create({
    data: {
      organizationId: org.id,
      apiConnectionId: connectionId,
      primaryAddress: `mbx-${randomUUID().slice(0, 8)}@corp.example`,
      domainId,
      status: 'active',
      scopeState: options.scope ?? 'in_scope',
    },
    select: { id: true },
  });
  const publicId = uuidv7();
  await fx.prisma.apiMessageCopy.create({
    data: {
      receivedAt: m.receivedAt,
      publicId,
      organizationId: org.id,
      apiConnectionId: connectionId,
      mailboxId: mailbox.id,
      messageId: m.messageId,
      source: 'journal',
      seenJournal: true,
      direction: 'inbound',
      status: 'scanned',
      verdict: 'malware',
      verdictAuthority: options.authority ?? 'copy',
      policyState: options.disposition ? 'evaluated' : 'none',
      policyDisposition: options.disposition ?? null,
    },
  });
  return publicId;
}

/** The latest round-0 risk row of `m` (the reason codes of a copy's detect scan). */
async function riskRow(org: Org, m: Msg, reasonCodes: string[]): Promise<void> {
  await fx.prisma.messageRiskScore.create({
    data: {
      receivedAt: m.receivedAt,
      messageId: m.messageId,
      organizationId: org.id,
      scanId: m.scanId,
      lifecycleRound: 0,
      revision: 0,
      direction: 'inbound',
      status: 'scored',
      score: 870,
      level: 'high',
      verdict: 'phishing',
      recommendedAction: 'quarantine',
      hardBlocks: [],
      reasonCodes,
      contributions: [],
      groups: [],
      engines: [],
      failures: [],
      floors: [],
      trust: {},
      evidence: {},
      explanation: [],
      explanationText: 'it',
      profileSource: 'platform',
      profileIdText: 'rsk-default/1',
      profileSha256: 'a'.repeat(64),
      inputSha256: 'b'.repeat(64),
      scorerVersion: 'risk-score/1',
      signalMapVersion: 'risk-signals/1',
      inputVersion: 'risk-input/1',
      durationUs: 10,
    },
  });
}

async function sandboxSubmission(org: Org, m: Msg): Promise<bigint> {
  const row = await fx.prisma.sandboxSubmission.create({
    data: {
      receivedAt: m.receivedAt,
      messageId: m.messageId,
      organizationId: org.id,
      scanId: m.scanId,
      attachmentId: 1n,
      partIndex: 3,
      sha256: 'c'.repeat(64),
      sizeBytes: 1024,
      detectedType: 'seven_zip',
      objectKey: `org/${org.id.toString()}/att/it/${randomUUID()}`,
      attachmentVerdict: 'suspicious',
      reasonCodes: [],
      requestedEventId: uuidv7(),
      status: 'completed',
    },
    select: { id: true },
  });
  return row.id;
}

const detected = (org: Org, m: Msg, detectionIds: string[], overrides = {}) =>
  envelope(EventTypes.MessageCopyDetected, org.id, {
    messageId: m.messageId.toString(),
    messagePublicId: m.publicId,
    receivedAt: m.receivedAt.toISOString(),
    detectionIds,
    copies: {
      counted: detectionIds.length,
      remediation: { pending: detectionIds.length, simulated: 0, skipped: 0, none: 0 },
    },
    ...overrides,
  });

const sandboxed = (org: Org, m: Msg, submissionId: bigint) =>
  envelope(EventTypes.AttachmentSandboxCompleted, org.id, {
    submissionId: submissionId.toString(),
    messageId: m.messageId.toString(),
    receivedAt: m.receivedAt.toISOString(),
    scanId: m.scanId.toString(),
  });

const storedOf = (org: Org, sourceEventId: string) =>
  fx.prisma.webhookEvent.findMany({
    where: { organizationId: org.id, sourceEventId },
    orderBy: { id: 'asc' },
  });

const alertsOf = async (org: Org) =>
  (
    await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: EventTypes.NotificationAlertRequested },
      orderBy: { id: 'asc' },
    })
  ).map((r) => ({ eventId: r.eventId, payload: notificationAlertRequestedV1.parse(r.payload) }));

/** Metadata only: no local part, subject, object key or matched value in a stored payload. */
function assertContentFree(json: string): void {
  const data = parseStoredEnvelope(json).data as { message?: Record<string, unknown> };
  const copy = structuredClone(data);
  if (copy.message) delete copy.message.internetMessageId;
  const text = JSON.stringify(copy).toLowerCase();
  for (const forbidden of ['@', 'alice', 'bob', 'carol', 'quarterly', 'org/', 'eml', 'mbx-']) {
    expect(text).not.toContain(forbidden);
  }
}

beforeAll(() => {
  metrics = new MetricsService({ service: 'webhook-worker-it' });
  const sink = () => undefined;
  service = new FanoutService({
    prisma: fx.prisma,
    index: new SubscriptionIndex(fx.prisma, 0, sink, logger),
    reads: new FanoutReads(sink),
    pending: new PendingCounts(10_000),
    metrics: new WebhookMetrics(metrics),
    logger,
    txTimeoutMs: 30_000,
    consumer: CONSUMER,
  });
});

afterAll(async () => {
  const where = { organizationId: { in: fx.organizationIds } };
  await fx.prisma.messageIdempotency.deleteMany({ where: { consumer: CONSUMER } });
  await fx.prisma.apiMessageCopy.deleteMany({ where });
  await fx.prisma.apiMailbox.deleteMany({ where });
  await fx.prisma.apiModeConnection.deleteMany({ where });
  await fx.prisma.providerConnection.deleteMany({ where });
  await fx.prisma.messageRiskScore.deleteMany({ where });
  await fx.prisma.sandboxSubmission.deleteMany({ where });
  await fx.cleanup();
});

describe('copy_detected → mailbox.threat.detected / mailbox.dlp.detected (A9.1)', () => {
  it('a threat with DLP yields both types, filtered deliveries, both alerts, deterministic ids', async () => {
    const org = await fx.organization('api-both');
    const other = await fx.organization('api-both-other');
    const domain = await fx.domain(org.id, 'api-both');
    const elsewhere = await fx.domain(org.id, 'api-elsewhere');
    const m = await copyMessage(org, domain.id);
    await riskRow(org, m, ['phishing.known_bad_url', 'auth.dmarc_fail']);
    const all = await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/all',
      eventTypes: ['mailbox.threat.detected', 'mailbox.dlp.detected', 'email.threat.detected'],
    });
    const spamOnly = await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/spam',
      eventTypes: ['mailbox.threat.detected', 'mailbox.dlp.detected'],
      filters: { verdicts: ['spam'] },
    });
    const outboundOnly = await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/outbound',
      eventTypes: ['mailbox.threat.detected', 'mailbox.dlp.detected'],
      filters: { directions: ['outbound'] },
    });
    const otherDomain = await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/domain',
      eventTypes: ['mailbox.dlp.detected'],
      filters: { domainIds: [elsewhere.publicId] },
    });
    await fx.subscription(other.id, {
      url: 'https://hooks.receiver.test/other',
      eventTypes: ['mailbox.threat.detected', 'mailbox.dlp.detected'],
    });
    const ids = [uuidv7(), uuidv7()];
    const e = detected(org, m, ids, {
      dlp: { action: 'quarantine', verdict: 'suspicious', categories: ['payment_card', 'iban'] },
    });
    await expect(service.handle(e)).resolves.toBe('handled');

    const stored = await storedOf(org, e.eventId);
    expect(stored.map((s) => [s.eventType, s.severity])).toEqual([
      ['mailbox.threat.detected', 'high'],
      ['mailbox.dlp.detected', 'high'],
    ]);
    expect(stored.map((s) => s.eventId)).toEqual([
      webhookEventId(e.eventId, 'mailbox.threat.detected', 'scan'),
      webhookEventId(e.eventId, 'mailbox.dlp.detected', 'dlp'),
    ]);
    for (const s of stored) {
      expect(s).toMatchObject({ messageId: m.messageId, domainId: domain.id });
      assertContentFree(s.payloadJson);
    }
    const threat = parseStoredEnvelope(stored[0]!.payloadJson);
    expect(threat.organizationId).toBe(org.publicId);
    expect(threat.data).toMatchObject({
      message: { id: m.publicId, domainId: domain.publicId, recipientCount: 2 },
      detection: {
        stage: 'scan',
        verdict: 'malicious',
        riskScore: 870,
        reasonCodes: ['phishing.known_bad_url', 'auth.dmarc_fail'],
        protectionMode: 'api',
        direction: 'inbound',
        copySource: 'journal',
        policyDisposition: 'quarantine',
        mailboxCount: 2,
        remediation: { pending: 2, simulated: 0, skipped: 0 },
        attachment: null,
        detectionIds: ids,
      },
    });
    const dlp = parseStoredEnvelope(stored[1]!.payloadJson);
    expect(dlp.data).toMatchObject({
      dlp: { action: 'quarantine', categories: ['payment_card', 'iban'], mailboxCount: 2 },
    });

    const deliveries = async (sub: { id: bigint }) =>
      (await fx.prisma.webhookDelivery.findMany({ where: { subscriptionId: sub.id } })).map(
        (d) => d.eventType,
      );
    expect((await deliveries(all)).sort()).toEqual([
      'mailbox.dlp.detected',
      'mailbox.threat.detected',
    ]);
    // `verdicts` filters the threat type only; the DLP type carries no verdict.
    expect(await deliveries(spamOnly)).toEqual(['mailbox.dlp.detected']);
    expect(await deliveries(outboundOnly)).toEqual([]);
    expect(await deliveries(otherDomain)).toEqual([]);
    expect(await fx.prisma.webhookEvent.count({ where: { organizationId: other.id } })).toBe(0);

    const alerts = await alertsOf(org);
    expect(alerts.map((a) => [a.eventId, a.payload.kind, a.payload.severity])).toEqual([
      [webhookEventId(e.eventId, 'alert:threat_detected'), 'threat_detected', 'high'],
      [webhookEventId(e.eventId, 'alert:dlp_detected'), 'dlp_detected', 'high'],
    ]);
    expect(alerts[1]!.payload.refs).toEqual({
      webhookEventId: stored[1]!.eventId,
      messageId: m.messageId.toString(),
      receivedAt: m.receivedAt.toISOString(),
    });
    const windows = await fx.prisma.notificationAlertWindow.findMany({
      where: { organizationId: org.id },
      orderBy: { kind: 'asc' },
    });
    expect(windows.map((w) => [w.kind, w.scopeKey, w.eventCount])).toEqual([
      ['dlp_detected', '-', 1],
      ['threat_detected', '-', 1],
    ]);

    // A redelivery is a duplicate (ledger): nothing twice.
    await expect(service.handle(e)).resolves.toBe('duplicate');
    expect(await storedOf(org, e.eventId)).toHaveLength(2);
    expect(await alertsOf(org)).toHaveLength(2);
  });

  it('outbound DLP: never remediated, matched by direction; alert settings and throttle apply', async () => {
    const org = await fx.organization('api-outbound');
    const domain = await fx.domain(org.id, 'api-outbound');
    await fx.prisma.notificationSettings.create({
      data: {
        organizationId: org.id,
        settings: { alerts: { dlpDetected: { minSeverity: 'high', throttleMinutes: 15 } } },
        settingsSha256: '0'.repeat(64),
      },
    });
    const outboundOnly = await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/outbound',
      eventTypes: ['mailbox.dlp.detected'],
      filters: { directions: ['outbound'], minSeverity: 'medium' },
    });
    const send = async (action: string) => {
      const m = await copyMessage(org, domain.id);
      const e = detected(org, m, [uuidv7()], {
        verdict: 'clean',
        direction: 'outbound',
        dlp: { action, verdict: 'suspicious', categories: ['payment_card'] },
        copies: { counted: 1, remediation: { pending: 0, simulated: 0, skipped: 1, none: 0 } },
      });
      await service.handle(e);
      return e;
    };
    const block = await send('block');
    const [stored] = await storedOf(org, block.eventId);
    const data = parseStoredEnvelope(stored!.payloadJson).data as {
      dlp: { remediation: unknown; direction: string };
    };
    expect(data.dlp).toMatchObject({ direction: 'outbound', remediation: null });
    expect(
      await fx.prisma.webhookDelivery.count({ where: { subscriptionId: outboundOnly.id } }),
    ).toBe(1);
    // A second high detection in the same 15-minute window is counted, not alerted again.
    await send('quarantine');
    // require_approval (medium) is below the tenant's `high` minimum: no alert window.
    const approval = await send('require_approval');
    expect(await storedOf(org, approval.eventId)).toHaveLength(1); // delivered (medium ≥ medium)
    const alerts = await alertsOf(org);
    expect(alerts.map((a) => a.payload.kind)).toEqual(['dlp_detected']);
    const windows = await fx.prisma.notificationAlertWindow.findMany({
      where: { organizationId: org.id, kind: 'dlp_detected' },
    });
    expect(windows).toHaveLength(1);
    expect(windows[0]!.eventCount).toBe(2);
    expect(
      new Date(alerts[0]!.payload.window.to).getTime() -
        new Date(alerts[0]!.payload.window.from).getTime(),
    ).toBe(15 * 60_000);
  });
});

describe('sandbox of a copy message (A9.1, ADR-0106)', () => {
  it('yields mailbox.threat.detected (stage sandbox, counted copies) and no email.threat.detected', async () => {
    const org = await fx.organization('api-sandbox');
    const apiDomain = await fx.domain(org.id, 'api-sandbox-api');
    const hybridDomain = await fx.domain(org.id, 'api-sandbox-hybrid');
    await fx.prisma.domain.update({
      where: { id: apiDomain.id },
      data: { protectionMode: 'api' },
    });
    await fx.prisma.domain.update({
      where: { id: hybridDomain.id },
      data: { protectionMode: 'hybrid' },
    });
    const connection = await apiConnection(org);
    const m = await copyMessage(org, apiDomain.id);
    const counted = [
      await copy(org, connection, m, hybridDomain.id, { disposition: 'allow' }),
      await copy(org, connection, m, apiDomain.id, { disposition: 'quarantine' }),
    ];
    // Never counted: inline verdict authority (P-I3) and an excluded mailbox (B6).
    await copy(org, connection, m, hybridDomain.id, { authority: 'inline', disposition: 'reject' });
    await copy(org, connection, m, apiDomain.id, { scope: 'excluded', disposition: 'reject' });
    const sub = await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/sandbox',
      eventTypes: ['mailbox.threat.detected', 'email.threat.detected'],
    });
    const e = sandboxed(org, m, await sandboxSubmission(org, m));
    await expect(service.handle(e)).resolves.toBe('handled');

    const stored = await storedOf(org, e.eventId);
    expect(stored.map((s) => s.eventType)).toEqual(['mailbox.threat.detected']);
    expect(stored[0]!.eventId).toBe(
      webhookEventId(e.eventId, 'mailbox.threat.detected', 'sandbox:3'),
    );
    assertContentFree(stored[0]!.payloadJson);
    expect(parseStoredEnvelope(stored[0]!.payloadJson).data).toMatchObject({
      detection: {
        stage: 'sandbox',
        verdict: 'malicious',
        riskScore: null,
        protectionMode: 'api',
        direction: 'inbound',
        copySource: 'journal',
        policyDisposition: 'quarantine',
        mailboxCount: 2,
        remediation: null,
        attachment: { partIndex: 3, sha256: 'c'.repeat(64), detectedType: 'seven_zip' },
        detectionIds: counted,
      },
    });
    expect(await fx.prisma.webhookDelivery.count({ where: { subscriptionId: sub.id } })).toBe(1);
    const alerts = await alertsOf(org);
    expect(alerts.map((a) => a.payload.kind)).toEqual(['threat_detected']);
  });

  it('hybrid only: protection mode hybrid; only inline-authority copies → no event at all', async () => {
    const org = await fx.organization('api-sandbox-h');
    const hybridDomain = await fx.domain(org.id, 'api-sandbox-h');
    await fx.prisma.domain.update({
      where: { id: hybridDomain.id },
      data: { protectionMode: 'hybrid' },
    });
    const connection = await apiConnection(org);
    await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/h',
      eventTypes: ['mailbox.threat.detected', 'email.threat.detected'],
    });
    const m = await copyMessage(org, hybridDomain.id);
    await copy(org, connection, m, hybridDomain.id);
    const e = sandboxed(org, m, await sandboxSubmission(org, m));
    await service.handle(e);
    const [stored] = await storedOf(org, e.eventId);
    expect(
      (parseStoredEnvelope(stored!.payloadJson).data as { detection: { protectionMode: string } })
        .detection.protectionMode,
    ).toBe('hybrid');

    const inlineOnly = await copyMessage(org, hybridDomain.id);
    await copy(org, connection, inlineOnly, hybridDomain.id, { authority: 'inline' });
    const e2 = sandboxed(org, inlineOnly, await sandboxSubmission(org, inlineOnly));
    await expect(service.handle(e2)).resolves.toBe('handled');
    expect(await storedOf(org, e2.eventId)).toEqual([]);
  });

  it('a gateway message keeps email.threat.detected only', async () => {
    const org = await fx.organization('api-sandbox-gw');
    const domain = await fx.domain(org.id, 'api-sandbox-gw');
    await fx.subscription(org.id, {
      url: 'https://hooks.receiver.test/gw',
      eventTypes: ['mailbox.threat.detected', 'email.threat.detected'],
    });
    const m = await fx.message(org.id, { domainId: domain.id });
    const e = sandboxed(org, m, await sandboxSubmission(org, m));
    await service.handle(e);
    expect((await storedOf(org, e.eventId)).map((s) => s.eventType)).toEqual([
      'email.threat.detected',
    ]);
  });
});
