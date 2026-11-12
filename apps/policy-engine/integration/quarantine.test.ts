/**
 * Step 5.3 quarantine on the real MySQL writer and MinIO (docs/plan/steps/17-quarantine.md
 * §9.2): the evaluation transaction writes entries atomically and idempotently (Q2, Q5, Q6),
 * per-recipient splits approve only the allowed recipients, rescans supersede, the release
 * executor (Q13) releases from `quarantined` (E14), `delivered` (E28) and `delivery_pending` (no
 * edge) and blocks when it must, the sweeper (Q19) expires without releasing, purges or retains
 * objects (Q17), adopts held messages without entries (Q8) and schedules digests (Q20), and the
 * policy copy carries a policy URL rewrite (Q23). Fixtures live in it-pe-* organizations.
 */
import { randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  type QuarantineReleaseRequestedV1,
  quarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { normalizeUrl } from '@email-gateway/url-security';
import { afterAll, describe, expect, it } from 'vitest';
import {
  buildPipeline,
  buildQuarantine,
  DEFAULT_EML,
  Fixtures,
  type MessageFixture,
} from './support/fixtures';

const fx = new Fixtures();
/** The releasing operator of each tenant (a user of that organization). */
const requesters = new Map<bigint, { id: bigint; publicId: string }>();

afterAll(async () => {
  await fx.cleanup();
});

const policy = (rules: unknown[]) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority: 100,
  rules,
});
const rule = (id: string, actions: unknown[], extra: Record<string, unknown> = {}) => ({
  id,
  priority: 10,
  when: { field: 'direction', op: 'equals', value: 'inbound' },
  actions,
  ...extra,
});

async function tenant(label: string, rules: unknown[]): Promise<bigint> {
  const id = await fx.organization(label);
  requesters.set(id, await fx.user(id, 'operator@corp.example'));
  if (rules.length > 0) await fx.publish(id, `p-${label}`, policy(rules));
  return id;
}

const entriesOf = (m: MessageFixture) =>
  fx.prisma.quarantineMessage.findMany({
    where: { messageId: m.messageId, messageReceivedAt: m.receivedAt },
    orderBy: [{ lifecycleRound: 'asc' }, { rcptSeq: 'asc' }],
  });
const recipientsOf = (m: MessageFixture) =>
  fx.prisma.emailRecipient.findMany({
    where: { messageId: m.messageId, receivedAt: m.receivedAt },
    orderBy: { rcptSeq: 'asc' },
    select: { id: true, address: true, status: true, finalAction: true },
  });
const approvalsOf = async (m: MessageFixture) =>
  (await fx.outbox(m, EventTypes.DeliveryApproved)).map((r) => deliveryApprovedV1.parse(r.payload));

/** What the api does for `POST …/release` (Q13.1): action + pending log per entry, `releasing`. */
async function queueRelease(
  organizationId: bigint,
  m: MessageFixture,
  entryIds: bigint[],
  mode: 'operator' | 'self' | 'approved' = 'operator',
  approvalRequestId: { id: bigint; publicId: string } | null = null,
  /** Who queued the release (default: the tenant's operator; the approver in `approved` mode). */
  queuedBy?: { id: bigint; publicId: string },
): Promise<EventEnvelope<QuarantineReleaseRequestedV1>> {
  const releaseId = randomUUID();
  const requester = queuedBy ?? requesters.get(organizationId)!;
  const entries = await fx.prisma.quarantineMessage.findMany({ where: { id: { in: entryIds } } });
  for (const e of entries) {
    const action = await fx.prisma.quarantineAction.create({
      data: {
        organizationId,
        quarantineMessageId: e.id,
        action: 'release_queued',
        actorType: 'user',
        actorUserId: requester.id,
        actorId: requester.publicId,
        reason: 'integration test release',
      },
    });
    await fx.prisma.quarantineReleaseLog.create({
      data: {
        organizationId,
        quarantineMessageId: e.id,
        actionId: action.id,
        releasePublicId: releaseId,
        mode,
        approvalRequestId: approvalRequestId?.id ?? null,
        requestedByType: 'user',
        requestedById: requester.publicId,
        releasedTo: e.recipientAddress,
        status: 'pending',
      },
    });
    await fx.prisma.quarantineMessage.update({
      where: { id: e.id },
      data: {
        status: 'releasing',
        rowVersion: { increment: 1 },
        ...(approvalRequestId ? { approvalRequestId: approvalRequestId.id } : {}),
      },
    });
  }
  const eventId = uuidv7();
  return {
    eventId,
    eventType: EventTypes.QuarantineReleaseRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-q-${releaseId}`,
    organizationId: organizationId.toString(),
    payload: {
      releaseId,
      messageId: m.messageId.toString(),
      receivedAt: m.receivedAt.toISOString(),
      entryIds: entries.map((e) => e.publicId),
      mode,
      approvalRequestId: approvalRequestId?.publicId ?? null,
      requestedBy: { type: 'user', id: requester.publicId },
      requestedAt: new Date().toISOString(),
    },
  };
}

/** A decided (`approved`) `release_approval` request of an entry, as the api writes it (Q14). */
function approvedRequest(
  organizationId: bigint,
  entryId: bigint,
  o: {
    requestedBy: { type: 'user'; userId: bigint } | { type: 'api_key'; apiKeyId: bigint };
    decidedByUserId: bigint;
    reasons: string[];
  },
) {
  return fx.prisma.quarantineApprovalRequest.create({
    data: {
      organizationId,
      quarantineMessageId: entryId,
      kind: 'release_approval',
      status: 'approved',
      approvalReasons: o.reasons,
      approvedReasons: o.reasons,
      requestedByType: o.requestedBy.type,
      requestedByUserId: o.requestedBy.type === 'user' ? o.requestedBy.userId : null,
      requestedByApiKeyId: o.requestedBy.type === 'api_key' ? o.requestedBy.apiKeyId : null,
      decidedByUserId: o.decidedByUserId,
      decidedAt: new Date(),
      expiresAt: new Date(Date.now() + 86_400_000),
    },
    select: { id: true, publicId: true },
  });
}

/** Moves a fixture message to `status` directly (a delivery-phase state set by the test). */
async function setState(m: MessageFixture, status: 'delivered' | 'delivery_pending' | 'scanning') {
  await fx.prisma.emailMessage.update({
    where: { id_receivedAt: { id: m.messageId, receivedAt: m.receivedAt } },
    data: { status, version: { increment: 1 }, statusReason: `it_${status}` },
  });
}

describe('evaluation writes the quarantine store (Q2, Q5, Q6)', () => {
  it('QUARANTINE → entries per recipient in the evaluation commit; a duplicate event adds nothing', async () => {
    const t = await tenant('store', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('store') });
    const m = await fx.message(t, { recipients: ['bob@corp.example', 'Carol@Corp.Example'] });
    const event = fx.scanned(m);
    expect(await p.consumer.handler(event)).toBe('handled');
    expect(await p.consumer.handler(event)).toBe('duplicate');

    const entries = await entriesOf(m);
    expect(entries).toHaveLength(2);
    const now = Date.now();
    for (const [i, e] of entries.entries()) {
      expect(e).toMatchObject({
        organizationId: t,
        lifecycleRound: 0,
        scanId: m.scanId,
        evaluationSeq: 0,
        rcptSeq: i,
        recipientId: m.recipients[i]!.id,
        recipientAddress: ['bob@corp.example', 'carol@corp.example'][i],
        direction: 'inbound',
        kind: 'quarantine',
        origin: 'policy',
        reason: 'policy',
        primaryEngine: 'policy',
        status: 'held',
        envelopeFrom: 'alice@partner.example',
        headerFrom: 'alice@partner.example',
        decisionSource: 'tenant_rule',
        decisiveRuleId: 'q',
        emlObjectKey: m.emlObjectKey,
        subject: null,
        rowVersion: 1,
        hasHardBlock: false,
        riskLevel: 'none',
        riskScore: 40,
      });
      // Hold period: organization default 30 days (no settings row).
      expect(e.expiresAt.getTime() - e.quarantinedAt.getTime()).toBe(30 * 86_400_000);
      expect(Math.abs(e.quarantinedAt.getTime() - now)).toBeLessThan(60_000);
      expect(JSON.stringify(e.explanation)).not.toContain('@');
    }
    expect(await recipientsOf(m)).toEqual([
      expect.objectContaining({ status: 'quarantined', finalAction: 'quarantine' }),
      expect.objectContaining({ status: 'quarantined', finalAction: 'quarantine' }),
    ]);
    const actions = await fx.prisma.quarantineAction.findMany({
      where: { quarantineMessageId: { in: entries.map((e) => e.id) } },
    });
    expect(actions.map((a) => [a.action, a.actorType])).toEqual([
      ['quarantine', 'system'],
      ['quarantine', 'system'],
    ]);
    const events = await fx.prisma.emailEvent.findMany({
      where: { messageId: m.messageId, eventType: 'quarantine.created' },
    });
    expect(events.map((e) => e.details)).toEqual([
      { entries: 2, kind: 'quarantine', origin: 'policy', round: 0 },
    ]);
    expect(await approvalsOf(m)).toEqual([]);
    expect(await p.registry.metrics()).toContain(
      'quarantine_entries_created_total{origin="policy",kind="quarantine",reason="policy",direction="inbound",service="policy-engine-it"} 2',
    );
  });

  it('a rolled-back evaluation leaves no entry (atomic with the lifecycle edge)', async () => {
    const t = await tenant('atomic', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('atomic') });
    const m = await fx.message(t);
    const event = fx.scanned(m);
    await expect(
      fx.prisma.$transaction(
        async (tx) => {
          await p.evaluation.evaluate(event, tx);
          throw new Error('crash before commit');
        },
        { timeout: 120_000, maxWait: 120_000 },
      ),
    ).rejects.toThrow('crash before commit');
    expect(await entriesOf(m)).toEqual([]);
    expect((await fx.lifecycle(m)).status).toBe('scanned');
    expect(await p.consumer.handler(event)).toBe('handled');
    expect(await entriesOf(m)).toHaveLength(1);
  });

  it('REQUIRE_APPROVAL → pending_approval entries with policy_review requests and one approval_requested notice', async () => {
    const t = await tenant('review', [rule('h', [{ type: 'REQUIRE_APPROVAL' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('review') });
    const m = await fx.message(t, { recipients: ['a@corp.example', 'b@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const entries = await entriesOf(m);
    expect(entries.map((e) => [e.kind, e.status])).toEqual([
      ['review', 'pending_approval'],
      ['review', 'pending_approval'],
    ]);
    expect(entries[0]!.expiresAt.getTime() - entries[0]!.quarantinedAt.getTime()).toBe(
      7 * 86_400_000,
    );
    const requests = await fx.prisma.quarantineApprovalRequest.findMany({
      where: { quarantineMessageId: { in: entries.map((e) => e.id) } },
      orderBy: { id: 'asc' },
    });
    expect(requests.map((r) => [r.kind, r.status, r.requestedByType, r.approvalReasons])).toEqual([
      ['policy_review', 'pending', 'system', ['review']],
      ['policy_review', 'pending', 'system', ['review']],
    ]);
    expect(entries.map((e) => e.approvalRequestId)).toEqual(requests.map((r) => r.id));
    expect(requests[0]!.expiresAt).toEqual(entries[0]!.expiresAt);
    const notices = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
    });
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ aggregateType: 'quarantine', aggregateId: t.toString() });
    expect(quarantineNotificationRequestedV1.parse(notices[0]!.payload)).toMatchObject({
      kind: 'approval_requested',
      refs: { approvalRequestIds: requests.map((r) => r.publicId) },
    });
    expect((await fx.lifecycle(m)).status).toBe('held_for_review');
  });

  it('a recipient-scoped rule splits: approvals only for the allowed recipient, an entry for the held one', async () => {
    const t = await tenant('split', [
      rule('q-eve', [{ type: 'QUARANTINE' }], {
        when: { field: 'recipient.address', op: 'in', value: ['eve@corp.example'] },
      }),
    ]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('split') });
    const m = await fx.message(t, { recipients: ['bob@corp.example', 'eve@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    expect(await fx.lifecycle(m)).toMatchObject({
      status: 'approved',
      statusReason: 'policy_partial',
      finalAction: 'partial',
    });
    const [row] = await fx.evaluations(m);
    expect(row).toMatchObject({ recipientSplit: true, action: 'partial' });
    expect(row!.recipientDecisions).toEqual([
      expect.objectContaining({ rcptSeq: 0, disposition: 'allow' }),
      expect.objectContaining({ rcptSeq: 1, disposition: 'quarantine', source: 'tenant_rule' }),
    ]);
    const approvals = await approvalsOf(m);
    expect(approvals).toHaveLength(1);
    expect(approvals[0]!.recipients).toEqual([
      { recipientId: m.recipients[0]!.id.toString(), rcptSeq: 0 },
    ]);
    const entries = await entriesOf(m);
    expect(entries.map((e) => [e.rcptSeq, e.recipientAddress, e.status])).toEqual([
      [1, 'eve@corp.example', 'held'],
    ]);
    expect(await recipientsOf(m)).toEqual([
      expect.objectContaining({ status: 'pending', finalAction: 'deliver' }),
      expect.objectContaining({ status: 'quarantined', finalAction: 'quarantine' }),
    ]);
  });

  it('a rescan supersedes the earlier round: entries superseded, recipients re-decided, new entries', async () => {
    const t = await tenant('rescan', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rescan') });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const next = await fx.rescan(m);
    expect(await p.consumer.handler(fx.scanned(next))).toBe('handled');
    const entries = await entriesOf(m);
    expect(entries.map((e) => [e.lifecycleRound, e.status, e.terminalReason])).toEqual([
      [0, 'superseded', 'superseded'],
      [1, 'held', null],
    ]);
    const actions = await fx.prisma.quarantineAction.findMany({
      where: { quarantineMessageId: entries[0]!.id },
      orderBy: { id: 'asc' },
    });
    expect(actions.map((a) => a.action)).toEqual(['quarantine', 'supersede']);
    expect(await recipientsOf(m)).toEqual([expect.objectContaining({ status: 'quarantined' })]);
  });
});

describe('policy URL rewrite after the scan (Q23)', () => {
  it('rewrites the delivered copy with click tokens when the round was skipped as disabled', async () => {
    const t = await tenant('rewrite', [
      rule('rw', [{ type: 'URL_REWRITE', ifNotRewritten: 'quarantine' }]),
    ]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rewrite') });
    const link = 'https://example.org/landing';
    const eml = DEFAULT_EML.replace('Hello Bob.', `Hello Bob. See ${link} today.`);
    const m = await fx.message(t, { eml });
    await fx.prisma.urlRewrite.create({
      data: {
        receivedAt: m.receivedAt,
        messageId: m.messageId,
        organizationId: t,
        scanId: m.scanId!,
        lifecycleRound: 0,
        status: 'skipped',
        skipReason: 'disabled',
        settingsVersion: 'it/1',
      },
    });
    const n = normalizeUrl(link);
    if (!n.ok) throw new Error('fixture url');
    await fx.prisma.messageUrl.create({
      data: {
        receivedAt: m.receivedAt,
        messageId: m.messageId,
        organizationId: t,
        urlSeq: 0,
        url: n.url.redirect,
        urlSha256: n.url.sha256,
        scheme: 'https',
        host: 'example.org',
        registrableDomain: 'example.org',
        hostKind: 'domain',
        sources: { text: 1 },
        occurrences: 1,
        firstLifecycleRound: 0,
        extractorVersion: 'it/1',
      },
    });
    await fx.prisma.emailMessageParse.create({
      data: {
        receivedAt: m.receivedAt,
        messageId: m.messageId,
        organizationId: t,
        status: 'parsed',
        attempts: 1,
        parserVersion: 'mime/1',
        structure: [{ index: 0, contentType: 'text/plain' }],
        startedAt: m.receivedAt,
        completedAt: m.receivedAt,
      },
    });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [row] = await fx.evaluations(m);
    expect(row).toMatchObject({ disposition: 'allow', deliveredObject: 'policy_copy' });
    expect(row!.delivery).toMatchObject({
      urlRewrite: {
        required: true,
        policyRewritable: true,
        policyAttempt: { status: 'rewritten', skipReason: null },
      },
    });
    expect(
      (row!.actions as Array<{ type: string; status: string }>).find(
        (a) => a.type === 'URL_REWRITE',
      )?.status,
    ).toBe('enforced');
    const copy = await fx.object(row!.objectKey!);
    const text = copy.body.toString('latin1');
    expect(text).not.toContain(link);
    expect(text).toContain(p.config.URL_CLICK_BASE_URL.replace(/\/+$/, ''));
    expect(copy.tags).toEqual({ 'eg-object': 'policy-copy' });
    expect(await p.registry.metrics()).toContain(
      'policy_url_rewrite_total{result="rewritten",service="policy-engine-it"} 1',
    );
  });

  it('a policy rewrite that cannot run (no parse) under ifNotRewritten=quarantine re-evaluates and holds', async () => {
    const t = await tenant('rewrite-skip', [
      rule('rw', [{ type: 'URL_REWRITE', ifNotRewritten: 'quarantine' }]),
    ]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rewrite-skip') });
    const m = await fx.message(t);
    await fx.prisma.urlRewrite.create({
      data: {
        receivedAt: m.receivedAt,
        messageId: m.messageId,
        organizationId: t,
        scanId: m.scanId!,
        lifecycleRound: 0,
        status: 'skipped',
        skipReason: 'disabled',
        settingsVersion: 'it/1',
      },
    });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [row] = await fx.evaluations(m);
    expect(row).toMatchObject({ disposition: 'quarantine', deliveredObject: 'none' });
    expect((await fx.lifecycle(m)).status).toBe('quarantined');
    expect(await entriesOf(m)).toHaveLength(1);
    expect(await approvalsOf(m)).toEqual([]);
  });
});

describe('release executor (Q13)', () => {
  it('quarantined → E14: a release copy with X-EG-Quarantine-Release, approval of the new round, entry released', async () => {
    const t = await tenant('rel-q', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rel-q') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('rel-q-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [entry] = await entriesOf(m);
    const event = await queueRelease(t, m, [entry!.id]);
    expect(await q.consumer.handler(event)).toBe('handled');
    expect(await q.consumer.handler(event)).toBe('duplicate');

    const lifecycle = await fx.lifecycle(m);
    expect(lifecycle).toMatchObject({
      status: 'approved',
      statusReason: 'quarantine_release',
      lifecycleRound: 1,
    });
    expect(lifecycle.history.at(-1)).toMatchObject({
      fromStatus: 'quarantined',
      toStatus: 'approved',
      actorRole: 'quarantine',
      actorService: 'policy-engine',
    });
    const [released] = await entriesOf(m);
    expect(released).toMatchObject({
      status: 'released',
      decidedByType: 'user',
      terminalReason: 'released',
    });
    expect(released!.releasedAt).not.toBeNull();
    const [log] = await fx.prisma.quarantineReleaseLog.findMany({
      where: { releasePublicId: event.payload.releaseId },
    });
    expect(log).toMatchObject({
      status: 'dispatched',
      deliveredObject: 'policy_copy',
      deliverySeq: 0,
      lifecycleRoundAfter: 1,
      revalidationScanId: m.scanId,
    });
    expect(log!.revalidation).toMatchObject({
      outcome: 'release',
      approvalReasons: [],
      summary: {
        disposition: 'quarantine',
        source: 'tenant_rule',
        decisiveRuleRef: expect.any(String),
      },
    });
    const approvals = await approvalsOf(m);
    expect(approvals).toEqual([
      expect.objectContaining({
        source: 'quarantine_release',
        lifecycleRound: 1,
        deliverySeq: 0,
        emlS3Key: log!.objectKey,
        recipients: [{ recipientId: m.recipients[0]!.id.toString(), rcptSeq: 0 }],
      }),
    ]);
    expect(log!.approvalEventIds).toEqual([
      (await fx.outbox(m, EventTypes.DeliveryApproved))[0]!.eventId,
    ]);
    const copy = await fx.object(log!.objectKey!);
    expect(
      copy.body
        .toString('latin1')
        .startsWith(`X-EG-Quarantine-Release: ${event.payload.releaseId}\r\n`),
    ).toBe(true);
    expect(log!.objectKey).toMatch(
      new RegExp(
        `^org/${t.toString()}/policy/\\d{4}/\\d{2}/\\d{2}/${m.messageId.toString()}/r1-[0-9a-f]{32}\\.eml$`,
      ),
    );
    expect(await recipientsOf(m)).toEqual([expect.objectContaining({ status: 'pending' })]);
    expect(await q.registry.metrics()).toContain(
      'quarantine_releases_total{result="dispatched",mode="operator",service="policy-engine-it-q"} 1',
    );
  });

  it('delivered (split, partial delivery) → E28 new round, delivered once to the held recipient only', async () => {
    const t = await tenant('rel-d', [
      rule('q-eve', [{ type: 'QUARANTINE' }], {
        when: { field: 'recipient.address', op: 'in', value: ['eve@corp.example'] },
      }),
    ]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rel-d') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('rel-d-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t, { recipients: ['bob@corp.example', 'eve@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    await setState(m, 'delivered');
    await fx.prisma.emailRecipient.update({
      where: {
        id_receivedAt: { id: m.recipients[0]!.id, receivedAt: m.receivedAt },
      },
      data: { status: 'delivered' },
    });
    const [entry] = await entriesOf(m);
    expect(await q.consumer.handler(await queueRelease(t, m, [entry!.id]))).toBe('handled');
    expect(await fx.lifecycle(m)).toMatchObject({
      status: 'approved',
      statusReason: 'quarantine_partial_release',
      lifecycleRound: 1,
    });
    const approvals = await approvalsOf(m);
    expect(approvals.map((a) => [a.source, a.lifecycleRound, a.recipients])).toEqual([
      ['policy', 0, [{ recipientId: m.recipients[0]!.id.toString(), rcptSeq: 0 }]],
      ['quarantine_release', 1, [{ recipientId: m.recipients[1]!.id.toString(), rcptSeq: 1 }]],
    ]);
  });

  it('delivery_pending → no transition: the approval carries the current round', async () => {
    const t = await tenant('rel-p', [
      rule('q-eve', [{ type: 'QUARANTINE' }], {
        when: { field: 'recipient.address', op: 'in', value: ['eve@corp.example'] },
      }),
    ]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rel-p') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('rel-p-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t, { recipients: ['bob@corp.example', 'eve@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    await setState(m, 'delivery_pending');
    const before = await fx.lifecycle(m);
    const [entry] = await entriesOf(m);
    expect(await q.consumer.handler(await queueRelease(t, m, [entry!.id]))).toBe('handled');
    const after = await fx.lifecycle(m);
    expect(after).toMatchObject({ status: 'delivery_pending', lifecycleRound: 0 });
    expect(after.history).toHaveLength(before.history.length);
    const release = (await approvalsOf(m)).find((a) => a.source === 'quarantine_release');
    expect(release).toMatchObject({ lifecycleRound: 0, deliverySeq: 0 });
  });

  it('blocked paths: message busy, policy now rejects (approval required), stale verdicts (rescan required), stale event', async () => {
    const t = await tenant('rel-b', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rel-b') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('rel-b-x'),
      organizationIds: [t],
    });

    // 1. A re-decision in progress (scanning) → message_busy, entry back to held, notice.
    const busy = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(busy))).toBe('handled');
    await setState(busy, 'scanning');
    const [b] = await entriesOf(busy);
    const busyEvent = await queueRelease(t, busy, [b!.id]);
    expect(await q.consumer.handler(busyEvent)).toBe('handled');
    expect((await entriesOf(busy))[0]!.status).toBe('held');
    expect(
      (
        await fx.prisma.quarantineReleaseLog.findFirstOrThrow({
          where: { releasePublicId: busyEvent.payload.releaseId },
        })
      ).status,
    ).toBe('message_busy');
    expect(await approvalsOf(busy)).toEqual([]);

    // 2. The current policy rejects → approval reason policy_reject → a release_approval request.
    const rejected = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(rejected))).toBe('handled');
    await fx.publish(t, 'p-rel-b', policy([rule('r', [{ type: 'REJECT' }])]));
    const [r] = await entriesOf(rejected);
    const rejectEvent = await queueRelease(t, rejected, [r!.id]);
    expect(await q.consumer.handler(rejectEvent)).toBe('handled');
    const [pending] = await entriesOf(rejected);
    expect(pending!.status).toBe('pending_approval');
    const request = await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({
      where: { id: pending!.approvalRequestId! },
    });
    expect(request).toMatchObject({
      kind: 'release_approval',
      status: 'pending',
      approvalReasons: ['policy_reject'],
      requestedByType: 'user',
      requestedByUserId: requesters.get(t)!.id,
    });
    expect(
      (
        await fx.prisma.quarantineReleaseLog.findFirstOrThrow({
          where: { releasePublicId: rejectEvent.payload.releaseId },
        })
      ).status,
    ).toBe('approval_required');
    expect((await fx.lifecycle(rejected)).status).toBe('quarantined');

    // 3. Verdicts older than 72 h on a message with URLs → rescan_required.
    await fx.publish(t, 'p-rel-b', policy([rule('q', [{ type: 'QUARANTINE' }])]));
    const old = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(old))).toBe('handled');
    await fx.prisma.emailScan.updateMany({
      where: { messageId: old.messageId },
      data: { completedAt: new Date(Date.now() - 80 * 3_600_000) },
    });
    await fx.prisma.messageUrl.create({
      data: {
        receivedAt: old.receivedAt,
        messageId: old.messageId,
        organizationId: t,
        urlSeq: 0,
        url: 'https://example.org/',
        urlSha256: 'a'.repeat(64),
        scheme: 'https',
        host: 'example.org',
        hostKind: 'domain',
        sources: { text: 1 },
        occurrences: 1,
        firstLifecycleRound: 0,
        extractorVersion: 'it/1',
      },
    });
    const [o] = await entriesOf(old);
    const staleEvent = await queueRelease(t, old, [o!.id]);
    expect(await q.consumer.handler(staleEvent)).toBe('handled');
    expect((await entriesOf(old))[0]!.status).toBe('held');
    const staleLog = await fx.prisma.quarantineReleaseLog.findFirstOrThrow({
      where: { releasePublicId: staleEvent.payload.releaseId },
    });
    expect(staleLog).toMatchObject({ status: 'rescan_required', blockedReason: 'rescan_required' });
    expect(staleLog.revalidation).toMatchObject({
      staleness: { stale: true, causes: ['verdict_age'] },
    });

    // 4. An event whose entries are no longer releasing → ledger only, logs marked stale.
    const again = { ...staleEvent, eventId: uuidv7() };
    expect(await q.consumer.handler(again)).toBe('handled');
    expect(await q.registry.metrics()).toContain(
      'quarantine_releases_total{result="stale",mode="operator",service="policy-engine-it-q"} 1',
    );

    // Blocked releases notify the requesting user.
    const notices = (
      await fx.prisma.messageOutbox.findMany({
        where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
      })
    ).map((n) => quarantineNotificationRequestedV1.parse(n.payload));
    expect(notices.filter((n) => n.kind === 'release_blocked')).toHaveLength(3);
  });
});

describe('release executor: separation of duties on approved releases (Q14)', () => {
  it('new reasons after an approval open a request whose requester is the original requester, not the approver', async () => {
    const t = await tenant('sod-chain', [rule('q', [{ type: 'QUARANTINE' }])]);
    const asker = await fx.user(t, 'asker@corp.example');
    const approver = await fx.user(t, 'approver@corp.example');
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('sod-chain') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('sod-chain-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [e] = await entriesOf(m);
    // The asker's request was approved for `hard_block`; the policy now rejects (policy_reject).
    const approved = await approvedRequest(t, e!.id, {
      requestedBy: { type: 'user', userId: asker.id },
      decidedByUserId: approver.id,
      reasons: ['hard_block'],
    });
    await fx.publish(t, 'p-sod-chain', policy([rule('r', [{ type: 'REJECT' }])]));
    const ev = await queueRelease(t, m, [e!.id], 'approved', approved, approver);
    expect(await q.consumer.handler(ev)).toBe('handled');

    const [held] = await entriesOf(m);
    expect(held!.status).toBe('pending_approval');
    expect(held!.approvalRequestId).not.toBe(approved.id);
    const followUp = await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({
      where: { id: held!.approvalRequestId! },
    });
    // The asker stays the requester: checkApprover refuses the asker on the new reasons.
    expect(followUp).toMatchObject({
      kind: 'release_approval',
      status: 'pending',
      approvalReasons: ['policy_reject'],
      requestedByType: 'user',
      requestedByUserId: asker.id,
      requestedByApiKeyId: null,
    });
    // The release itself was queued by the approver (actor of the release_blocked action).
    const blocked = await fx.prisma.quarantineAction.findFirstOrThrow({
      where: { quarantineMessageId: e!.id, action: 'release_blocked' },
    });
    expect(blocked).toMatchObject({ actorId: approver.publicId, result: 'approval_required' });
    expect(await approvalsOf(m)).toEqual([]);
  });

  it('an approved release of an API-key request decided by the key creator is refused', async () => {
    const t = await tenant('sod-key', [rule('q', [{ type: 'QUARANTINE' }])]);
    const owner = await fx.user(t, 'owner@corp.example');
    const other = await fx.user(t, 'other@corp.example');
    const key = await fx.apiKey(t, owner.id);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('sod-key') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('sod-key-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t, { recipients: ['a@corp.example', 'b@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [a, b] = await entriesOf(m);

    // Decided by the creator of the requesting key → approval_not_valid, entry back to held.
    const self = await approvedRequest(t, a!.id, {
      requestedBy: { type: 'api_key', apiKeyId: key.id },
      decidedByUserId: owner.id,
      reasons: [],
    });
    const refused = await queueRelease(t, m, [a!.id], 'approved', self, owner);
    expect(await q.consumer.handler(refused)).toBe('handled');
    expect((await entriesOf(m))[0]!.status).toBe('held');
    expect(
      await fx.prisma.quarantineReleaseLog.findFirstOrThrow({
        where: { releasePublicId: refused.payload.releaseId },
      }),
    ).toMatchObject({ status: 'refused', blockedReason: 'approval_not_valid' });

    // Decided by another user → released.
    const fine = await approvedRequest(t, b!.id, {
      requestedBy: { type: 'api_key', apiKeyId: key.id },
      decidedByUserId: other.id,
      reasons: [],
    });
    const ok = await queueRelease(t, m, [b!.id], 'approved', fine, other);
    expect(await q.consumer.handler(ok)).toBe('handled');
    expect((await entriesOf(m))[1]!.status).toBe('released');
  });
});

describe('sweeper (Q19, Q17, Q8, Q20)', () => {
  it('expiry never releases: entry expired, recipient discarded, E26 quarantine_expired, purge scheduled and done', async () => {
    const t = await tenant('expire', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('expire') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('expire-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    await fx.prisma.quarantineMessage.updateMany({
      where: { messageId: m.messageId },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    const first = await q.sweeper.sweepOnce();
    expect(first).toMatchObject({ outcome: 'swept', expired: 1, messagesExpired: 1, purged: 1 });
    const [entry] = await entriesOf(m);
    expect(entry).toMatchObject({ status: 'expired', terminalReason: 'expired' });
    expect(entry!.objectPurgedAt).not.toBeNull();
    expect(await recipientsOf(m)).toEqual([expect.objectContaining({ status: 'discarded' })]);
    expect(await fx.lifecycle(m)).toMatchObject({
      status: 'expired',
      statusReason: 'quarantine_expired',
    });
    expect(await approvalsOf(m)).toEqual([]);
    expect(await q.objects.exists(m.emlObjectKey)).toBe(false);
    const purge = await fx.prisma.quarantineObjectPurge.findFirstOrThrow({
      where: { messageId: m.messageId },
    });
    expect(purge).toMatchObject({ status: 'purged' });
    const second = await q.sweeper.sweepOnce();
    expect(second).toMatchObject({ outcome: 'swept', expired: 0, purged: 0 });
    expect(await q.registry.metrics()).toMatch(
      /quarantine_sweep_last_success_timestamp_seconds\{service="policy-engine-it-q"\} [1-9]/,
    );
  });

  it('a legal hold keeps the object (retained), its release lets the next pass purge it', async () => {
    const t = await tenant('hold', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('hold') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('hold-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const hold = await fx.prisma.archiveLegalHold.create({
      data: { organizationId: t, name: 'litigation', reason: 'it', criteria: {}, status: 'active' },
    });
    await fx.prisma.quarantineMessage.updateMany({
      where: { messageId: m.messageId },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    expect(await q.sweeper.sweepOnce()).toMatchObject({ expired: 1, purged: 0 });
    expect(
      await fx.prisma.quarantineObjectPurge.findFirstOrThrow({ where: { messageId: m.messageId } }),
    ).toMatchObject({ status: 'retained', reason: 'legal_hold' });
    expect(await q.objects.exists(m.emlObjectKey)).toBe(true);

    await fx.prisma.archiveLegalHold.update({
      where: { id: hold.id },
      data: { status: 'released', releasedAt: new Date() },
    });
    await fx.prisma.quarantineObjectPurge.updateMany({
      where: { messageId: m.messageId },
      data: { purgeAfter: new Date(Date.now() - 1_000) },
    });
    expect(await q.sweeper.sweepOnce()).toMatchObject({ purged: 1 });
    expect(await q.objects.exists(m.emlObjectKey)).toBe(false);
  });

  it('adopts a held message without entries (held by 5.2) with origin adopted', async () => {
    const t = await tenant('adopt', [rule('h', [{ type: 'REQUIRE_APPROVAL' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('adopt') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('adopt-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t, { recipients: ['a@corp.example', 'b@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    // As step 5.2 left it: no entries, recipients pending.
    const ids = (await entriesOf(m)).map((e) => e.id);
    await fx.prisma.quarantineAction.deleteMany({ where: { quarantineMessageId: { in: ids } } });
    await fx.prisma.quarantineApprovalRequest.deleteMany({
      where: { quarantineMessageId: { in: ids } },
    });
    await fx.prisma.quarantineMessage.deleteMany({ where: { id: { in: ids } } });
    await fx.prisma.emailRecipient.updateMany({
      where: { messageId: m.messageId },
      data: { status: 'pending', finalAction: null },
    });

    const report = await q.sweeper.sweepOnce();
    expect(report.adopted).toBe(1);
    const adopted = await entriesOf(m);
    expect(adopted.map((e) => [e.origin, e.kind, e.status, e.reason, e.decisiveRuleId])).toEqual([
      ['adopted', 'review', 'pending_approval', 'policy', 'h'],
      ['adopted', 'review', 'pending_approval', 'policy', 'h'],
    ]);
    // expires_at = max(now + 1 day, computeExpiry(received_at)) = received + 7 days.
    expect(adopted[0]!.expiresAt.getTime()).toBe(m.receivedAt.getTime() + 7 * 86_400_000);
    expect(await recipientsOf(m)).toEqual([
      expect.objectContaining({ status: 'quarantined', finalAction: 'require_approval' }),
      expect.objectContaining({ status: 'quarantined', finalAction: 'require_approval' }),
    ]);
    expect((await q.sweeper.sweepOnce()).adopted).toBe(0);
  });

  it('a rescanned quarantine-expired message (all recipients discarded) ends expired again, never blocks adoption', async () => {
    const t = await tenant('expire-rescan', [rule('q', [{ type: 'QUARANTINE' }])]);
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('expire-rescan') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('expire-rescan-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    await fx.prisma.quarantineMessage.updateMany({
      where: { messageId: m.messageId },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    expect(await q.sweeper.sweepOnce()).toMatchObject({ expired: 1, messagesExpired: 1 });
    expect((await fx.lifecycle(m)).status).toBe('expired');

    // An operator rescans the expired message (E19 from expired); the new round re-decides
    // only pending recipients — none — so the message is held with no entry of its round.
    const next = await fx.rescan(m);
    expect(await p.consumer.handler(fx.scanned(next))).toBe('handled');
    expect((await fx.lifecycle(m)).status).toBe('quarantined');
    expect((await entriesOf(m)).map((e) => [e.lifecycleRound, e.status])).toEqual([[0, 'expired']]);
    expect(await recipientsOf(m)).toEqual([expect.objectContaining({ status: 'discarded' })]);

    // The sweeper ends it (E26 quarantine_expired) instead of selecting it on every pass.
    const report = await q.sweeper.sweepOnce();
    expect(report).toMatchObject({ outcome: 'swept', adopted: 0, messagesExpired: 1 });
    const after = await fx.lifecycle(m);
    expect(after).toMatchObject({ status: 'expired', statusReason: 'quarantine_expired' });
    expect(after.history.at(-1)).toMatchObject({
      fromStatus: 'quarantined',
      toStatus: 'expired',
      lifecycleRound: next.round,
    });
    expect(await approvalsOf(m)).toEqual([]);
    expect(await q.sweeper.sweepOnce()).toMatchObject({ adopted: 0, messagesExpired: 0 });
  });

  it('approval-request expiry: a release request returns its entry to held; a policy review expires the entry and the message', async () => {
    const t = await tenant('appr-exp', [rule('q', [{ type: 'QUARANTINE' }])]);
    const requester = requesters.get(t)!;
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('appr-exp') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('appr-exp-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [e] = await entriesOf(m);
    // A pending release_approval request (as the api writes it) that expired a minute ago.
    const request = await fx.prisma.quarantineApprovalRequest.create({
      data: {
        organizationId: t,
        quarantineMessageId: e!.id,
        kind: 'release_approval',
        status: 'pending',
        approvalReasons: ['hard_block'],
        requestedByType: 'user',
        requestedByUserId: requester.id,
        expiresAt: new Date(Date.now() - 60_000),
      },
      select: { id: true, publicId: true },
    });
    await fx.prisma.quarantineMessage.update({
      where: { id: e!.id },
      data: {
        status: 'pending_approval',
        approvalRequestId: request.id,
        rowVersion: { increment: 1 },
      },
    });

    const first = await q.sweeper.sweepOnce();
    expect(first).toMatchObject({ outcome: 'swept', approvalsExpired: 1, expired: 0 });
    expect(
      await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({ where: { id: request.id } }),
    ).toMatchObject({ status: 'expired', decidedAt: expect.any(Date) });
    expect((await entriesOf(m))[0]!.status).toBe('held');
    expect(
      await fx.prisma.quarantineAction.findFirstOrThrow({
        where: { quarantineMessageId: e!.id, action: 'approval_expired' },
      }),
    ).toMatchObject({ actorType: 'system', result: 'expired', approvalRequestId: request.id });
    const decided = (
      await fx.prisma.messageOutbox.findMany({
        where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
      })
    )
      .map((n) => quarantineNotificationRequestedV1.parse(n.payload))
      .filter((n) => n.kind === 'approval_decided');
    expect(decided).toEqual([
      expect.objectContaining({
        decision: 'expired',
        refs: expect.objectContaining({
          approvalRequestIds: [request.publicId],
          entryId: e!.publicId,
        }),
      }),
    ]);
    expect((await fx.lifecycle(m)).status).toBe('quarantined');
    expect((await q.sweeper.sweepOnce()).approvalsExpired).toBe(0);

    // A policy review whose request expired before its entry: entry expired, message E26.
    await fx.publish(t, 'p-appr-exp', policy([rule('h', [{ type: 'REQUIRE_APPROVAL' }])]));
    const r = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(r))).toBe('handled');
    const [re] = await entriesOf(r);
    expect(re).toMatchObject({ kind: 'review', status: 'pending_approval' });
    await fx.prisma.quarantineApprovalRequest.updateMany({
      where: { quarantineMessageId: re!.id },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    const second = await q.sweeper.sweepOnce();
    expect(second).toMatchObject({ approvalsExpired: 1, expired: 1, messagesExpired: 1 });
    expect((await entriesOf(r))[0]).toMatchObject({ status: 'expired', terminalReason: 'expired' });
    expect(
      await fx.prisma.quarantineApprovalRequest.findFirstOrThrow({
        where: { quarantineMessageId: re!.id },
      }),
    ).toMatchObject({ kind: 'policy_review', status: 'expired' });
    expect(await recipientsOf(r)).toEqual([expect.objectContaining({ status: 'discarded' })]);
    expect(await fx.lifecycle(r)).toMatchObject({
      status: 'expired',
      statusReason: 'quarantine_expired',
    });
  });

  it('entry retention deletes terminal entries older than the cut with their rows; newer ones stay', async () => {
    const t = await tenant('retain', [rule('q', [{ type: 'QUARANTINE' }])]);
    const requester = requesters.get(t)!;
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('retain') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('retain-x'),
      organizationIds: [t],
    });
    const old = await fx.message(t);
    const recent = await fx.message(t);
    for (const m of [old, recent]) expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    const [o] = await entriesOf(old);
    const [n] = await entriesOf(recent);
    // Both expire (terminal); the old one gets a release log, an approval request and a grant.
    await fx.prisma.quarantineMessage.updateMany({
      where: { id: { in: [o!.id, n!.id] } },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    expect(await q.sweeper.sweepOnce()).toMatchObject({ expired: 2 });
    const action = await fx.prisma.quarantineAction.create({
      data: {
        organizationId: t,
        quarantineMessageId: o!.id,
        action: 'release_queued',
        actorType: 'user',
        actorUserId: requester.id,
        actorId: requester.publicId,
      },
    });
    await fx.prisma.quarantineReleaseLog.create({
      data: {
        organizationId: t,
        quarantineMessageId: o!.id,
        actionId: action.id,
        releasePublicId: randomUUID(),
        mode: 'operator',
        requestedByType: 'user',
        requestedById: requester.publicId,
        releasedTo: o!.recipientAddress,
        status: 'stale',
      },
    });
    await fx.prisma.quarantineApprovalRequest.create({
      data: {
        organizationId: t,
        quarantineMessageId: o!.id,
        kind: 'release_request',
        status: 'cancelled',
        approvalReasons: [],
        requestedByType: 'user',
        requestedByUserId: requester.id,
        expiresAt: new Date(Date.now() + 86_400_000),
      },
    });
    await fx.prisma.quarantineDownloadGrant.create({
      data: {
        jti: uuidv7(),
        organizationId: t,
        userId: requester.id,
        quarantineMessageId: o!.id,
        object: 'eml',
        // Far in the future: only the entry's retention removes it.
        expiresAt: new Date(Date.now() + 86_400_000),
      },
    });
    // The old entry ended 200 days ago (QUARANTINE_ENTRY_RETENTION_DAYS = 186).
    await fx.prisma.quarantineMessage.update({
      where: { id: o!.id },
      data: { stateChangedAt: new Date(Date.now() - 200 * 86_400_000) },
    });

    const report = await q.sweeper.sweepOnce();
    expect(report).toMatchObject({ outcome: 'swept', entriesDeleted: 1 });
    expect(await fx.prisma.quarantineMessage.findUnique({ where: { id: o!.id } })).toBeNull();
    const byEntry = { where: { quarantineMessageId: o!.id } };
    expect(await fx.prisma.quarantineAction.count(byEntry)).toBe(0);
    expect(await fx.prisma.quarantineReleaseLog.count(byEntry)).toBe(0);
    expect(await fx.prisma.quarantineApprovalRequest.count(byEntry)).toBe(0);
    expect(await fx.prisma.quarantineDownloadGrant.count(byEntry)).toBe(0);
    // The message's last quarantine reference is gone: its `purged` purge row too.
    expect(
      await fx.prisma.quarantineObjectPurge.count({ where: { messageId: old.messageId } }),
    ).toBe(0);
    // The newer terminal entry and its trail stay.
    expect((await entriesOf(recent)).map((e) => e.status)).toEqual(['expired']);
    expect(
      (
        await fx.prisma.quarantineAction.findMany({
          where: { quarantineMessageId: n!.id },
          orderBy: { id: 'asc' },
        })
      ).map((a) => a.action),
    ).toEqual(['quarantine', 'expire', 'object_purged']);
    expect((await q.sweeper.sweepOnce()).entriesDeleted).toBe(0);
  });

  it('digests reach every organization when more organizations than the batch have held mail', async () => {
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('digest-fair') });
    const orgs: bigint[] = [];
    for (const label of ['digest-fair-1', 'digest-fair-2', 'digest-fair-3']) {
      const t = await tenant(label, [rule('q', [{ type: 'QUARANTINE' }])]);
      orgs.push(t);
      await fx.prisma.organizationSetting.create({
        data: { organizationId: t, digestSchedule: '* * * * *', timezone: 'UTC' },
      });
      await fx.prisma.user.create({
        data: {
          organizationId: t,
          email: 'held@corp.example',
          displayName: 'Held',
          status: 'active',
          emailVerifiedAt: new Date(),
        },
      });
      const m = await fx.message(t, { recipients: ['held@corp.example'] });
      expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
      await fx.prisma.quarantineMessage.updateMany({
        where: { messageId: m.messageId },
        data: { quarantinedAt: new Date(Date.now() - 2 * 3_600_000) },
      });
    }
    // One organization per sweep: before the cursor, every sweep took the lowest id only.
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('digest-fair-x'),
      organizationIds: orgs,
      digestBatchSize: 1,
    });
    const per: number[] = [];
    for (let i = 0; i < 3; i += 1) per.push((await q.sweeper.sweepOnce()).digests);
    expect(per).toEqual([1, 1, 1]);
    const digests = await fx.prisma.quarantineDigest.findMany({
      where: { organizationId: { in: orgs } },
      select: { organizationId: true },
    });
    expect(digests.map((d) => d.organizationId).sort()).toEqual([...orgs].sort());
  });

  it('schedules one digest per user with held mail (idempotent) and refreshes the gauges', async () => {
    const t = await tenant('digest', [rule('q', [{ type: 'QUARANTINE' }])]);
    await fx.prisma.organizationSetting.create({
      data: { organizationId: t, digestSchedule: '* * * * *', timezone: 'UTC' },
    });
    const bob = await fx.prisma.user.create({
      data: {
        organizationId: t,
        email: 'bob@corp.example',
        displayName: 'Bob',
        status: 'active',
        emailVerifiedAt: new Date(),
      },
    });
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('digest') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('digest-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t, { recipients: ['bob@corp.example', 'nobody@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    // The entry's user_id is the informational directory lookup.
    expect((await entriesOf(m)).map((e) => e.userId)).toEqual([bob.id, null]);
    // Held two hours ago: inside a due window (entries held after the last instant wait for the
    // next one).
    await fx.prisma.quarantineMessage.updateMany({
      where: { messageId: m.messageId },
      data: { quarantinedAt: new Date(Date.now() - 2 * 3_600_000) },
    });
    const first = await q.sweeper.sweepOnce();
    expect(first.digests).toBe(1);
    const digests = await fx.prisma.quarantineDigest.findMany({ where: { organizationId: t } });
    expect(digests.map((d) => [d.userId, d.entryCount])).toEqual([[bob.id, 1]]);
    const notices = (
      await fx.prisma.messageOutbox.findMany({
        where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
      })
    ).map((n) => ({
      eventId: n.eventId,
      payload: quarantineNotificationRequestedV1.parse(n.payload),
    }));
    expect(notices).toEqual([
      {
        eventId: digests[0]!.eventId,
        payload: expect.objectContaining({
          kind: 'user_digest',
          refs: { userId: bob.publicId, digestId: digests[0]!.publicId },
        }),
      },
    ]);
    expect((await q.sweeper.sweepOnce()).digests).toBe(0);
    const metrics = await q.registry.metrics();
    expect(metrics).toContain('quarantine_entries{state="held",service="policy-engine-it-q"} 2');
    expect(metrics).toContain('quarantine_pending_approvals{service="policy-engine-it-q"} 0');
  });

  it('digests skip opted-out users and organizations without end-user access; admin alerts are rate-bounded', async () => {
    const t = await tenant('digest-opt', [rule('h', [{ type: 'REQUIRE_APPROVAL' }])]);
    await fx.prisma.organizationSetting.create({
      data: { organizationId: t, digestSchedule: '* * * * *', timezone: 'UTC' },
    });
    const mk = (email: string) =>
      fx.prisma.user.create({
        data: {
          organizationId: t,
          email,
          displayName: email,
          status: 'active',
          emailVerifiedAt: new Date(),
        },
      });
    const ann = await mk('ann@corp.example');
    const ben = await mk('ben@corp.example');
    await fx.prisma.quarantineUserPreference.create({
      data: { organizationId: t, userId: ben.id, digestOptOut: true },
    });
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('digest-opt') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('digest-opt-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t, { recipients: ['ann@corp.example', 'ben@corp.example'] });
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    await fx.prisma.quarantineMessage.updateMany({
      where: { messageId: m.messageId },
      data: { quarantinedAt: new Date(Date.now() - 2 * 3_600_000) },
    });
    // Review requests waiting for more than an hour → one admin alert per interval.
    await fx.prisma.quarantineApprovalRequest.updateMany({
      where: { organizationId: t },
      data: { createdAt: new Date(Date.now() - 2 * 3_600_000) },
    });
    const first = await q.sweeper.sweepOnce();
    expect(first).toMatchObject({ digests: 1, alerts: 1 });
    const digests = await fx.prisma.quarantineDigest.findMany({ where: { organizationId: t } });
    expect(digests.map((d) => d.userId)).toEqual([ann.id]);
    expect((await q.sweeper.sweepOnce()).alerts).toBe(0);
    const kinds = (
      await fx.prisma.messageOutbox.findMany({
        where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
        orderBy: { id: 'asc' },
      })
    ).map((n) => quarantineNotificationRequestedV1.parse(n.payload).kind);
    expect(kinds.sort()).toEqual(['admin_alert', 'approval_requested', 'user_digest']);

    // endUser.enabled = false → no digest run at all.
    const off = await tenant('digest-off', [rule('q', [{ type: 'QUARANTINE' }])]);
    await fx.prisma.organizationSetting.create({
      data: { organizationId: off, digestSchedule: '* * * * *', timezone: 'UTC' },
    });
    await fx.prisma.quarantineSettings.create({
      data: {
        organizationId: off,
        settings: { endUser: { enabled: false } },
        settingsSha256: '0'.repeat(64),
      },
    });
    const p2 = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('digest-off') });
    const q2 = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('digest-off-x'),
      organizationIds: [off],
    });
    const m2 = await fx.message(off);
    expect(await p2.consumer.handler(fx.scanned(m2))).toBe('handled');
    expect((await q2.sweeper.sweepOnce()).digests).toBe(0);
    expect(
      await fx.prisma.quarantineDigestRun.count({
        where: { organizationId: off, kind: 'user_digest' },
      }),
    ).toBe(0);
  });
});
