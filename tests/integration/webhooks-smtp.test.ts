import { randomBytes } from 'node:crypto';
import { eicar } from '@email-gateway/attachment-corpus';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import { attachmentMessage } from './support/attachment-stack';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { waitForLifecycle } from './support/lifecycle';
import { clearSinkDomain } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import { createAndPublishPolicy } from './support/policy';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { postIdem, waitForEntries, waitForReleaseOutcome } from './support/quarantine';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import { corpusEml, messagePublicId, sendToMx } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import {
  ALL_EVENT_TYPES,
  createWebhook,
  deliveryDetail,
  headerProblems,
  ofMessage,
  ofType,
  payloadProblems,
  programReceiver,
  receivedRequests,
  verifyReceived,
  waitForRequests,
  webhookRowCounts,
  webhooksStackGate,
  type CreatedWebhook,
  type ReceivedRequest,
} from './support/webhooks';

/**
 * Step 6.2 webhooks end to end (docs/plan/steps/19-webhooks-notifications.md §10.4, W1–W12,
 * ADR-0054/0055): real SMTP into the Compose Postfix, the 2.x–5.x pipeline on the live
 * containers, the webhook-worker (fanout + delivery roles) projecting the internal events into
 * public webhook events and POSTing them through the SSRF-guarded client (dns-sink → 203.0.113.20,
 * test-CA HTTPS) to the TEST-ONLY `webhook-receiver`, subscriptions created through the live api.
 *
 * Organization A (webhooks feature on): four subscriptions — every type, a `minSeverity: high`
 * filter, a retry endpoint (503 + Retry-After once) and nothing else; a tenant policy that
 * QUARANTINEs `r6hold` and REJECTs `r6rej`. Organization B (feature on): one subscription on
 * its own path, one clean message. Messages: clean (received, scanned, delivered), EICAR
 * (threat detected, rejected), held (policy triggered, quarantined; released through the api →
 * released, delivered), rejected by the tenant rule (policy triggered, rejected).
 *
 * Every request is checked twice for its signature (the receiver with the registered secret,
 * and here with `verifyWebhookSignature` of @email-gateway/webhooks), for the exact header set
 * and for content (no `@` outside `internetMessageId`, no `://`, no `org/`, no subject, local
 * part, body phrase or file name, ≤ 16 KiB, envelope organization = the public id).
 *
 * `domain.verified` / `domain.dns.failed` are not produced here: the stack's domain DNS is
 * static (fixtures insert verified domains); both are covered by the api and webhook-worker
 * integration suites (§10.3). Security alerts are off for the fixture organizations
 * (FIXTURE_NOTIFICATION_SETTINGS); webhooks-notifications.test.ts covers them.
 */
const gate = await webhooksStackGate();
const fx = new SmtpFixtures();
const run = randomBytes(3).toString('hex');
const suiteStart = new Date();

let orgA = 0n;
let orgB = 0n;
let orgAPublicId = '';
let orgBPublicId = '';
let inA: FixtureDomain;
let inB: FixtureDomain;
let adminA: ApiSession | undefined;
let analystA: ApiSession | undefined;
let adminB: ApiSession | undefined;
let holdPolicyId = '';

const hooks: {
  all?: CreatedWebhook;
  high?: CreatedWebhook;
  retry?: CreatedWebhook;
  allB?: CreatedWebhook;
} = {};

// Local parts: distinct from every fixture label (domain names may appear in payloads).
const LP = { clean: 'r6clean', eicar: 'r6eicar', hold: 'r6hold', rej: 'r6rej', b: 'r6orgb' };
const SUBJECT_TOKEN = `WH6S${run}`;
const EICAR_FILE = `wh6-${run}-invoice.txt`;
const SENDER = 'alice@clean.scan.test';

type Msg = { id: bigint; receivedAt: Date; publicId: string };
const msgs: { clean?: Msg; eicar?: Msg; hold?: Msg; rej?: Msg; b?: Msg } = {};
let releaseId = '';

/** Strings that must never appear in any payload (§2.0 invariant 1). */
const forbidden = () => [
  SUBJECT_TOKEN,
  EICAR_FILE,
  'alice',
  'Warehouse inventory',
  'reconciliation sheet',
  ...Object.values(LP),
];

const path = (org: string, name: string) => `it-wh6-${run}/${org}/${name}`;

async function inbound(org: bigint, rcpt: string, eml: string): Promise<Msg> {
  const sent = await sendToMx({ from: SENDER, to: [rcpt], helo: 'mx.clean.scan.test', data: eml });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  const row = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
  return {
    id: row.id,
    receivedAt: row.receivedAt,
    publicId: await messagePublicId(fx.prisma, row),
  };
}

const cleanEml = () => corpusEml('clean/clean-dkim-aligned.eml');

/** Waits until A's all-types endpoint holds every `types` event of message `m`. */
function eventsOf(m: Msg, types: readonly string[], hookPath = hooks.all!.path) {
  return waitForRequests(
    hookPath,
    `${types.join(', ')} of message ${m.publicId}`,
    (requests) => types.every((t) => ofType(ofMessage(requests, m.publicId), t).length > 0),
    300_000,
  ).then((requests) => ofMessage(requests, m.publicId));
}

const one = (requests: readonly ReceivedRequest[], type: string) => {
  const found = ofType(requests, type);
  expect(found.length, `${type} requests`).toBeGreaterThanOrEqual(1);
  // Every request of one event carries the same event id and identical bytes (W4).
  expect(new Set(found.map((r) => r.eventId)).size, `${type}: one event`).toBe(1);
  return found[0]!;
};

beforeAll(async () => {
  assertStackReady(gate);
  orgA = await fx.organization('wh6a');
  inA = await fx.domain(orgA, 'wh6a-in');
  await fx.destinations(inA, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  orgB = await fx.organization('wh6b');
  inB = await fx.domain(orgB, 'wh6b-in');
  await fx.destinations(inB, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.feature(orgA, 'webhooks', true);
  await fx.feature(orgB, 'webhooks', true);
  const refA = await organizationRef(fx, orgA);
  const refB = await organizationRef(fx, orgB);
  orgAPublicId = refA.publicId;
  orgBPublicId = refB.publicId;
  adminA = await apiSession(fx.prisma, refA, 'organization_admin');
  analystA = await apiSession(fx.prisma, refA, 'security_analyst');
  adminB = await apiSession(fx.prisma, refB, 'organization_admin');

  const policy = await createAndPublishPolicy(adminA, adminA, 'WH6 rules', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'wh6-hold',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.hold },
        actions: [{ type: 'QUARANTINE' }],
      },
      {
        id: 'wh6-reject',
        priority: 20,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.rej },
        actions: [{ type: 'REJECT' }],
      },
    ],
  });
  holdPolicyId = policy.policyId;
}, 600_000);

afterAll(async () => {
  if (gate.skip) return;
  // Soft-delete the subscriptions first (pending deliveries cancelled, the fanout stops
  // matching within its cache TTL), then remove every row of the fixture organizations.
  for (const [session, hook] of [
    [adminA, hooks.all],
    [adminA, hooks.high],
    [adminA, hooks.retry],
    [adminB, hooks.allB],
  ] as const) {
    if (session && hook) {
      const res = await session.delete(`/webhooks/${hook.id}`, idempotencyKey());
      expect(res.status, `DELETE /webhooks/${hook.id}`).toBe(204);
    }
  }
  await sleep(6_000);
  for (const session of [adminA, analystA, adminB]) await session?.remove();
  const names = [inA, inB].filter(Boolean).map((d) => d.name);
  for (const service of ['postfix-outbound', 'postfix'] as const) {
    const queued = involving(await listQueue(service), names);
    await deleteQueued(
      service,
      queued.map((m) => m.queue_id),
    );
  }
  for (const domain of names) await clearSinkDomain(domain, 'all').catch(() => undefined);
  const removed = [orgA, orgB].filter((id) => id !== 0n);
  await fx.cleanup();
  await purgeDormantQueues();
  if (removed.length === 0) return;
  const { PrismaClient } = await import('@email-gateway/database');
  const prisma = new PrismaClient({ datasourceUrl: process.env.DATABASE_URL });
  try {
    expect(await webhookRowCounts(prisma, removed)).toEqual({
      subscriptions: 0,
      events: 0,
      deliveries: 0,
      attempts: 0,
      replays: 0,
      alertWindows: 0,
      settings: 0,
    });
    expect(await prisma.organization.count({ where: { id: { in: removed } } })).toBe(0);
  } finally {
    await prisma.$disconnect();
  }
}, 600_000);

describe.skipIf(gate.skip)(
  'webhooks stack: SMTP → events → signed deliveries',
  { timeout: 900_000 },
  () => {
    it('(1) subscriptions through the api: secret once, redacted idempotent replay, receiver programmed', async () => {
      hooks.all = await createWebhook(adminA!, {
        name: 'WH6 all events',
        path: path('a', 'all'),
        eventTypes: [...ALL_EVENT_TYPES],
      });
      hooks.high = await createWebhook(adminA!, {
        name: 'WH6 high severity',
        path: path('a', 'high'),
        eventTypes: ['email.scanned', 'email.threat.detected'],
        filters: { minSeverity: 'high' },
      });
      hooks.retry = await createWebhook(adminA!, {
        name: 'WH6 retry',
        path: path('a', 'retry'),
        eventTypes: ['email.received'],
      });
      hooks.allB = await createWebhook(adminB!, {
        name: 'WH6 org B',
        path: path('b', 'all'),
        eventTypes: [...ALL_EVENT_TYPES],
      });
      // The first email.received of the retry endpoint answers 503 + Retry-After: 2, then 200.
      await programReceiver(hooks.retry.path, [{ status: 503, retryAfter: 2, body: 'busy' }], 200);

      // ADR-0057: the same Idempotency-Key replays the creation without the secret.
      const replay = await adminA!.post(
        '/webhooks',
        { name: 'WH6 all events', url: hooks.all.url, eventTypes: [...ALL_EVENT_TYPES] },
        { 'Idempotency-Key': hooks.all.idempotencyKey },
      );
      expect(replay.status).toBe(201);
      expect(replay.headers.get('idempotency-replayed')).toBe('true');
      expect(replay.body).toMatchObject({ id: hooks.all.id, secret: null });
      expect(JSON.stringify(replay.body)).not.toContain('whsec_');

      // GET never shows the secret; organization B cannot see A's webhook.
      const got = await adminA!.get(`/webhooks/${hooks.all.id}`);
      expect(got.status).toBe(200);
      expect(got.body).toMatchObject({ id: hooks.all.id, status: 'active', secretVersion: 1 });
      expect(JSON.stringify(got.body)).not.toMatch(/whsec_|secretCiphertext/);
      expect((await adminB!.get(`/webhooks/${hooks.all.id}`)).status).toBe(404);
      const list = await adminA!.get('/webhooks');
      expect((list.body as { data: { id: string }[] }).data.map((w) => w.id).sort()).toEqual(
        [hooks.all.id, hooks.high.id, hooks.retry.id].sort(),
      );
      // The fanout caches the subscription index for WEBHOOK_SUBSCRIPTION_CACHE_SECONDS (5 s).
      await sleep(6_000);
    });

    it('(2) clean inbound mail: email.received, email.scanned, email.delivered', async () => {
      expect(hooks.all, 'case 1 ran').toBeDefined();
      msgs.clean = await inbound(orgA, `${LP.clean}@${inA.name}`, cleanEml());
      await waitForLifecycle(fx.prisma, msgs.clean, 'delivered', undefined, 240_000);
      const events = await eventsOf(msgs.clean, [
        'email.received',
        'email.scanned',
        'email.delivered',
      ]);
      const received = one(events, 'email.received');
      expect(received.envelope).toMatchObject({
        type: 'email.received',
        version: 1,
        organizationId: orgAPublicId,
        data: {
          message: {
            id: msgs.clean.publicId,
            direction: 'inbound',
            domainId: inA.publicId,
            senderDomain: 'clean.scan.test',
            recipientCount: 1,
            recipientDomains: [inA.name],
          },
        },
      });
      const scanned = one(events, 'email.scanned');
      expect(scanned.envelope.data).toMatchObject({
        scan: { lifecycleRound: 0, kind: 'initial', outcome: 'scanned', verdict: 'clean' },
      });
      const delivered = one(events, 'email.delivered');
      expect(delivered.envelope.data).toMatchObject({
        delivery: { outcome: 'complete', lifecycleRound: 0, recipients: { delivered: 1 } },
      });
      // occurredAt is the source event's time, so the id is deterministic per source (W3).
      expect(new Date(received.envelope.occurredAt).getTime()).toBeLessThanOrEqual(
        new Date(delivered.envelope.occurredAt).getTime(),
      );
      record('webhooks-smtp', { clean: events.map((r) => r.eventType).join(',') });
    });

    it('(3) EICAR: email.threat.detected (malicious, high) and email.rejected; the minSeverity filter passes only high events', async () => {
      const built = attachmentMessage({
        from: `Alice <${SENDER}>`,
        to: [`${LP.eicar}@${inA.name}`],
        subject: `${SUBJECT_TOKEN} EICAR`,
        attachments: [{ filename: EICAR_FILE, contentType: 'text/plain', bytes: eicar() }],
      });
      msgs.eicar = await inbound(orgA, `${LP.eicar}@${inA.name}`, built.text);
      await waitForLifecycle(fx.prisma, msgs.eicar, 'rejected', undefined, 240_000);
      const events = await eventsOf(msgs.eicar, [
        'email.received',
        'email.scanned',
        'email.threat.detected',
        'email.rejected',
      ]);
      const threat = one(events, 'email.threat.detected');
      expect(threat.envelope.data).toMatchObject({
        message: { id: msgs.eicar.publicId },
        detection: { stage: 'scan', verdict: 'malicious', lifecycleRound: 0, attachment: null },
      });
      const rejected = one(events, 'email.rejected');
      const rejection = (rejected.envelope.data as { rejection: { reason: string; stage: string } })
        .rejection;
      expect(rejection.stage).toBe('policy');
      expect(['policy_discard', 'policy_reject']).toContain(rejection.reason);
      // No tenant rule matched the EICAR recipient: no email.policy.triggered.
      expect(ofType(events, 'email.policy.triggered')).toEqual([]);

      // The high-severity subscription: the EICAR scan and threat events, nothing of the clean message.
      const high = await waitForRequests(
        hooks.high!.path,
        'the high-severity events of the EICAR message',
        (r) =>
          ofType(ofMessage(r, msgs.eicar!.publicId), 'email.threat.detected').length > 0 &&
          ofType(ofMessage(r, msgs.eicar!.publicId), 'email.scanned').length > 0,
      );
      expect(ofMessage(high, msgs.clean!.publicId)).toEqual([]);
      for (const r of high) {
        expect(['email.scanned', 'email.threat.detected']).toContain(r.eventType);
        expect(r.envelope.data.message?.id).toBe(msgs.eicar.publicId);
      }
      record('webhooks-smtp', { eicar_rejection: rejection.reason });
    });

    it('(4) tenant QUARANTINE rule: email.policy.triggered and email.quarantined; a release through the api: email.released and a second email.delivered', async () => {
      msgs.hold = await inbound(orgA, `${LP.hold}@${inA.name}`, cleanEml());
      const entries = await waitForEntries(fx.prisma, msgs.hold, 1);
      await waitForLifecycle(fx.prisma, msgs.hold, 'quarantined', 'policy_quarantine', 240_000);
      const events = await eventsOf(msgs.hold, [
        'email.received',
        'email.scanned',
        'email.policy.triggered',
        'email.quarantined',
      ]);
      const triggered = one(events, 'email.policy.triggered');
      expect(triggered.envelope.data).toMatchObject({
        policy: {
          disposition: 'quarantine',
          decisionSource: 'tenant_rule',
          decisive: { policyId: holdPolicyId, versionNo: 1, ruleId: 'wh6-hold' },
          matchedRules: [{ policyId: holdPolicyId, versionNo: 1, ruleId: 'wh6-hold' }],
          lifecycleRound: 0,
        },
      });
      const quarantined = one(events, 'email.quarantined');
      expect(quarantined.envelope.data).toMatchObject({
        quarantine: {
          origin: 'policy',
          lifecycleRound: 0,
          entryCount: 1,
          kinds: { quarantine: 1, review: 0 },
          entryIds: [entries[0]!.publicId],
        },
      });

      const res = await postIdem(
        analystA!,
        `/quarantine/entries/${entries[0]!.publicId}/release`,
        { reason: 'webhook stack release' },
        'wh6-release',
      );
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      releaseId = (res.body as { releaseId: string }).releaseId;
      const [log] = await waitForReleaseOutcome(fx.prisma, releaseId);
      // Never delivered before: the release is the message's first delivery (sequence 0).
      expect(log).toMatchObject({ status: 'dispatched', deliverySeq: 0 });
      const after = await waitForRequests(
        hooks.all!.path,
        'email.released and the round-1 email.delivered',
        (r) => {
          const own = ofMessage(r, msgs.hold!.publicId);
          return (
            ofType(own, 'email.released').length > 0 &&
            ofType(own, 'email.delivered').some(
              (d) =>
                (d.envelope.data as { delivery: { lifecycleRound: number } }).delivery
                  .lifecycleRound === 1,
            )
          );
        },
        300_000,
      );
      const released = one(ofMessage(after, msgs.hold.publicId), 'email.released');
      expect(released.envelope.data).toMatchObject({
        release: {
          releaseId,
          mode: 'operator',
          entryIds: [entries[0]!.publicId],
          recipientCount: 1,
          deliverySeq: 0,
        },
      });
      record('webhooks-smtp', { released: releaseId });
    });

    it('(5) tenant REJECT rule: email.policy.triggered and email.rejected', async () => {
      msgs.rej = await inbound(orgA, `${LP.rej}@${inA.name}`, cleanEml());
      await waitForLifecycle(fx.prisma, msgs.rej, 'rejected', undefined, 240_000);
      const events = await eventsOf(msgs.rej, ['email.policy.triggered', 'email.rejected']);
      expect(one(events, 'email.policy.triggered').envelope.data).toMatchObject({
        policy: {
          disposition: 'reject',
          decisive: { policyId: holdPolicyId, ruleId: 'wh6-reject' },
        },
      });
      const rejection = (
        one(events, 'email.rejected').envelope.data as {
          rejection: { reason: string; stage: string };
        }
      ).rejection;
      expect(rejection).toMatchObject({ stage: 'policy' });
      expect(['policy_reject', 'policy_discard']).toContain(rejection.reason);
      expect(ofType(events, 'email.quarantined')).toEqual([]);
      record('webhooks-smtp', { tenant_reject: rejection.reason });
    });

    it('(6) organization B gets its own events only; A never sees B', async () => {
      msgs.b = await inbound(orgB, `${LP.b}@${inB.name}`, cleanEml());
      const own = await eventsOf(
        msgs.b,
        ['email.received', 'email.scanned', 'email.delivered'],
        hooks.allB!.path,
      );
      expect(own.length).toBeGreaterThanOrEqual(3);
      const bAll = await receivedRequests(hooks.allB!.path);
      const aIds = [msgs.clean, msgs.eicar, msgs.hold, msgs.rej].map((m) => m!.publicId);
      for (const r of bAll) {
        expect(r.envelope.organizationId).toBe(orgBPublicId);
        expect(aIds).not.toContain(r.envelope.data.message?.id);
        expect(r.headers['eg-subscription-id']).toBe(hooks.allB!.id);
      }
      for (const p of [hooks.all!.path, hooks.high!.path, hooks.retry!.path]) {
        for (const r of await receivedRequests(p)) {
          expect(r.envelope.organizationId).toBe(orgAPublicId);
          expect(r.envelope.data.message?.id).not.toBe(msgs.b.publicId);
        }
      }
      // The api answers B's principal like a missing resource for A's subscription and delivery.
      const anyA = (await receivedRequests(hooks.all!.path))[0]!;
      expect(
        (await adminB!.get(`/webhooks/${hooks.all!.id}/deliveries/${anyA.deliveryId}`)).status,
      ).toBe(404);
      expect(
        (await adminB!.get(`/webhooks/${hooks.allB!.id}/deliveries/${anyA.deliveryId}`)).status,
      ).toBe(404);
      record('webhooks-smtp', { org_b_requests: bAll.length });
    });

    it('(7) every request: signature valid at the receiver and with verifyWebhookSignature, exact headers, metadata only', async () => {
      const all = [
        { hook: hooks.all!, org: orgAPublicId },
        { hook: hooks.high!, org: orgAPublicId },
        { hook: hooks.retry!, org: orgAPublicId },
        { hook: hooks.allB!, org: orgBPublicId },
      ];
      let checked = 0;
      for (const { hook, org } of all) {
        for (const r of await receivedRequests(hook.path)) {
          expect(r.signatureValid, `${hook.path} ${r.eventType}`).toBe(true);
          expect(verifyReceived(r, [hook.secret])).toEqual({ ok: true });
          // Another subscription's secret never verifies it.
          const other = all.find((x) => x.hook !== hook)!.hook.secret;
          expect(verifyReceived(r, [other]).ok).toBe(false);
          expect(headerProblems(r, hook.id), `${hook.path} ${r.eventType}`).toEqual([]);
          expect(payloadProblems(r, org, forbidden()), `${hook.path} ${r.eventType}`).toEqual([]);
          checked += 1;
        }
      }
      expect(checked).toBeGreaterThanOrEqual(20);
      record('webhooks-smtp', { requests_checked: checked });
    });

    it('(8) retries: 503 + Retry-After then 200 → succeeded with 2 attempts in the delivery history', async () => {
      const requests = await waitForRequests(
        hooks.retry!.path,
        'the retried first delivery',
        (r) => r.length >= 2 && r.some((x) => x.attempt === 2 && x.deliveryId === r[0]!.deliveryId),
        240_000,
      );
      const first = requests[0]!;
      const second = requests.find((x) => x.attempt === 2 && x.deliveryId === first.deliveryId)!;
      expect(first.attempt).toBe(1);
      expect(second.eventId).toBe(first.eventId);
      expect(second.body.equals(first.body)).toBe(true);
      expect(second.receivedAt.getTime() - first.receivedAt.getTime()).toBeGreaterThanOrEqual(
        2_000,
      );
      const detail = await waitFor(
        'the retried delivery recorded as succeeded',
        async () => {
          const d = await deliveryDetail(adminA!, hooks.retry!.id, first.deliveryId);
          return d.status === 'succeeded' ? d : undefined;
        },
        { timeoutMs: 60_000, intervalMs: 1_000 },
      );
      expect(detail).toMatchObject({
        id: first.deliveryId,
        eventId: first.eventId,
        eventType: 'email.received',
        trigger: 'event',
        deliverySeq: 0,
        attemptCount: 2,
        lastResponseCode: 200,
      });
      expect(
        detail.attempts.map((a) => [a.attemptNo, a.outcome, a.httpStatus, a.retryAfterSeconds]),
      ).toEqual([
        [1, 'http_error', 503, 2],
        [2, 'succeeded', 200, null],
      ]);
      expect(detail.attempts[0]!.signatureCount).toBe(1);
      expect(detail.event?.id).toBe(first.eventId);
      record('webhooks-smtp', {
        retry_gap_ms: second.receivedAt.getTime() - first.receivedAt.getTime(),
      });
    });

    it('(9) replays: a single delivery and a time range re-send the stored envelope with the same EG-Event-Id', async () => {
      const before = await receivedRequests(hooks.all!.path);
      const originals = ofType(before, 'email.received').filter((r) => r.attempt === 1);
      expect(originals.length).toBeGreaterThanOrEqual(4);

      // Single delivery replay.
      const target = originals[0]!;
      const single = await adminA!.post(
        `/webhooks/${hooks.all!.id}/deliveries/${target.deliveryId}/replay`,
        {},
        idempotencyKey(),
      );
      expect(single.status, JSON.stringify(single.body)).toBe(202);
      const singleId = (single.body as { deliveryId: string }).deliveryId;
      expect(singleId).not.toBe(target.deliveryId);
      const afterSingle = await waitForRequests(hooks.all!.path, 'the single replay', (r) =>
        r.some((x) => x.deliveryId === singleId),
      );
      const replayed = afterSingle.find((x) => x.deliveryId === singleId)!;
      expect(replayed.eventId).toBe(target.eventId);
      expect(replayed.body.equals(target.body)).toBe(true);
      expect(replayed.headers['eg-signature']).not.toBe(target.headers['eg-signature']);
      const singleDetail = await deliveryDetail(adminA!, hooks.all!.id, singleId);
      expect(singleDetail).toMatchObject({ trigger: 'replay', deliverySeq: 1 });

      // Range replay of the succeeded email.received deliveries since the suite started.
      const range = await adminA!.post(
        `/webhooks/${hooks.all!.id}/replays`,
        {
          from: new Date(suiteStart.getTime() - 60_000).toISOString(),
          to: new Date(Date.now() + 60_000).toISOString(),
          statuses: ['succeeded'],
          eventTypes: ['email.received'],
        },
        idempotencyKey(),
      );
      expect(range.status, JSON.stringify(range.body)).toBe(202);
      const replayId = (range.body as { replayId: string }).replayId;
      const done = await waitFor(
        'the range replay completed',
        async () => {
          const res = await adminA!.get(`/webhooks/${hooks.all!.id}/replays/${replayId}`);
          const body = res.body as { status: string };
          return body.status === 'completed' || body.status === 'failed' ? body : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 1_000 },
      );
      expect(done).toMatchObject({
        status: 'completed',
        matchedCount: originals.length,
        createdCount: originals.length,
        truncated: false,
      });
      const originalIds = new Set(originals.map((r) => r.eventId));
      const knownDeliveries = new Set(afterSingle.map((r) => r.deliveryId));
      const after = await waitForRequests(hooks.all!.path, 'the range replay deliveries', (r) => {
        const fresh = r.filter(
          (x) => !knownDeliveries.has(x.deliveryId) && x.eventType === 'email.received',
        );
        return new Set(fresh.map((x) => x.eventId)).size >= originals.length;
      });
      const fresh = after.filter(
        (x) => !knownDeliveries.has(x.deliveryId) && x.eventType === 'email.received',
      );
      for (const r of fresh) {
        expect(originalIds.has(r.eventId), 'replayed event id is an original one').toBe(true);
        const original = originals.find((o) => o.eventId === r.eventId)!;
        expect(r.body.equals(original.body)).toBe(true);
        expect(r.signatureValid).toBe(true);
        expect(verifyReceived(r, [hooks.all!.secret])).toEqual({ ok: true });
      }
      record('webhooks-smtp', { range_replay: `${done.status}:${fresh.length}` });
    });
  },
);
