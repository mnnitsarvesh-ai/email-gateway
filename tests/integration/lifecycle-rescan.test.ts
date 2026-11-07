import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { copiesOfEvent, eventually, ManagementApi, purgeDormantQueues } from './support/broker';
import { stack } from './support/env';
import {
  expectConsistentHistory,
  historyOf,
  insertFixtureMessage,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { MessagingScenario } from './support/messaging-scenario';
import {
  ATTACHMENT_LEDGER,
  BEC_LEDGER,
  becResultsOf,
  DLP_LEDGER,
  dlpResultsOf,
  engineResultsOf,
  REQUIRED_ENGINES,
  RSPAMD_LEDGER,
  scanRoundsOf,
  stageReadyEventsOf,
  URL_LEDGER,
  waitForRoundComplete,
} from './support/scan-stack';
import { messagingStackGate, record } from './support/messaging-stack';
import { organizationRef } from './support/routing';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Administrative rescan through the LIVE api, relay, broker and scan stage (docs/plan/steps/
 * 08-message-lifecycle.md L10.2, §9 "Stack"; the scan stage of step 4.1, docs/plan/steps/
 * 09-rspamd.md S2, S14, and topology v4 of step 4.2, 10-attachment-scanning.md A1/A2). A stored
 * message in `scan_failed` (fixture, L8.6, with its parse row and no attachments) is rescanned
 * with `POST /api/v1/messages/{id}/rescan`: E19 moves it to `scanning` with round + 1 and writes
 * `mail.message.rescan_requested.v1`, which the relay publishes to `email.security`. The topology
 * binds it to FOUR scan queues, all consumed by the email-worker scan role since topology v7:
 * `scan.spam`, (since v4) `scan.attachment`, (since v5, step 4.3 U2) `scan.url` and (since v7,
 * step 4.5 D2) `scan.dlp`. The scan role scans round 1 with the stage-1 engines (Rspamd; the
 * attachment engine `skipped`, `attachment.none`; the URL engine `skipped`, `url.none`: the
 * fixture has no stored body; the DLP engine `skipped`, `dlp.not_inbound`: the fixture is
 * inbound) and completes it (`scanned`), after which the dev pass-through approves round 1 and
 * the message is delivered. `scan.auth` lost its event bindings in v3 and receives nothing.
 *
 * Step 4.5 (D2): `scan.dlp` was the last dormant scan queue bound to the request and is a work
 * queue now, so the exactly-one-copy assertion moves to where the request still rests without a
 * consumer: the `email.events` → `email.analytics` firehose (dormant, `org.#`) holds exactly one
 * copy of it (peeked through the management API, then purged); the dlp consumer
 * (`email-worker.scan.dlp`) handles the request exactly once (one ledger row) and writes round
 * 1's dlp final and `dlp_scan_results` row. The dormant `scan.sandbox` and the other non-scan
 * dormant queues never receive it.
 *
 * Step 4.4 (B2, B3): round 1 also requires the stage-2 `bec` engine; `scan.bec` binds only
 * `scan_stage_ready.v1`, so it gets NO copy of the rescan request: the transaction that inserts
 * the last of round 1's rspamd/url finals writes the round's stage trigger, and the bec consumer
 * finalizes round 1 with a new `bec_scan_results` row.
 *
 * Timing (step 4.4 §9, 4.3 §13.10): the dormant queues are shared with every other suite, whose
 * late traffic may still arrive after a purge. The suite therefore never asserts a queue depth:
 * it inspects the queues without losing messages (management `get` with requeue) and asserts
 * exactly one message with THIS run's rescan event id in each dormant queue the request is bound
 * to, none with that id in any other dormant queue, and that its own message is gone after the
 * purge.
 */
/**
 * Dormant queues bound to the rescan request (v7: none of the scan queues; the analytics
 * firehose through `email.events`).
 */
const DORMANT_SCAN_QUEUES = ['email.analytics'];
/** Dormant queues that must never receive the rescan request (v3+: scan.auth unbound). */
const NOT_BOUND_QUEUES = ['scan.auth', 'scan.sandbox', 'email.quarantine', 'email.policy.evaluate'];
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('lifecycle-rescan', fx);
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
let session: ApiSession | undefined;

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('lc-rescan');
  session = await apiSession(
    fx.prisma,
    await organizationRef(fx, scenario.org),
    'security_analyst',
  );
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await session?.remove();
  await scenario.teardown(); // purges the dormant queues (L16)
}, 300_000);

describe.skipIf(gate.skip)('lifecycle stack: administrative rescan', { timeout: 300_000 }, () => {
  it('lands one rescan request in the dormant firehose and none in scan.sandbox; the five engines scan round 1 (dlp included) and the message is delivered', async () => {
    const message = await insertFixtureMessage(fx, {
      organizationId: scenario.org,
      domainId: scenario.domain.id,
      state: 'scan_failed',
      recipients: [`scan@${scenario.domain.name}`],
      subject: 'Lifecycle rescan',
    });
    // Older traffic out of the way (not required for the assertions below, which only count
    // this run's event id; late copies of other suites may still arrive).
    await purgeDormantQueues(mgmt, vhost);

    const res = await session!.post(
      `/messages/${message.publicId}/rescan`,
      { expectedVersion: message.version, reason: 'stack test: scan engines recovered' },
      { 'Idempotency-Key': `it-rescan-${fx.suffix}` },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({
      messageId: message.publicId,
      state: 'scanning',
      version: 3,
      lifecycleRound: 1,
    });
    const rescanEventId = (res.body as { rescanEventId: string }).rescanEventId;
    expect(rescanEventId).toMatch(/^[0-9a-f-]{36}$/);
    // The E19 row (version 3, round 1); the scan stage may already have moved on since step 4.1.
    const history = (await historyOf(fx.prisma, message)).filter((h) => h.version <= 3);
    expect(history.at(-1)).toMatchObject({
      fromStatus: 'scan_failed',
      toStatus: 'scanning',
      reasonCode: 'admin_rescan',
      lifecycleRound: 1,
      actorRole: 'operator',
      actorType: 'user',
      actorId: session!.userPublicId,
    });
    await expectConsistentHistory(fx.prisma, message);

    // The relay publishes the request; one copy in the dormant firehose, none elsewhere.
    await eventually(
      async () => {
        const copies = await Promise.all(
          DORMANT_SCAN_QUEUES.map((q) => copiesOfEvent(mgmt, vhost, q, rescanEventId)),
        );
        return copies.every((n) => n >= 1);
      },
      30_000,
      'the rescan request in the dormant firehose',
      500,
    );
    // The relay marks the row after the broker confirm, so the copies can be visible first.
    await eventually(
      async () =>
        (
          await fx.prisma.messageOutbox.findFirstOrThrow({
            where: { organizationId: scenario.org, eventId: rescanEventId },
          })
        ).publishedAt !== null,
      30_000,
      'the rescan outbox row to be marked published',
      250,
    );
    const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: { organizationId: scenario.org, eventId: rescanEventId },
    });
    expect(outbox.eventType).toBe('mail.message.rescan_requested.v1');
    expect(outbox.publishedAt).not.toBeNull();
    for (const queue of DORMANT_SCAN_QUEUES) {
      // Exactly one copy of this run's request, whatever else the queue holds.
      const depth = (await mgmt.queue(vhost, queue)).messages;
      const ours = (await mgmt.peek(vhost, queue, depth + 200)).filter(
        (m) => (JSON.parse(m.payload) as { eventId?: string }).eventId === rescanEventId,
      );
      expect(ours, queue).toHaveLength(1);
      const copy = ours[0];
      expect(copy!.routingKey).toBe(
        `org.${scenario.org.toString()}.mail.message.rescan_requested.v1`,
      );
      const envelope = JSON.parse(copy!.payload) as {
        eventId: string;
        eventType: string;
        payload: { messageId: string; lifecycleRound: number; scanKind: string; emlS3Key: string };
      };
      expect(envelope).toMatchObject({
        eventId: rescanEventId,
        eventType: 'mail.message.rescan_requested.v1',
        payload: {
          messageId: message.id.toString(),
          lifecycleRound: 1,
          scanKind: 'rescan',
          emlS3Key: message.emlObjectKey,
        },
      });
      // Peeking requeued it: still exactly one.
      expect(await copiesOfEvent(mgmt, vhost, queue, rescanEventId), queue).toBe(1);
    }
    // Not bound to scan.auth (v3), the sandbox, quarantine or policy queues (the dormant
    // `email.policy.evaluate` is bound to `scanned.v1` for step 5.2 and may hold round 1's
    // `scanned.v1`, but never the rescan request itself).
    for (const queue of NOT_BOUND_QUEUES) {
      expect(await copiesOfEvent(mgmt, vhost, queue, rescanEventId), queue).toBe(0);
    }

    // scan.spam and scan.attachment: the scan role consumed both copies (one ledger row per
    // engine consumer for the rescan event), opened
    // round 1 (`rescan`) and completed it; the pass-through approved round 1 and it was
    // delivered (E19 → E6 → E27 → E20 → E23).
    const round = await waitForRoundComplete(fx.prisma, message, 1);
    expect(round).toMatchObject({
      scanKind: 'rescan',
      status: 'completed',
      triggerEventId: rescanEventId,
      requiredEngines: [...REQUIRED_ENGINES],
    });
    expect(await scanRoundsOf(fx.prisma, message)).toHaveLength(1);
    for (const consumer of [RSPAMD_LEDGER, ATTACHMENT_LEDGER, URL_LEDGER, DLP_LEDGER]) {
      expect(
        await fx.prisma.messageIdempotency.count({
          where: { consumer, eventId: rescanEventId },
        }),
        consumer,
      ).toBe(1);
    }
    // Step 4.5 (D2): the dlp consumer took the rescan request exactly once and finalized round 1
    // (inbound fixture: `skipped`, `dlp.not_inbound`) with exactly one dlp_scan_results row.
    const dlpRows = await dlpResultsOf(fx.prisma, message);
    expect(dlpRows.map((r) => [r.lifecycleRound, r.scanId, r.verdict, r.action])).toEqual([
      [1, round.id, 'skipped', 'allow'],
    ]);
    // Step 4.4: scan.bec got no copy of the request (no ledger row of the bec consumer for it);
    // round 1's own stage trigger reached it exactly once and bec finalized round 1.
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: BEC_LEDGER, eventId: rescanEventId },
      }),
    ).toBe(0);
    const stage = await stageReadyEventsOf(fx.prisma, scenario.org, message);
    expect(stage).toHaveLength(1);
    expect(stage[0]!.payload).toMatchObject({
      lifecycleRound: 1,
      scanId: round.id.toString(),
      scanKind: 'rescan',
      engine: 'bec',
    });
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: BEC_LEDGER, eventId: stage[0]!.eventId },
      }),
    ).toBe(1);
    const becRows = await becResultsOf(fx.prisma, message);
    expect(becRows.map((r) => [r.lifecycleRound, r.scanId])).toEqual([[1, round.id]]);
    const finals = (await engineResultsOf(fx.prisma, message)).filter((r) => r.isFinal);
    expect(finals.map((r) => r.engine).sort()).toEqual([
      'attachment',
      'bec',
      'dlp',
      'rspamd',
      'url',
    ]);
    expect(finals.filter((r) => r.engine === 'dlp')).toEqual([
      expect.objectContaining({
        scanId: round.id,
        outcome: 'skipped',
        reasonCodes: ['dlp.not_inbound'],
      }),
    ]);
    expect(finals.find((r) => r.engine === 'attachment')).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['attachment.none'],
    });
    expect(finals.find((r) => r.engine === 'url')).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['url.none'],
    });
    for (const queue of ['scan.spam', 'scan.attachment', 'scan.url', 'scan.bec', 'scan.dlp']) {
      expect((await mgmt.queue(vhost, queue)).messages, queue).toBe(0);
    }
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await pathOf(fx.prisma, message)).toEqual([
      [null, 'received', 'smtp_accepted'],
      ['received', 'persisted', 'committed'],
      ['persisted', 'scan_failed', 'scan_error'],
      ['scan_failed', 'scanning', 'admin_rescan'],
      ['scanning', 'scanned', 'scan_complete'],
      ['scanned', 'approved', 'dev_passthrough'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_complete'],
    ]);
    expect((await historyOf(fx.prisma, message)).slice(3).map((h) => h.lifecycleRound)).toEqual([
      1, 1, 1, 1, 1,
    ]);
    await expectConsistentHistory(fx.prisma, message);

    // Just before the purge, still exactly one copy of this run's request per dormant queue.
    for (const queue of DORMANT_SCAN_QUEUES) {
      expect(await copiesOfEvent(mgmt, vhost, queue, rescanEventId), queue).toBe(1);
    }
    const depths = await purgeDormantQueues(mgmt, vhost);
    for (const queue of DORMANT_SCAN_QUEUES) expect(depths[queue]).toBeGreaterThanOrEqual(1);
    // The run's own request is gone after the purge (other suites' late copies may arrive).
    for (const queue of [...DORMANT_SCAN_QUEUES, ...NOT_BOUND_QUEUES]) {
      expect(await copiesOfEvent(mgmt, vhost, queue, rescanEventId), queue).toBe(0);
    }

    // A second rescan with a stale version is refused without a second request.
    const stale = await session!.post(
      `/messages/${message.publicId}/rescan`,
      { expectedVersion: message.version, reason: 'stack test: stale version on purpose' },
      { 'Idempotency-Key': `it-rescan-${fx.suffix}-stale` },
    );
    expect(stale.status).toBe(409);
    const current = await lifecycleOf(fx.prisma, message);
    expect(stale.body).toMatchObject({
      code: 'message_version_conflict',
      currentVersion: current.version,
    });
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: scenario.org, eventType: 'mail.message.rescan_requested.v1' },
      }),
    ).toBe(1);
    record('lifecycle-rescan', {
      dormant_queues_with_one_copy: DORMANT_SCAN_QUEUES.length,
      round1_verdict: round.scanVerdict,
    });
  });
});
