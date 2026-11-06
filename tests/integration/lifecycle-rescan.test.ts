import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { eventually, ManagementApi, purgeDormantQueues } from './support/broker';
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
  engineResultsOf,
  REQUIRED_ENGINES,
  RSPAMD_LEDGER,
  scanRoundsOf,
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
 * binds it to FOUR scan queues: the dormant `scan.dlp` holds exactly one copy (peeked through the
 * management API, then purged); `scan.spam`, (since v4) `scan.attachment` and (since v5, step 4.3
 * U2) `scan.url` are consumed by the email-worker scan role, which scans round 1 with the three
 * required engines (Rspamd; the attachment engine `skipped`, `attachment.none`; the URL engine
 * `skipped`, `url.none`: the fixture has no stored body) and completes it (`scanned`), after which
 * the dev pass-through approves round 1 and the message is delivered. `scan.auth` lost its event
 * bindings in v3 and receives nothing.
 */
const DORMANT_SCAN_QUEUES = ['scan.dlp'];
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
  it('lands one rescan request in each dormant scan queue; scan.spam scans round 1 and the message is delivered', async () => {
    const message = await insertFixtureMessage(fx, {
      organizationId: scenario.org,
      domainId: scenario.domain.id,
      state: 'scan_failed',
      recipients: [`scan@${scenario.domain.name}`],
      subject: 'Lifecycle rescan',
    });
    // Nothing else of this run is in the dormant queues.
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

    // The relay publishes the request; one copy per dormant scan queue, none elsewhere.
    await eventually(
      async () => {
        const depths = await Promise.all(DORMANT_SCAN_QUEUES.map((q) => mgmt.queue(vhost, q)));
        return depths.every((d) => d.messages === 1);
      },
      30_000,
      'one rescan request in each dormant scan queue',
      250,
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
      const [copy] = await mgmt.peek(vhost, queue, 1);
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
      expect((await mgmt.queue(vhost, queue)).messages).toBe(1);
    }
    // Not bound to scan.auth (v3), the sandbox, quarantine or policy queues. The dormant
    // `email.policy.evaluate` (bound to `scanned.v1` for step 5.2) may already hold the
    // `scanned.v1` of round 1 below, but never the rescan request itself.
    for (const queue of ['scan.auth', 'scan.sandbox', 'email.quarantine']) {
      expect((await mgmt.queue(vhost, queue)).messages, queue).toBe(0);
    }
    const policy = await mgmt.peek(vhost, 'email.policy.evaluate', 20);
    expect(policy.map((m) => m.routingKey)).not.toContain(
      `org.${scenario.org.toString()}.mail.message.rescan_requested.v1`,
    );

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
    for (const consumer of [RSPAMD_LEDGER, ATTACHMENT_LEDGER]) {
      expect(
        await fx.prisma.messageIdempotency.count({
          where: { consumer, eventId: rescanEventId },
        }),
        consumer,
      ).toBe(1);
    }
    const finals = (await engineResultsOf(fx.prisma, message)).filter((r) => r.isFinal);
    expect(finals.map((r) => r.engine).sort()).toEqual(['attachment', 'rspamd', 'url']);
    expect(finals.find((r) => r.engine === 'attachment')).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['attachment.none'],
    });
    expect(finals.find((r) => r.engine === 'url')).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['url.none'],
    });
    for (const queue of ['scan.spam', 'scan.attachment', 'scan.url']) {
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

    const depths = await purgeDormantQueues(mgmt, vhost);
    for (const queue of DORMANT_SCAN_QUEUES) expect(depths[queue]).toBe(1);
    // Queue statistics refresh every few seconds: wait for the purge to show.
    await eventually(
      async () =>
        (await Promise.all(DORMANT_SCAN_QUEUES.map((q) => mgmt.queue(vhost, q)))).every(
          (d) => d.messages === 0,
        ),
      20_000,
      'the scan queues empty after the purge',
      500,
    );

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
      dormant_scan_queues_with_one_copy: DORMANT_SCAN_QUEUES.length,
      round1_verdict: round.scanVerdict,
    });
  });
});
