import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { eventually, ManagementApi, purgeDormantQueues } from './support/broker';
import { stack } from './support/env';
import {
  expectConsistentHistory,
  historyOf,
  insertFixtureMessage,
  lifecycleOf,
} from './support/lifecycle';
import { MessagingScenario } from './support/messaging-scenario';
import { messagingStackGate, record } from './support/messaging-stack';
import { organizationRef } from './support/routing';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Administrative rescan through the LIVE api, relay and broker (docs/plan/steps/
 * 08-message-lifecycle.md L10.2, L7 topology v2, §9 "Stack"). A stored message in `scan_failed`
 * (fixture, L8.6) is rescanned with `POST /api/v1/messages/{id}/rescan`: E19 moves it to
 * `scanning` with round + 1 and writes `mail.message.rescan_requested.v1`, which the relay
 * publishes to `email.security`; topology v2 binds it to the five dormant scan queues
 * (`scan.auth`, `scan.spam`, `scan.url`, `scan.attachment`, `scan.dlp`) and nothing else. Each
 * queue holds exactly one copy (peeked through the management API, then purged).
 */
const SCAN_QUEUES = ['scan.auth', 'scan.spam', 'scan.url', 'scan.attachment', 'scan.dlp'];
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

describe.skipIf(gate.skip)('lifecycle stack: administrative rescan', { timeout: 180_000 }, () => {
  it('lands one rescan request in each of the five scan queues; the message is scanning, round 1', async () => {
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
    expect(await lifecycleOf(fx.prisma, message)).toEqual({
      status: 'scanning',
      statusReason: 'admin_rescan',
      version: 3,
      lifecycleRound: 1,
    });
    const history = await historyOf(fx.prisma, message);
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

    // The relay publishes the request; one copy per scan queue, none elsewhere.
    await eventually(
      async () => {
        const depths = await Promise.all(SCAN_QUEUES.map((q) => mgmt.queue(vhost, q)));
        return depths.every((d) => d.messages === 1);
      },
      30_000,
      'one rescan request in each scan queue',
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
    for (const queue of SCAN_QUEUES) {
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
    // Not bound to the sandbox, policy, quarantine or archive queues.
    for (const queue of ['scan.sandbox', 'email.policy.evaluate', 'email.quarantine']) {
      expect((await mgmt.queue(vhost, queue)).messages).toBe(0);
    }
    const depths = await purgeDormantQueues(mgmt, vhost);
    for (const queue of SCAN_QUEUES) expect(depths[queue]).toBe(1);
    // Queue statistics refresh every few seconds: wait for the purge to show.
    await eventually(
      async () =>
        (await Promise.all(SCAN_QUEUES.map((q) => mgmt.queue(vhost, q)))).every(
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
    expect(stale.body).toMatchObject({ code: 'message_version_conflict', currentVersion: 3 });
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: scenario.org, eventType: 'mail.message.rescan_requested.v1' },
      }),
    ).toBe(1);
    record('lifecycle-rescan', { scan_queues_with_one_copy: SCAN_QUEUES.length });
  });
});
