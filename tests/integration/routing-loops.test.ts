import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiRunning, apiSession, type ApiSession } from './support/api-client';
import { composeOk, waitFor } from './support/compose';
import { deliveriesOf, waitForDeliveries, waitForMessage } from './support/deliveries';
import { maillogOffset, maillogSince } from './support/maillog';
import { involving, listQueue, waitForLog } from './support/postfix';
import { organizationRef, RELAY_SINK_HOST, sendInbound, sleep } from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Loop prevention (docs/plan/steps/05-routing.md §9 item 4, R10):
 * (a) two tenants' routes relay into each other: A's and B's destination is `relay-sink`, which
 *     sends everything back to the gateway MX with the recipient domain swapped
 *     (RELAY_SINK_RECIPIENT_REWRITE, set through Compose for this suite; only that container is
 *     recreated). The second arrival for A carries A's own `d=in` trace → `554 5.4.6` at
 *     ingestion: one message per tenant, never an endless loop.
 * (b) a self-referencing destination (the gateway's own host name) written directly to the DB
 *     is never used (`retry:4.4.1` → deferred `no_destination`, never delivered), and the api
 *     refuses the same host with `422 gateway_host`.
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let orgA = 0n;
let orgB = 0n;
let orgC = 0n;
let aLoop: FixtureDomain;
let bLoop: FixtureDomain;
let selfRef: FixtureDomain;
let session: ApiSession | undefined;
let relayRecreated = false;

async function recreateRelaySink(rewrite: string) {
  await composeOk(
    ['--profile', 'smtp-test', 'up', '-d', '--wait', '--force-recreate', '--no-deps', 'relay-sink'],
    { timeoutMs: 120_000, env: { RELAY_SINK_RECIPIENT_REWRITE: rewrite } },
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  orgA = await fx.organization('loop-a');
  orgB = await fx.organization('loop-b');
  orgC = await fx.organization('loop-c');
  aLoop = await fx.domain(orgA, 'loop-a');
  bLoop = await fx.domain(orgB, 'loop-b');
  selfRef = await fx.domain(orgC, 'loop-self');
  await fx.destinations(aLoop, [{ host: RELAY_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(bLoop, [{ host: RELAY_SINK_HOST, tlsMode: 'opportunistic' }]);
  relayRecreated = true;
  await recreateRelaySink(`${aLoop.name}=${bLoop.name},${bLoop.name}=${aLoop.name}`);
}, 180_000);

afterAll(async () => {
  if (gate.skip) return;
  await session?.remove();
  if (relayRecreated) await recreateRelaySink('');
  for (const service of ['postfix', 'postfix-outbound'] as const) {
    const left = involving(await listQueue(service), [aLoop.name, bLoop.name, selfRef.name]);
    for (const m of left) {
      await composeOk(['exec', '-T', service, 'postsuper', '-d', m.queue_id]);
    }
  }
  await fx.cleanup();
}, 240_000);

describe.skipIf(gate.skip)('routing stack: loops (§9 item 4)', { timeout: 300_000 }, () => {
  it('stops a loop between two tenants’ routes at the second arrival (554 5.4.6), bounded', async () => {
    const since = new Date(Date.now() - 1_000);
    const offset = await maillogOffset();
    // Null sender: the refusal at the end of the loop can never produce a DSN to anyone.
    const sent = await sendInbound({
      from: '',
      to: [`loop@${aLoop.name}`],
      subject: 'Routing loop between tenants',
    });
    const first = await waitForMessage(fx.prisma, orgA, { mtaQueueId: sent.queueId! });
    expect(first.direction).toBe('inbound');
    // A → relay-sink → gateway MX as B's mail → B → relay-sink → gateway MX as A's mail again.
    const bMessage = await waitFor(
      'the relayed copy ingested for tenant B',
      () =>
        fx.prisma.emailMessage
          .findFirst({ where: { organizationId: orgB } })
          .then((row) => row ?? undefined),
      { timeoutMs: 120_000 },
    );
    expect(bMessage.direction).toBe('inbound');
    const refusal = await waitForLog(
      'postfix',
      since,
      new RegExp(`to=<loop@${aLoop.name.replace(/\./g, '\\.')}>.*5\\.4\\.6`, 'i'),
      180_000,
    );
    expect(refusal).toMatch(/554 5\.4\.6/);
    expect(refusal).toMatch(/status=bounced/);

    // Bounded: no further arrivals or deliveries after a wait (≥ two worker and Postfix cycles).
    await sleep(30_000);
    expect(await fx.messageCount(orgA)).toBe(1);
    expect(await fx.messageCount(orgB)).toBe(1);
    const aDeliveries = await deliveriesOf(fx.prisma, orgA, first.id);
    const bDeliveries = await deliveriesOf(fx.prisma, orgB, bMessage.id);
    expect(aDeliveries.map((d) => d.status)).toEqual(['delivered']);
    expect(bDeliveries.map((d) => d.status)).toEqual(['delivered']);
    // Each tenant's reinjection hop delivered exactly once to relay-sink.
    const sentLines = (await maillogSince(offset)).filter(
      (l) => /relay=relay\.sink\.test\[172\.31\.250\.29\]:25/.test(l) && /status=sent/.test(l),
    );
    expect(sentLines).toHaveLength(2);
    expect(
      involving(await listQueue('postfix'), [aLoop.name, bLoop.name]).length +
        involving(await listQueue('postfix-outbound'), [aLoop.name, bLoop.name]).length,
    ).toBe(0);
  });

  it('never delivers to a self-referencing destination: deferred no_destination', async () => {
    const gatewayHost = process.env.POSTFIX_MYHOSTNAME ?? 'mx.gateway.local';
    // Written directly to the DB (bypassing the api's validation): the gateway's own MX name.
    await fx.destinations(selfRef, [{ host: gatewayHost, tlsMode: 'opportunistic' }]);
    const offset = await maillogOffset();
    const sent = await sendInbound({
      from: '',
      to: [`self@${selfRef.name}`],
      subject: 'Routing self-referencing destination',
    });
    const message = await waitForMessage(fx.prisma, orgC, { mtaQueueId: sent.queueId! });
    const [deferred] = await waitForDeliveries(
      fx.prisma,
      orgC,
      message.id,
      'delivery deferred with no_destination',
      (rows) => rows[0]?.status === 'deferred' && rows[0].lastErrorClass === 'no_destination',
    );
    expect(deferred!.finalSmtpResponse ?? '').toMatch(/Destination not configured/);
    // Still deferred after more worker retries; never queued for, or delivered to, any host.
    await sleep(20_000);
    const [later] = await deliveriesOf(fx.prisma, orgC, message.id);
    expect(later!.status).toBe('deferred');
    expect(later!.deliveredAt).toBeNull();
    expect(later!.outboundQueueId).toBeNull();
    const [reinjection] = await fx.prisma.deliveryReinjection.findMany({
      where: { organizationId: orgC, messageId: message.id },
    });
    expect(reinjection).toMatchObject({ status: 'pending', lastErrorClass: 'no_destination' });
    expect(reinjection!.attempts).toBeGreaterThanOrEqual(2);
    // postfix-outbound refused it at RCPT (10026 resolves the transport map there).
    const lines = await maillogSince(offset);
    expect(
      lines.some(
        (l) =>
          l.includes('postfix/reinject-inbound/smtpd') &&
          l.includes('NOQUEUE: reject') &&
          l.includes(`self@${selfRef.name}`) &&
          l.includes('Destination not configured'),
      ),
    ).toBe(true);
    expect(
      lines.some((l) => l.includes(`to=<self@${selfRef.name}>`) && /status=sent/.test(l)),
    ).toBe(false);
  });

  it('the api refuses the same self-referencing host with 422 gateway_host', async () => {
    expect(await apiRunning(), 'the api must run (API_HOST_PORT) for this check').toBe(true);
    session = await apiSession(fx.prisma, await organizationRef(fx, orgC), 'domain_admin');
    const res = await session.put(`/domains/${selfRef.publicId}/destinations`, {
      provider: 'custom',
      servers: [{ host: process.env.POSTFIX_MYHOSTNAME ?? 'mx.gateway.local' }],
    });
    expect(res.status).toBe(422);
    expect(res.body).toMatchObject({ statusCode: 422, reason: 'gateway_host' });
    // The api shows what is stored (the direct DB row), unchanged by the refused PUT.
    const current = await session.get(`/domains/${selfRef.publicId}/destinations`);
    expect(current.status).toBe(200);
    expect((current.body as { servers: { host: string }[] }).servers.map((s) => s.host)).toEqual([
      process.env.POSTFIX_MYHOSTNAME ?? 'mx.gateway.local',
    ]);
  });
});
