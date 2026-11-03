import { createConnection, type Socket } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';
import { buildMessage } from './support/messages';
import { SmtpClient } from './support/smtp-client';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { reply, swaks, toolsAddresses } from './support/smtp-tools';

/**
 * Connection and size limits through the real Postfix instances (docs/plan/steps/04-smtp-gateway.md
 * D4, D11, D15; brief inbound requirements 7 and 9, review findings of §12.7):
 *
 * - the per-tenant message-size limit, with and without a declared SIZE=, inbound (policy at
 *   RCPT and at END-OF-MESSAGE) and on outbound submission without SIZE= (END-OF-MESSAGE);
 * - Postfix's global `message_size_limit` (552 at MAIL for a declared SIZE= above it);
 * - the per-client connection count limit (postscreen/anvil, 421);
 * - the per-client-IP recipient rate (D6, 450 4.7.1). The shared adapter keeps its configured
 *   SMTP_RATE_CLIENT_RCPT_PER_MINUTE: the test fills smtp-tools' fixed-window counters
 *   (`sa:rl:ip:{ip}:{minute}`) above any limit instead, so the decision itself still comes from
 *   the adapter through Postfix's policy delegation (§12.8).
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
const TENANT_LIMIT = 4096;
const GLOBAL_LIMIT = Number(process.env.POSTFIX_MESSAGE_SIZE_LIMIT ?? 52_428_800);
const CONNECTION_LIMIT = Number(process.env.POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT ?? 50);
let small: FixtureDomain;
let outDomain: FixtureDomain;
let sasl: { username: string; password: string };

/** A body of about `bytes` bytes in 76-character lines. */
const filler = (bytes: number) =>
  Array.from({ length: Math.ceil(bytes / 78) }, () => 'x'.repeat(76)).join('\r\n');

beforeAll(async () => {
  assertStackReady(gate);
  const orgIn = await fx.organization('lim-in');
  small = await fx.domain(orgIn, 'lim-small', { maxMessageSizeBytes: TENANT_LIMIT });
  const orgOut = await fx.organization('lim-out');
  outDomain = await fx.domain(orgOut, 'lim-out', { outboundEnabled: true });
  await fx.dkimKey(outDomain);
  await fx.limit(orgOut, 'max_message_size_bytes', TENANT_LIMIT);
  sasl = await fx.saslConnector(orgOut, 'lim');
}, 60_000);

afterAll(async () => {
  if (!gate.skip) await fx.cleanup();
}, 120_000);

/** EHLO on a raw session from the host to an SMTP host port. */
async function session(port: number): Promise<SmtpClient> {
  const { client, banner } = await SmtpClient.connect(stack.host, port);
  expect(banner).toMatch(/^220[ -]/m);
  expect(await client.command('EHLO limits.integration.test')).toMatch(/^250 /m);
  return client;
}

describe.skipIf(gate.skip)('SMTP stack: message size limits', { timeout: 120_000 }, () => {
  it('inbound: a declared SIZE= above the tenant limit is refused at RCPT with 5.3.4', async () => {
    const client = await session(stack.ports.smtp);
    try {
      expect(
        await client.command(`MAIL FROM:<sender@example.org> SIZE=${TENANT_LIMIT + 1}`),
      ).toMatch(/^250 /);
      expect(await client.command(`RCPT TO:<alice@${small.name}>`)).toMatch(
        /^55\d 5\.3\.4 .*Message too big for recipient/,
      );
    } finally {
      client.close();
    }
  });

  it('inbound: without SIZE= the tenant limit is enforced at END-OF-MESSAGE with 5.3.4', async () => {
    const to = [`alice@${small.name}`];
    const big = buildMessage({
      from: 'sender@example.org',
      to,
      subject: 'Too big',
      body: filler(TENANT_LIMIT * 2),
    });
    const refused = await swaks({
      server: 'postfix',
      port: 25,
      from: 'sender@example.org',
      to,
      data: big.text,
    });
    expect(reply(refused, 'RCPT#0').code).toBe(250);
    expect(reply(refused, 'DATA-END').text).toMatch(/^55\d 5\.3\.4 .*Message too big/);

    const fits = buildMessage({ from: 'sender@example.org', to, subject: 'Fits' });
    const accepted = await swaks({
      server: 'postfix',
      port: 25,
      from: 'sender@example.org',
      to,
      data: fits.text,
    });
    expect(reply(accepted, 'DATA-END').text).toMatch(/^250 2\.0\.0 Ok: queued as /);
  });

  it('outbound submission: without SIZE= the tenant limit is enforced at END-OF-MESSAGE', async () => {
    const to = ['customer@example.com'];
    const from = `alice@${outDomain.name}`;
    const submit = (data: string) =>
      swaks({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        auth: sasl,
        from,
        to,
        data,
      });
    const big = buildMessage({ from, to, subject: 'Too big', body: filler(TENANT_LIMIT * 2) });
    const refused = await submit(big.text);
    expect(reply(refused, 'AUTH').code).toBe(235);
    expect(reply(refused, 'RCPT#0').code).toBe(250);
    expect(reply(refused, 'DATA-END').text).toMatch(/^55\d 5\.3\.4 .*Message too big/);

    const fits = await submit(buildMessage({ from, to, subject: 'Fits' }).text);
    expect(reply(fits, 'DATA-END').text).toMatch(/^250 2\.0\.0 Ok: queued as /);
  });

  it("a declared SIZE= above Postfix's message_size_limit is refused at MAIL with 552 5.3.4", async () => {
    for (const port of [stack.ports.smtp, stack.ports.outboundRelay]) {
      const client = await session(port);
      try {
        expect(
          await client.command(`MAIL FROM:<sender@example.org> SIZE=${GLOBAL_LIMIT + 1}`),
        ).toMatch(/^552 5\.3\.4 Message size exceeds fixed limit/);
      } finally {
        client.close();
      }
    }
  });
});

describe.skipIf(gate.skip)('SMTP stack: per-client-IP rate limit', { timeout: 120_000 }, () => {
  it('inbound MX: a client over its recipient rate gets 450 4.7.1, and 250 once the window clears', async () => {
    const ips = await toolsAddresses();
    expect(ips.length).toBeGreaterThan(0);
    for (const ip of ips) fx.trackClientIp(ip);
    // The adapter's current fixed window, and its neighbours in case a minute boundary passes.
    const minute = Math.floor(Date.now() / 60_000);
    const keys = ips.flatMap((ip) =>
      [minute - 1, minute, minute + 1].map((window) => `sa:rl:ip:${ip}:${window}`),
    );
    const rcpt = () =>
      swaks({
        server: 'postfix',
        port: 25,
        from: 'sender@example.org',
        to: [`alice@${small.name}`],
        quitAfter: 'RCPT',
      });
    try {
      const pipeline = fx.redis.multi();
      for (const key of keys) pipeline.set(key, 1_000_000_000, 'PX', 180_000);
      await pipeline.exec();

      const limited = await rcpt();
      expect(reply(limited, 'RCPT#0').text).toMatch(/^450 4\.7\.1 .*Rate limit exceeded/);
    } finally {
      await fx.redis.del(...keys);
    }
    const allowed = await rcpt();
    expect(reply(allowed, 'RCPT#0').code).toBe(250);
  });
});

interface Probe {
  socket: Socket;
  /** Everything the server sent so far. */
  received: string;
}

describe.skipIf(gate.skip)('SMTP stack: connection limits', { timeout: 120_000 }, () => {
  it(`inbound MX: more than ${CONNECTION_LIMIT} parallel sessions from one client get 421`, async () => {
    const probes: Probe[] = [];
    try {
      for (let i = 0; i < CONNECTION_LIMIT + 5; i++) {
        const socket = createConnection({ host: stack.host, port: stack.ports.smtp });
        const probe: Probe = { socket, received: '' };
        socket.setEncoding('utf8');
        socket.on('data', (chunk: string) => (probe.received += chunk));
        socket.on('error', () => undefined);
        probes.push(probe);
        await new Promise<void>((resolve) => {
          socket.once('connect', () => resolve());
          socket.once('error', () => resolve());
        });
      }
      const refused = () => probes.filter((p) => /(^|\n)421[ -]4\.7\.0 /.test(p.received));
      const deadline = Date.now() + 30_000;
      while (refused().length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 250));
      }
      expect(refused().length).toBeGreaterThan(0);
      expect(refused()[0]!.received).toMatch(/421[ -]4\.7\.0 .*too many connections/i);
      // The sessions within the limit were greeted normally.
      const greeted = probes.filter((p) => /^220[ -]/.test(p.received)).length;
      expect(greeted).toBeGreaterThan(0);
    } finally {
      for (const probe of probes) probe.socket.destroy();
    }
  });
});
