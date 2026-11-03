import { randomInt } from 'node:crypto';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DUNNO,
  MUST_STARTTLS,
  NOT_READY_FOR_OUTBOUND,
  RATE_LIMITED,
  RELAY_DENIED,
  SENDER_NOT_AUTHORIZED,
  SIGNING_UNAVAILABLE,
  SUPPRESSED,
  TOO_BIG,
  TOO_BIG_FOR_RECIPIENT,
  UNKNOWN_USER,
} from '../src/shared/replies';
import { postfixAction } from '../src/policy/policy-protocol';
import {
  InSessionFixtures,
  policy as policyOnWire,
  type Services,
  startServices,
} from './in-session-support/harness';

/** Compares in terms of the semantic constants: decode the wire form back (550 → REJECT). */
const policy = async (p: number, attributes: Record<string, string>): Promise<string> => {
  const action = await policyOnWire(p, attributes);
  const semantic = [
    DUNNO,
    MUST_STARTTLS,
    NOT_READY_FOR_OUTBOUND,
    RATE_LIMITED,
    RELAY_DENIED,
    SENDER_NOT_AUTHORIZED,
    SIGNING_UNAVAILABLE,
    SUPPRESSED,
    TOO_BIG,
    TOO_BIG_FOR_RECIPIENT,
    UNKNOWN_USER,
  ].find((constant) => postfixAction(constant) === action);
  return semantic ?? action;
};

/**
 * Policy delegation (step 2.2 D4, D11) in-process over TCP against the real MySQL writer and
 * Redis (and redis-dkim for reinject-outbound). Fixtures have random names and are removed.
 */
const fx = new InSessionFixtures();
let services: Services;
let port: number;
let dkimWriter: Redis | undefined;

let orgA: bigint;
let orgB: bigint;
let orgLimited: bigint;
let open: string;
let allowList: string;
let monitor: string;
let small: string;
let sender: string;
let senderNoDkim: string;
let senderB: string;
let limited: string;
let sasl: { username: string };
let fingerprint: string;
const network: [number, number, number] = [100, randomInt(64, 128), randomInt(0, 256)];
const clientIn = (n: number) => fx.trackIp(`198.18.${randomInt(0, 256)}.${n}`);

beforeAll(async () => {
  orgA = await fx.organization('a');
  orgB = await fx.organization('b');
  orgLimited = await fx.organization('limited');
  open = (await fx.domain(orgA, 'open')).name;
  const allow = await fx.domain(orgA, 'allow', {
    recipientValidation: 'list',
    rejectUnknownRecipients: true,
  });
  allowList = allow.name;
  await fx.recipients(orgA, allow.id, ['alice', 'bob']);
  monitor = (
    await fx.domain(orgA, 'monitor', {
      recipientValidation: 'list',
      rejectUnknownRecipients: false,
    })
  ).name;
  small = (await fx.domain(orgA, 'small', { maxMessageSizeBytes: 1000 })).name;
  sender = (await fx.domain(orgA, 'sender', { outboundEnabled: true, activeDkimKey: true })).name;
  senderNoDkim = (await fx.domain(orgA, 'nodkim', { outboundEnabled: true })).name;
  senderB = (await fx.domain(orgB, 'sender-b', { outboundEnabled: true, activeDkimKey: true }))
    .name;
  limited = (await fx.domain(orgLimited, 'limited', { outboundEnabled: true, activeDkimKey: true }))
    .name;
  await fx.limit(orgLimited, 'inbound_recipients_per_minute', 0n);
  await fx.limit(orgLimited, 'outbound_recipients_per_minute', 1n);
  sasl = await fx.saslConnector(orgA, 'a');
  await fx.saslConnector(orgLimited, 'lim');
  await fx.sourceIpConnector(orgA, 'net', network, true);
  fingerprint = await fx.certificateConnector(orgA, 'cert');
  await fx.suppression(orgA, 'blocked@remote.example');
  await fx.suppression(orgA, 'expired@remote.example', new Date(Date.now() - 60_000));

  if (process.env.REDIS_DKIM_URL) {
    dkimWriter = new Redis(process.env.REDIS_DKIM_URL, { maxRetriesPerRequest: 1 });
    await dkimWriter.hset('dkim_selectors', sender, `s${fx.suffix}`);
  }
  // Negative cache entries of the shared non-tenant names probed below.
  for (const name of ['internet.example', 'remote.example'])
    fx.extraRedisKeys.add(`sa:dom:${name}`);
  services = await startServices({ SMTP_CACHE_INVALIDATION_POLL_MS: '0' });
  port = services.policyPort;
});

afterAll(async () => {
  await services?.close();
  if (dkimWriter) {
    await dkimWriter.hdel('dkim_selectors', sender).catch(() => undefined);
    dkimWriter.disconnect();
  }
  await fx.cleanup();
});

const inbound = (recipient: string, extra: Record<string, string> = {}) =>
  policy(port, {
    policy_context: 'inbound',
    sender: 'someone@internet.example',
    recipient,
    client_address: clientIn(1),
    ...extra,
  });

describe('policy: inbound (D4)', () => {
  it('accepts recipients of an active tenant domain (accept-all)', async () => {
    expect(await inbound(`anyone@${open}`)).toBe(DUNNO);
    expect(await inbound(`Someone.Else@${open.toUpperCase()}`)).toBe(DUNNO);
  });

  it('refuses unknown and non-active domains', async () => {
    expect(await inbound(`x@unknown-${fx.suffix}.test`)).toBe(RELAY_DENIED);
    const suspended = (await fx.domain(orgA, 'suspended', { status: 'suspended' })).name;
    expect(await inbound(`x@${suspended}`)).toBe(RELAY_DENIED);
  });

  it('authoritative allow-list: listed (with extension) accepted, unknown 5.1.1', async () => {
    expect(await inbound(`Alice@${allowList}`)).toBe(DUNNO);
    expect(await inbound(`bob+news@${allowList}`)).toBe(DUNNO);
    expect(await inbound(`mallory@${allowList}`)).toBe(UNKNOWN_USER);
  });

  it('monitor mode accepts unknown recipients', async () => {
    expect(await inbound(`mallory@${monitor}`)).toBe(DUNNO);
  });

  it('enforces the tenant size limit at RCPT (declared SIZE) and at END-OF-MESSAGE', async () => {
    expect(await inbound(`a@${small}`, { size: '2000' })).toBe(TOO_BIG_FOR_RECIPIENT);
    const instance = `it.${fx.suffix}.size`;
    expect(await inbound(`a@${small}`, { instance })).toBe(DUNNO);
    expect(await inbound(`a@${open}`, { instance })).toBe(DUNNO);
    expect(
      await inbound('', {
        instance,
        protocol_state: 'END-OF-MESSAGE',
        size: '1001',
        recipient: '',
      }),
    ).toBe(TOO_BIG);
    expect(
      await inbound('', { instance, protocol_state: 'END-OF-MESSAGE', size: '999', recipient: '' }),
    ).toBe(DUNNO);
  });

  it('defers when the tenant inbound limit is 0', async () => {
    const domain = (await fx.domain(orgLimited, 'limited-in')).name;
    expect(await inbound(`x@${domain}`)).toBe(RATE_LIMITED);
  });

  it('defers over the per-client-IP rate', async () => {
    const restricted = await startServices({
      SMTP_RATE_CLIENT_RCPT_PER_MINUTE: '2',
      SMTP_CACHE_INVALIDATION_POLL_MS: '0',
    });
    try {
      const ip = clientIn(2);
      const ask = () =>
        policy(restricted.policyPort, {
          policy_context: 'inbound',
          recipient: `x@${open}`,
          client_address: ip,
        });
      const answers = [await ask(), await ask(), await ask()];
      // A window boundary between the calls may reset the counter; at least the limit holds.
      expect(answers.slice(0, 2)).toEqual([DUNNO, DUNNO]);
      expect([DUNNO, RATE_LIMITED]).toContain(answers[2]);
      if (answers[2] === DUNNO) expect(await ask()).toBe(RATE_LIMITED);
    } finally {
      await restricted.close();
    }
  });
});

const submission = (extra: Record<string, string>) =>
  policy(port, {
    policy_context: 'submission',
    sasl_username: sasl.username,
    encryption_protocol: 'TLSv1.3',
    sender: `user@${sender}`,
    recipient: 'carol@remote.example',
    client_address: clientIn(3),
    ...extra,
  });

describe('policy: submission and relay (D11)', () => {
  it('accepts an authenticated tenant sender and records the reputation event', async () => {
    expect(await submission({})).toBe(DUNNO);
    const day = new Date().toISOString().slice(0, 10).replaceAll('-', '');
    await expect.poll(() => fx.redis.hget(`rep:${orgA}:${day}`, 'submitted')).not.toBeNull();
  });

  it('refuses unknown connectors and unauthorized senders', async () => {
    expect(await submission({ sasl_username: `egc-unknown-${fx.suffix}` })).toBe(RELAY_DENIED);
    expect(await submission({ sender: `user@${senderB}` })).toBe(SENDER_NOT_AUTHORIZED);
    expect(await submission({ sender: `user@${open}` })).toBe(SENDER_NOT_AUTHORIZED);
    expect(await submission({ sender: '' })).toBe(SENDER_NOT_AUTHORIZED);
  });

  it('refuses a sender domain without an active DKIM key', async () => {
    expect(await submission({ sender: `user@${senderNoDkim}` })).toBe(NOT_READY_FOR_OUTBOUND);
  });

  it('honours suppressions (expired ones no longer apply)', async () => {
    expect(await submission({ recipient: 'Blocked@Remote.example' })).toBe(SUPPRESSED);
    expect(await submission({ recipient: 'expired@remote.example' })).toBe(DUNNO);
  });

  it('enforces the per-tenant outbound per-minute limit', async () => {
    const lim = await fx.prisma.smtpConnector.findFirstOrThrow({
      where: { organizationId: orgLimited, authType: 'sasl' },
    });
    const ask = () => submission({ sasl_username: lim.saslUsername!, sender: `user@${limited}` });
    const first = await ask();
    const second = await ask();
    // A minute boundary may fall between the two calls; then a third call is limited.
    expect([first, second]).toContain(RATE_LIMITED);
  });

  it('relay: a source-IP connector requires TLS', async () => {
    const ip = fx.trackIp(`${network.join('.')}.7`);
    const relay = { policy_context: 'relay', sasl_username: '', client_address: ip };
    expect(await submission({ ...relay, encryption_protocol: '' })).toBe(MUST_STARTTLS);
    expect(await submission(relay)).toBe(DUNNO);
    expect(await submission({ ...relay, client_address: clientIn(4) })).toBe(RELAY_DENIED);
  });

  it("relay: a client certificate (Postfix's colon-separated fingerprint) authorizes", async () => {
    const postfixFingerprint = fingerprint.toUpperCase().match(/../g)!.join(':');
    expect(
      await submission({
        policy_context: 'relay',
        sasl_username: '',
        ccert_fingerprint: postfixFingerprint,
        client_address: clientIn(5),
      }),
    ).toBe(DUNNO);
  });
});

describe('policy: reinjection (D11)', () => {
  it('reinject-inbound only to tenant domains', async () => {
    const ask = (recipient: string) =>
      policy(port, { policy_context: 'reinject-inbound', sender: 'x@internet.example', recipient });
    expect(await ask(`bob@${open}`)).toBe(DUNNO);
    expect(await ask('victim@internet.example')).toBe(RELAY_DENIED);
  });

  it('reinject-outbound: tenant sender with a published selector; others refused or deferred', async () => {
    const ask = (from: string, recipient = 'carol@remote.example') =>
      policy(port, { policy_context: 'reinject-outbound', sender: from, recipient });
    expect(await ask('x@internet.example')).toBe(SENDER_NOT_AUTHORIZED);
    expect(await ask(`user@${open}`)).toBe(SENDER_NOT_AUTHORIZED);
    expect(await ask(`user@${sender}`, 'blocked@remote.example')).toBe(SUPPRESSED);
    expect(await ask(`user@${senderNoDkim}`)).toBe(SIGNING_UNAVAILABLE);
    if (dkimWriter) expect(await ask(`user@${sender}`)).toBe(DUNNO);
  });
});
