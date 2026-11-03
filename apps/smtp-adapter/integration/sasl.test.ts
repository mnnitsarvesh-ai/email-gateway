import { randomInt } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  InSessionFixtures,
  SaslClient,
  type Services,
  startServices,
} from './in-session-support/harness';

/**
 * Dovecot-auth-protocol server (step 2.2 D10) in-process over TCP against connectors in the
 * real MySQL writer (Argon2id hashes) and the failure counters in Redis.
 */
const fx = new InSessionFixtures();
let services: Services;
let active: { username: string; secret: string };
let disabled: { username: string; secret: string };
let suspendedOrgConnector: { username: string; secret: string };
const ip = () => fx.trackIp(`198.18.${randomInt(0, 256)}.${randomInt(1, 255)}`);
const clients: SaslClient[] = [];
const connect = async () => {
  const client = await SaslClient.connect(services.saslPort);
  clients.push(client);
  return client;
};

beforeAll(async () => {
  const org = await fx.organization('sasl');
  const suspended = await fx.organization('sasl-susp', 'suspended');
  active = await fx.saslConnector(org, 'a');
  disabled = await fx.saslConnector(org, 'd', 'disabled');
  suspendedOrgConnector = await fx.saslConnector(suspended, 's');
  services = await startServices({
    SMTP_AUTH_MAX_FAILURES_PER_IP: '3',
    SMTP_CACHE_INVALIDATION_POLL_MS: '0',
  });
});

afterAll(async () => {
  clients.forEach((c) => c.close());
  await services?.close();
  await fx.cleanup();
});

describe('SASL (D10)', () => {
  it('authenticates an active connector with its secret', async () => {
    const client = await connect();
    expect(await client.plain(1, active.username, active.secret, ip())).toBe(
      `OK\t1\tuser=${active.username}`,
    );
    // Second AUTH on the same connection (verification cache hit).
    expect(await client.plain(2, active.username, active.secret, ip())).toBe(
      `OK\t2\tuser=${active.username}`,
    );
  });

  it('fails a wrong secret, an unknown user, a disabled connector and a suspended organization', async () => {
    const client = await connect();
    expect(await client.plain(1, active.username, 'wrong', ip())).toBe(
      `FAIL\t1\tuser=${active.username}`,
    );
    const unknown = `egc-unknown-${fx.suffix}`;
    expect(await client.plain(2, unknown, active.secret, ip())).toBe(`FAIL\t2\tuser=${unknown}`);
    expect(await client.plain(3, disabled.username, disabled.secret, ip())).toBe(
      `FAIL\t3\tuser=${disabled.username}`,
    );
    expect(
      await client.plain(4, suspendedOrgConnector.username, suspendedOrgConnector.secret, ip()),
    ).toBe(`FAIL\t4\tuser=${suspendedOrgConnector.username}`);
  });

  it('throttles a client IP after SMTP_AUTH_MAX_FAILURES_PER_IP failures (connection closed = temporary)', async () => {
    const client = await connect();
    const attacker = ip();
    for (let i = 1; i <= 3; i += 1) {
      expect(await client.plain(i, active.username, 'wrong', attacker)).toBe(
        `FAIL\t${i}\tuser=${active.username}`,
      );
    }
    // Temporary failure: closed without a reply (Postfix answers 454 4.7.0; see SaslServerService).
    expect(await client.plain(4, active.username, active.secret, attacker)).toBe('<closed>');
    expect(Number(await fx.redis.get(`sa:authfail:${attacker}`))).toBe(3);
    expect(await fx.redis.pttl(`sa:authfail:${attacker}`)).toBeGreaterThan(0);
  });

  it('applies a disable on the next AUTH (status read every time)', async () => {
    const org = await fx.organization('sasl-flip');
    const flip = await fx.saslConnector(org, 'f');
    const client = await connect();
    expect(await client.plain(1, flip.username, flip.secret, ip())).toBe(
      `OK\t1\tuser=${flip.username}`,
    );
    await fx.prisma.smtpConnector.update({ where: { id: flip.id }, data: { status: 'disabled' } });
    expect(await client.plain(2, flip.username, flip.secret, ip())).toBe(
      `FAIL\t2\tuser=${flip.username}`,
    );
  });
});
