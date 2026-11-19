import { randomInt } from 'node:crypto';
import { smtpAuthRecordedV1, smtpSubmissionRecordedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mailboxSha256, restrictionCacheKey } from '../src/ato/restriction.service';
import { AtoTelemetryRecorder } from '../src/ato/telemetry-recorder';
import { postfixAction } from '../src/policy/policy-protocol';
import { ATO_SEND_RESTRICTED, ATO_SEND_RESTRICTED_DEFER, DUNNO } from '../src/shared/replies';
import { DomainCacheInvalidator } from '../src/tenancy/domain-cache-invalidator.service';
import {
  InSessionFixtures,
  policy,
  SaslClient,
  type Services,
  startServices,
} from './in-session-support/harness';

/**
 * Account takeover telemetry and enforcement of the smtp-adapter (step 8.4 D4, D14, §10.2)
 * in-process over TCP against the real MySQL writer and Redis: SASL and policy telemetry into
 * `message_outbox`, sending restrictions at RCPT, authentication blocks before the secret is
 * verified, cache invalidation through the outbox tail, fail-closed behaviour and the kill
 * switch. Synthetic organizations only; every row and key is removed.
 */
const fx = new InSessionFixtures();
let services: Services;
let killSwitchOff: Services | undefined;
let orgA: bigint;
let orgB: bigint;
let platformId: bigint | null;
let senderDomain: string;
let senderDomainB: string;
let saslA: { username: string; secret: string; id: bigint };
let saslA2: { username: string; secret: string; id: bigint };
let saslB: { username: string; secret: string; id: bigint };
const ip = () => fx.trackIp(`198.18.${randomInt(0, 256)}.${randomInt(1, 255)}`);
const clients: SaslClient[] = [];

const recorder = () => services.moduleRef.get(AtoTelemetryRecorder);
const invalidator = () => services.moduleRef.get(DomainCacheInvalidator);

const submit = (port: number, extra: Record<string, string>) =>
  policy(port, {
    policy_context: 'submission',
    sasl_username: saslA.username,
    sender: `alice@${senderDomain}`,
    recipient: 'carol@remote.example',
    encryption_protocol: 'TLSv1.3',
    client_address: '203.0.113.20',
    ...extra,
  });

beforeAll(async () => {
  orgA = await fx.organization('ato-a');
  orgB = await fx.organization('ato-b');
  senderDomain = (
    await fx.domain(orgA, 'ato-sender', { outboundEnabled: true, activeDkimKey: true })
  ).name;
  senderDomainB = (
    await fx.domain(orgB, 'ato-sender-b', { outboundEnabled: true, activeDkimKey: true })
  ).name;
  saslA = await fx.saslConnector(orgA, 'atoa');
  saslA2 = await fx.saslConnector(orgA, 'atoa2');
  saslB = await fx.saslConnector(orgB, 'atob');
  const platform = await fx.prisma.organization.findFirst({
    where: { kind: 'platform' },
    select: { id: true },
  });
  platformId = platform?.id ?? null;
  fx.extraRedisKeys.add('sa:dom:remote.example');
  services = await startServices({
    SMTP_CACHE_INVALIDATION_POLL_MS: '0',
    SMTP_ATO_TELEMETRY_ENABLED: 'true',
    // Flushed explicitly by the tests.
    SMTP_ATO_TELEMETRY_FLUSH_MS: '10000',
    SMTP_ATO_RESTRICTION_CACHE_SECONDS: '60',
  });
  // Start the outbox tail at the current maximum.
  await invalidator().poll();
});

afterAll(async () => {
  clients.forEach((c) => c.close());
  await killSwitchOff?.close();
  await services?.close();
  await fx.cleanup();
});

describe('ATO telemetry (D4)', () => {
  it('records SASL decisions after the reply into per-organization outbox batches', async () => {
    const client = await SaslClient.connect(services.saslPort);
    clients.push(client);
    const clientIp = ip();
    expect(await client.plain(1, saslA.username, saslA.secret, clientIp)).toBe(
      `OK\t1\tuser=${saslA.username}`,
    );
    expect(await client.plain(2, saslA.username, 'wrong', clientIp)).toBe(
      `FAIL\t2\tuser=${saslA.username}`,
    );
    expect(await client.plain(3, saslB.username, saslB.secret, ip())).toBe(
      `OK\t3\tuser=${saslB.username}`,
    );
    const unknown = `egc-${'q'.repeat(20)}`;
    expect(await client.plain(4, unknown, 'whatever', ip())).toBe(`FAIL\t4\tuser=${unknown}`);
    await recorder().flush();

    const rowsA = await fx.telemetryRows([orgA]);
    const authA = rowsA.filter((r) => r.eventType === 'smtp.auth.recorded.v1');
    expect(authA).toHaveLength(1);
    const payload = smtpAuthRecordedV1.parse(authA[0]!.payload);
    expect(authA[0]!.aggregateId).toBe(String(orgA));
    expect(payload.entries.map((e) => [e.result, e.connectorId, e.failureReason])).toEqual([
      ['ok', String(saslA.id), null],
      ['fail', String(saslA.id), 'bad_credentials'],
    ]);
    expect(payload.entries[0]!.clientIp).toBe(clientIp);
    const rowsB = await fx.telemetryRows([orgB]);
    expect(rowsB).toHaveLength(1);

    if (platformId !== null) {
      const platformRows = await fx.telemetryRows([platformId]);
      const entries = platformRows.flatMap((row) => smtpAuthRecordedV1.parse(row.payload).entries);
      const entry = entries.find((e) => e.usernameClass === 'unknown_generated_format');
      expect(entry).toMatchObject({ result: 'fail', connectorId: null });
      expect(entry!.usernameHash).toMatch(/^[0-9a-f]{16}$/);
      expect(JSON.stringify(platformRows.map((r) => r.payload))).not.toContain(unknown);
    }
  });

  it('records an accepted submission at END-OF-MESSAGE (not a refused one)', async () => {
    const eom = {
      protocol_state: 'END-OF-MESSAGE',
      queue_id: '4AtoQ1d',
      helo_name: 'mail.tenant.example',
      recipient_count: '2',
      size: '4096',
    };
    expect(await submit(services.policyPort, eom)).toBe(DUNNO);
    // Recorded after the answer (setImmediate + a cached connector lookup).
    await new Promise((resolve) => setTimeout(resolve, 200));
    await recorder().flush();
    const rows = (await fx.telemetryRows([orgA])).filter(
      (r) => r.eventType === 'smtp.submission.recorded.v1',
    );
    expect(rows).toHaveLength(1);
    const payload = smtpSubmissionRecordedV1.parse(rows[0]!.payload);
    expect(payload.entries).toEqual([
      expect.objectContaining({
        context: 'submission',
        connectorId: String(saslA.id),
        connectorAuthType: 'sasl',
        queueId: '4AtoQ1d',
        clientIp: '203.0.113.20',
        heloName: 'mail.tenant.example',
        tlsProtocol: 'TLSv1.3',
        senderAddress: `alice@${senderDomain}`,
        recipientCount: 2,
        sizeBytes: 4096,
      }),
    ]);
  });
});

describe('ATO sending restriction (D14)', () => {
  it('refuses a restricted mailbox at RCPT; another mailbox and another tenant still pass', async () => {
    const id = await fx.restriction(orgA, {
      kind: 'send_block',
      scope: 'mailbox',
      mailboxSha256: mailboxSha256(`ceo@${senderDomain}`),
    });
    // The SASL tests above cached the (then empty) list for the TTL; applying a restriction
    // writes `ato.restriction.changed.v1`, which the outbox tail turns into a delete.
    await fx.restrictionChangedEvent(orgA, id, {
      kind: 'send_block',
      scope: 'mailbox',
      connectorId: null,
      mailboxSha256: mailboxSha256(`ceo@${senderDomain}`),
      status: 'active',
    });
    expect(await invalidator().poll()).toBeGreaterThanOrEqual(1);
    expect(await submit(services.policyPort, { sender: `CEO@${senderDomain}` })).toBe(
      postfixAction(ATO_SEND_RESTRICTED),
    );
    expect(postfixAction(ATO_SEND_RESTRICTED)).toBe(
      '550 5.7.1 Sending temporarily restricted by security policy',
    );
    expect(await submit(services.policyPort, { sender: `bob@${senderDomain}` })).toBe(DUNNO);
    expect(
      await submit(services.policyPort, {
        sasl_username: saslB.username,
        sender: `ceo@${senderDomainB}`,
      }),
    ).toBe(DUNNO);
    // Inbound mail to the same mailbox is never affected.
    expect(
      await policy(services.policyPort, {
        policy_context: 'inbound',
        sender: 'someone@internet.example',
        recipient: `ceo@${senderDomain}`,
        client_address: ip(),
      }),
    ).not.toContain('restricted');

    // Lifted through the ATO store: the outbox tail invalidates the cache.
    await fx.prisma.atoSmtpRestriction.update({
      where: { id },
      data: { status: 'lifted', liftedAt: new Date() },
    });
    expect(await submit(services.policyPort, { sender: `ceo@${senderDomain}` })).toBe(
      postfixAction(ATO_SEND_RESTRICTED),
    ); // still cached
    await fx.restrictionChangedEvent(orgA, id, {
      kind: 'send_block',
      scope: 'mailbox',
      connectorId: null,
      mailboxSha256: mailboxSha256(`ceo@${senderDomain}`),
      status: 'lifted',
    });
    expect(await invalidator().poll()).toBeGreaterThanOrEqual(1);
    expect(await fx.redis.exists(restrictionCacheKey(orgA))).toBe(0);
    expect(await submit(services.policyPort, { sender: `ceo@${senderDomain}` })).toBe(DUNNO);
  });

  it('connector scope in defer mode; expired rows are ignored', async () => {
    const id = await fx.restriction(orgA, {
      kind: 'send_block',
      scope: 'connector',
      connectorId: saslA2.id,
      mode: 'defer',
    });
    await fx.redis.del(restrictionCacheKey(orgA));
    expect(await submit(services.policyPort, { sasl_username: saslA2.username })).toBe(
      ATO_SEND_RESTRICTED_DEFER,
    );
    expect(await submit(services.policyPort, {})).toBe(DUNNO);
    await fx.prisma.atoSmtpRestriction.update({
      where: { id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await fx.redis.del(restrictionCacheKey(orgA));
    expect(await submit(services.policyPort, { sasl_username: saslA2.username })).toBe(DUNNO);
  });

  it('kill switch: SMTP_ATO_ENFORCEMENT_ENABLED=false passes a restricted sender', async () => {
    await fx.restriction(orgB, {
      kind: 'send_block',
      scope: 'connector',
      connectorId: saslB.id,
    });
    await fx.redis.del(restrictionCacheKey(orgB));
    const ask = (port: number) =>
      submit(port, { sasl_username: saslB.username, sender: `x@${senderDomainB}` });
    expect(await ask(services.policyPort)).toBe(postfixAction(ATO_SEND_RESTRICTED));
    killSwitchOff = await startServices({
      SMTP_CACHE_INVALIDATION_POLL_MS: '0',
      SMTP_ATO_ENFORCEMENT_ENABLED: 'false',
    });
    expect(await ask(killSwitchOff.policyPort)).toBe(DUNNO);
  });
});

describe('ATO authentication block (D14)', () => {
  it('refuses the right secret like wrong credentials, never counts the IP, and lifts', async () => {
    const id = await fx.restriction(orgA, {
      kind: 'auth_block',
      scope: 'connector',
      connectorId: saslA2.id,
    });
    await fx.redis.del(restrictionCacheKey(orgA));
    const client = await SaslClient.connect(services.saslPort);
    clients.push(client);
    const serverIp = ip();
    for (let i = 1; i <= 5; i += 1) {
      expect(await client.plain(i, saslA2.username, saslA2.secret, serverIp)).toBe(
        `FAIL\t${i}\tuser=${saslA2.username}`,
      );
    }
    expect(await fx.redis.get(`sa:authfail:${serverIp}`)).toBeNull();
    // Another connector of the tenant is unaffected.
    expect(await client.plain(6, saslA.username, saslA.secret, serverIp)).toBe(
      `OK\t6\tuser=${saslA.username}`,
    );

    await recorder().flush();
    const entries = (await fx.telemetryRows([orgA]))
      .filter((r) => r.eventType === 'smtp.auth.recorded.v1')
      .flatMap((r) => smtpAuthRecordedV1.parse(r.payload).entries);
    expect(
      entries.filter((e) => e.result === 'blocked' && e.connectorId === String(saslA2.id)),
    ).toHaveLength(5);
    expect(entries.every((e) => e.result !== 'blocked' || e.failureReason === 'ato_blocked')).toBe(
      true,
    );

    await fx.prisma.atoSmtpRestriction.update({ where: { id }, data: { status: 'lifted' } });
    await fx.redis.del(restrictionCacheKey(orgA));
    expect(await client.plain(7, saslA2.username, saslA2.secret, serverIp)).toBe(
      `OK\t7\tuser=${saslA2.username}`,
    );
  });

  it('connector_ip scope blocks only the listed range', async () => {
    await fx.restriction(orgB, {
      kind: 'auth_block',
      scope: 'connector_ip',
      connectorId: saslB.id,
      range: {
        cidr: '198.51.100.0/24',
        version: 4,
        start: Buffer.from([198, 51, 100, 0]),
        end: Buffer.from([198, 51, 100, 255]),
      },
    });
    // The send_block of the kill-switch test is on the same organization; only auth matters here.
    await fx.redis.del(restrictionCacheKey(orgB));
    const client = await SaslClient.connect(services.saslPort);
    clients.push(client);
    expect(await client.plain(1, saslB.username, saslB.secret, '198.51.100.9')).toBe(
      `FAIL\t1\tuser=${saslB.username}`,
    );
    expect(await client.plain(2, saslB.username, saslB.secret, ip())).toBe(
      `OK\t2\tuser=${saslB.username}`,
    );
  });

  it('fails closed: an unreadable restriction cache closes the auth connection (temporary)', async () => {
    // A non-JSON value under the key makes the service reload from the writer; to simulate a
    // Redis failure the key is turned into a hash, so GET answers WRONGTYPE.
    await fx.redis.del(restrictionCacheKey(orgA));
    await fx.redis.hset(restrictionCacheKey(orgA), 'x', '1');
    const client = await SaslClient.connect(services.saslPort);
    clients.push(client);
    expect(await client.plain(1, saslA.username, saslA.secret, ip())).toBe('<closed>');
    // The policy tempfails as well.
    expect(await submit(services.policyPort, {})).toBe(
      'DEFER_IF_PERMIT 4.3.5 Policy service temporarily unavailable',
    );
    await fx.redis.del(restrictionCacheKey(orgA));
    const again = await SaslClient.connect(services.saslPort);
    clients.push(again);
    expect(await again.plain(2, saslA.username, saslA.secret, ip())).toBe(
      `OK\t2\tuser=${saslA.username}`,
    );
  });
});
