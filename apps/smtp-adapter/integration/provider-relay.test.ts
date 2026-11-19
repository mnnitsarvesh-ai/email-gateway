import { randomBytes, randomUUID } from 'node:crypto';
import { Test, type TestingModule } from '@nestjs/testing';
import { DatabaseModule, MetricsModule, RedisModule } from '@email-gateway/common';
import { generateProbeToken, probeTokenSha256 } from '@email-gateway/mail-routing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AdapterCoreModule } from '../src/app.module';
import { loadSmtpAdapterConfig } from '../src/config';
import { EmlStore, type EmlUploadOptions } from '../src/ingestion/eml-store';
import { IngestionModule, LmtpOutboundListener } from '../src/ingestion/ingestion.module';
import type { MessageSink } from '../src/ingestion/message-reader';
import { PolicyModule } from '../src/policy/policy.module';
import { PolicyServerService } from '../src/policy/policy-server.service';
import { signatureIdOf } from '../src/provider-relay/proof-verifier';
import { ProviderRelayModule } from '../src/provider-relay/provider-relay.module';
import { providerRelayCacheKey } from '../src/provider-relay/provider-relay-resolver.service';
import { RelayCountersService } from '../src/provider-relay/relay-counters.service';
import {
  RELAY_MARKER_RETRY_TTL_SECONDS,
  relayMarkerKey,
} from '../src/provider-relay/relay-marker.store';
import { SmtpSharedModule } from '../src/shared/shared.module';
import { InSessionFixtures, policy } from './in-session-support/harness';
import {
  type DkimTestKey,
  generateDkimKey,
  keyRecordName,
  signMessage,
  testMessage,
} from './provider-relay-support/dkim';
import { DnsStub } from './provider-relay-support/dns-stub';
import { deliver } from './support/lmtp-client';

/**
 * Step 8.2 §10.2 (WP3): the provider relay end to end inside the adapter — policy delegation
 * (RCPT, END-OF-MESSAGE marker) → LMTP ingestion (proof, probe interception) — against the real
 * MySQL writer and Redis of the .env, DKIM keys generated at runtime and published through an
 * in-process DNS stub (PROVIDER_RELAY_DNS_SERVERS), never the Internet. The EML store is an
 * in-memory double (no object storage is written); everything else is the production wiring.
 * Synthetic organizations only; every row and key is removed afterwards.
 */

const M365_CLIENT = '198.51.100.70';
const GOOGLE_CLIENT = '198.51.100.71';
const PROBE_TOKEN = generateProbeToken();

class MemoryEmlStore {
  readonly objects = new Map<string, Buffer>();
  readonly deleted: string[] = [];
  startUpload(options: EmlUploadOptions): MessageSink {
    const chunks: Buffer[] = [];
    let aborted = false;
    return {
      failed: false,
      write: (chunk) => {
        chunks.push(chunk);
        return Promise.resolve();
      },
      finish: () => {
        if (!aborted) this.objects.set(options.key, Buffer.concat(chunks));
        return Promise.resolve();
      },
      abort: () => {
        aborted = true;
      },
    };
  }
  copy(source: string, target: string): Promise<void> {
    this.objects.set(target, this.objects.get(source)!);
    return Promise.resolve();
  }
  delete(key: string): Promise<void> {
    this.deleted.push(key);
    this.objects.delete(key);
    return Promise.resolve();
  }
}

const fx = new InSessionFixtures();
const store = new MemoryEmlStore();
const replayKeys = new Set<string>();
let dns: DnsStub;
let moduleRef: TestingModule;
let policyPort: number;
let lmtpPort: number;
let m365Org: bigint;
let googleOrg: bigint;
let m365Domain: { id: bigint; name: string };
let googleDomain: { id: bigint; name: string };
let m365Key: DkimTestKey;
let googleKey: DkimTestKey;
let m365ConnectionId: bigint;
let googleConnectionId: bigint;
let runId: bigint;
const tenantId = randomUUID();
const googleCustomer = `C0${randomBytes(4).toString('hex')}`;
let queueSeq = 0;

const queueId = (): string => `Q${fx.suffix}${(queueSeq += 1).toString().padStart(4, '0')}`;

async function connection(input: {
  organizationId: bigint;
  provider: 'microsoft_365' | 'google_workspace';
  tenant: string;
  domainId: bigint;
}): Promise<bigint> {
  const created = await fx.prisma.providerConnection.create({
    data: {
      organizationId: input.organizationId,
      provider: input.provider,
      displayName: `it-${fx.suffix}-${input.provider}`,
      status: 'active',
      externalTenantId: input.tenant,
      tenantVerifiedAt: new Date(),
      activeTenantKey: `${input.provider}:${input.tenant}`,
      outboundMode: 'active',
    },
  });
  await fx.prisma.providerConnectionDomain.create({
    data: {
      organizationId: input.organizationId,
      connectionId: created.id,
      domainId: input.domainId,
      providerVerification: 'verified',
    },
  });
  await fx.prisma.smtpConnector.create({
    data: {
      organizationId: input.organizationId,
      name: `relay-${input.provider}-${fx.suffix}`,
      authType: 'provider_relay',
      requireTls: true,
      providerConnectionId: created.id,
    },
  });
  return created.id;
}

beforeAll(async () => {
  dns = await DnsStub.start();
  m365Org = await fx.organization('m365');
  googleOrg = await fx.organization('google');
  m365Domain = await fx.domain(m365Org, 'm365', { outboundEnabled: true, activeDkimKey: true });
  googleDomain = await fx.domain(googleOrg, 'gws', { outboundEnabled: true, activeDkimKey: true });
  m365Key = generateDkimKey(m365Domain.name, { selector: 'selector1' });
  googleKey = generateDkimKey(googleDomain.name, { selector: 'google' });
  dns.setTxt(keyRecordName(m365Key), m365Key.txt);
  dns.setTxt(keyRecordName(googleKey), googleKey.txt);
  m365ConnectionId = await connection({
    organizationId: m365Org,
    provider: 'microsoft_365',
    tenant: tenantId,
    domainId: m365Domain.id,
  });
  googleConnectionId = await connection({
    organizationId: googleOrg,
    provider: 'google_workspace',
    tenant: googleCustomer,
    domainId: googleDomain.id,
  });
  const run = await fx.prisma.providerValidationRun.create({
    data: {
      organizationId: m365Org,
      connectionId: m365ConnectionId,
      kind: 'outbound',
      status: 'awaiting_probe',
      requestedByType: 'system',
      probeTokenSha256: probeTokenSha256(PROBE_TOKEN),
      probeExpiresAt: new Date(Date.now() + 3600_000),
    },
  });
  runId = run.id;
  fx.trackIp(M365_CLIENT);
  fx.trackIp(GOOGLE_CLIENT);
  for (const provider of ['microsoft_365', 'google_workspace'] as const) {
    for (const domain of [m365Domain.name, googleDomain.name]) {
      fx.extraRedisKeys.add(providerRelayCacheKey(provider, domain));
    }
  }

  const loaded = loadSmtpAdapterConfig({
    ...process.env,
    LOG_LEVEL: 'fatal',
    POLICY_HOST: '127.0.0.1',
    POLICY_PORT: String(43_000 + Math.floor(Math.random() * 2000)),
    MAIL_LISTEN_HOST: '127.0.0.1',
    APP_ENV: 'ci',
    PROVIDER_RELAY_ENABLED: 'true',
    PROVIDER_RELAY_DNS_SERVERS: dns.address,
    PROVIDER_RELAY_DNS_TIMEOUT_MS: '500',
    PROVIDER_EGRESS_EXTRA_RANGES: JSON.stringify({
      microsoft_365: [`${M365_CLIENT}/32`],
      google_workspace: [`${GOOGLE_CLIENT}/32`],
    }),
    PROVIDER_PROBE_DOMAIN: 'probe.mail-gateway.test',
  });
  // Free ports for the LMTP listeners (the schema requires ≥ 1; the listener accepts 0).
  const config = { ...loaded, LMTP_INBOUND_PORT: 0, LMTP_OUTBOUND_PORT: 0 };
  moduleRef = await Test.createTestingModule({
    imports: [
      AdapterCoreModule.forRoot(config),
      DatabaseModule.forRoot({ url: config.DATABASE_URL }),
      RedisModule.forRoot({ url: config.REDIS_URL }),
      MetricsModule.forRoot({ service: 'smtp-adapter-it' }),
      SmtpSharedModule,
      ProviderRelayModule,
      PolicyModule,
      IngestionModule.forRoot({
        config,
        listenHost: '127.0.0.1',
        internalNetworks: '127.0.0.0/8,::1/128',
        logLevel: 'silent',
      }),
    ],
  })
    .overrideProvider(EmlStore)
    .useValue(store)
    .compile();
  await moduleRef.init();
  policyPort = moduleRef.get(PolicyServerService).address();
  lmtpPort = moduleRef.get(LmtpOutboundListener).port();
});

afterAll(async () => {
  await moduleRef?.close();
  await dns?.close();
  const where = { organizationId: { in: fx.organizationIds } };
  try {
    await fx.prisma.providerRelayCounter.deleteMany({ where });
    await fx.prisma.providerProbeObservation.deleteMany({ where });
    await fx.prisma.providerValidationRun.deleteMany({ where });
    await fx.prisma.providerConnectionDomain.deleteMany({ where });
    await fx.prisma.smtpConnector.deleteMany({ where });
    await fx.prisma.providerConnection.deleteMany({ where });
    await fx.prisma.messageOutbox.deleteMany({ where });
    await fx.prisma.emailMessageStatusHistory.deleteMany({ where });
    await fx.prisma.emailEvent.deleteMany({ where });
    await fx.prisma.emailRecipient.deleteMany({ where });
    await fx.prisma.emailMessage.deleteMany({ where });
    await fx.prisma.messageIdentity.deleteMany({ where });
    if (replayKeys.size > 0) await fx.redis.del(...replayKeys);
  } finally {
    await fx.cleanup();
  }
});

/** The relay as Postfix drives it: RCPT per recipient, END-OF-MESSAGE, then LMTP to :10051. */
async function relay(input: {
  client: string;
  from: string;
  to: string[];
  message: string;
  queue?: string;
}): Promise<{ rcpt: string[]; eom: string | null; lmtp: string[]; queue: string }> {
  const queue = input.queue ?? queueId();
  const base = {
    policy_context: 'relay',
    client_address: input.client,
    sender: input.from,
    encryption_protocol: 'TLSv1.3',
    encryption_cipher: 'TLS_AES_256_GCM_SHA384',
  };
  const rcpt: string[] = [];
  for (const recipient of input.to) rcpt.push(await policy(policyPort, { ...base, recipient }));
  const accepted = input.to.filter((_, i) => rcpt[i] === 'DUNNO');
  if (accepted.length === 0) return { rcpt, eom: null, lmtp: [], queue };
  const eom = await policy(policyPort, {
    ...base,
    protocol_state: 'END-OF-MESSAGE',
    queue_id: queue,
    size: String(input.message.length),
  });
  if (eom !== 'DUNNO') return { rcpt, eom, lmtp: [], queue };
  const delivery = await deliver({
    port: lmtpPort,
    lhlo: 'out.gateway.local',
    xforward: {
      ADDR: input.client,
      HELO: 'provider.test',
      NAME: '[UNAVAILABLE]',
      PROTO: 'ESMTP',
      IDENT: queue,
      SOURCE: 'REMOTE',
    },
    from: input.from,
    to: accepted,
    message: input.message,
  });
  return { rcpt, eom, lmtp: delivery.data.map((reply) => reply.text), queue };
}

async function signed(
  key: DkimTestKey,
  from: string,
  to: string,
  headers: string[],
): Promise<string> {
  const text = await signMessage(testMessage({ from, to, extraHeaders: headers }), [key], {
    signTime: new Date(),
  });
  const b = /\bb=([^;]+)/.exec(text.slice(0, text.indexOf('\r\nFrom:')).replace(/\bbh=[^;]+;/, ''));
  if (b) replayKeys.add(`sa:prelay:dkim:${signatureIdOf(b[1]!)}`);
  return text;
}

const messagesOf = (organizationId: bigint, queue: string) =>
  fx.prisma.emailMessage.findMany({ where: { organizationId, mtaQueueId: queue } });

describe('provider relay: Microsoft 365 (D7, D8)', () => {
  it('relays a message with the tenant header and an aligned DKIM signature', async () => {
    const from = `alice@${m365Domain.name}`;
    const message = await signed(m365Key, from, 'bob@external.example', [
      `X-MS-Exchange-CrossTenant-Id: ${tenantId}`,
    ]);
    const result = await relay({
      client: M365_CLIENT,
      from,
      to: ['bob@external.example'],
      message,
    });
    expect(result.rcpt).toEqual(['DUNNO']);
    expect(result.eom).toBe('DUNNO');
    expect(result.lmtp).toEqual(['250 2.0.0 Ok']);
    const [stored] = await messagesOf(m365Org, result.queue);
    expect(stored).toBeDefined();
    expect(store.objects.get(stored!.emlObjectKey)?.toString()).toBe(message);
    const received = await fx.prisma.emailEvent.findFirst({
      where: { organizationId: m365Org, messageId: stored!.id, eventType: 'received' },
    });
    expect((received!.details as Record<string, unknown>).providerRelay).toEqual({
      provider: 'microsoft_365',
      connectionId: (
        await fx.prisma.providerConnection.findUniqueOrThrow({ where: { id: m365ConnectionId } })
      ).publicId,
      proof: 'pass',
    });
    // The marker carries no address beyond the client IP.
    const marker = JSON.parse((await fx.redis.get(relayMarkerKey(result.queue)))!) as Record<
      string,
      unknown
    >;
    expect(marker).toMatchObject({
      v: 1,
      provider: 'microsoft_365',
      clientAddress: M365_CLIENT,
      tenantId,
    });
    expect(JSON.stringify(marker)).not.toContain('@');
  });

  it('refuses a forged tenant header with 550 5.7.26 and keeps nothing', async () => {
    const from = `alice@${m365Domain.name}`;
    const message = await signed(m365Key, from, 'bob@external.example', [
      `X-MS-Exchange-CrossTenant-Id: ${tenantId}`,
      `X-MS-Exchange-CrossTenant-Id: ${randomUUID()}`,
    ]);
    const before = store.objects.size;
    const result = await relay({
      client: M365_CLIENT,
      from,
      to: ['bob@external.example', 'carol@external.example'],
      message,
    });
    expect(result.lmtp).toEqual([
      '550 5.7.26 Sender not authenticated by the linked provider tenant',
      '550 5.7.26 Sender not authenticated by the linked provider tenant',
    ]);
    expect(await messagesOf(m365Org, result.queue)).toEqual([]);
    expect(store.objects.size).toBe(before);
    expect(store.deleted.length).toBeGreaterThan(0);
  });

  it('refuses an unsigned message with 550 5.7.26', async () => {
    const from = `alice@${m365Domain.name}`;
    const message = testMessage({
      from,
      to: 'bob@external.example',
      extraHeaders: [`X-MS-Exchange-CrossTenant-Id: ${tenantId}`],
    });
    const result = await relay({
      client: M365_CLIENT,
      from,
      to: ['bob@external.example'],
      message,
    });
    expect(result.lmtp).toEqual([
      '550 5.7.26 Sender not authenticated by the linked provider tenant',
    ]);
  });

  it('tempfails while the key cannot be looked up, keeping the marker for the retries', async () => {
    const from = `alice@${m365Domain.name}`;
    const message = await signed(m365Key, from, 'bob@external.example', [
      `X-MS-Exchange-CrossTenant-Id: ${tenantId}`,
    ]);
    dns.fail(keyRecordName(m365Key), 'servfail');
    try {
      const result = await relay({
        client: M365_CLIENT,
        from,
        to: ['bob@external.example'],
        message,
      });
      expect(result.lmtp).toEqual(['451 4.3.0 Temporary failure, please retry']);
      expect(await fx.redis.ttl(relayMarkerKey(result.queue))).toBeGreaterThan(3600);
      expect(await fx.redis.ttl(relayMarkerKey(result.queue))).toBeLessThanOrEqual(
        RELAY_MARKER_RETRY_TTL_SECONDS,
      );
    } finally {
      dns.clearFailures();
    }
  });

  it('refuses null senders, and relay-denies non-provider clients and unknown sender domains', async () => {
    const base = {
      policy_context: 'relay',
      encryption_protocol: 'TLSv1.3',
      recipient: 'bob@external.example',
    };
    expect(await policy(policyPort, { ...base, client_address: M365_CLIENT, sender: '' })).toBe(
      '550 5.7.1 Null-sender mail is not accepted on the provider relay',
    );
    expect(
      await policy(policyPort, {
        ...base,
        client_address: '203.0.113.200',
        sender: `alice@${m365Domain.name}`,
      }),
    ).toBe('550 5.7.1 Relay access denied');
    expect(
      await policy(policyPort, {
        ...base,
        client_address: M365_CLIENT,
        sender: `alice@${googleDomain.name}`,
      }),
    ).toBe('550 5.7.1 Relay access denied');
    expect(
      await policy(policyPort, {
        ...base,
        client_address: M365_CLIENT,
        sender: `alice@${m365Domain.name}`,
        encryption_protocol: '',
      }),
    ).toBe('550 5.7.1 Must issue a STARTTLS command first');
  });

  it('answers 451 for normal recipients while outbound is probe_only', async () => {
    await fx.prisma.providerConnection.update({
      where: { id: m365ConnectionId },
      data: { outboundMode: 'probe_only' },
    });
    await fx.redis.del(providerRelayCacheKey('microsoft_365', m365Domain.name));
    try {
      const reply = await policy(policyPort, {
        policy_context: 'relay',
        client_address: M365_CLIENT,
        sender: `alice@${m365Domain.name}`,
        recipient: 'bob@external.example',
        encryption_protocol: 'TLSv1.3',
      });
      expect(reply).toBe(
        '451 4.7.1 Outbound routing through the gateway is not active yet for this organization',
      );
    } finally {
      await fx.prisma.providerConnection.update({
        where: { id: m365ConnectionId },
        data: { outboundMode: 'active' },
      });
      await fx.redis.del(providerRelayCacheKey('microsoft_365', m365Domain.name));
    }
  });
});

describe('validation probes (D10)', () => {
  const probe = `eg-probe-${PROBE_TOKEN}@probe.mail-gateway.test`;

  it('intercepts a probe: evidence row linked to the run, nothing stored, idempotent', async () => {
    const from = `alice@${m365Domain.name}`;
    const message = await signed(m365Key, from, probe, [
      `X-MS-Exchange-CrossTenant-Id: ${tenantId}`,
    ]);
    const objectsBefore = store.objects.size;
    const first = await relay({ client: M365_CLIENT, from, to: [probe], message });
    expect(first.rcpt).toEqual(['DUNNO']);
    expect(first.lmtp).toEqual(['250 2.0.0 Ok']);
    // Postfix redelivers the same queue file (e.g. after a lost reply).
    const again = await deliver({
      port: lmtpPort,
      lhlo: 'out.gateway.local',
      xforward: { ADDR: M365_CLIENT, IDENT: first.queue, SOURCE: 'REMOTE' },
      from,
      to: [probe],
      message,
    });
    expect(again.data.map((reply) => reply.text)).toEqual(['250 2.0.0 Ok']);
    const rows = await fx.prisma.providerProbeObservation.findMany({
      where: { connectionId: m365ConnectionId, queueId: first.queue },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      organizationId: m365Org,
      validationRunId: runId,
      tokenSha256: probeTokenSha256(PROBE_TOKEN),
      provider: 'microsoft_365',
      clientIp: M365_CLIENT,
      tlsProtocol: 'TLSv1.3',
      envelopeFromDomain: m365Domain.name,
      headerFromDomain: m365Domain.name,
      tenantHeader: 'match',
      dkim: 'aligned_pass',
      proofResult: 'pass',
      failureCode: null,
    });
    expect(store.objects.size).toBe(objectsBefore);
    expect(await messagesOf(m365Org, first.queue)).toEqual([]);
  });

  it('refuses probe addresses outside provider-relay sessions', async () => {
    expect(
      await policy(policyPort, {
        policy_context: 'inbound',
        client_address: '203.0.113.9',
        sender: 'x@example.org',
        recipient: probe,
      }),
    ).toBe('550 5.1.1 User unknown');
  });
});

describe('provider relay: Google Workspace (D8 freshness and replay)', () => {
  it('accepts five deliveries of one signature and refuses the sixth', async () => {
    const from = `alice@${googleDomain.name}`;
    const message = await signed(googleKey, from, 'bob@external.example', []);
    const replies: string[] = [];
    for (let i = 0; i < 6; i++) {
      const result = await relay({
        client: GOOGLE_CLIENT,
        from,
        to: ['bob@external.example'],
        message,
      });
      replies.push(result.lmtp[0]!);
    }
    expect(replies.slice(0, 5)).toEqual(Array(5).fill('250 2.0.0 Ok'));
    expect(replies[5]).toBe('550 5.7.26 Sender not authenticated by the linked provider tenant');
  });

  it('a Google sender never relays through the Microsoft 365 ranges', async () => {
    expect(
      await policy(policyPort, {
        policy_context: 'relay',
        client_address: GOOGLE_CLIENT,
        sender: `alice@${m365Domain.name}`,
        recipient: 'bob@external.example',
        encryption_protocol: 'TLSv1.3',
      }),
    ).toBe('550 5.7.1 Relay access denied');
  });
});

describe('hourly counters (D8.2)', () => {
  it('flushes additive counters and the last accepted time', async () => {
    await moduleRef.get(RelayCountersService).flush();
    const m365 = await fx.prisma.providerRelayCounter.findMany({
      where: { connectionId: m365ConnectionId },
    });
    const totals = m365.reduce(
      (sum, row) => ({
        accepted: sum.accepted + row.accepted,
        proofFailed: sum.proofFailed + row.proofFailed,
        tempFailed: sum.tempFailed + row.tempFailed,
        probes: sum.probes + row.probes,
      }),
      { accepted: 0, proofFailed: 0, tempFailed: 0, probes: 0 },
    );
    expect(totals).toEqual({ accepted: 1, proofFailed: 2, tempFailed: 1, probes: 1 });
    const google = await fx.prisma.providerRelayCounter.findMany({
      where: { connectionId: googleConnectionId },
    });
    expect(google.reduce((sum, row) => sum + row.accepted, 0)).toBe(5);
    expect(google.reduce((sum, row) => sum + row.proofFailed, 0)).toBe(1);
    const connection = await fx.prisma.providerConnection.findUniqueOrThrow({
      where: { id: m365ConnectionId },
    });
    expect(connection.lastRelayAcceptedAt).not.toBeNull();
    expect(connection.rowVersion).toBe(1);
  });
});
