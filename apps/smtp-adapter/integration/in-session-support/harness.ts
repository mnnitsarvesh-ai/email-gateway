import { Test, type TestingModule } from '@nestjs/testing';
import { DatabaseModule, MetricsModule, RedisModule } from '@email-gateway/common';
import { hash } from 'argon2';
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { createConnection, type Socket } from 'node:net';
import { Redis } from 'ioredis';
import {
  type DomainStatus,
  type MailDestinationProvider,
  type OrganizationStatus,
  PrismaClient,
  type RecipientValidation,
  type TlsMode,
} from '@email-gateway/database';
import { AdapterCoreModule } from '../../src/app.module';
import { loadSmtpAdapterConfig, type SmtpAdapterConfig } from '../../src/config';
import { PolicyModule } from '../../src/policy/policy.module';
import { PolicyServerService } from '../../src/policy/policy-server.service';
import { SaslModule } from '../../src/sasl/sasl.module';
import { SaslServerService } from '../../src/sasl/sasl-server.service';
import { SmtpSharedModule } from '../../src/shared/shared.module';
import { encodeNetstring, NetstringDecoder } from '../../src/socketmap/netstring';
import { SocketmapModule } from '../../src/socketmap/socketmap.module';
import { SocketmapServerService } from '../../src/socketmap/socketmap-server.service';

/**
 * In-process harness for the policy, socketmap and SASL listeners against the real MySQL writer
 * (DATABASE_URL) and Redis (REDIS_URL) of the Compose stack. Every fixture uses random names and
 * is removed by `cleanup()` together with the Redis keys the adapter wrote for it.
 */

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export interface Services {
  moduleRef: TestingModule;
  config: Readonly<SmtpAdapterConfig>;
  policyPort: number;
  socketmapPort: number;
  saslPort: number;
  close(): Promise<void>;
}

/** Boots the in-session modules with real infrastructure on random loopback ports. */
export async function startServices(overrides: Record<string, string> = {}): Promise<Services> {
  const base = 41_000 + randomInt(0, 2_000) * 3;
  const config = loadSmtpAdapterConfig({
    ...process.env,
    LOG_LEVEL: 'fatal',
    POLICY_HOST: '127.0.0.1',
    MAIL_LISTEN_HOST: '127.0.0.1',
    POLICY_PORT: String(base),
    SOCKETMAP_PORT: String(base + 1),
    SASL_AUTH_PORT: String(base + 2),
    SMTP_AUTH_FAILURE_DELAY_MS: '20',
    ...overrides,
  });
  const moduleRef = await Test.createTestingModule({
    imports: [
      AdapterCoreModule.forRoot(config),
      DatabaseModule.forRoot({ url: config.DATABASE_URL }),
      RedisModule.forRoot({ url: config.REDIS_URL }),
      MetricsModule.forRoot({ service: 'smtp-adapter-it' }),
      SmtpSharedModule,
      PolicyModule,
      SocketmapModule,
      SaslModule,
    ],
  }).compile();
  moduleRef.enableShutdownHooks();
  await moduleRef.init();
  return {
    moduleRef,
    config,
    policyPort: moduleRef.get(PolicyServerService).address(),
    socketmapPort: moduleRef.get(SocketmapServerService).address(),
    saslPort: moduleRef.get(SaslServerService).address(),
    close: () => moduleRef.close(),
  };
}

// --- Protocol clients -------------------------------------------------------------------------

/** One policy delegation request; returns the action as sent on the wire (`postfixAction`). */
export async function policy(port: number, attributes: Record<string, string>): Promise<string> {
  const request = {
    request: 'smtpd_access_policy',
    protocol_state: 'RCPT',
    instance: `it.${randomBytes(6).toString('hex')}`,
    client_address: '192.0.2.10',
    ...attributes,
  };
  const body = `${Object.entries(request)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')}\n\n`;
  const reply = await roundTrip(port, body, (data) => data.endsWith('\n\n'));
  const match = /^action=(.*)\n\n$/.exec(reply);
  if (!match) throw new Error(`unexpected policy reply ${JSON.stringify(reply)}`);
  return match[1]!;
}

/** One socketmap lookup; returns the decoded reply. */
export async function socketmap(port: number, map: string, key: string): Promise<string> {
  const decoder = new NetstringDecoder();
  let reply: string | undefined;
  await roundTrip(port, encodeNetstring(`${map} ${key}`).toString(), (_, chunk) => {
    const [payload] = decoder.push(Buffer.from(chunk));
    if (payload) reply = payload.toString();
    return reply !== undefined;
  });
  if (reply === undefined) throw new Error('socketmap connection closed without a reply');
  return reply;
}

function roundTrip(
  port: number,
  payload: string,
  done: (data: string, chunk: string) => boolean,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ port, host: '127.0.0.1' });
    let data = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      data += chunk;
      if (done(data, chunk)) {
        socket.end();
        resolve(data);
      }
    });
    socket.on('error', reject);
    socket.on('close', () => resolve(data));
    socket.write(payload);
  });
}

/** Line client for the Dovecot auth protocol (Postfix side). */
export class SaslClient {
  private buffer = '';
  private waiters: (() => void)[] = [];
  private closed = false;

  private constructor(private readonly socket: Socket) {
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.waiters.splice(0).forEach((w) => w());
    });
    socket.on('close', () => {
      this.closed = true;
      this.waiters.splice(0).forEach((w) => w());
    });
    socket.on('error', () => undefined);
  }

  static async connect(port: number): Promise<SaslClient> {
    const socket = createConnection({ port, host: '127.0.0.1' });
    await new Promise((r) => socket.once('connect', r));
    const client = new SaslClient(socket);
    while ((await client.line()) !== 'DONE') {
      /* handshake */
    }
    socket.write('VERSION\t1\t0\nCPID\t1234\n');
    return client;
  }

  async line(): Promise<string | null> {
    for (;;) {
      const newline = this.buffer.indexOf('\n');
      if (newline !== -1) {
        const line = this.buffer.slice(0, newline);
        this.buffer = this.buffer.slice(newline + 1);
        return line;
      }
      if (this.closed) return null;
      await new Promise<void>((r) => this.waiters.push(r));
    }
  }

  /** AUTH PLAIN with an initial response over a `secured` session. */
  async plain(id: number, username: string, secret: string, clientIp: string): Promise<string> {
    const resp = Buffer.from(`\0${username}\0${secret}`).toString('base64');
    this.socket.write(
      `AUTH\t${id}\tPLAIN\tservice=smtp\tnologin\tlip=127.0.0.1\trip=${clientIp}\tsecured\tresp=${resp}\n`,
    );
    return (await this.line()) ?? '<closed>';
  }

  close(): void {
    this.socket.destroy();
  }
}

// --- Database fixtures ------------------------------------------------------------------------

export class InSessionFixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly redis = new Redis(requireEnv('REDIS_URL'), { maxRetriesPerRequest: 2 });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly domainNames: string[] = [];
  readonly outboxEventIds: string[] = [];
  readonly extraRedisKeys = new Set<string>();
  /** Patterns of Redis keys to delete in cleanup (SCAN MATCH). */
  readonly redisPatterns = new Set<string>(['sa:inst:it.*']);
  private planId: bigint | undefined;

  name(label: string): string {
    return `it-${this.suffix}-${label}.test`;
  }

  async organization(label: string, status: OrganizationStatus = 'active'): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-sa-${this.suffix}`,
          name: 'smtp-adapter in-session test',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-sa-${this.suffix}-${label}`,
        name: `In-session ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status,
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async domain(
    organizationId: bigint,
    label: string,
    options: {
      status?: DomainStatus;
      inboundEnabled?: boolean;
      outboundEnabled?: boolean;
      recipientValidation?: RecipientValidation;
      rejectUnknownRecipients?: boolean;
      maxMessageSizeBytes?: number;
      activeDkimKey?: boolean;
    } = {},
  ): Promise<{ id: bigint; name: string }> {
    const name = this.name(label);
    this.domainNames.push(name);
    const domain = await this.prisma.domain.create({
      data: {
        organizationId,
        name,
        status: options.status ?? 'active',
        inboundEnabled: options.inboundEnabled ?? true,
        outboundEnabled: options.outboundEnabled ?? false,
      },
    });
    if (
      options.recipientValidation !== undefined ||
      options.rejectUnknownRecipients !== undefined ||
      options.maxMessageSizeBytes !== undefined
    ) {
      await this.prisma.domainSetting.create({
        data: {
          organizationId,
          domainId: domain.id,
          recipientValidation: options.recipientValidation ?? 'none',
          rejectUnknownRecipients: options.rejectUnknownRecipients ?? false,
          maxMessageSizeBytes: options.maxMessageSizeBytes ?? null,
        },
      });
    }
    if (options.activeDkimKey) {
      await this.prisma.domainDkimKey.create({
        data: {
          organizationId,
          domainId: domain.id,
          selector: `s${this.suffix}`,
          algorithm: 'rsa_2048',
          publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest',
          privateKeyRef: 'test-only-reference',
          status: 'active',
          activatedAt: new Date(),
        },
      });
    }
    this.redisPatterns.add(`sa:rcpt:${domain.id}:*`);
    return { id: domain.id, name };
  }

  /** Registers the Redis keys the adapter derives from a client IP used by a test. */
  trackIp(ip: string): string {
    this.redisPatterns.add(`sa:rl:ip:${ip}:*`);
    this.extraRedisKeys.add(`sa:conn:ip:${ip}`);
    this.extraRedisKeys.add(`sa:authfail:${ip}`);
    return ip;
  }

  async recipients(organizationId: bigint, domainId: bigint, localParts: string[]): Promise<void> {
    await this.prisma.domainRecipientAddress.createMany({
      data: localParts.map((localPart) => ({ organizationId, domainId, localPart })),
    });
  }

  async limit(organizationId: bigint, limitKey: string, limitValue: bigint): Promise<void> {
    await this.prisma.organizationLimit.create({
      data: { organizationId, limitKey, limitValue, source: 'override' },
    });
  }

  async suppression(organizationId: bigint, address: string, expiresAt: Date | null = null) {
    await this.prisma.deliverySuppression.create({
      data: { organizationId, address, reason: 'manual', source: 'test', expiresAt },
    });
  }

  async destination(
    organizationId: bigint,
    domainId: bigint,
    host: string,
    options: {
      port?: number;
      priority?: number;
      tlsMode?: TlsMode;
      enabled?: boolean;
      provider?: MailDestinationProvider;
      tlsVerifyNames?: string | null;
    } = {},
  ): Promise<void> {
    await this.prisma.domainMailServer.create({
      data: {
        organizationId,
        domainId,
        role: 'inbound_destination',
        host,
        port: options.port ?? 25,
        priority: options.priority ?? 10,
        tlsMode: options.tlsMode ?? 'opportunistic',
        enabled: options.enabled ?? true,
        provider: options.provider ?? 'custom',
        tlsVerifyNames: options.tlsVerifyNames ?? null,
      },
    });
    this.extraRedisKeys.add(`sa:tls:v2:${host.toLowerCase().replace(/\.$/, '')}`);
  }

  /** A `domain.routing.changed.v1` outbox row, as the api writes it (step 2.3 R2). */
  async domainRoutingEvent(
    organizationId: bigint,
    domainId: bigint,
    name: string,
    hosts: string[],
  ): Promise<void> {
    const eventId = randomUUID();
    this.outboxEventIds.push(eventId);
    await this.prisma.messageOutbox.create({
      data: {
        eventId,
        organizationId,
        eventType: 'domain.routing.changed.v1',
        aggregateType: 'domain',
        aggregateId: String(domainId),
        correlationId: `it-${this.suffix}`,
        payload: {
          domainId: String(domainId),
          domainPublicId: randomUUID(),
          name,
          hosts,
          changedAt: new Date().toISOString(),
        },
      },
    });
  }

  /** A `sasl` connector with an Argon2id hash of a random secret. */
  async saslConnector(
    organizationId: bigint,
    label: string,
    status: 'active' | 'disabled' = 'active',
  ): Promise<{ username: string; secret: string; id: bigint }> {
    const username = `egc-it${this.suffix}${label}`.slice(0, 64);
    const secret = randomBytes(32).toString('base64url');
    const connector = await this.prisma.smtpConnector.create({
      data: {
        organizationId,
        name: `sasl-${label}`,
        authType: 'sasl',
        status,
        saslUsername: username,
        secretHash: await hash(secret, { type: 2, timeCost: 2, memoryCost: 19_456 }),
        secretSetAt: new Date(),
      },
    });
    this.extraRedisKeys.add(`sa:conn:sasl:${username}`);
    return { username, secret, id: connector.id };
  }

  /** A `source_ip` connector for one IPv4 /24 (start..end as 4-byte big-endian). */
  async sourceIpConnector(
    organizationId: bigint,
    label: string,
    network: [number, number, number],
    requireTls = true,
  ): Promise<bigint> {
    const connector = await this.prisma.smtpConnector.create({
      data: { organizationId, name: `ip-${label}`, authType: 'source_ip', requireTls },
    });
    await this.prisma.smtpConnectorNetwork.create({
      data: {
        organizationId,
        connectorId: connector.id,
        cidr: `${network.join('.')}.0/24`,
        ipVersion: 4,
        rangeStart: Buffer.from([...network, 0]),
        rangeEnd: Buffer.from([...network, 255]),
      },
    });
    return connector.id;
  }

  async certificateConnector(organizationId: bigint, label: string): Promise<string> {
    const fingerprint = randomBytes(32).toString('hex');
    await this.prisma.smtpConnector.create({
      data: {
        organizationId,
        name: `cert-${label}`,
        authType: 'client_certificate',
        certFingerprintSha256: fingerprint,
      },
    });
    this.extraRedisKeys.add(`sa:conn:fp:${fingerprint}`);
    return fingerprint;
  }

  /** A `domain.status.changed.v1` outbox row, as the api writes it. */
  async domainStatusEvent(organizationId: bigint, domainId: bigint, name: string, status: string) {
    const eventId = randomUUID();
    this.outboxEventIds.push(eventId);
    await this.prisma.messageOutbox.create({
      data: {
        eventId,
        organizationId,
        eventType: 'domain.status.changed.v1',
        aggregateType: 'domain',
        aggregateId: String(domainId),
        correlationId: `it-${this.suffix}`,
        payload: {
          domainId: String(domainId),
          domainPublicId: randomUUID(),
          name,
          previousStatus: 'active',
          status,
          reason: null,
          changedAt: new Date().toISOString(),
        },
      },
    });
  }

  async cleanup(): Promise<void> {
    try {
      const orgs = this.organizationIds;
      if (this.outboxEventIds.length > 0) {
        await this.prisma.messageOutbox.deleteMany({
          where: { eventId: { in: this.outboxEventIds } },
        });
      }
      if (orgs.length > 0) {
        const where = { organizationId: { in: orgs } };
        await this.prisma.smtpConnectorNetwork.deleteMany({ where });
        await this.prisma.smtpConnector.deleteMany({ where });
        await this.prisma.deliverySuppression.deleteMany({ where });
        await this.prisma.organizationLimit.deleteMany({ where });
        await this.prisma.domainRecipientAddress.deleteMany({ where });
        await this.prisma.domainSetting.deleteMany({ where });
        await this.prisma.domainDkimKey.deleteMany({ where });
        await this.prisma.domainMailServer.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: orgs } } });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
      await this.deleteRedisKeys();
    } finally {
      await this.prisma.$disconnect();
      this.redis.disconnect();
    }
  }

  private async deleteRedisKeys(): Promise<void> {
    const patterns = [
      ...this.redisPatterns,
      `sa:*${this.suffix}*`,
      ...this.organizationIds.flatMap((id) => [`sa:lim:${id}`, `sa:rl:*:${id}:*`, `rep:${id}:*`]),
    ];
    const keys = new Set(this.extraRedisKeys);
    for (const pattern of patterns) {
      let cursor = '0';
      do {
        const [next, found] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
        cursor = next;
        found.forEach((key) => keys.add(key));
      } while (cursor !== '0');
    }
    if (keys.size > 0) await this.redis.del(...keys);
  }
}
