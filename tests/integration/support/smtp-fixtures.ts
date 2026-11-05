import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  S3Client,
} from '@aws-sdk/client-s3';
import { hash } from 'argon2';
import {
  createCipheriv,
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { join } from 'node:path';
import {
  type MailDestinationProvider,
  PrismaClient,
  type RecipientValidation,
  type TlsMode,
} from '@email-gateway/database';
import { Redis } from 'ioredis';
import { composeExec, repoRoot, run, runningServices } from './compose';
import { stack } from './env';

export const sha256 = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');

/**
 * SecretBox-compatible encryption (mirror of apps/api/src/crypto/secret-box.ts): AES-256-GCM
 * with DATA_ENCRYPTION_KEY, 12-byte IV, 16-byte tag, format `v1.k1.<iv>.<tag>.<ct>` (base64url
 * parts), caller-supplied AAD. Used to store DKIM private keys exactly as the api does, so the
 * api's own publisher (dkim:sync) decrypts and publishes them.
 */
export function secretBoxEncrypt(plaintext: string, aad: string): string {
  const key = Buffer.from(process.env.DATA_ENCRYPTION_KEY ?? '', 'hex');
  if (key.length !== 32) throw new Error('DATA_ENCRYPTION_KEY must be 64 hex characters (.env)');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [
    'v1',
    'k1',
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

export interface DomainOptions {
  inboundEnabled?: boolean;
  outboundEnabled?: boolean;
  recipientValidation?: RecipientValidation;
  rejectUnknownRecipients?: boolean;
  maxMessageSizeBytes?: number;
}

export interface FixtureDomain {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
}

/** One destination server row (domain_mail_servers, role inbound_destination). */
export interface DestinationServerFixture {
  host: string;
  tlsMode: TlsMode;
  port?: number;
  priority?: number;
  /** Step 2.3 R2; default `custom`. */
  provider?: MailDestinationProvider;
  /** Postfix `match=` list for `verify` (NULL = nexthop). */
  tlsVerifyNames?: string | null;
}

export interface DkimFixture {
  selector: string;
  /** DNS `p=` value (base64 SPKI DER). */
  publicKey: string;
}

/**
 * Per-run fixtures for the stack SMTP suites (docs/plan/steps/04-smtp-gateway.md §9): random
 * organization and domain names, connectors, allow-lists, limits, suppressions and DKIM keys on
 * the MySQL WRITER, and a full cleanup (rows, S3 objects under the organizations' prefixes,
 * adapter cache / rate-limit / reputation keys in Redis, published DKIM keys).
 */
export class SmtpFixtures {
  readonly prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  readonly redis = new Redis(stack.redisUrl(), { maxRetriesPerRequest: 2 });
  readonly s3: S3Client;
  readonly bucket: string;
  /** Random per run; part of every name. */
  readonly suffix = randomUUID().replaceAll('-', '').slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly domains: FixtureDomain[] = [];
  private readonly redisKeys = new Set<string>();
  private readonly redisPatterns = new Set<string>();
  private planId: bigint | undefined;
  private publishedDkim = false;

  constructor() {
    // Some suites stop Redis on purpose; reconnection errors are expected, not test failures.
    this.redis.on('error', () => undefined);
    const s3 = stack.s3();
    this.bucket = s3.mailBucket;
    this.s3 = new S3Client({
      region: s3.region,
      endpoint: s3.endpoint,
      forcePathStyle: true,
      credentials: { accessKeyId: s3.accessKeyId, secretAccessKey: s3.secretAccessKey },
    });
  }

  /** `it-<suffix>-<label>.test` (RFC 2606 reserved TLD; never a real domain). */
  name(label: string): string {
    return `it-${this.suffix}-${label}.test`;
  }

  /** A recipient domain under the dns-sink zone, e.g. `it-<suffix>-<label>.sink.test`. */
  sinkDomain(label: string): string {
    return `it-${this.suffix}-${label}.sink.test`;
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-smtp-${this.suffix}`,
          name: 'SMTP stack test',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-smtp-${this.suffix}-${label}`,
        name: `SMTP stack ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status: 'active',
      },
    });
    this.organizationIds.push(org.id);
    for (const prefix of ['sa:rl:in', 'sa:rl:out', 'sa:rl:outd', 'dw:rl:out', 'dw:rl:outd']) {
      this.redisPatterns.add(`${prefix}:${org.id.toString()}:*`);
    }
    this.redisPatterns.add(`rep:${org.id.toString()}:*`);
    this.redisKeys.add(`sa:lim:${org.id.toString()}`);
    return org.id;
  }

  /** An `active` (verified) domain of `organizationId`. */
  async domain(
    organizationId: bigint,
    label: string,
    options: DomainOptions = {},
  ): Promise<FixtureDomain> {
    return this.domainNamed(organizationId, this.name(label), options);
  }

  /**
   * An `active` domain with an explicit name, for names outside `it-<suffix>-<label>.test`
   * (step 2.3: another tenant's domain under `*.gwtenant.sink.test`, reached through the
   * gateway MX). Callers keep the `it-<suffix>-` prefix in the first label.
   */
  async domainNamed(
    organizationId: bigint,
    name: string,
    options: DomainOptions = {},
  ): Promise<FixtureDomain> {
    if (!name.startsWith(`it-${this.suffix}-`))
      throw new Error(`fixture domain ${name} lacks the run prefix`);
    const row = await this.prisma.domain.create({
      data: {
        organizationId,
        name,
        status: 'active',
        verifiedAt: new Date(),
        activatedAt: new Date(),
        inboundEnabled: options.inboundEnabled ?? true,
        outboundEnabled: options.outboundEnabled ?? false,
      },
      select: { id: true, publicId: true },
    });
    if (
      options.recipientValidation !== undefined ||
      options.rejectUnknownRecipients !== undefined ||
      options.maxMessageSizeBytes !== undefined
    ) {
      await this.prisma.domainSetting.create({
        data: {
          organizationId,
          domainId: row.id,
          recipientValidation: options.recipientValidation ?? 'none',
          rejectUnknownRecipients: options.rejectUnknownRecipients ?? false,
          maxMessageSizeBytes: options.maxMessageSizeBytes ?? null,
        },
      });
    }
    const domain = { id: row.id, publicId: row.publicId, organizationId, name };
    this.domains.push(domain);
    this.redisKeys.add(`sa:dom:${name}`);
    // smtp-adapter cache keys (apps/smtp-adapter/src/tenancy/cache-keys.ts); step 2.3 R2 moved
    // the route list to `sa:route:v2:` and the TLS answers to one `sa:tls:v2:{host}` per host.
    this.redisKeys.add(`sa:route:v2:${name}`);
    this.redisPatterns.add(`sa:rcpt:${row.id.toString()}:*`);
    return domain;
  }

  /** Allow-list entries (domain_recipient_addresses). */
  async recipients(domain: FixtureDomain, localParts: readonly string[]): Promise<void> {
    await this.prisma.domainRecipientAddress.createMany({
      data: localParts.map((localPart) => ({
        organizationId: domain.organizationId,
        domainId: domain.id,
        localPart,
      })),
    });
  }

  /** The tenant's inbound destination server (domain_mail_servers, role inbound_destination). */
  async destination(domain: FixtureDomain, host: string, tlsMode: TlsMode, port = 25) {
    await this.destinations(domain, [{ host, tlsMode, port }]);
  }

  /**
   * Several destination servers of one domain (step 2.3 R2: next-hop list ordered by
   * `(priority, id)`, so rows are inserted in the given order), written like the api's
   * `PUT /domains/{id}/destinations` stores them. The adapter's route and TLS cache keys are
   * dropped so the new rows are answered at once.
   */
  async destinations(domain: FixtureDomain, servers: readonly DestinationServerFixture[]) {
    for (const server of servers) {
      const port = server.port ?? 25;
      await this.prisma.domainMailServer.create({
        data: {
          organizationId: domain.organizationId,
          domainId: domain.id,
          role: 'inbound_destination',
          host: server.host,
          port,
          priority: server.priority ?? 10,
          tlsMode: server.tlsMode,
          provider: server.provider ?? 'custom',
          tlsVerifyNames: server.tlsVerifyNames ?? null,
          enabled: true,
        },
      });
      const tlsKey = `sa:tls:v2:${server.host.toLowerCase().replace(/\.$/, '')}`;
      this.redisKeys.add(tlsKey);
      await this.redis.del(tlsKey);
    }
    await this.redis.del(`sa:route:v2:${domain.name}`);
  }

  async limit(organizationId: bigint, limitKey: string, limitValue: number): Promise<void> {
    await this.prisma.organizationLimit.create({
      data: { organizationId, limitKey, limitValue: BigInt(limitValue), source: 'override' },
    });
  }

  async suppression(organizationId: bigint, address: string): Promise<void> {
    await this.prisma.deliverySuppression.create({
      data: { organizationId, address: address.toLowerCase(), reason: 'manual', source: 'test' },
    });
  }

  /**
   * A `sasl` connector with a random secret stored as an Argon2id PHC hash with the api's
   * parameters (AUTH_ARGON2_*), exactly as the api's connector service stores it.
   */
  async saslConnector(organizationId: bigint, label: string) {
    // Same shape as the api's generated usernames: `egc-` + 20 lower-case base32 characters.
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    const username = `egc-${[...randomBytes(20)].map((b) => alphabet[b % 32]).join('')}`;
    // Same format as the api (32 random bytes, base64url); never starting with `-`, which the
    // swaks test client cannot pass on its command line.
    let password = randomBytes(32).toString('base64url');
    while (password.startsWith('-')) password = randomBytes(32).toString('base64url');
    await this.prisma.smtpConnector.create({
      data: {
        organizationId,
        name: `sasl-${label}`,
        authType: 'sasl',
        saslUsername: username,
        secretHash: await hash(password, {
          type: 2, // argon2id
          memoryCost: Number(process.env.AUTH_ARGON2_MEMORY_KIB ?? 19_456),
          timeCost: Number(process.env.AUTH_ARGON2_TIME_COST ?? 2),
          parallelism: Number(process.env.AUTH_ARGON2_PARALLELISM ?? 1),
        }),
        secretSetAt: new Date(),
      },
    });
    this.redisKeys.add(`sa:conn:sasl:${username}`);
    return { username, password };
  }

  /** A `source_ip` connector with one /32 network per address. */
  async sourceIpConnector(
    organizationId: bigint,
    label: string,
    addresses: readonly string[],
    requireTls = false,
  ): Promise<void> {
    const connector = await this.prisma.smtpConnector.create({
      data: { organizationId, name: `ip-${label}`, authType: 'source_ip', requireTls },
    });
    for (const ip of addresses) {
      const bytes = Buffer.from(ip.split('.').map(Number));
      await this.prisma.smtpConnectorNetwork.create({
        data: {
          organizationId,
          connectorId: connector.id,
          cidr: `${ip}/32`,
          ipVersion: 4,
          rangeStart: bytes,
          rangeEnd: bytes,
        },
      });
      this.trackClientIp(ip);
    }
  }

  async certificateConnector(organizationId: bigint, label: string, fingerprint: string) {
    await this.prisma.smtpConnector.create({
      data: {
        organizationId,
        name: `cert-${label}`,
        authType: 'client_certificate',
        certFingerprintSha256: fingerprint,
        requireTls: true,
      },
    });
    this.redisKeys.add(`sa:conn:fp:${fingerprint}`);
  }

  /**
   * Drops the adapter's cached connector lookups (`sa:conn:ip:*`, 30 s TTL, D11) for addresses,
   * so a connector created by the test is seen at once instead of after the TTL (the documented
   * propagation delay of connector changes).
   */
  async forgetConnectorCache(addresses: readonly string[]): Promise<void> {
    if (addresses.length > 0) await this.redis.del(...addresses.map((ip) => `sa:conn:ip:${ip}`));
  }

  /** Registers the adapter keys derived from a client IP (connector cache, rate, AUTH failures). */
  trackClientIp(ip: string): void {
    this.redisKeys.add(`sa:conn:ip:${ip}`);
    this.redisKeys.add(`sa:authfail:${ip}`);
    this.redisPatterns.add(`sa:rl:ip:${ip}:*`);
  }

  /**
   * An `active` RSA-2048 DKIM key whose private key is stored SecretBox-encrypted with the AAD
   * `dkim:<domain public id>:<selector>`, like the api's domain configuration service does.
   */
  async dkimKey(domain: FixtureDomain): Promise<DkimFixture> {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const selector = `it${this.suffix}`;
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    await this.prisma.domainDkimKey.create({
      data: {
        organizationId: domain.organizationId,
        domainId: domain.id,
        selector,
        algorithm: 'rsa_2048',
        publicKey: spki,
        privateKeyCiphertext: secretBoxEncrypt(pem, `dkim:${domain.publicId}:${selector}`),
        status: 'active',
        activatedAt: new Date(),
      },
    });
    return { selector, publicKey: spki };
  }

  /**
   * Runs one reconciliation of the api's DKIM signing publisher (`dkim:sync`): inside the `api`
   * container when the apps profile runs (CI), otherwise the built CLI on the host
   * (apps/api/dist, reading the repository .env).
   */
  async dkimSync(): Promise<string> {
    this.publishedDkim = true;
    const services = await runningServices();
    const result = services.has('api')
      ? await composeExec('api', ['node', 'dist/modules/domains/cli/dkim-sync.js'], {
          timeoutMs: 60_000,
        })
      : await run('node', ['--env-file=../../.env', 'dist/modules/domains/cli/dkim-sync.js'], {
          cwd: join(repoRoot, 'apps/api'),
          timeoutMs: 60_000,
        });
    if (result.exitCode !== 0) {
      throw new Error(
        `dkim:sync exited ${result.exitCode} (build the api first: pnpm --filter @email-gateway/api build): ${result.stderr.trim()}`,
      );
    }
    return result.stdout.trim();
  }

  // --- S3 -------------------------------------------------------------------------------------

  async objectKeys(organizationId: bigint): Promise<string[]> {
    const keys: string[] = [];
    let token: string | undefined;
    do {
      const page = await this.s3.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: `org/${organizationId.toString()}/`,
          ContinuationToken: token,
        }),
      );
      for (const item of page.Contents ?? []) if (item.Key) keys.push(item.Key);
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
    return keys;
  }

  /**
   * The EML objects of step 2.2 ingestion (`org/{id}/eml/…`) only. Since step 3.1 the running
   * email-worker also stores the parsed parts of every message under `org/{id}/part/…`
   * (docs/plan/steps/06-mime-ingestion.md M11); suites that count what INGESTION stored use this.
   */
  async emlObjectKeys(organizationId: bigint): Promise<string[]> {
    const prefix = `org/${organizationId.toString()}/eml/`;
    return (await this.objectKeys(organizationId)).filter((key) => key.startsWith(prefix));
  }

  async object(key: string): Promise<Buffer> {
    const result = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    return Buffer.from(await result.Body!.transformToByteArray());
  }

  // --- Queries ----------------------------------------------------------------------------------

  messages(organizationId: bigint) {
    return this.prisma.emailMessage.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
    });
  }

  messageCount(organizationId: bigint): Promise<number> {
    return this.prisma.emailMessage.count({ where: { organizationId } });
  }

  // --- Cleanup ----------------------------------------------------------------------------------

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        // Step 2.3: with the delivery-worker running (dev pass-through), every ingested message
        // of a run is also planned and reinjected; its delivery rows go with the fixtures.
        // Reinjection rows early, so the worker claims nothing more of this run. Consumer
        // ledger rows before them: they are found through the outbox rows deleted below.
        await this.deleteLedgerRows(ids);
        // Messages before their outbox rows (step 3.2): an approval still in flight then finds
        // no message (rejected and acked) instead of a message whose approval's outbox row is
        // gone (which the planner dead-letters as `approval_not_issued`).
        await this.prisma.emailMessage.deleteMany({ where });
        await this.deleteDeliveryRows(ids);
        await this.deleteParseRows(ids);
        await this.deleteScanRows(ids);
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        // Step 3.3: api Idempotency-Key records of lifecycle operations (no foreign key).
        await this.prisma.apiIdempotencyKey.deleteMany({ where });
        // Step 4.1: tenant scan thresholds (foreign key to organizations, Restrict).
        await this.prisma.scanEngineSetting.deleteMany({ where });
        // Step 4.2: attachment rescan jobs scoped to a fixture organization (Restrict).
        await this.prisma.attachmentRescanJob.deleteMany({ where });
        await this.prisma.bounceEvent.deleteMany({ where });
        await this.prisma.deliverySuppression.deleteMany({ where });
        await this.prisma.organizationLimit.deleteMany({ where });
        await this.prisma.smtpConnectorNetwork.deleteMany({ where });
        await this.prisma.smtpConnector.deleteMany({ where });
        await this.prisma.domainRecipientAddress.deleteMany({ where });
        await this.prisma.domainSetting.deleteMany({ where });
        await this.prisma.domainMailServer.deleteMany({ where });
        await this.prisma.domainDkimKey.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
        // A worker session that was in flight during the first pass may still have committed.
        await new Promise((r) => setTimeout(r, 1_500));
        await this.deleteDeliveryRows(ids);
        await this.deleteParseRows(ids);
        await this.deleteScanRows(ids);
        for (const id of ids) {
          for (const key of await this.objectKeys(id)) {
            await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
          }
        }
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
      await this.cleanRedis();
      // Unpublish the fixture keys from redis-dkim (the publisher prunes what MySQL no longer has).
      if (this.publishedDkim) await this.dkimSync();
    } finally {
      await this.prisma.$disconnect();
      this.redis.disconnect();
      this.s3.destroy();
    }
  }

  /** Delivery rows of step 2.3 (worker, adapter bounce matching, recorder) of `ids`. */
  private async deleteDeliveryRows(ids: readonly bigint[]): Promise<void> {
    const where = { organizationId: { in: [...ids] } };
    await this.prisma.deliveryReinjection.deleteMany({ where });
    await this.prisma.deliveryStatusEvent.deleteMany({ where });
    await this.prisma.deliveryAttempt.deleteMany({ where });
    await this.prisma.emailDelivery.deleteMany({ where });
    await this.prisma.emailMessageStatusHistory.deleteMany({ where });
    await this.prisma.messageOutbox.deleteMany({ where });
    await this.prisma.emailEvent.deleteMany({ where });
  }

  /**
   * Step 3.1 rows (docs/plan/steps/06-mime-ingestion.md §3): with the email-worker running, every
   * ingested message of a run is also parsed (parse row, allow-listed headers, attachments,
   * `parsed` event and `mail.message.parsed.v1` outbox row; the part objects go with the org
   * prefix).
   */
  private async deleteParseRows(ids: readonly bigint[]): Promise<void> {
    const where = { organizationId: { in: [...ids] } };
    await this.prisma.emailAttachment.deleteMany({ where });
    await this.prisma.emailHeader.deleteMany({ where });
    await this.prisma.emailMessageParse.deleteMany({ where });
    await this.prisma.messageOutbox.deleteMany({ where });
    await this.prisma.emailEvent.deleteMany({ where });
  }

  /**
   * Step 4.1 rows (docs/plan/steps/09-rspamd.md §3): with the email-worker scan role running,
   * every parsed message of a run is also scanned (scan round, engine results incl. failed
   * attempts, authentication results, `scanned.v1` outbox row and `scan.*` events; step 4.2:
   * attachment results and sandbox submissions).
   */
  private async deleteScanRows(ids: readonly bigint[]): Promise<void> {
    const where = { organizationId: { in: [...ids] } };
    // Step 4.2 (docs/plan/steps/10-attachment-scanning.md §3): per-attachment results and
    // sandbox submissions of the attachment engine (child rows of the final, no foreign keys).
    await this.prisma.attachmentScanResult.deleteMany({ where });
    await this.prisma.sandboxSubmission.deleteMany({ where });
    await this.prisma.emailAuthResult.deleteMany({ where });
    await this.prisma.scanEngineResult.deleteMany({ where });
    await this.prisma.emailScan.deleteMany({ where });
    await this.prisma.messageOutbox.deleteMany({ where });
    await this.prisma.emailEvent.deleteMany({ where });
  }

  /**
   * Consumer ledger rows (`message_idempotency`) and consumer progress rows
   * (`message_consumer_progress`, step 3.2) of this run's outbox events, any consumer.
   */
  private async deleteLedgerRows(ids: readonly bigint[]): Promise<void> {
    const events = await this.prisma.messageOutbox.findMany({
      where: { organizationId: { in: [...ids] } },
      select: { eventId: true },
    });
    const eventIds = events.map((e) => e.eventId);
    for (let i = 0; i < eventIds.length; i += 1000) {
      await this.prisma.messageIdempotency.deleteMany({
        where: { eventId: { in: eventIds.slice(i, i + 1000) } },
      });
      await this.prisma.messageConsumerProgress.deleteMany({
        where: { eventId: { in: eventIds.slice(i, i + 1000) } },
      });
    }
  }

  private async cleanRedis(): Promise<void> {
    const keys = new Set(this.redisKeys);
    for (const pattern of this.redisPatterns) {
      let cursor = '0';
      do {
        const [next, batch] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
        cursor = next;
        batch.forEach((k) => keys.add(k));
      } while (cursor !== '0');
    }
    const all = [...keys];
    for (let i = 0; i < all.length; i += 500) await this.redis.del(...all.slice(i, i + 500));
  }
}
