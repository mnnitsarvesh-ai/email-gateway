import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  DeleteObjectsCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { AdvisoryLocks, uuidv7 } from '@email-gateway/common';
import { Prisma, PrismaClient, type ProtectionMode } from '@email-gateway/database';
import {
  EventTypes,
  type EventEnvelope,
  type MessageCopyScannedV1,
} from '@email-gateway/event-contracts';
import { immediateSleep, type RunningSimulators } from '@email-gateway/idp-adapters/testing';
import type { RateBudget } from '@email-gateway/idp-adapters';
import { createLogger, type Logger } from '@email-gateway/logger';
import {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
} from '@email-gateway/provider-integrations';
import { Redis } from 'ioredis';
import { MailboxComponents, type ComponentDeps } from '../../src/components';
import { loadWorkerConfig, type WorkerConfig } from '../../src/config';
import { COPIES_CONSUMER } from '../../src/copies/copies.handler';
import type { MailboxAccessTokens } from '../../src/runtime/provider-runtime';
import type { MailboxRedis } from '../../src/runtime/redis-stores';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export const silent: Logger = createLogger({ service: 'mailbox-worker-it', level: 'silent' });

/** A settable clock shared by the worker components and the simulators. */
export class Clock {
  private current = new Date(Math.floor(Date.now() / 1000) * 1000);
  now = (): Date => new Date(this.current.getTime());
  ms = (): number => this.current.getTime();
  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
  set(at: Date): void {
    this.current = new Date(at.getTime());
  }
}

export const sha256 = (value: string | Uint8Array): string =>
  createHash('sha256').update(value).digest('hex');

/**
 * Simulator tokens for the mailbox grants (TEST SEAM of `MailboxAccessTokens`): the in-process
 * simulators accept tokens their registry issued for a directory, profile and (Google) subject.
 * Records every request so suites can assert the subjects (Gmail = the mailbox, Directory = the
 * delegated administrator). Production uses 8.2's `ProviderTokenService` (see `custody.test.ts`).
 */
export class SimAccessTokens implements MailboxAccessTokens {
  readonly directories = new Map<string, string>();
  readonly requests: { connectionPublicId: string; resource: string; subject?: string }[] = [];

  constructor(
    private readonly sims: () => RunningSimulators,
    private readonly clock: Clock,
  ) {}

  getAccessToken(
    grant: { organizationId: bigint; connectionPublicId: string; profile: string },
    _signal: AbortSignal,
    options: { resource?: 'graph' | 'o365_management' | 'google'; subject?: string } = {},
  ): Promise<{ token: string; expiresAt: Date }> {
    const directoryId = this.directories.get(grant.connectionPublicId);
    if (!directoryId) return Promise.reject(new Error('unknown test connection'));
    const resource = options.resource ?? 'graph';
    this.requests.push({
      connectionPublicId: grant.connectionPublicId,
      resource,
      ...(options.subject ? { subject: options.subject } : {}),
    });
    const token = this.sims().tokens.issue({
      directoryId,
      resource: resource === 'google' ? 'google' : 'graph',
      profile: grant.profile,
      ...(options.subject ? { subject: options.subject } : {}),
      expiresAt: this.clock.ms() + 3_600_000,
    });
    return Promise.resolve({ token, expiresAt: new Date(this.clock.ms() + 3_600_000) });
  }

  invalidate(): void {}
}

export interface TestConnection {
  providerConnectionId: bigint;
  providerConnectionPublicId: string;
  grantId: bigint;
  apiConnectionId: bigint;
  apiConnectionPublicId: string;
  provider: 'microsoft_365' | 'google_workspace';
}

export interface TestOrg {
  id: bigint;
  domains: Map<string, bigint>;
}

/**
 * Synthetic `it-apimode-<run>-*` organizations (never organizations 1, 2, 16946 or user 21416),
 * domains, 8.2 connections and grants, journal intake sources, journal copies (EML in MinIO), and
 * the removal of every row, object and Redis key the suites and the worker wrote for them.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly redis = new Redis(requireEnv('REDIS_URL'), {
    lazyConnect: false,
    maxRetriesPerRequest: 2,
  });
  readonly s3 = new S3Client({
    region: requireEnv('S3_REGION'),
    endpoint: process.env.S3_ENDPOINT,
    forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true',
    credentials: {
      accessKeyId: requireEnv('S3_ACCESS_KEY_ID'),
      secretAccessKey: requireEnv('S3_SECRET_ACCESS_KEY'),
    },
  });
  readonly bucket = requireEnv('S3_BUCKET_MAIL');

  /**
   * @param prefix slug prefix of the synthetic organizations and plan (`it-apimode` for the
   *   API-1 suites, `it-apirem` for the step API-2 remediation suites).
   */
  constructor(readonly prefix = 'it-apimode') {
    this.redis.on('error', () => undefined);
  }
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly eventIds: string[] = [];
  readonly connectionPublicIds: string[] = [];
  /** API connection ids created by the suite (counter keys). */
  readonly apiConnectionIds: string[] = [];
  private planId: bigint | undefined;
  private readonly built: MailboxComponents[] = [];
  private readonly locks: AdvisoryLocks[] = [];

  async organization(
    label: string,
    options: { mode?: ProtectionMode; entitled?: boolean } = {},
  ): Promise<TestOrg> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `${this.prefix}-${this.suffix}`,
          name: 'mailbox-worker integration',
          defaultLimits: {},
          defaultFeatures: { api_mode_protection: true },
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `${this.prefix}-${this.suffix}-${label}`,
        name: `IT API mode ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        protectionMode: options.mode ?? 'inline',
      },
    });
    this.organizationIds.push(org.id);
    if (options.entitled === false) {
      await this.prisma.organizationFeature.create({
        data: { organizationId: org.id, featureKey: 'api_mode_protection', enabled: false },
      });
    }
    return { id: org.id, domains: new Map() };
  }

  async domain(org: TestOrg, name: string, mode: ProtectionMode | null): Promise<bigint> {
    const domain = await this.prisma.domain.create({
      data: {
        organizationId: org.id,
        name,
        status: 'active',
        inboundEnabled: mode !== 'api',
        protectionMode: mode,
      },
    });
    org.domains.set(name, domain.id);
    return domain.id;
  }

  /** An active, bound 8.2 connection with linked domains and the mailbox-access grant. */
  async connection(
    org: TestOrg,
    provider: 'microsoft_365' | 'google_workspace',
    input: {
      tenantId: string;
      domains: string[];
      grantStatus?: 'active' | 'revoked' | 'error' | 'pending_consent';
      subjectEmail?: string;
      feeds?: { enabled: boolean; mode?: 'poll' | 'notify' };
    },
  ): Promise<TestConnection> {
    const pc = await this.prisma.providerConnection.create({
      data: {
        organizationId: org.id,
        provider,
        displayName: `it-apimode-${randomUUID().slice(0, 8)}`,
        status: 'active',
        externalTenantId: input.tenantId,
        activeTenantKey: `it-apimode:${randomUUID()}`,
        tenantVerifiedAt: new Date(),
      },
    });
    for (const name of input.domains) {
      const domainId = org.domains.get(name);
      if (domainId === undefined) throw new Error(`unknown fixture domain ${name}`);
      await this.prisma.providerConnectionDomain.create({
        data: {
          organizationId: org.id,
          connectionId: pc.id,
          domainId,
          providerVerification: 'verified',
        },
      });
    }
    const profile =
      provider === 'microsoft_365'
        ? M365_MAILBOX_REMEDIATION_PROFILE
        : GOOGLE_MAILBOX_REMEDIATION_PROFILE;
    const grant = await this.prisma.providerConnectionGrant.create({
      data: {
        organizationId: org.id,
        connectionId: pc.id,
        profile: profile.key,
        profileVersion: profile.version,
        authMethod:
          provider === 'microsoft_365' ? 'customer_app_secret' : 'customer_service_account',
        status: input.grantStatus ?? 'active',
        subjectEmail: input.subjectEmail ?? null,
        requestedPermissions: [...profile.permissions],
        observedPermissions: [...profile.permissions],
        verifiedAt: new Date(),
      },
    });
    const publicId = uuidv7();
    const api = await this.prisma.apiModeConnection.create({
      data: {
        publicId,
        organizationId: org.id,
        providerConnectionId: pc.id,
        provider,
        feedsEnabled: input.feeds?.enabled ?? false,
        feedMode: input.feeds?.mode ?? 'poll',
        nextInventoryAt: new Date(Date.now() + 365 * 86_400_000),
      },
    });
    this.connectionPublicIds.push(publicId);
    this.apiConnectionIds.push(api.id.toString());
    return {
      providerConnectionId: pc.id,
      providerConnectionPublicId: pc.publicId,
      grantId: grant.id,
      apiConnectionId: api.id,
      apiConnectionPublicId: publicId,
      provider,
    };
  }

  async journalSource(
    org: TestOrg,
    connection: TestConnection | null,
    kind: 'microsoft_365_journal' | 'google_workspace_copy' | 'smtp_bcc' = 'microsoft_365_journal',
  ): Promise<bigint> {
    const source = await this.prisma.journalIntakeSource.create({
      data: {
        organizationId: org.id,
        kind,
        displayName: `it-apimode-${randomUUID().slice(0, 8)}`,
        status: 'active',
        providerConnectionId: connection?.providerConnectionId ?? null,
        addressHash: randomBytes(32).toString('hex'),
        verifiedAt: new Date(),
        healthStatus: 'healthy',
      },
    });
    return source.id;
  }

  /** Uploads an EML to the mail bucket under the organization's prefix. */
  async putEml(organizationId: bigint, eml: string): Promise<string> {
    const key = `org/${organizationId.toString()}/eml/it/${randomUUID()}.eml`;
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: eml,
        ContentType: 'message/rfc822',
      }),
    );
    return key;
  }

  /** A journal-intake registry copy (as the smtp-adapter commits it) with its stored EML. */
  async journalCopy(
    org: TestOrg,
    sourceId: bigint,
    input: {
      eml: string;
      recipients: string[];
      messageId: string | null;
      from: string;
      receivedAt: Date;
    },
  ): Promise<{ id: bigint; publicId: string; receivedAt: Date }> {
    const key = await this.putEml(org.id, input.eml);
    const identity = await this.prisma.messageIdentity.create({
      data: {
        organizationId: org.id,
        ingestKey: `it:${randomUUID()}`,
        receivedAt: input.receivedAt,
      },
    });
    await this.prisma.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt: input.receivedAt,
        organizationId: org.id,
        direction: 'inbound',
        ingestSource: 'journal_intake',
        status: 'journaled',
        statusChangedAt: input.receivedAt,
        internetMessageId: input.messageId === null ? null : `<${input.messageId}>`,
        envelopeFrom: input.from,
        headerFrom: input.from,
        subject: 'Synthetic journal copy',
        sizeBytes: Buffer.byteLength(input.eml),
        recipientCount: input.recipients.length,
        emlObjectKey: key,
        emlSha256: sha256(input.eml),
      },
    });
    await this.prisma.emailRecipient.createMany({
      data: input.recipients.map((address, rcptSeq) => ({
        receivedAt: input.receivedAt,
        messageId: identity.id,
        organizationId: org.id,
        rcptSeq,
        address,
        status: 'journaled' as const,
      })),
    });
    await this.prisma.journalIntakeMessage.create({
      data: {
        messageId: identity.id,
        receivedAt: input.receivedAt,
        organizationId: org.id,
        sourceId,
        kind: 'microsoft_365_journal',
        format: 'copy',
        envelope: {},
        proof: {},
        reportSha256: sha256(input.eml),
        reportSizeBytes: Buffer.byteLength(input.eml),
        scanRequested: true,
      },
    });
    return { id: identity.id, publicId: identity.publicId, receivedAt: input.receivedAt };
  }

  /** An inline gateway message (hybrid link target) with one recipient and a policy verdict. */
  async gatewayMessage(
    org: TestOrg,
    input: {
      messageId: string;
      recipient: string;
      receivedAt: Date;
      finalVerdict: 'clean' | 'spam';
    },
  ): Promise<bigint> {
    const identity = await this.prisma.messageIdentity.create({
      data: {
        organizationId: org.id,
        ingestKey: `it:${randomUUID()}`,
        receivedAt: input.receivedAt,
      },
    });
    await this.prisma.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt: input.receivedAt,
        organizationId: org.id,
        direction: 'inbound',
        ingestSource: 'gateway',
        status: 'delivered',
        statusChangedAt: input.receivedAt,
        internetMessageId: `<${input.messageId}>`,
        envelopeFrom: 'sender@sender.example',
        sizeBytes: 100,
        recipientCount: 1,
        emlObjectKey: `org/${org.id.toString()}/eml/it/inline.eml`,
        emlSha256: sha256('inline'),
        finalVerdict: input.finalVerdict,
      },
    });
    await this.prisma.emailRecipient.create({
      data: {
        receivedAt: input.receivedAt,
        messageId: identity.id,
        organizationId: org.id,
        rcptSeq: 0,
        address: input.recipient,
        status: 'delivered',
      },
    });
    return identity.id;
  }

  /** A `mail.message.copy_scanned.v1` envelope as the email-worker's outbox row is relayed. */
  copyScanned(
    organizationId: bigint,
    message: { id: bigint; publicId: string; receivedAt: Date },
    input: Partial<Omit<MessageCopyScannedV1, 'completedAt'>> & { completedAt: Date },
  ): EventEnvelope<MessageCopyScannedV1> {
    const eventId = uuidv7();
    this.eventIds.push(eventId);
    const outcome = input.outcome ?? 'scanned';
    return {
      eventId,
      eventType: EventTypes.MessageCopyScanned,
      occurredAt: input.completedAt.toISOString(),
      correlationId: `it-apimode-${this.suffix}`,
      organizationId: organizationId.toString(),
      payload: {
        messageId: message.id.toString(),
        messagePublicId: message.publicId,
        receivedAt: message.receivedAt.toISOString(),
        ingestSource: input.ingestSource ?? 'journal_intake',
        lifecycleRound: 0,
        scanId: outcome === 'parse_failed' ? null : (input.scanId ?? '1'),
        outcome,
        verdict: outcome === 'parse_failed' ? null : (input.verdict ?? 'clean'),
        riskScore: outcome === 'parse_failed' ? null : (input.riskScore ?? 10),
        completedAt: input.completedAt.toISOString(),
      },
    };
  }

  /** Worker configuration for the suites: the in-process simulators over http, every role. */
  config(sims: RunningSimulators, overrides: Record<string, string> = {}): Readonly<WorkerConfig> {
    return loadWorkerConfig({
      ...process.env,
      APP_ENV: 'local',
      MAILBOX_WORKER_ROLES: 'copies,feeds,inventory,health',
      API_MODE_GRAPH_URL: sims.baseUrl('graph'),
      API_MODE_GMAIL_URL: sims.baseUrl('gmail'),
      API_MODE_GOOGLE_ADMIN_URL: sims.baseUrl('google-admin'),
      API_MODE_ALLOW_HTTP_ENDPOINTS: 'true',
      API_MODE_GRAPH_NOTIFICATION_URL: '',
      API_MODE_FETCH_CONCURRENCY_PER_CONNECTION: '4',
      // The suites call faster than a tenant would; budget isolation has its own test budget.
      API_MODE_GRAPH_REQUESTS_PER_SECOND: '1000',
      API_MODE_GMAIL_REQUESTS_PER_SECOND: '1000',
      API_MODE_DIRECTORY_REQUESTS_PER_SECOND: '1000',
      ...overrides,
    });
  }

  /** Worker components restricted to this run's organizations (no loops started). */
  components(
    config: Readonly<WorkerConfig>,
    input: {
      clock: Clock;
      tokens: MailboxAccessTokens;
      budget?: RateBudget;
      maxPagesPerSync?: number;
    },
  ): MailboxComponents {
    const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
    this.locks.push(locks);
    const deps: ComponentDeps = {
      prisma: this.prisma,
      redis: this.redis as unknown as MailboxRedis,
      locks,
      s3: this.s3,
      mailBucket: this.bucket,
      metrics: null,
      logger: silent,
      now: input.clock.now,
      organizationIds: this.organizationIds,
      tokens: input.tokens,
      sleep: immediateSleep,
      lockPrefix: `it-${this.suffix}:`,
      ...(input.budget ? { budget: input.budget } : {}),
      ...(input.maxPagesPerSync !== undefined ? { maxPagesPerSync: input.maxPagesPerSync } : {}),
    };
    const components = new MailboxComponents(config, deps);
    this.built.push(components);
    return components;
  }

  async cleanup(): Promise<void> {
    for (const c of this.built) await c.stop().catch(() => undefined);
    for (const l of this.locks) await l.close().catch(() => undefined);
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        const inIds = Prisma.join(ids);
        // Step API-2: quarantine entries (mailbox-located), their actions, release logs and
        // approval requests, then remediation actions (RESTRICT on mailboxes and connections)
        // and policies (RESTRICT on domains).
        await this.prisma.messageOutbox.deleteMany({ where });
        // Step API-3 (§3.4 purge order): clawback targets (cascade with their clawbacks),
        // clawbacks and user reports before remediation actions, mailboxes and connections.
        await this.prisma.apiClawbackTarget.deleteMany({ where });
        await this.prisma.apiClawback.deleteMany({ where });
        await this.prisma.apiUserReport.deleteMany({ where });
        await this.prisma.quarantineApprovalRequest.deleteMany({ where });
        await this.prisma.quarantineReleaseLog.deleteMany({ where });
        await this.prisma.quarantineAction.deleteMany({ where });
        await this.prisma.quarantineMessage.deleteMany({ where });
        await this.prisma.quarantineSettings.deleteMany({ where });
        await this.prisma.apiRemediationAction.deleteMany({ where });
        await this.prisma.apiRemediationPolicy.deleteMany({ where });
        await this.prisma.user.deleteMany({ where });
        await this.prisma
          .$executeRaw`DELETE FROM message_risk_scores WHERE organization_id IN (${inIds})`;
        await this.prisma
          .$executeRaw`DELETE FROM api_message_copies WHERE organization_id IN (${inIds})`;
        await this.prisma.apiCopyDedupeKey.deleteMany({ where });
        await this.prisma.apiModeCounter.deleteMany({ where });
        await this.prisma.apiMailboxAddress.deleteMany({ where });
        await this.prisma.apiMailbox.deleteMany({ where });
        await this.prisma.apiModeConnection.deleteMany({ where });
        await this.prisma
          .$executeRaw`DELETE FROM journal_intake_messages WHERE organization_id IN (${inIds})`;
        await this.prisma.journalIntakeSource.deleteMany({ where });
        await this.prisma.$executeRaw`DELETE FROM email_events WHERE organization_id IN (${inIds})`;
        await this.prisma
          .$executeRaw`DELETE FROM email_message_status_history WHERE organization_id IN (${inIds})`;
        await this.prisma
          .$executeRaw`DELETE FROM email_recipients WHERE organization_id IN (${inIds})`;
        await this.prisma
          .$executeRaw`DELETE FROM email_messages WHERE organization_id IN (${inIds})`;
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.auditLog.deleteMany({ where });
        await this.prisma.notificationAlertWindow.deleteMany({ where });
        await this.prisma.providerConnectionDomain.deleteMany({ where });
        await this.prisma.providerConnectionGrant.deleteMany({ where });
        await this.prisma.providerConnection.deleteMany({ where });
        await this.prisma.domainMxRecord.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organizationFeature.deleteMany({ where });
        await this.prisma.apiModeOrgSetting.deleteMany({ where });
        // The live policy-engine's digest scheduler may have planned a digest for held entries.
        await this.prisma.quarantineDigest.deleteMany({ where });
        await this.prisma.quarantineDigestRun.deleteMany({ where });
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
      }
      if (this.eventIds.length > 0) {
        await this.prisma.messageIdempotency.deleteMany({
          where: { consumer: COPIES_CONSUMER, eventId: { in: this.eventIds } },
        });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
      // Step API-3: the suite's TI sweep cursors (prefixed with the run's lock prefix).
      await this.prisma.apiModeCursor.deleteMany({
        where: { name: { startsWith: `it-${this.suffix}:` } },
      });
      for (const id of ids) await this.deleteObjects(`org/${id.toString()}/`);
      await this.deleteRedisKeys();
    } finally {
      await this.prisma.$disconnect();
      await this.redis.quit().catch(() => undefined);
      this.s3.destroy();
    }
  }

  private async deleteObjects(prefix: string): Promise<void> {
    for (;;) {
      const listed = await this.s3.send(
        new ListObjectsV2Command({ Bucket: this.bucket, Prefix: prefix, MaxKeys: 1000 }),
      );
      const keys = (listed.Contents ?? []).map((o) => ({ Key: o.Key! }));
      if (keys.length === 0) return;
      await this.s3.send(
        new DeleteObjectsCommand({ Bucket: this.bucket, Delete: { Objects: keys } }),
      );
      if (!listed.IsTruncated) return;
    }
  }

  private async deleteRedisKeys(): Promise<void> {
    const patterns = this.connectionPublicIds.flatMap((id) => [
      `mbx:rb:${id}:*`,
      `mbx:throttle:${id}:*`,
    ]);
    patterns.push(...this.apiConnectionIds.map((id) => `mbx:cnt:${id}:*`));
    // Step API-3 C10.1: per-reporter rate-limit keys of the suite's organizations.
    patterns.push(...this.organizationIds.map((id) => `mbx:rpt:${id.toString()}:*`));
    for (const pattern of patterns) {
      let cursor = '0';
      do {
        const [next, keys] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
        cursor = next;
        if (keys.length > 0) await this.redis.del(...keys);
      } while (cursor !== '0');
    }
  }
}

/** Polls `check` until it returns a truthy value (or throws after `timeoutMs`). */
export async function eventually<T>(
  check: () => Promise<T | null | undefined | false>,
  timeoutMs = 15_000,
): Promise<T> {
  const started = Date.now();
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() - started > timeoutMs) throw new Error('condition not met in time');
    await new Promise((r) => setTimeout(r, 100));
  }
}
