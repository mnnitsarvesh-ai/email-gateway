import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  S3Client,
} from '@aws-sdk/client-s3';
import { randomUUID } from 'node:crypto';
import {
  type JournalIntakeSourceKind,
  type JournalIntakeSourceStatus,
  PrismaClient,
  type ProtectionMode,
} from '@email-gateway/database';
import { Redis } from 'ioredis';
import {
  type IntakeCredentials,
  intakeCredentials,
  testIntakeSecret,
} from '../../src/journal-intake/testing/fixtures';
import { requireEnv, s3Config } from '../support/stack';

/**
 * Synthetic `it-jrnl-*` organizations with journal intake sources for the smtp-adapter journal
 * intake suite (step 8.6 §9.2): plan with the intake features and limits, archive settings,
 * verified domains, a bound provider connection, sources with derived address / token hashes
 * (random test secret). `cleanup()` removes every row the suite or the adapter wrote for them,
 * the S3 objects under their prefixes and the Redis keys of their sources. Organizations 1, 2
 * and 16946 and their users are never touched (only ids created here are deleted).
 */
export class JournalFixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly redis = new Redis(requireEnv('REDIS_URL'), { maxRetriesPerRequest: 2 });
  readonly s3: S3Client;
  readonly bucket: string;
  readonly suffix = randomUUID().slice(0, 8);
  readonly secret = testIntakeSecret();
  readonly organizationIds: bigint[] = [];
  readonly sourceIds: bigint[] = [];
  readonly addressHashes: string[] = [];
  private planId: bigint | undefined;

  constructor() {
    const config = s3Config();
    this.bucket = config.S3_BUCKET_MAIL;
    this.s3 = new S3Client({
      region: config.S3_REGION,
      endpoint: config.S3_ENDPOINT,
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
      credentials:
        config.S3_ACCESS_KEY_ID && config.S3_SECRET_ACCESS_KEY
          ? { accessKeyId: config.S3_ACCESS_KEY_ID, secretAccessKey: config.S3_SECRET_ACCESS_KEY }
          : undefined,
    });
  }

  /**
   * `archivingEnabled` (default true) is `archive_settings.enabled`; `protectionMode` (default
   * inline) the organization's mode; `features` are `organization_features` rows overriding the
   * plan (step API-1: e.g. `api_mode_protection`, which the test plan does not grant).
   */
  async organization(
    label: string,
    options: {
      scanEnabled?: boolean;
      archivingEnabled?: boolean;
      protectionMode?: ProtectionMode;
      features?: Record<string, boolean>;
    } = {},
  ): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-jrnl-${this.suffix}`,
          name: 'smtp-adapter journal intake test',
          defaultLimits: {
            journal_intake_messages_per_minute: 1000,
            journal_intake_max_message_bytes: 10 * 1024 * 1024,
          },
          defaultFeatures: { archiving: true, journal_intake: true },
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-jrnl-${this.suffix}-${label}`,
        name: `Journal intake ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        ...(options.protectionMode ? { protectionMode: options.protectionMode } : {}),
      },
    });
    this.organizationIds.push(org.id);
    for (const [featureKey, enabled] of Object.entries(options.features ?? {})) {
      await this.prisma.organizationFeature.create({
        data: { organizationId: org.id, featureKey, enabled },
      });
    }
    await this.prisma.archiveSetting.create({
      data: {
        organizationId: org.id,
        enabled: options.archivingEnabled ?? true,
        settings: options.scanEnabled ? { intake: { scanEnabled: true } } : undefined,
      },
    });
    return org.id;
  }

  async domain(
    organizationId: bigint,
    name: string,
    options: { inboundEnabled?: boolean; protectionMode?: ProtectionMode } = {},
  ): Promise<bigint> {
    const row = await this.prisma.domain.create({
      data: {
        organizationId,
        name,
        status: 'active',
        inboundEnabled: options.inboundEnabled ?? false,
        ...(options.protectionMode ? { protectionMode: options.protectionMode } : {}),
      },
      select: { id: true },
    });
    return row.id;
  }

  async connection(
    organizationId: bigint,
    provider: 'microsoft_365' | 'google_workspace',
    tenant: string,
    domainId: bigint,
  ): Promise<bigint> {
    const created = await this.prisma.providerConnection.create({
      data: {
        organizationId,
        provider,
        displayName: `it-jrnl-${this.suffix}-${provider}`,
        status: 'active',
        externalTenantId: tenant,
        tenantVerifiedAt: new Date(),
        activeTenantKey: `${provider}:${tenant}`,
      },
    });
    await this.prisma.providerConnectionDomain.create({
      data: {
        organizationId,
        connectionId: created.id,
        domainId,
        providerVerification: 'verified',
      },
    });
    return created.id;
  }

  async source(input: {
    organizationId: bigint;
    kind: JournalIntakeSourceKind;
    domain: string;
    providerConnectionId?: bigint;
    networks?: string[];
    status?: JournalIntakeSourceStatus;
    requireTls?: boolean;
  }): Promise<{ id: bigint; publicId: string; credentials: IntakeCredentials }> {
    const publicId = randomUUID();
    const credentials = intakeCredentials(this.secret, publicId, 1, input.domain);
    const row = await this.prisma.journalIntakeSource.create({
      data: {
        publicId,
        organizationId: input.organizationId,
        kind: input.kind,
        displayName: `it-jrnl-${this.suffix}-${input.kind}-${this.sourceIds.length}`,
        status: input.status ?? 'pending_verification',
        providerConnectionId: input.providerConnectionId ?? null,
        networks: input.networks ? { v: 1, cidrs: input.networks } : undefined,
        requireTls: input.requireTls ?? true,
        addressHash: credentials.addressHash,
        headerTokenHash:
          input.kind === 'google_workspace_copy' ? credentials.headerTokenHash : null,
      },
      select: { id: true },
    });
    this.sourceIds.push(row.id);
    this.addressHashes.push(credentials.addressHash);
    return { id: row.id, publicId, credentials };
  }

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

  async object(key: string): Promise<Buffer> {
    const result = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    return Buffer.from(await result.Body!.transformToByteArray());
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    const where = { organizationId: { in: ids } };
    try {
      if (ids.length > 0) {
        await this.prisma.journalIntakeMessage.deleteMany({ where });
        await this.prisma.journalIntakeCounter.deleteMany({ where });
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.journalIntakeSource.deleteMany({ where });
        await this.prisma.providerConnectionDomain.deleteMany({ where });
        await this.prisma.providerConnection.deleteMany({ where });
        await this.prisma.archiveSetting.deleteMany({ where });
        await this.prisma.organizationFeature.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
        for (const id of ids) {
          for (const key of await this.objectKeys(id)) {
            await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
          }
        }
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
      const keys = [
        ...this.addressHashes.map((h) => `sa:jintake:src:${h}`),
        ...(await this.scan('sa:jintake:cnt:*')).filter((k) =>
          this.sourceIds.some((id) => k.startsWith(`sa:jintake:cnt:${id.toString()}:`)),
        ),
        ...(await this.scan('sa:rl:jintake_*')).filter(
          (k) =>
            this.sourceIds.some((id) => k.startsWith(`sa:rl:jintake_src:${id.toString()}:`)) ||
            ids.some((id) => k.startsWith(`sa:rl:jintake_org:${id.toString()}:`)),
        ),
        ...(await this.scan('sa:jintake:inst:it.*')),
        ...(await this.scan(`sa:jintake:q:J${this.suffix}*`)),
        ...(await this.scan('sa:inst:it.*')),
        ...(await this.scan(`sa:dom:*it-jrnl-${this.suffix}*`)),
        ...(await this.scan(`sa:lim:*`)).filter((k) => ids.some((id) => k === `sa:lim:${id}`)),
        ...(await this.scan('sa:rl:in:*')).filter((k) =>
          ids.some((id) => k.startsWith(`sa:rl:in:${id.toString()}:`)),
        ),
      ];
      if (keys.length > 0) await this.redis.del(...keys);
      const dirty = (await this.redis.smembers('sa:jintake:cnt:dirty')).filter((k) =>
        this.sourceIds.some((id) => k.startsWith(`sa:jintake:cnt:${id.toString()}:`)),
      );
      if (dirty.length > 0) await this.redis.srem('sa:jintake:cnt:dirty', ...dirty);
    } finally {
      await this.prisma.$disconnect();
      this.redis.disconnect();
      this.s3.destroy();
    }
  }

  private async scan(pattern: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';
    do {
      const [next, batch] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
      cursor = next;
      keys.push(...batch);
    } while (cursor !== '0');
    return keys;
  }
}
