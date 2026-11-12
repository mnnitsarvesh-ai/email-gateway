import {
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectTaggingCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { randomBytes, randomUUID } from 'node:crypto';
import { MetricsService, S3Service, uuidv7, withTransactionDefaults } from '@email-gateway/common';
import { s3ConfigSchema } from '@email-gateway/config';
import {
  type MessageDirection,
  type MessageOutbox,
  type MessageStatus,
  type PolicyExecutionLog,
  type Prisma,
  PrismaClient,
} from '@email-gateway/database';
import { type EventEnvelope, EventTypes } from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import { canonicalJson, POLICY_DEFAULT_PLATFORM_ID, sha256Hex } from '@email-gateway/policy-dsl';
import { urlRewriteConfig } from '../../src/core.module';
import { loadWorkerConfig } from '../../src/config';
import { S3PolicyCopyWriter } from '../../src/delivery/policy-copy';
import { CopyFactsReader } from '../../src/delivery/policy-url-rewrite';
import { DirectoryRepository } from '../../src/evaluation/directory.repository';
import {
  PolicyEvaluationService,
  type TriggerPayload,
} from '../../src/evaluation/evaluation.service';
import { FactsRepository } from '../../src/evaluation/facts.repository';
import { PolicyEvaluateConsumer } from '../../src/evaluation/policy-evaluate.consumer';
import { SnapshotCache } from '../../src/evaluation/snapshot-cache';
import { type LoadedSnapshot, SnapshotRepository } from '../../src/evaluation/snapshot.repository';
import { PolicyMetrics, type PolicyRead } from '../../src/metrics/policy-metrics';
import { QuarantineMetrics, type QuarantineRead } from '../../src/metrics/quarantine-metrics';
import { DigestScheduler } from '../../src/quarantine/digest-scheduler';
import { DisposalFactsReader, S3QuarantineObjects } from '../../src/quarantine/disposal';
import { ReleaseExecutor } from '../../src/quarantine/release-executor';
import { ReleaseFactsReader } from '../../src/quarantine/release-facts';
import { QuarantineReleaseConsumer } from '../../src/quarantine/release.consumer';
import { QuarantineSettingsRepository } from '../../src/quarantine/settings.repository';
import { QuarantineStoreWriter } from '../../src/quarantine/store-writer';
import { QuarantineSweeper } from '../../src/quarantine/sweeper';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export const silentLogger: Logger = createLogger({ service: 'policy-engine-it', level: 'silent' });

export const TX_TIMEOUT_MS = 120_000;

export const DEFAULT_EML = [
  'Received: from mail.partner.example by mx.gateway.local',
  'From: Alice <alice@partner.example>',
  'To: bob@corp.example',
  'Subject: quarterly numbers',
  'X-EG-Policy-Tag: forged-by-sender',
  'Message-ID: <it@partner.example>',
  '',
  'Hello Bob.',
  '.leading dot line',
  '',
].join('\r\n');

export interface MessageFixture {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  emlObjectKey: string;
  scanId: bigint | null;
  round: number;
  recipients: { id: bigint; rcptSeq: number; address: string }[];
}

/** Lifecycle paths a fixture is inserted with (rows of every step, like the other suites). */
const PATHS: Record<string, [MessageStatus, string, string][]> = {
  persisted: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
  ],
  scanned: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
    ['scanning', 'scan_started', 'scanner'],
    ['scanned', 'scan_complete', 'scanner'],
  ],
  scan_failed: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
    ['scanning', 'scan_started', 'scanner'],
    ['scan_failed', 'scan_timeout', 'scanner'],
  ],
};

/**
 * The engine configuration of the suites: the repository's .env (URL click-token key, click base
 * URL and bounds), loaded the way the service does. Never printed.
 */
export function engineConfig(overrides: Record<string, string> = {}) {
  return loadWorkerConfig({ ...process.env, ...overrides });
}

/** The pipeline as EvaluationModule builds it, on a given client (the fixtures' by default). */
export function buildPipeline(
  prisma: PrismaClient,
  s3: S3Service,
  options: {
    consumer: string;
    cacheEntries?: number;
    service?: MetricsService;
    config?: Record<string, string>;
  },
) {
  const config = engineConfig(options.config);
  const service = options.service ?? new MetricsService({ service: 'policy-engine-it' });
  const metrics = new PolicyMetrics(service);
  const quarantineMetrics = new QuarantineMetrics(service);
  const inconsistent = (read: PolicyRead) => metrics.inconsistentReads.inc({ read });
  const qInconsistent = (read: QuarantineRead) => quarantineMetrics.inconsistentReads.inc({ read });
  const rewrite = urlRewriteConfig(config);
  const bounds = {
    maxHoldDays: config.QUARANTINE_MAX_HOLD_DAYS,
    maxReviewDays: config.QUARANTINE_MAX_REVIEW_DAYS,
  };
  const evaluation = new PolicyEvaluationService({
    facts: new FactsRepository(inconsistent),
    snapshots: new SnapshotRepository(
      new SnapshotCache<LoadedSnapshot>(options.cacheEntries ?? 100),
      POLICY_DEFAULT_PLATFORM_ID,
      inconsistent,
    ),
    directory: new DirectoryRepository(inconsistent),
    copies: new S3PolicyCopyWriter(s3.client, s3.mailBucket, {
      maxMessageBytes: 26_214_400,
      maxHeaderBytes: 262_144,
    }),
    quarantine: {
      store: new QuarantineStoreWriter(qInconsistent),
      settings: new QuarantineSettingsRepository(bounds, qInconsistent, () =>
        quarantineMetrics.settingsInvalid.inc(),
      ),
      copyFacts: new CopyFactsReader(rewrite, inconsistent),
      urlRewrite: rewrite,
      bannerMaxPartBytes: config.POLICY_BANNER_MAX_PART_BYTES,
      bounds,
    },
    metrics,
    logger: silentLogger,
    copyTimeoutMs: 60_000,
  });
  const feed = { start: () => undefined, stop: () => Promise.resolve() };
  const consumer = new PolicyEvaluateConsumer(
    feed,
    evaluation,
    prisma,
    metrics,
    TX_TIMEOUT_MS,
    options.consumer,
    quarantineMetrics,
  );
  return { evaluation, consumer, metrics, quarantineMetrics, registry: service, config };
}

/**
 * Per-run fixtures in `it-pe-<suffix>-*` organizations on the real writer and MinIO, and
 * cleanup of every row and object the engine can write for them.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly s3 = new S3Service(s3ConfigSchema.parse(process.env));
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private readonly consumers = new Set<string>();
  private readonly eventIds = new Set<string>();
  private planId: bigint | undefined;

  consumer(label: string): string {
    const name = `it-pe-${this.suffix}.${label}`;
    this.consumers.add(name);
    return name;
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-pe-${this.suffix}`,
          name: 'policy-engine integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-pe-${this.suffix}-${label}`,
        name: `Policy ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status: 'active',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  /**
   * A message with its EML in MinIO, recipients and, for scanned / scan_failed rounds, the
   * round's `email_scans` row, `rspamd` final, auth row and (scanned) a clean revision-0 risk row.
   */
  async message(
    organizationId: bigint,
    options: {
      state?: 'scanned' | 'scan_failed' | 'persisted';
      direction?: MessageDirection;
      recipients?: string[];
      round?: number;
      risk?: boolean;
      eml?: string;
    } = {},
  ): Promise<MessageFixture> {
    const state = options.state ?? 'scanned';
    const path = PATHS[state]!;
    const round = options.round ?? 0;
    const receivedAt = new Date(Math.floor(Date.now() / 1000) * 1000);
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-pe-${randomUUID()}`, receivedAt },
      select: { id: true },
    });
    const messageId = identity.id;
    const emlObjectKey = `org/${organizationId.toString()}/eml/it/${randomUUID()}.eml`;
    const eml = options.eml ?? DEFAULT_EML;
    await this.s3.client.send(
      new PutObjectCommand({
        Bucket: this.s3.mailBucket,
        Key: emlObjectKey,
        Body: Buffer.from(eml, 'latin1'),
      }),
    );
    const direction = options.direction ?? 'inbound';
    const recipients = options.recipients ?? ['bob@corp.example'];
    await this.prisma.emailMessage.create({
      data: {
        id: messageId,
        receivedAt,
        organizationId,
        direction,
        status: path[path.length - 1]![0],
        version: path.length - 1,
        lifecycleRound: round,
        statusReason: path[path.length - 1]![1],
        statusChangedAt: receivedAt,
        envelopeFrom: direction === 'inbound' ? 'alice@partner.example' : 'bob@corp.example',
        headerFrom: direction === 'inbound' ? 'alice@partner.example' : 'bob@corp.example',
        sizeBytes: Buffer.byteLength(eml, 'latin1'),
        recipientCount: recipients.length,
        emlObjectKey,
        emlSha256: '0'.repeat(64),
        clientIp: '198.51.100.7',
        clientName: 'mx1.partner.example',
      },
    });
    await this.prisma.emailMessageStatusHistory.createMany({
      data: path.map(([toStatus, reasonCode, actorRole], version) => ({
        receivedAt,
        messageId,
        organizationId,
        version,
        fromStatus: version === 0 ? null : path[version - 1]![0],
        toStatus,
        reasonCode,
        lifecycleRound: version === path.length - 1 ? round : 0,
        actorRole,
        actorService: 'policy-engine-it',
        changedAt: receivedAt,
        occurredAt: receivedAt,
      })),
    });
    await this.prisma.emailRecipient.createMany({
      data: recipients.map((address, rcptSeq) => ({
        receivedAt,
        messageId,
        organizationId,
        rcptSeq,
        address,
        direction,
      })),
    });
    const rows = await this.prisma.emailRecipient.findMany({
      where: { messageId, receivedAt },
      orderBy: { rcptSeq: 'asc' },
      select: { id: true, rcptSeq: true, address: true },
    });
    const fixture: MessageFixture = {
      messageId,
      receivedAt,
      organizationId,
      emlObjectKey,
      scanId: null,
      round,
      recipients: rows,
    };
    if (state === 'persisted') {
      await this.prisma.emailMessageParse.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          status: 'parse_failed',
          attempts: 1,
          parserVersion: 'mime/1',
          failureReason: 'parser_error',
          startedAt: receivedAt,
          completedAt: receivedAt,
        },
      });
      return fixture;
    }
    fixture.scanId = await this.round(fixture, {
      failed: state === 'scan_failed',
      risk: options.risk ?? state === 'scanned',
    });
    return fixture;
  }

  /** The rows of one scan round (also used for a rescan: round + 1). */
  async round(
    m: MessageFixture,
    options: { failed?: boolean; risk?: boolean } = {},
  ): Promise<bigint> {
    const base = {
      receivedAt: m.receivedAt,
      messageId: m.messageId,
      organizationId: m.organizationId,
    };
    const scan = await this.prisma.emailScan.create({
      data: {
        ...base,
        scanKind: m.round === 0 ? 'initial' : 'rescan',
        status: options.failed ? 'timed_out' : 'completed',
        lifecycleRound: m.round,
        scanVerdict: options.failed ? 'timeout' : 'clean',
        requiredEngines: ['rspamd'],
        reasonCodes: [],
        startedAt: m.receivedAt,
        completedAt: m.receivedAt,
      },
      select: { id: true },
    });
    await this.prisma.scanEngineResult.create({
      data: {
        ...base,
        scanId: scan.id,
        engine: 'rspamd',
        isFinal: true,
        outcome: options.failed ? 'timeout' : 'clean',
        durationMs: 5,
        completedAt: m.receivedAt,
        reasonCodes: [],
      },
    });
    await this.prisma.emailAuthResult.create({
      data: {
        ...base,
        scanId: scan.id,
        engine: 'rspamd',
        spf: 'pass',
        dkim: 'pass',
        dmarc: 'pass',
        dmarcPolicy: 'reject',
        arc: 'none',
      },
    });
    if (options.risk) {
      await this.prisma.messageRiskScore.create({
        data: {
          ...base,
          scanId: scan.id,
          lifecycleRound: m.round,
          revision: 0,
          direction: 'inbound',
          status: 'scored',
          score: 40,
          level: 'none',
          verdict: 'clean',
          recommendedAction: 'deliver',
          hardBlocks: [],
          reasonCodes: [],
          contributions: [],
          groups: {},
          engines: [{ engine: 'rspamd', status: 'definite', outcome: 'clean' }],
          failures: [],
          floors: [],
          trust: {},
          evidence: { aiRaiseOnly: false },
          explanation: [],
          explanationText: '',
          profileSource: 'platform',
          profileIdText: 'rsk-default/1',
          profileSha256: '0'.repeat(64),
          inputSha256: '0'.repeat(64),
          scorerVersion: 'risk/1',
          signalMapVersion: 'map/1',
          inputVersion: 'risk-input/1',
          durationUs: 10,
        },
      });
    }
    return scan.id;
  }

  /** The round's `url_rewrites` row and its object (rewritten copy). */
  async rewrite(m: MessageFixture, eml: string): Promise<string> {
    const key = `org/${m.organizationId.toString()}/rewrite/it/${m.messageId.toString()}/r${m.round}-${randomUUID()}.eml`;
    await this.s3.client.send(
      new PutObjectCommand({
        Bucket: this.s3.mailBucket,
        Key: key,
        Body: Buffer.from(eml, 'latin1'),
      }),
    );
    await this.prisma.urlRewrite.create({
      data: {
        receivedAt: m.receivedAt,
        messageId: m.messageId,
        organizationId: m.organizationId,
        scanId: m.scanId!,
        lifecycleRound: m.round,
        status: 'rewritten',
        objectKey: key,
        settingsVersion: 'it/1',
      },
    });
    return key;
  }

  /** Moves a fixture to the next round (as a rescan E19 + E6 would) with new round rows. */
  async rescan(m: MessageFixture): Promise<MessageFixture> {
    const current = await this.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: m.messageId, receivedAt: m.receivedAt } },
      select: { status: true, version: true, lifecycleRound: true },
    });
    const round = current.lifecycleRound + 1;
    const steps: [MessageStatus, string, string][] = [
      ['scanning', 'admin_rescan', 'operator'],
      ['scanned', 'scan_complete', 'scanner'],
    ];
    let version = current.version;
    let from = current.status;
    for (const [toStatus, reasonCode, actorRole] of steps) {
      version += 1;
      await this.prisma.emailMessageStatusHistory.create({
        data: {
          receivedAt: m.receivedAt,
          messageId: m.messageId,
          organizationId: m.organizationId,
          version,
          fromStatus: from,
          toStatus,
          reasonCode,
          lifecycleRound: round,
          actorRole,
          actorService: 'policy-engine-it',
          changedAt: new Date(),
          occurredAt: new Date(),
        },
      });
      from = toStatus;
    }
    await this.prisma.emailMessage.update({
      where: { id_receivedAt: { id: m.messageId, receivedAt: m.receivedAt } },
      data: { status: 'scanned', version, lifecycleRound: round, statusReason: 'scan_complete' },
    });
    const next: MessageFixture = { ...m, round };
    next.scanId = await this.round(next, { risk: true });
    return next;
  }

  /** `mail.message.scanned.v1` of the fixture's round, as the scan stage writes it. */
  scanned(
    m: MessageFixture,
    outcome: 'scanned' | 'scan_failed' = 'scanned',
  ): EventEnvelope<TriggerPayload> {
    const eventId = uuidv7();
    this.eventIds.add(eventId);
    return {
      eventId,
      eventType: EventTypes.MessageScanned,
      occurredAt: new Date().toISOString(),
      correlationId: `it-pe-${this.suffix}`,
      organizationId: m.organizationId.toString(),
      payload: {
        messageId: m.messageId.toString(),
        receivedAt: m.receivedAt.toISOString(),
        direction: 'inbound',
        emlS3Key: m.emlObjectKey,
        lifecycleRound: m.round,
        scanId: m.scanId!.toString(),
        scanKind: m.round === 0 ? 'initial' : 'rescan',
        outcome,
        verdict: outcome === 'scanned' ? 'clean' : 'timeout',
        engines: [
          {
            engine: 'rspamd',
            required: true,
            outcome: outcome === 'scanned' ? 'clean' : 'timeout',
            attempts: 1,
          },
        ],
        reasonCodes: [],
        completedAt: m.receivedAt.toISOString(),
      },
    };
  }

  parseFailed(m: MessageFixture): EventEnvelope<TriggerPayload> {
    const eventId = uuidv7();
    this.eventIds.add(eventId);
    return {
      eventId,
      eventType: EventTypes.MessageParseFailed,
      occurredAt: new Date().toISOString(),
      correlationId: `it-pe-${this.suffix}`,
      organizationId: m.organizationId.toString(),
      payload: {
        messageId: m.messageId.toString(),
        receivedAt: m.receivedAt.toISOString(),
        direction: 'inbound',
        emlS3Key: m.emlObjectKey,
        reason: 'parser_error',
        attempts: 1,
        parserVersion: 'mime/1',
      },
    };
  }

  /**
   * Publishes and activates a policy version as the api does (P17): the policy (created once
   * per name), a published version with the canonical hash, the pointer, and
   * `policy_settings.generation + 1` in one transaction.
   */
  async publish(
    organizationId: bigint,
    name: string,
    doc: Record<string, unknown>,
  ): Promise<{ publicId: string; versionNo: number; versionId: bigint; generation: bigint }> {
    return this.prisma.$transaction(async (tx) => {
      const settings = await tx.policySettings.upsert({
        where: { organizationId },
        create: { organizationId, generation: 0, settings: {}, settingsSha256: sha256Hex('{}') },
        update: {},
      });
      const policy =
        (await tx.emailPolicy.findFirst({ where: { organizationId, name } })) ??
        (await tx.emailPolicy.create({
          data: {
            organizationId,
            name,
            direction: doc.direction as 'inbound',
            priority: doc.priority as number,
            status: 'draft',
          },
        }));
      const last = await tx.policyVersion.aggregate({
        where: { policyId: policy.id },
        _max: { version: true },
      });
      const versionNo = (last._max.version ?? 0) + 1;
      const version = await tx.policyVersion.create({
        data: {
          organizationId,
          policyId: policy.id,
          version: versionNo,
          status: 'published',
          definition: doc as unknown as Prisma.InputJsonValue,
          definitionSha256: sha256Hex(canonicalJson(doc)),
          dslVersion: 'policy-dsl/1',
          references: { departmentIds: [], userIds: [] },
          ruleCount: (doc.rules as unknown[]).length,
          publishedAt: new Date(),
        },
      });
      await tx.emailPolicy.update({
        where: { id: policy.id },
        data: { activeVersionId: version.id, status: 'active', rowVersion: { increment: 1 } },
      });
      const bumped = await tx.policySettings.update({
        where: { id: settings.id },
        data: { generation: { increment: 1 }, rowVersion: { increment: 1 } },
      });
      return {
        publicId: policy.publicId,
        versionNo,
        versionId: version.id,
        generation: bumped.generation,
      };
    });
  }

  async department(organizationId: bigint, name: string, addresses: string[]): Promise<string> {
    const dept = await this.prisma.tenantDepartment.create({
      data: { organizationId, name },
      select: { id: true, publicId: true },
    });
    for (const address of addresses) {
      await this.prisma.tenantDepartmentMember.create({
        data: { organizationId, departmentId: dept.id, address },
      });
    }
    return dept.publicId;
  }

  /** A tenant user (lower-cased e-mail); `deleted` sets `deleted_at`. */
  async user(
    organizationId: bigint,
    email: string,
    options: { status?: 'invited' | 'active' | 'disabled' | 'locked'; deleted?: boolean } = {},
  ): Promise<{ id: bigint; publicId: string }> {
    return this.prisma.user.create({
      data: {
        organizationId,
        email: email.toLowerCase(),
        displayName: email,
        status: options.status ?? 'active',
        ...(options.deleted ? { deletedAt: new Date() } : {}),
      },
      select: { id: true, publicId: true },
    });
  }

  /** An API key of the organization created by `createdByUserId` (never used to call). */
  apiKey(
    organizationId: bigint,
    createdByUserId: bigint | null,
  ): Promise<{ id: bigint; publicId: string }> {
    const prefix = `itpe${randomBytes(6).toString('hex')}`;
    return this.prisma.apiKey.create({
      data: {
        organizationId,
        name: `it-${prefix}`,
        keyPrefix: prefix,
        keyHash: '0'.repeat(64),
        scopes: [],
        createdByUserId,
      },
      select: { id: true, publicId: true },
    });
  }

  /** User members (`user_id`, address NULL) of a department, by its public id. */
  async addUserMembers(organizationId: bigint, departmentPublicId: string, userIds: bigint[]) {
    const dept = await this.prisma.tenantDepartment.findUniqueOrThrow({
      where: { publicId: departmentPublicId },
      select: { id: true },
    });
    await this.prisma.tenantDepartmentMember.createMany({
      data: userIds.map((userId) => ({ organizationId, departmentId: dept.id, userId })),
    });
  }

  async lifecycle(m: MessageFixture) {
    const row = await this.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: m.messageId, receivedAt: m.receivedAt } },
      select: {
        status: true,
        statusReason: true,
        version: true,
        lifecycleRound: true,
        finalAction: true,
        finalVerdict: true,
        riskScore: true,
      },
    });
    const history = await this.prisma.emailMessageStatusHistory.findMany({
      where: { messageId: m.messageId, receivedAt: m.receivedAt },
      orderBy: { version: 'asc' },
    });
    return { ...row, history };
  }

  evaluations(m: MessageFixture): Promise<PolicyExecutionLog[]> {
    return this.prisma.policyExecutionLog.findMany({
      where: { messageId: m.messageId, receivedAt: m.receivedAt },
      orderBy: { evaluationSeq: 'asc' },
    });
  }

  outbox(m: MessageFixture, eventType?: string): Promise<MessageOutbox[]> {
    return this.prisma.messageOutbox.findMany({
      where: {
        aggregateId: m.messageId.toString(),
        organizationId: m.organizationId,
        ...(eventType ? { eventType } : {}),
      },
      orderBy: { id: 'asc' },
    });
  }

  async object(key: string): Promise<{
    body: Buffer;
    tags: Record<string, string>;
    contentType?: string;
    versions: number;
  }> {
    const got = await this.s3.client.send(
      new GetObjectCommand({ Bucket: this.s3.mailBucket, Key: key }),
    );
    const body = Buffer.from(await got.Body!.transformToByteArray());
    const tagging = await this.s3.client.send(
      new GetObjectTaggingCommand({ Bucket: this.s3.mailBucket, Key: key }),
    );
    const versions = await this.s3.client.send(
      new ListObjectVersionsCommand({ Bucket: this.s3.mailBucket, Prefix: key }),
    );
    return {
      body,
      tags: Object.fromEntries((tagging.TagSet ?? []).map((t) => [t.Key!, t.Value!])),
      ...(got.ContentType ? { contentType: got.ContentType } : {}),
      versions: (versions.Versions ?? []).filter((v) => v.Key === key).length,
    };
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.quarantineReleaseLog.deleteMany({ where });
        await this.prisma.quarantineAction.deleteMany({ where });
        await this.prisma.quarantineApprovalRequest.deleteMany({ where });
        await this.prisma.quarantineDownloadGrant.deleteMany({ where });
        await this.prisma.quarantineDigest.deleteMany({ where });
        await this.prisma.quarantineDigestRun.deleteMany({ where });
        await this.prisma.quarantineObjectPurge.deleteMany({ where });
        await this.prisma.quarantineUserPreference.deleteMany({ where });
        await this.prisma.quarantineSettings.deleteMany({ where });
        await this.prisma.quarantineMessage.deleteMany({ where });
        await this.prisma.archiveLegalHold.deleteMany({ where });
        await this.prisma.emailArchive.deleteMany({ where });
        await this.prisma.organizationSetting.deleteMany({ where });
        await this.prisma.messageUrl.deleteMany({ where });
        await this.prisma.policyExecutionLog.deleteMany({ where });
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.urlRewrite.deleteMany({ where });
        await this.prisma.messageRiskScore.deleteMany({ where });
        await this.prisma.emailAuthResult.deleteMany({ where });
        await this.prisma.scanEngineResult.deleteMany({ where });
        await this.prisma.emailScan.deleteMany({ where });
        await this.prisma.emailMessageParse.deleteMany({ where });
        await this.prisma.emailDelivery.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.tenantDepartmentMember.deleteMany({ where });
        await this.prisma.tenantDepartment.deleteMany({ where });
        await this.prisma.apiKey.deleteMany({ where });
        await this.prisma.user.deleteMany({ where });
        await this.prisma.emailPolicy.updateMany({ where, data: { activeVersionId: null } });
        await this.prisma.policyVersion.deleteMany({ where });
        await this.prisma.emailPolicy.deleteMany({ where });
        await this.prisma.policySettings.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
        for (const id of ids) await this.deletePrefix(`org/${id.toString()}/`);
      }
      if (this.eventIds.size > 0) {
        await this.prisma.messageIdempotency.deleteMany({
          where: { eventId: { in: [...this.eventIds] } },
        });
        await this.prisma.messageConsumerProgress.deleteMany({
          where: { eventId: { in: [...this.eventIds] } },
        });
      }
      if (this.consumers.size > 0) {
        await this.prisma.messageIdempotency.deleteMany({
          where: { consumer: { in: [...this.consumers] } },
        });
        await this.prisma.messageConsumerProgress.deleteMany({
          where: { consumer: { in: [...this.consumers] } },
        });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
      this.s3.onModuleDestroy();
    }
  }

  /** Every version of every object under the prefix (the mail bucket is versioned). */
  private async deletePrefix(prefix: string): Promise<void> {
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    do {
      const page = await this.s3.client.send(
        new ListObjectVersionsCommand({
          Bucket: this.s3.mailBucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionMarker,
        }),
      );
      for (const v of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
        await this.s3.client.send(
          new DeleteObjectCommand({
            Bucket: this.s3.mailBucket,
            Key: v.Key!,
            VersionId: v.VersionId,
          }),
        );
      }
      keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
      versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
    } while (keyMarker);
    const rest = await this.s3.client.send(
      new ListObjectsV2Command({ Bucket: this.s3.mailBucket, Prefix: prefix }),
    );
    if ((rest.Contents ?? []).length > 0) throw new Error(`objects left under ${prefix}`);
  }
}

/** A leader lock that always leads (the suites sweep their own organizations only). */
export const alwaysLeader = {
  ensure: () => Promise.resolve(true),
  release: () => Promise.resolve(),
};

/**
 * The quarantine role as QuarantineModule builds it (executor, consumer with an idle feed,
 * sweeper restricted to the suite's organizations), on the fixtures' client and MinIO.
 */
export function buildQuarantine(
  prisma: PrismaClient,
  s3: S3Service,
  options: {
    consumer: string;
    organizationIds: bigint[];
    service?: MetricsService;
    config?: Record<string, string>;
    now?: () => Date;
    /** Digest scheduler bounds (default 200 organizations, 5000 users per sweep). */
    digestBatchSize?: number;
    digestMaxUsersPerSweep?: number;
  },
) {
  const config = engineConfig(options.config);
  const service = options.service ?? new MetricsService({ service: 'policy-engine-it-q' });
  const metrics = new PolicyMetrics(service);
  const q = new QuarantineMetrics(service);
  const inconsistent = (read: PolicyRead) => metrics.inconsistentReads.inc({ read });
  const sink = (read: QuarantineRead) => q.inconsistentReads.inc({ read });
  const rewrite = urlRewriteConfig(config);
  const bounds = {
    maxHoldDays: config.QUARANTINE_MAX_HOLD_DAYS,
    maxReviewDays: config.QUARANTINE_MAX_REVIEW_DAYS,
  };
  const settings = new QuarantineSettingsRepository(bounds, sink, () => q.settingsInvalid.inc());
  const store = new QuarantineStoreWriter(sink);
  const objects = new S3QuarantineObjects(s3.client, s3.mailBucket);
  const executor = new ReleaseExecutor({
    facts: new FactsRepository(inconsistent),
    snapshots: new SnapshotRepository(
      new SnapshotCache<LoadedSnapshot>(100),
      POLICY_DEFAULT_PLATFORM_ID,
      inconsistent,
    ),
    directory: new DirectoryRepository(inconsistent),
    releaseFacts: new ReleaseFactsReader(sink),
    settings,
    store,
    copies: new S3PolicyCopyWriter(s3.client, s3.mailBucket, {
      maxMessageBytes: 26_214_400,
      maxHeaderBytes: 262_144,
    }),
    copyFacts: new CopyFactsReader(rewrite, inconsistent),
    objectExists: (key, signal) => objects.exists(key, signal),
    urlRewrite: rewrite,
    bannerMaxPartBytes: config.POLICY_BANNER_MAX_PART_BYTES,
    bounds,
    staleness: {
      maxVerdictAgeHours: config.QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS,
      signatureMaxLagHours: config.QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS,
    },
    copyTimeoutMs: 60_000,
    policySink: inconsistent,
    sink,
    lifecycleMetrics: metrics.lifecycle,
    logger: silentLogger,
    ...(options.now ? { now: options.now } : {}),
  });
  const feed = { start: () => undefined, stop: () => Promise.resolve() };
  const consumer = new QuarantineReleaseConsumer(
    feed,
    executor,
    prisma,
    q,
    TX_TIMEOUT_MS,
    options.consumer,
  );
  const sweeper = new QuarantineSweeper({
    prisma,
    locks: alwaysLeader,
    objects,
    store,
    settings,
    disposal: new DisposalFactsReader(sink),
    digests: new DigestScheduler({
      prisma: withTransactionDefaults(prisma, { timeoutMs: TX_TIMEOUT_MS }),
      settings,
      sink,
      logger: silentLogger,
      maxUsersPerSweep: options.digestMaxUsersPerSweep ?? 5_000,
      batchSize: options.digestBatchSize ?? 200,
      organizationIds: options.organizationIds,
    }),
    metrics: q,
    lifecycleMetrics: metrics.lifecycle,
    sink,
    logger: silentLogger,
    intervalMs: 60_000,
    txTimeoutMs: TX_TIMEOUT_MS,
    batchSize: 200,
    retentionDays: config.QUARANTINE_ENTRY_RETENTION_DAYS,
    bounds,
    organizationIds: options.organizationIds,
    ...(options.now ? { now: options.now } : {}),
  });
  return { executor, consumer, sweeper, metrics: q, registry: service, objects };
}
