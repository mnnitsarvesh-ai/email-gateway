import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import {
  type AdvisoryLocks,
  AmqpConnection,
  ConfirmPublisher,
  type HandleOutcome,
  MetricsService,
  uuidv7,
} from '@email-gateway/common';
import type {
  EmailScan,
  MessageOutbox,
  Prisma,
  PrismaClient,
  SandboxAnalysis,
  SandboxSubmission,
  ScanEngineResult,
} from '@email-gateway/database';
import {
  type AttachmentSandboxRequestedV1,
  type EventEnvelope,
  EventTypes,
  type SandboxTaskCompletedV1,
} from '@email-gateway/event-contracts';
import type { WorkerConfig } from '../../src/config';
import { classifyScanFailure } from '../../src/scanning/engine-consumer';
import { createSandboxJobs, type SandboxJobs } from '../../src/scanning/sandbox/sandbox-engine';
import { ScanMetrics } from '../../src/scanning/scan-metrics';
import { ScanRepository } from '../../src/scanning/scan-repository';
import type { ScanRound } from '../../src/scanning/scan-store';
import { AttachmentFixtures, type AttachmentMessage, testLocks } from './attachments';
import { createTestVhost, type TestVhost } from './broker';
import { silentLogger, workerConfig } from './fixtures';
import type { ScanFixtures } from './scan';

const REPO_ROOT = resolve(__dirname, '../../../..');

/** Overrides of the sandbox suites (the rest comes from the repository's .env). */
export const SANDBOX_IT: Record<string, string> = {
  SANDBOX_ENABLED: 'true',
  SCAN_CONSUMERS: 'sandbox',
  SCAN_RETRY_BASE_MS: '100',
  SCAN_RETRY_MAX_MS: '200',
  SCAN_S3_TIMEOUT_MS: '3000',
  SANDBOX_PUBLISH_HASHES: 'false',
};

/** A synthetic benign shell script (never executed: the sandbox here is the email-worker side). */
export const benignScript = (label: string): Buffer =>
  Buffer.from(
    `#!/bin/sh\n# eg sandbox integration ${label} ${randomBytes(8).toString('hex')}\necho ok\n`,
  );

export interface SandboxRound {
  message: AttachmentMessage;
  scan: ScanRound;
  attachmentId: bigint;
  objectKey: string;
  sha256: string;
  /** The `sandbox_requested.v1` envelope as the event-relay publishes it. */
  event: EventEnvelope<AttachmentSandboxRequestedV1>;
}

/**
 * Fixtures of the sandbox suites (step 4.6 §9.2) on the real MySQL writer and MinIO: tenants
 * with the plan feature and the `sandbox` engine setting, rounds opened and finalized through
 * the real `ScanRepository` (the attachment final writes the `sandbox_submissions` row and its
 * `sandbox_requested.v1` outbox row exactly as step 4.2 does), sandbox bucket helpers and the
 * cleanup of every row and object the sandbox engine writes for the run.
 */
export class SandboxFixtures {
  readonly att: AttachmentFixtures;
  readonly config: Readonly<WorkerConfig>;
  readonly repo: ScanRepository;
  readonly taskIds = new Set<string>();
  readonly hashes = new Set<string>();
  private readonly lockName: string;
  private readonly locks: AdvisoryLocks[] = [];

  constructor(
    readonly fx: ScanFixtures,
    overrides: Record<string, string> = {},
  ) {
    this.att = new AttachmentFixtures(fx);
    this.config = workerConfig({ ...SANDBOX_IT, ...overrides });
    const metrics = new ScanMetrics(new MetricsService({ service: `it-sbx-${fx.suffix}` }));
    this.repo = new ScanRepository(fx.prisma, this.config.SCAN_DB_TIMEOUT_MS, metrics.lifecycle);
    this.lockName = `scan:sandbox:it-${fx.suffix}`;
  }

  get prisma(): PrismaClient {
    return this.fx.prisma;
  }

  get bucket(): string {
    return this.config.SANDBOX_S3_BUCKET;
  }

  /** A tenant with the plan feature `attachment_sandbox` and/or the `sandbox` setting. */
  async tenant(
    label: string,
    options: { feature?: boolean; settings?: Record<string, unknown> | null } = {},
  ): Promise<bigint> {
    const org = await this.fx.organization(label);
    if (options.feature !== false) {
      await this.prisma.organizationFeature.create({
        data: { organizationId: org, featureKey: 'attachment_sandbox', enabled: true },
      });
    }
    const settings = options.settings === undefined ? { enabled: true } : options.settings;
    if (settings !== null) {
      await this.prisma.scanEngineSetting.create({
        data: {
          organizationId: org,
          engine: 'sandbox',
          settings: settings as Prisma.InputJsonObject,
        },
      });
    }
    return org;
  }

  /** The sandbox engine wired as ScanningModule wires it, with per-run ledger and lock names. */
  jobs(
    options: { now?: () => Date; connection?: AmqpConnection; publisher?: ConfirmPublisher } = {},
  ) {
    const registry = new MetricsService({ service: `it-sbx-${randomUUID().slice(0, 6)}` });
    // Handlers are called in-process unless a test passes its vhost connection (never started here).
    const connection =
      options.connection ??
      new AmqpConnection({
        urls: ['amqp://unused:unused@127.0.0.1:1/unused'],
        connectionName: 'it-sandbox-unused',
        logger: silentLogger,
      });
    const publisher =
      options.publisher ??
      new ConfirmPublisher({
        connection,
        logger: silentLogger,
        appId: 'email-worker',
        confirmTimeoutMs: 1_000,
        maxMessageBytes: 131_072,
      });
    const locks = testLocks();
    this.locks.push(locks);
    const jobs = createSandboxJobs({
      config: this.config,
      prisma: this.prisma,
      s3: this.fx.s3,
      locks,
      registry,
      settingsInvalid: () => undefined,
      connection,
      publisher,
      logger: silentLogger,
      dispatchConsumer: this.fx.consumer('sandbox-dispatch'),
      resultsConsumer: this.fx.consumer('sandbox-results'),
      lockName: this.lockName,
      organizationIds: this.fx.organizationIds,
      ...(options.now ? { now: options.now } : {}),
    });
    return { jobs, registry };
  }

  /**
   * A message with one stored attachment and a round whose attachment final submits it to the
   * sandbox (step 4.2 A11 through `ScanRepository.finalize`). `required` is the round's snapshot
   * of required engines (`['attachment', 'dlp']` keeps the round open after the attachment final).
   */
  async round(
    organizationId: bigint,
    bytes: Buffer,
    options: {
      required?: string[];
      message?: AttachmentMessage;
      lifecycleRound?: number;
    } = {},
  ): Promise<SandboxRound> {
    const message =
      options.message ?? (await this.att.message(organizationId, [{ bytes, filename: 'run.sh' }]));
    const attachment = message.attachments[0]!;
    const record = await this.repo.loadMessage(
      message.messageId,
      message.receivedAt,
      organizationId,
    );
    if (!record) throw new Error('fixture message not found');
    const now = new Date();
    const lifecycleRound = options.lifecycleRound ?? 0;
    const opened = await this.repo.openRound({
      message: record,
      round: lifecycleRound,
      scanKind: lifecycleRound === 0 ? 'initial' : 'rescan',
      trigger: lifecycleRound === 0 ? 'parsed' : 'rescan',
      engine: 'attachment',
      eventId: uuidv7(),
      correlationId: `it-sbx-${this.fx.suffix}`,
      requiredEngines: options.required ?? ['attachment'],
      deadlineSeconds: 1_800,
      now,
    });
    if (opened.kind !== 'open') throw new Error(`round not opened: ${opened.reason}`);
    const result = await this.repo.finalize({
      consumer: this.fx.consumer('attachment-final'),
      eventId: uuidv7(),
      round: opened.round,
      final: {
        engine: 'attachment',
        attempt: 1,
        outcome: 'suspicious',
        errorCode: null,
        engineVersion: 'it-attachment/1',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['type.script'],
        evidence: null,
        durationMs: 5,
        settingsVersion: null,
        auth: null,
        childRows: {
          sandbox: [
            {
              attachmentId: attachment.id,
              partIndex: 1,
              sha256: attachment.sha256,
              sizeBytes: bytes.length,
              detectedType: 'script_shell',
              objectKey: attachment.objectKey!,
              attachmentVerdict: 'suspicious',
              reasonCodes: ['type.script'],
            },
          ],
        },
      },
      completion: { causationEventId: null, correlationId: `it-sbx-${this.fx.suffix}`, now },
    });
    if (result.kind !== 'handled') throw new Error('attachment final not written');
    const submission = await this.prisma.sandboxSubmission.findFirstOrThrow({
      where: { scanId: opened.round.scanId, receivedAt: opened.round.receivedAt },
    });
    const outbox = await this.prisma.messageOutbox.findFirstOrThrow({
      where: { eventId: submission.requestedEventId },
    });
    return {
      message,
      scan: opened.round,
      attachmentId: attachment.id,
      objectKey: attachment.objectKey!,
      sha256: attachment.sha256,
      event: {
        eventId: outbox.eventId,
        eventType: EventTypes.AttachmentSandboxRequested,
        occurredAt: outbox.createdAt.toISOString(),
        correlationId: outbox.correlationId ?? `it-sbx-${this.fx.suffix}`,
        organizationId: outbox.organizationId.toString(),
        payload: outbox.payload as unknown as AttachmentSandboxRequestedV1,
      },
    };
  }

  /** Completes the round with a clean `dlp` final (the second required engine). */
  async completeRound(scan: ScanRound): Promise<void> {
    const result = await this.repo.finalize({
      consumer: this.fx.consumer('dlp-final'),
      eventId: uuidv7(),
      round: scan,
      final: {
        engine: 'dlp',
        attempt: 1,
        outcome: 'clean',
        errorCode: null,
        engineVersion: 'it-dlp/1',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['clean.no_findings'],
        evidence: null,
        durationMs: 5,
        settingsVersion: null,
        auth: null,
      },
      completion: {
        causationEventId: null,
        correlationId: `it-sbx-${this.fx.suffix}`,
        now: new Date(),
      },
    });
    if (result.kind !== 'handled' || result.completion.kind !== 'completed') {
      throw new Error('round not completed');
    }
  }

  /** A `task_completed.v1` envelope as the controller publishes it (tracked for cleanup). */
  resultEvent(
    organizationId: bigint,
    payload: SandboxTaskCompletedV1,
  ): EventEnvelope<SandboxTaskCompletedV1> {
    this.taskIds.add(payload.taskId);
    return {
      eventId: uuidv7(),
      eventType: EventTypes.SandboxTaskCompleted,
      occurredAt: new Date().toISOString(),
      correlationId: `it-sbx-${this.fx.suffix}-result`,
      organizationId: organizationId.toString(),
      payload,
    };
  }

  async putObject(key: string, body: Buffer): Promise<void> {
    await this.fx.s3.client.send(
      new PutObjectCommand({ Bucket: this.bucket, Key: key, Body: body }),
    );
  }

  async getObject(key: string): Promise<Buffer | null> {
    try {
      const out = await this.fx.s3.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      return Buffer.from(await out.Body!.transformToByteArray());
    } catch {
      return null;
    }
  }

  async objectExists(key: string): Promise<boolean> {
    try {
      await this.fx.s3.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch {
      return false;
    }
  }

  analyses(sha256: string): Promise<SandboxAnalysis[]> {
    return this.prisma.sandboxAnalysis.findMany({ where: { sha256 }, orderBy: { id: 'asc' } });
  }

  submission(round: SandboxRound): Promise<SandboxSubmission> {
    return this.prisma.sandboxSubmission.findFirstOrThrow({
      where: { scanId: round.scan.scanId, receivedAt: round.scan.receivedAt },
    });
  }

  finalOf(round: SandboxRound): Promise<ScanEngineResult | null> {
    return this.prisma.scanEngineResult.findFirst({
      where: {
        scanId: round.scan.scanId,
        receivedAt: round.scan.receivedAt,
        engine: 'sandbox',
        isFinal: true,
      },
    });
  }

  scanRow(round: SandboxRound): Promise<EmailScan> {
    return this.prisma.emailScan.findFirstOrThrow({
      where: { id: round.scan.scanId, receivedAt: round.scan.receivedAt },
    });
  }

  outbox(eventType: string, where: Prisma.MessageOutboxWhereInput = {}): Promise<MessageOutbox[]> {
    return this.prisma.messageOutbox.findMany({
      where: { eventType, organizationId: { in: this.fx.organizationIds }, ...where },
      orderBy: { id: 'asc' },
    });
  }

  track(analysis: { publicId: string }): void {
    this.taskIds.add(analysis.publicId);
  }

  async cleanup(): Promise<void> {
    const orgs = this.fx.organizationIds;
    try {
      const analyses = await this.prisma.sandboxAnalysis.findMany({
        where: {
          OR: [{ organizationId: { in: orgs } }, { publicId: { in: [...this.taskIds] } }],
        },
        select: { id: true, publicId: true, sampleObjectKey: true, sha256: true },
      });
      const ids = analyses.map((a) => a.id);
      const artifacts = await this.prisma.sandboxArtifact.findMany({
        where: { analysisId: { in: ids } },
        select: { objectKey: true },
      });
      for (const a of analyses) this.taskIds.add(a.publicId);
      const keys = [
        ...analyses.flatMap((a) => (a.sampleObjectKey ? [a.sampleObjectKey] : [])),
        ...artifacts.map((a) => a.objectKey),
      ];
      for (const key of keys) {
        await this.fx.s3.client
          .send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }))
          .catch(() => undefined);
      }
      await this.prisma.sandboxArtifact.deleteMany({ where: { analysisId: { in: ids } } });
      await this.prisma.sandboxAnalysis.deleteMany({ where: { id: { in: ids } } });
      await this.prisma.sandboxSubmission.deleteMany({ where: { organizationId: { in: orgs } } });
      await this.prisma.organizationFeature.deleteMany({ where: { organizationId: { in: orgs } } });
      const hashes = [...this.hashes, ...analyses.map((a) => a.sha256)];
      if (hashes.length > 0) {
        await this.prisma.malwareSignature.deleteMany({
          where: { sha256: { in: hashes }, source: 'sandbox' },
        });
      }
    } finally {
      for (const locks of this.locks) await locks.close().catch(() => undefined);
      await this.att.cleanup();
    }
  }
}

/** Delivers like the consumer's hold retries: transient and retryable failures are redelivered. */
export async function deliver<T>(
  handle: (event: EventEnvelope<T>) => Promise<HandleOutcome>,
  event: EventEnvelope<T>,
  maxDeliveries = 12,
): Promise<HandleOutcome> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await handle(event);
    } catch (error) {
      if (classifyScanFailure(error) === 'fatal' || attempt >= maxDeliveries) throw error;
      await new Promise((r) => setTimeout(r, 50 * attempt));
    }
  }
}

/** `docker compose pause|unpause minio` (the MinIO-outage test; always unpaused in finally). */
export function composeMinio(action: 'pause' | 'unpause'): void {
  const result = spawnSync('docker', ['compose', action, 'minio'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  });
  if (result.status !== 0)
    throw new Error(`docker compose ${action} minio failed: ${result.stderr}`);
}

/** A throwaway vhost (topology v8) with a relay-like confirm publisher and a scanner connection. */
export class SandboxBroker {
  private constructor(
    readonly vhost: TestVhost,
    readonly connection: AmqpConnection,
    readonly publisher: ConfirmPublisher,
  ) {}

  static async start(): Promise<SandboxBroker> {
    const vhost = await createTestVhost();
    const connection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-sandbox',
      logger: silentLogger,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    const publisher = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    return new SandboxBroker(vhost, connection, publisher);
  }

  async publish(envelope: EventEnvelope<unknown>): Promise<void> {
    const [result] = await this.publisher.publishBatch([{ envelope }]);
    if (result?.outcome !== 'confirmed')
      throw new Error(`publish not confirmed: ${result?.outcome}`);
  }

  async close(): Promise<void> {
    await this.publisher.close();
    await this.connection.close();
    await this.vhost.cleanup();
  }
}

export type { SandboxJobs };
