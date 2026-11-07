import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ListObjectsV2Command, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { type HandleOutcome, MetricsService, uuidv7 } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import { type EventEnvelope, EventTypes } from '@email-gateway/event-contracts';
import type { WorkerConfig } from '../../src/config';
import { EngineAttemptFailedError } from '../../src/scanning/engine';
import { DlpMetrics } from '../../src/scanning/engines/dlp/dlp-metrics';
import type { DlpEngine } from '../../src/scanning/engines/dlp/dlp.engine';
import {
  createDlpEngine,
  type DlpEngineOverrides,
  dlpRegistration,
} from '../../src/scanning/engines/dlp/registration';
import type { ScanTriggerPayload } from '../../src/scanning/round-service';
import { ScanMetrics } from '../../src/scanning/scan-metrics';
import { createRoundService, createScanInfrastructure } from '../../src/scanning/scanning.module';
import { silentLogger, workerConfig } from './fixtures';
import type { ScanFixtures, ScanMessage } from './scan';

const sha = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

export interface DlpAttachmentSpec {
  bytes: Buffer;
  filename?: string | null;
  declaredContentType?: string | null;
  stored?: boolean;
}

export interface DlpMessageSpec {
  direction?: 'inbound' | 'outbound' | 'internal';
  from?: string;
  rcpt?: string[];
  subject?: string;
  text?: string | null;
  html?: string | null;
  attachments?: DlpAttachmentSpec[];
  limitsExceeded?: string[];
}

/** The base overrides of the dlp suites: the dlp engine alone decides a round. */
export const DLP_ONLY: Record<string, string> = {
  SCAN_ENGINES: 'dlp',
  SCAN_CONSUMERS: 'dlp',
  SCAN_SETTINGS_CACHE_TTL_MS: '0',
  DLP_TENANT_DATA_CACHE_TTL_MS: '0',
  SCAN_RETRY_BASE_MS: '100',
  SCAN_RETRY_MAX_MS: '200',
  SCAN_ROUND_DEADLINE_SECONDS: '1800',
  DLP_EXTRACTOR_POOL_SIZE: '2',
  // Source runs spawn the TypeScript child (no prlimit on macOS; Linux hosts have it).
  DLP_EXTRACTOR_RLIMITS: 'best_effort',
};

/**
 * Per-run DLP fixtures (step 4.5 §9 package integration) on top of the scan fixtures: outbound
 * messages with stored text/HTML bodies and attachment parts in MinIO (org-prefixed keys as
 * step 3.1 writes them), parse and attachment rows, the tenant's active domain, DLP policies,
 * rules, exceptions and the compliance row as the api writes them, and the cleanup of every DLP
 * row and evidence object of the run in FK order (evidence objects + rows → results → exceptions
 * → rules → policies → patterns → dictionaries → compliance) before the organizations.
 */
export class DlpFixtures {
  constructor(readonly fx: ScanFixtures) {}

  get prisma(): PrismaClient {
    return this.fx.prisma;
  }

  async domain(organizationId: bigint, name: string): Promise<void> {
    await this.prisma.domain.create({
      data: { organizationId, name, status: 'active', activatedAt: new Date() },
    });
  }

  async message(organizationId: bigint, spec: DlpMessageSpec): Promise<ScanMessage> {
    const message = await this.fx.message(organizationId, {
      eml: Buffer.from('From: a@b.test\r\nSubject: it\r\n\r\nbody\r\n'),
      envelope: {
        direction: spec.direction ?? 'outbound',
        ...(spec.from ? { from: spec.from } : {}),
        ...(spec.rcpt ? { rcpt: spec.rcpt } : {}),
      },
    });
    const { messageId, receivedAt } = message;
    if (spec.subject !== undefined) {
      await this.prisma.emailMessage.updateMany({
        where: { id: messageId, receivedAt, organizationId },
        data: { subject: spec.subject },
      });
    }
    const d = receivedAt;
    const date = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}`;
    const prefix = `org/${organizationId.toString()}/part/${date}/${messageId.toString()}/`;
    const put = async (key: string, body: Buffer) =>
      this.fx.s3.client.send(
        new PutObjectCommand({ Bucket: this.fx.s3.mailBucket, Key: key, Body: body }),
      );
    const body = async (name: string, content: string | null | undefined) => {
      if (content === null || content === undefined) return { key: null, sha: null, size: null };
      const bytes = Buffer.from(content, 'utf8');
      await put(prefix + name, bytes);
      return { key: prefix + name, sha: sha(bytes), size: bytes.length };
    };
    const text = await body('text.txt', spec.text);
    const html = await body('body.html', spec.html);
    const attachments = spec.attachments ?? [];
    await this.prisma.emailMessageParse.create({
      data: {
        receivedAt,
        messageId,
        organizationId,
        status: 'parsed',
        parserVersion: '1.0.0',
        limitsExceeded: spec.limitsExceeded ?? [],
        attachmentCount: attachments.length,
        textBodyObjectKey: text.key,
        textBodySha256: text.sha,
        textBodySizeBytes: text.size,
        htmlBodyObjectKey: html.key,
        htmlBodySha256: html.sha,
        htmlBodySizeBytes: html.size,
        startedAt: receivedAt,
        completedAt: receivedAt,
      },
    });
    for (const [index, a] of attachments.entries()) {
      const partIndex = index + 2;
      const stored = a.stored !== false;
      const objectKey = stored ? `${prefix}${String(partIndex)}.att` : null;
      if (objectKey) await put(objectKey, a.bytes);
      await this.prisma.emailAttachment.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          partIndex,
          partPath: `1.${String(partIndex)}`,
          depth: 1,
          disposition: 'attachment',
          filename: a.filename === undefined ? `file-${String(partIndex)}.bin` : a.filename,
          declaredContentType: a.declaredContentType ?? 'application/octet-stream',
          sizeBytes: a.bytes.length,
          sha256: sha(a.bytes),
          objectKey,
          flags: stored ? [] : ['not_stored_size_limit'],
        },
        select: { id: true },
      });
    }
    return message;
  }

  /** A policy with one rule as the api writes them; returns the public ids. */
  async policy(
    organizationId: bigint,
    rule: { conditions: Record<string, unknown>; action: string },
    directions: string[] = ['outbound', 'internal'],
  ): Promise<{
    policyId: string;
    ruleId: string;
    internalPolicyId: bigint;
    internalRuleId: bigint;
  }> {
    const policy = await this.prisma.dlpPolicy.create({
      data: {
        publicId: uuidv7(),
        organizationId,
        name: `it-dlp-${randomUUID().slice(0, 8)}`,
        priority: 10,
        directions,
      },
    });
    const created = await this.prisma.dlpPolicyRule.create({
      data: {
        publicId: uuidv7(),
        organizationId,
        policyId: policy.id,
        name: 'rule',
        priority: 1,
        conditions: rule.conditions as Prisma.InputJsonObject,
        action: rule.action as never,
      },
    });
    return {
      policyId: policy.publicId,
      ruleId: created.publicId,
      internalPolicyId: policy.id,
      internalRuleId: created.id,
    };
  }

  async exception(
    organizationId: bigint,
    scope: 'recipient_domain' | 'recipient_address' | 'sender_domain' | 'sender_address',
    value: string,
  ): Promise<string> {
    const publicId = uuidv7();
    await this.prisma.dlpException.create({
      data: {
        publicId,
        organizationId,
        scope,
        value,
        targetKey: 'all',
        reason: 'it-dlp exception',
        expiresAt: new Date(Date.now() + 30 * 86_400_000),
      },
    });
    return publicId;
  }

  async compliance(organizationId: bigint, enabled: boolean): Promise<void> {
    const now = new Date();
    const data = {
      aadhaarEnabled: enabled,
      aadhaarBasis: enabled ? ('regulatory_obligation' as const) : null,
      aadhaarReference: enabled ? 'IT-REF-1' : null,
      aadhaarAttested: enabled,
      aadhaarRecordedAt: enabled ? now : null,
      aadhaarReviewDueAt: enabled ? new Date(now.getTime() + 180 * 86_400_000) : null,
    };
    await this.prisma.dlpComplianceSettings.upsert({
      where: { organizationId },
      create: { organizationId, ...data },
      update: { ...data, version: { increment: 1 } },
    });
  }

  results(message: ScanMessage) {
    return this.prisma.dlpScanResult.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { scanId: 'asc' },
    });
  }

  evidenceRows(message: ScanMessage) {
    return this.prisma.dlpEvidence.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { scanId: 'asc' },
    });
  }

  incidents(message: ScanMessage) {
    return this.prisma.messageOutbox.findMany({
      where: {
        organizationId: message.organizationId,
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.MessageDlpIncident,
      },
      orderBy: { id: 'asc' },
    });
  }

  async finals(message: ScanMessage) {
    const rows = await this.prisma.scanEngineResult.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt, engine: 'dlp' },
      orderBy: [{ scanId: 'asc' }, { attempt: 'asc' }],
    });
    return { finals: rows.filter((r) => r.isFinal), attempts: rows.filter((r) => !r.isFinal) };
  }

  async evidenceObjects(organizationId: bigint): Promise<string[]> {
    const page = await this.fx.s3.client.send(
      new ListObjectsV2Command({
        Bucket: this.fx.s3.mailBucket,
        Prefix: `org/${organizationId.toString()}/dlp-evidence/`,
      }),
    );
    return (page.Contents ?? []).map((c) => c.Key!).sort();
  }

  async object(key: string): Promise<Buffer> {
    const out = await this.fx.s3.client.send(
      new GetObjectCommand({ Bucket: this.fx.s3.mailBucket, Key: key }),
    );
    return Buffer.from(await out.Body!.transformToByteArray());
  }

  async cleanup(): Promise<void> {
    const ids = this.fx.organizationIds;
    if (ids.length === 0) return;
    const where = { organizationId: { in: ids } };
    // Evidence objects are removed with the org prefix by ScanFixtures.cleanup (after this).
    await this.prisma.dlpEvidence.deleteMany({ where });
    await this.prisma.dlpScanResult.deleteMany({ where });
    await this.prisma.dlpException.deleteMany({ where });
    await this.prisma.dlpPolicyRule.deleteMany({ where });
    await this.prisma.dlpPolicy.deleteMany({ where });
    await this.prisma.dlpCustomPattern.deleteMany({ where });
    await this.prisma.dlpKeywordDictionary.deleteMany({ where });
    await this.prisma.dlpComplianceSettings.deleteMany({ where });
    await this.prisma.emailAttachment.deleteMany({ where });
    await this.prisma.emailMessageParse.deleteMany({ where });
    await this.prisma.domain.deleteMany({ where });
  }
}

/**
 * The dlp engine wired as ScanningModule wires it (registration, round service, shared settings
 * resolver, the repository with the evidence-orphan hook) on the suite's writer and MinIO, with
 * the **real extractor pool** (TypeScript child in source runs). Rounds require `dlp` only.
 * `deliver` retries retryable attempt failures as the consumer's hold retry does.
 */
export class DlpPipeline {
  private tmp: string | null = null;

  private constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly registry: MetricsService,
    readonly metrics: ScanMetrics,
    readonly dlpMetrics: DlpMetrics,
    readonly engine: DlpEngine,
    private readonly service: {
      handle(e: EventEnvelope<ScanTriggerPayload>): Promise<HandleOutcome>;
    },
    readonly consumer: string,
  ) {}

  static async start(
    fx: ScanFixtures,
    options: { overrides?: Record<string, string>; dlp?: DlpEngineOverrides } = {},
  ): Promise<DlpPipeline> {
    const tmp = mkdtempSync(join(tmpdir(), 'it-dlp-'));
    const config = workerConfig({
      ...DLP_ONLY,
      ATTACHMENT_INSPECTOR_TMPDIR: tmp,
      ...options.overrides,
    });
    const registry = new MetricsService({
      service: `email-worker-it-dlp-${randomUUID().slice(0, 6)}`,
    });
    const metrics = new ScanMetrics(registry);
    const infra = createScanInfrastructure({
      config,
      prisma: fx.prisma,
      s3: fx.s3,
      metrics,
      logger: silentLogger,
      registry,
    });
    const deps = { prisma: fx.prisma, s3: fx.s3, redis: null, registry };
    const engine = createDlpEngine(
      { config, logger: silentLogger, metrics, ...deps },
      options.dlp ?? {},
    );
    await engine.start();
    const consumer = fx.consumer(`dlp-${randomUUID().slice(0, 4)}`);
    const { service } = createRoundService({
      config,
      registration: dlpRegistration,
      ...infra,
      metrics,
      logger: silentLogger,
      consumer,
      deps,
      adapter: engine,
    });
    const pipeline = new DlpPipeline(
      config,
      registry,
      metrics,
      DlpMetrics.for(registry),
      engine,
      service,
      consumer,
    );
    pipeline.tmp = tmp;
    return pipeline;
  }

  async deliver(event: EventEnvelope<ScanTriggerPayload>, maxTries = 10): Promise<HandleOutcome> {
    for (let i = 1; ; i += 1) {
      try {
        return await this.service.handle(event);
      } catch (error) {
        if (!(error instanceof EngineAttemptFailedError) || i >= maxTries) throw error;
      }
    }
  }

  handle(event: EventEnvelope<ScanTriggerPayload>): Promise<HandleOutcome> {
    return this.service.handle(event);
  }

  text(): Promise<string> {
    return this.registry.metrics();
  }

  async close(): Promise<void> {
    await this.engine.stop();
    if (this.tmp) rmSync(this.tmp, { recursive: true, force: true });
  }
}
