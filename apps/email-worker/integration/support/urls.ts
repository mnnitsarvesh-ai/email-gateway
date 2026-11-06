import {
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectTaggingCommand,
  ListObjectsV2Command,
} from '@aws-sdk/client-s3';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { type HandleOutcome, MetricsService, RedisService, uuidv7 } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  messageReceivedV1,
  type UrlInspectionCompletedV1,
  urlInspectionCompletedV1,
} from '@email-gateway/event-contracts';
import {
  chainCacheKey,
  dynamicCacheKey,
  FETCHER_VERSION,
  normalizeIndicator,
  normalizeUrl,
} from '@email-gateway/url-security';
import type { WorkerConfig } from '../../src/config';
import { createMimeIngestionService } from '../../src/mime-ingestion/mime-ingestion.module';
import { MimeMetrics } from '../../src/mime-ingestion/mime-metrics';
import { EngineAttemptFailedError } from '../../src/scanning/engine';
import {
  createUrlEngine,
  type UrlEngineOverrides,
  urlRegistration,
} from '../../src/scanning/engines/url/registration';
import type { UrlEngine } from '../../src/scanning/engines/url/url.engine';
import { UrlMetrics } from '../../src/scanning/engines/url/url-metrics';
import { UrlResultsService } from '../../src/scanning/engines/url/url-results';
import type { ScanTriggerPayload } from '../../src/scanning/round-service';
import { ScanMetrics } from '../../src/scanning/scan-metrics';
import { createRoundService, createScanInfrastructure } from '../../src/scanning/scanning.module';
import { requireEnv, silentLogger, workerConfig } from './fixtures';
import type { ScanFixtures, ScanMessage } from './scan';

const REPO_ROOT = resolve(__dirname, '../../../..');

/** The test CA of test-pki (url-test's HTTPS leaf), copied from the running url-test container. */
export function testCaFile(): { path: string; cleanup: () => void } {
  let pem: string;
  try {
    pem = execFileSync('docker', ['compose', 'exec', '-T', 'url-test', 'cat', '/pki/ca/ca.pem'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
  } catch {
    throw new Error(
      'url-test is not running: docker compose --profile smtp-test up -d test-pki dns-sink url-test',
    );
  }
  const dir = mkdtempSync(join(tmpdir(), 'eg-url-ca-'));
  const path = join(dir, 'ca.pem');
  writeFileSync(path, pem, { mode: 0o600 });
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** url-test's published HTTP port (reset of the rebinding responder, health). */
export const urlTestHttp = (): string =>
  `http://127.0.0.1:${process.env.URL_TEST_HTTP_HOST_PORT ?? '18080'}`;

export async function requireUrlTest(): Promise<void> {
  const health = await fetch(`${urlTestHttp()}/health`).catch(() => null);
  if (!health?.ok) throw new Error('url-test is not reachable on its published port');
}

/** Base overrides of every url suite: the url engine alone decides a round. */
export function urlOnly(caFile: string): Record<string, string> {
  return {
    SCAN_ENGINES: 'url',
    SCAN_CONSUMERS: 'url',
    SCAN_SETTINGS_CACHE_TTL_MS: '0',
    SCAN_RETRY_BASE_MS: '100',
    SCAN_RETRY_MAX_MS: '200',
    URL_FETCH_CA_FILE: caFile,
    URL_FETCH_HEADER_TIMEOUT_MS: '2000',
    URL_FETCH_TOTAL_TIMEOUT_MS: '6000',
    URL_PROVIDER_TIMEOUT_MS: '3000',
    URL_DNS_TIMEOUT_MS: '1500',
    URL_DNS_TRIES: '1',
  };
}

export interface UrlState {
  messageUrls: Prisma.MessageUrlGetPayload<object>[];
  results: Prisma.UrlScanResultGetPayload<object>[];
  rewrites: Prisma.UrlRewriteGetPayload<object>[];
  inspections: Prisma.UrlDynamicInspectionGetPayload<object>[];
  inspectionEvents: Prisma.MessageOutboxGetPayload<object>[];
  finals: Prisma.ScanEngineResultGetPayload<object>[];
  attempts: Prisma.ScanEngineResultGetPayload<object>[];
  scans: Prisma.EmailScanGetPayload<object>[];
}

/**
 * URL fixtures on top of the scan fixtures (step 4.3 §9 package integration): messages parsed
 * by the real MIME stage (bodies and parts in MinIO, parse rows as step 3.1 writes them),
 * platform threat indicators of the run (source `it-url-<suffix>`), URL settings, and the
 * cleanup of every row, object and cache entry the url engine writes for the run.
 */
export class UrlFixtures {
  readonly source: string;
  readonly redis = new RedisService({ url: requireEnv('REDIS_URL') });
  private readonly cacheKeys = new Set<string>();
  private readonly mimeConsumer: string;

  constructor(readonly fx: ScanFixtures) {
    this.source = `it-url-${fx.suffix}`;
    this.mimeConsumer = fx.consumer('mime');
  }

  /** The MIME stage as MimeIngestionModule wires it (MIME_* overrides for limit tests). */
  private mimeStage(overrides: Record<string, string> = {}) {
    return createMimeIngestionService({
      config: workerConfig({ SCAN_ENGINES: 'rspamd', ...overrides }),
      prisma: this.fx.prisma,
      s3: this.fx.s3,
      metrics: new MimeMetrics(
        new MetricsService({ service: `it-url-mime-${randomUUID().slice(0, 6)}` }),
      ),
      logger: silentLogger,
      consumer: this.mimeConsumer,
    });
  }

  async deleteObject(key: string): Promise<void> {
    await this.fx.s3.client.send(
      new DeleteObjectCommand({ Bucket: this.fx.s3.mailBucket, Key: key }),
    );
  }

  get prisma(): PrismaClient {
    return this.fx.prisma;
  }

  /** A persisted message whose EML was parsed by the real MIME stage. */
  async message(
    organizationId: bigint,
    eml: string | Buffer,
    options: {
      direction?: 'inbound' | 'outbound' | 'internal';
      parse?: boolean;
      /** MIME_* overrides of the parse (e.g. MIME_MAX_BODY_BYTES for E1). */
      mime?: Record<string, string>;
    } = {},
  ): Promise<ScanMessage> {
    const message = await this.fx.message(organizationId, {
      eml: Buffer.from(eml),
      envelope: { direction: options.direction ?? 'inbound' },
    });
    if (options.parse === false) return message;
    const eventId = uuidv7();
    const outcome = await this.mimeStage(options.mime).handle({
      eventId,
      eventType: EventTypes.MessageReceived,
      occurredAt: new Date().toISOString(),
      correlationId: `it-url-${this.fx.suffix}-received`,
      organizationId: organizationId.toString(),
      payload: messageReceivedV1.parse({
        messageId: message.messageId.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: message.direction,
        emlS3Key: message.emlObjectKey,
        sizeBytes: message.sizeBytes,
        envelopeFrom: 'alice@clean.scan.test',
        recipientCount: 1,
      }),
    });
    if (outcome !== 'handled') throw new Error(`MIME stage did not handle the message: ${outcome}`);
    return message;
  }

  /** A platform indicator (`organization_id` NULL), value normalized as the api does (U16). */
  async indicator(
    type: 'url' | 'domain' | 'ip',
    raw: string,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'high',
    category: 'phishing' | 'malware' | 'spam' | 'scam' | 'c2' | 'other' = 'phishing',
  ): Promise<bigint> {
    const normalized = normalizeIndicator(type, raw);
    if (!normalized.ok) throw new Error(`invalid indicator (${normalized.code})`);
    const now = new Date();
    const row = await this.prisma.threatIndicator.create({
      data: {
        indicatorType: type,
        value: normalized.value,
        valueSha256: normalized.valueSha256,
        source: this.source,
        severity,
        category,
        confidence: 90,
        firstSeenAt: now,
        lastSeenAt: now,
        reason: 'url engine integration test',
      },
      select: { id: true },
    });
    return row.id;
  }

  async removeIndicator(id: bigint): Promise<void> {
    await this.prisma.threatIndicator.deleteMany({ where: { id, source: this.source } });
  }

  async settings(organizationId: bigint, value: Record<string, unknown>): Promise<void> {
    const settings = value as Prisma.InputJsonObject;
    await this.prisma.scanEngineSetting.upsert({
      where: { organizationId_engine: { organizationId, engine: 'url' } },
      create: { organizationId, engine: 'url', settings },
      update: { settings, version: { increment: 1 } },
    });
  }

  /** An active tenant domain (protected entry of U7 b). */
  async domain(organizationId: bigint, name: string): Promise<void> {
    await this.prisma.domain.create({
      data: { organizationId, name, status: 'active', activatedAt: new Date() },
    });
  }

  /** Tracks the cache entries of URLs a test fetched (removed in `cleanup`). */
  track(...urls: string[]): void {
    for (const raw of urls) {
      const result = normalizeUrl(raw);
      if (!result.ok) continue;
      this.cacheKeys.add(chainCacheKey(FETCHER_VERSION, result.url.identity));
      this.cacheKeys.add(dynamicCacheKey(result.url.sha256));
    }
  }

  async state(message: ScanMessage): Promise<UrlState> {
    const where = { messageId: message.messageId, receivedAt: message.receivedAt };
    const [messageUrls, results, rewrites, inspections, inspectionEvents, engineRows, scans] =
      await Promise.all([
        this.prisma.messageUrl.findMany({ where, orderBy: { urlSeq: 'asc' } }),
        this.prisma.urlScanResult.findMany({
          where,
          orderBy: [{ scanId: 'asc' }, { urlSeq: 'asc' }],
        }),
        this.prisma.urlRewrite.findMany({ where, orderBy: { scanId: 'asc' } }),
        this.prisma.urlDynamicInspection.findMany({
          where,
          orderBy: [{ scanId: 'asc' }, { urlSeq: 'asc' }],
        }),
        this.prisma.messageOutbox.findMany({
          where: {
            organizationId: message.organizationId,
            aggregateId: message.messageId.toString(),
            eventType: EventTypes.UrlInspectionRequested,
          },
          orderBy: { id: 'asc' },
        }),
        this.prisma.scanEngineResult.findMany({
          where: { ...where, engine: 'url' },
          orderBy: [{ scanId: 'asc' }, { attempt: 'asc' }],
        }),
        this.prisma.emailScan.findMany({ where, orderBy: { lifecycleRound: 'asc' } }),
      ]);
    return {
      messageUrls,
      results,
      rewrites,
      inspections,
      inspectionEvents,
      finals: engineRows.filter((r) => r.isFinal),
      attempts: engineRows.filter((r) => !r.isFinal),
      scans,
    };
  }

  /** The rewritten object: bytes and tags. */
  async object(
    key: string,
  ): Promise<{ body: Buffer; tags: Record<string, string>; type?: string }> {
    const got = await this.fx.s3.client.send(
      new GetObjectCommand({ Bucket: this.fx.s3.mailBucket, Key: key }),
    );
    const body = Buffer.from(await got.Body!.transformToByteArray());
    const tagging = await this.fx.s3.client.send(
      new GetObjectTaggingCommand({ Bucket: this.fx.s3.mailBucket, Key: key }),
    );
    return {
      body,
      tags: Object.fromEntries((tagging.TagSet ?? []).map((t) => [t.Key ?? '', t.Value ?? ''])),
      ...(got.ContentType ? { type: got.ContentType } : {}),
    };
  }

  /** Keys under `org/<org>/rewrite/` (orphans included). */
  async rewriteObjects(organizationId: bigint): Promise<string[]> {
    const page = await this.fx.s3.client.send(
      new ListObjectsV2Command({
        Bucket: this.fx.s3.mailBucket,
        Prefix: `org/${organizationId.toString()}/rewrite/`,
      }),
    );
    return (page.Contents ?? []).map((c) => c.Key ?? '').sort();
  }

  /** A `mail.url.inspection_completed.v1` envelope as the browser worker publishes it. */
  completed(
    organizationId: bigint,
    payload: Partial<UrlInspectionCompletedV1> &
      Pick<
        UrlInspectionCompletedV1,
        'inspectionId' | 'messageId' | 'receivedAt' | 'urlSeq' | 'urlSha256'
      >,
    eventId: string = uuidv7(),
  ): EventEnvelope<UrlInspectionCompletedV1> {
    return {
      eventId,
      eventType: EventTypes.UrlInspectionCompleted,
      occurredAt: new Date().toISOString(),
      correlationId: `it-url-${this.fx.suffix}-inspection`,
      organizationId: organizationId.toString(),
      payload: urlInspectionCompletedV1.parse({
        status: 'completed',
        errorCode: null,
        workerVersion: 'url-browser-worker/it',
        browserVersion: 'chromium/it',
        finalUrlSha256: null,
        finalHost: null,
        navigations: [],
        signals: {
          passwordFields: 0,
          forms: 0,
          crossOriginFormAction: false,
          formActionHosts: [],
          downloadAttempted: false,
          blockedRequests: 0,
          requests: 1,
          bytes: 100,
          titleBrandMatches: [],
          jsRedirect: false,
          dialogs: 0,
        },
        durationMs: 100,
        completedAt: new Date().toISOString(),
        ...payload,
      }),
    };
  }

  async cleanup(): Promise<void> {
    const ids = this.fx.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.urlDynamicInspection.deleteMany({ where });
        await this.prisma.urlRewrite.deleteMany({ where });
        await this.prisma.urlScanResult.deleteMany({ where });
        await this.prisma.messageUrl.deleteMany({ where });
        await this.prisma.emailAttachment.deleteMany({ where });
        await this.prisma.emailHeader.deleteMany({ where });
        await this.prisma.emailMessageParse.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
      }
      await this.prisma.threatIndicator.deleteMany({ where: { source: this.source } });
      if (this.cacheKeys.size > 0) await this.redis.client.unlink(...this.cacheKeys);
    } finally {
      await this.redis.onModuleDestroy();
    }
  }
}

/**
 * The url engine wired as ScanningModule wires it (registration, round service, settings
 * resolver, S3 EML reads) on the suite's writer, MinIO and Redis, called directly (no broker):
 * `deliver` retries retryable attempt failures like the queue consumer does.
 */
export class UrlPipeline {
  private constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly registry: MetricsService,
    readonly metrics: ScanMetrics,
    readonly urlMetrics: UrlMetrics,
    readonly engine: UrlEngine,
    readonly consumerName: string,
    private readonly service: {
      handle(event: EventEnvelope<ScanTriggerPayload>): Promise<HandleOutcome>;
    },
    readonly redis: RedisService,
  ) {}

  static start(
    fx: ScanFixtures,
    caFile: string,
    options: { overrides?: Record<string, string>; engine?: UrlEngineOverrides } = {},
  ): UrlPipeline {
    const config = workerConfig({ ...urlOnly(caFile), ...options.overrides });
    const registry = new MetricsService({
      service: `email-worker-it-url-${randomUUID().slice(0, 6)}`,
    });
    const metrics = new ScanMetrics(registry);
    const redis = new RedisService({ url: requireEnv('REDIS_URL') });
    const consumerName = fx.consumer(`url-${randomUUID().slice(0, 4)}`);
    const infra = createScanInfrastructure({
      config,
      prisma: fx.prisma,
      s3: fx.s3,
      metrics,
      logger: silentLogger,
    });
    const deps = { prisma: fx.prisma, s3: fx.s3, redis, registry };
    const engine = createUrlEngine(
      { config, logger: silentLogger, metrics, ...deps },
      options.engine ?? {},
    );
    const { service } = createRoundService({
      config,
      registration: urlRegistration,
      ...infra,
      metrics,
      logger: silentLogger,
      consumer: consumerName,
      adapter: engine,
      deps,
    });
    return new UrlPipeline(
      config,
      registry,
      metrics,
      UrlMetrics.for(registry),
      engine,
      consumerName,
      service,
      redis,
    );
  }

  handle(event: EventEnvelope<ScanTriggerPayload>): Promise<HandleOutcome> {
    return this.service.handle(event);
  }

  /** Handles the event, retrying a retryable attempt failure (as the consumer's hold retry). */
  async deliver(event: EventEnvelope<ScanTriggerPayload>, maxTries = 10): Promise<HandleOutcome> {
    for (let i = 1; ; i += 1) {
      try {
        return await this.service.handle(event);
      } catch (error) {
        if (!(error instanceof EngineAttemptFailedError) || i >= maxTries) throw error;
      }
    }
  }

  /** A results service of the run (own ledger consumer name). */
  results(fx: ScanFixtures): UrlResultsService {
    return new UrlResultsService({
      prisma: fx.prisma,
      txTimeoutMs: this.config.SCAN_DB_TIMEOUT_MS,
      cache: this.engine.cache,
      metrics: this.urlMetrics,
      logger: silentLogger,
      highScore: this.config.URL_LOOKALIKE_HIGH_SCORE,
      consumer: fx.consumer(`url-results-${randomUUID().slice(0, 4)}`),
    });
  }

  text(): Promise<string> {
    return this.registry.metrics();
  }

  async close(): Promise<void> {
    await this.redis.onModuleDestroy();
  }
}

/** An EML with a plain-text and an HTML body (multipart/alternative, CRLF). */
export function emlWithBodies(text: string, html: string, extraHeaders = ''): string {
  return [
    'From: Alice <alice@clean.scan.test>',
    'To: bob@customer.scan.test',
    'Subject: url engine integration',
    'Message-ID: <it-url-' + randomUUID() + '@clean.scan.test>',
    'Date: Thu, 05 Nov 2026 10:00:00 +0000',
    'MIME-Version: 1.0',
    ...(extraHeaders ? [extraHeaders] : []),
    'Content-Type: multipart/alternative; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    text,
    '--b1',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    html,
    '--b1--',
    '',
  ].join('\r\n');
}

/** An HTML-only EML. */
export function emlWithHtml(html: string): string {
  return [
    'From: Alice <alice@clean.scan.test>',
    'To: bob@customer.scan.test',
    'Subject: url engine integration',
    'Message-ID: <it-url-' + randomUUID() + '@clean.scan.test>',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    html,
    '',
  ].join('\r\n');
}

/** Links as an HTML body (each URL an `a[href]`). */
export const linksHtml = (...urls: string[]): string =>
  `<html><body>${urls.map((u, i) => `<p><a href="${u}">link ${String(i)}</a></p>`).join('')}</body></html>`;
