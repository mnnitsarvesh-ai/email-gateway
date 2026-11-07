import { createHash } from 'node:crypto';
import { MetricsService } from '@email-gateway/common';
import { type DlpExtraction, DlpDictionarySet, ExtractionSession } from '@email-gateway/dlp';
import { createLogger, type Logger } from '@email-gateway/logger';
import {
  DLP_PLATFORM_DEFAULTS,
  type DlpEffectiveSettings,
  resolveDlpSettings,
} from '@email-gateway/security-contracts';
import type { EngineScanContext } from '../../engine';
import type { PartPrefixRead, PartRead } from '../../parts/part-reader';
import { ByteBudget } from '../attachment/byte-budget';
import { inspectBytes } from '../attachment/inspector/inspect';
import { NOOP_YARA_ENGINE } from '../attachment/inspector/yara-engine';
import { DlpEngine, type DlpEngineLimits } from './dlp.engine';
import { DlpMetrics } from './dlp-metrics';
import type {
  DlpAttachmentRow,
  DlpMessageRow,
  DlpParseRow,
  DlpReadScope,
  DlpStore,
  DlpTenantRecord,
} from './dlp-store';
import type { EvidenceObjects } from './evidence-objects';
import { type DlpExtractJobLimits, walkSummaryOf } from './extractor/extraction';
import type { DlpExtractor, ExtractOutcome } from './extractor/pool';

/**
 * Unit-test support of the dlp engine (excluded from the build): an in-memory store, part
 * source and evidence bucket, and an **in-process** extractor that runs the same shared 4.2
 * walker and `ExtractionSession` the extractor child runs (no process isolation; the isolated
 * child is covered by the pool tests and the package integration suite). `outcome` overrides
 * let a test model the pool's kill and failure outcomes.
 */

export const TEST_KEK = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
export const ORG = 41n;
export const RECEIVED = new Date('2026-11-07T05:00:00.000Z');

export const sha = (bytes: Buffer | string): string =>
  createHash('sha256').update(bytes).digest('hex');

export function platformSettings(override: unknown = null): DlpEffectiveSettings {
  const resolved = resolveDlpSettings(DLP_PLATFORM_DEFAULTS, override);
  if (!resolved.ok) throw new Error('settings');
  return resolved.settings;
}

export const LIMITS: DlpEngineLimits = {
  maxAttachments: 5,
  attachmentMaxBytes: 1_000_000,
  bodyMaxBytes: 4_194_304,
  textMaxCharsPerPart: 1_000_000,
  textMaxCharsPerMessage: 4_000_000,
  detectTimeoutMs: 15_000,
  extractConcurrency: 2,
  scanChunkChars: 65_536,
  maxMatchesPerDetector: 1_000,
  maxFindings: 64,
  customScanMaxChars: 1_000_000,
  evidenceMaxBytes: 32_768,
  evidenceMaxMatches: 50,
  walk: {
    archiveMaxDepth: 3,
    archiveMaxEntries: 1_000,
    maxEntryBytes: 26_214_400,
    maxDecompressedBytes: 104_857_600,
    maxCompressionRatio: 100,
    maxEntryFindings: 20,
    yaraTimeoutMs: 10_000,
    cpuSeconds: 10,
    maxRssMb: 512,
  },
  extract: {
    maxTextChars: 1_000_000,
    maxSegments: 200,
    pdfMaxPages: 200,
    maxTableColumns: 64,
    maxXmlBytes: 26_214_400,
  },
};

export class InProcessExtractor implements DlpExtractor {
  readyCount = 1;
  readonly rlimitMode = 'none' as const;
  readonly permissionModel = false;
  /** Replaces the result of the next jobs (kills, failures). */
  outcomes: ExtractOutcome[] = [];
  jobs = 0;
  /** Wall time each job takes (a slow extractor); jobs in flight now and at most. */
  delayMs = 0;
  inFlight = 0;
  maxInFlight = 0;

  start(): Promise<void> {
    return Promise.resolve();
  }

  stop(): Promise<void> {
    return Promise.resolve();
  }

  async extract(
    bytes: Buffer,
    limits: DlpExtractJobLimits,
    hint: { declaredContentType: string | null; filenameExt: string | null },
  ): Promise<ExtractOutcome> {
    this.jobs += 1;
    const forced = this.outcomes.shift();
    this.inFlight += 1;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    try {
      if (this.delayMs > 0) await new Promise((r) => setTimeout(r, this.delayMs));
      if (forced) return forced;
      return await this.run(bytes, limits, hint);
    } finally {
      this.inFlight -= 1;
    }
  }

  private async run(
    bytes: Buffer,
    limits: DlpExtractJobLimits,
    hint: { declaredContentType: string | null; filenameExt: string | null },
  ): Promise<ExtractOutcome> {
    const session = new ExtractionSession(hint, limits.extract);
    const inspection = await inspectBytes(bytes, limits.walk, NOOP_YARA_ENGINE, {
      onEntry: session.visitor,
    });
    const extraction: DlpExtraction = await session.finish(
      bytes,
      inspection.type.detected,
      walkSummaryOf(inspection),
    );
    return { kind: 'result', result: extraction };
  }
}

export class MemoryParts {
  readonly objects = new Map<string, Buffer>();
  reads = 0;

  read(key: string, sizeBytes: number, sha256: string): Promise<PartRead> {
    this.reads += 1;
    const bytes = this.objects.get(key);
    if (!bytes) return Promise.resolve({ kind: 'missing' });
    if (bytes.length !== sizeBytes || sha(bytes) !== sha256)
      return Promise.resolve({ kind: 'integrity' });
    return Promise.resolve({ kind: 'ok', bytes });
  }

  readPrefix(key: string, maxBytes: number): Promise<PartPrefixRead> {
    this.reads += 1;
    const bytes = this.objects.get(key);
    if (!bytes) return Promise.resolve({ kind: 'missing' });
    return Promise.resolve({ kind: 'ok', bytes: bytes.subarray(0, maxBytes) });
  }
}

export class MemoryEvidence implements EvidenceObjects {
  readonly objects = new Map<string, Buffer>();
  failPut = false;
  failDelete = false;
  deleted: string[] = [];

  put(key: string, body: Buffer): Promise<void> {
    if (this.failPut) return Promise.reject(new Error('s3 down'));
    this.objects.set(key, body);
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    if (this.failDelete) return Promise.reject(new Error('s3 down'));
    this.deleted.push(key);
    this.objects.delete(key);
    return Promise.resolve();
  }
}

export function emptyTenant(overrides: Partial<DlpTenantRecord> = {}): DlpTenantRecord {
  return {
    tenantDomains: ['corp.example.test'],
    policies: [],
    internalIds: new Map(),
    exceptions: [],
    patterns: [],
    invalidPatterns: [],
    dictionaries: DlpDictionarySet.create([]),
    compliance: null,
    ...overrides,
  };
}

export interface MemoryMessage {
  message: DlpMessageRow;
  parse: DlpParseRow | null;
  attachments: DlpAttachmentRow[];
}

export class MemoryDlpStore implements DlpStore {
  tenant: DlpTenantRecord = emptyTenant();
  calls: string[] = [];

  constructor(public data: MemoryMessage) {}

  loadMessage(): Promise<DlpMessageRow> {
    this.calls.push('message');
    return Promise.resolve(this.data.message);
  }

  loadParse(): Promise<DlpParseRow | null> {
    this.calls.push('parse');
    return Promise.resolve(this.data.parse);
  }

  loadAttachments(_scope: DlpReadScope, limit: number): Promise<DlpAttachmentRow[]> {
    this.calls.push('attachments');
    return Promise.resolve(this.data.attachments.slice(0, limit));
  }

  tenantData(): Promise<DlpTenantRecord> {
    this.calls.push('tenant');
    return Promise.resolve(this.tenant);
  }
}

/** A message whose bodies and attachments live in `parts` (keys under the org prefix). */
export function messageWith(
  parts: MemoryParts,
  input: {
    subject?: string | null;
    text?: string | null;
    html?: string | null;
    attachments?: Array<{
      bytes: Buffer;
      filename?: string | null;
      declaredContentType?: string | null;
      stored?: boolean;
    }>;
    limitsExceeded?: string[];
    recipientCount?: number;
  },
): MemoryMessage {
  const prefix = `org/${ORG.toString()}/part/2026/11/07/9/`;
  const body = (name: string, content: string | null | undefined) => {
    if (content === null || content === undefined)
      return { key: null, sha256: null, sizeBytes: null };
    const bytes = Buffer.from(content, 'utf8');
    parts.objects.set(prefix + name, bytes);
    return { key: prefix + name, sha256: sha(bytes), sizeBytes: bytes.length };
  };
  const attachments = (input.attachments ?? []).map((a, i) => {
    const key = `${prefix}${String(i + 1)}.att`;
    const stored = a.stored !== false;
    if (stored) parts.objects.set(key, a.bytes);
    return {
      partIndex: i + 1,
      filename: a.filename === undefined ? `file-${String(i + 1)}.bin` : a.filename,
      declaredContentType: a.declaredContentType ?? null,
      sizeBytes: a.bytes.length,
      sha256: sha(a.bytes),
      objectKey: stored ? key : null,
      flags: stored ? [] : ['not_stored_size_limit'],
    };
  });
  return {
    message: {
      subject: input.subject === undefined ? 'Quarterly notes' : input.subject,
      envelopeFrom: 'alice@corp.example.test',
      headerFrom: 'alice@corp.example.test',
      recipientCount: input.recipientCount ?? 1,
    },
    parse: {
      status: 'parsed',
      limitsExceeded: input.limitsExceeded ?? [],
      attachmentCount: attachments.length,
      textBody: body('text.txt', input.text),
      htmlBody: body('body.html', input.html),
    },
    attachments,
  };
}

export function context(
  overrides: Partial<EngineScanContext> & { settings?: DlpEffectiveSettings } = {},
): EngineScanContext {
  return {
    organizationId: ORG,
    messageId: 9001n,
    receivedAt: RECEIVED,
    round: 0,
    scanId: 77n,
    scanKind: 'initial',
    direction: 'outbound',
    envelope: {
      clientIp: '192.0.2.1',
      clientHelo: 'mx',
      clientName: 'mx',
      envelopeFrom: 'alice@corp.example.test',
      recipients: ['bob@partner.example.org'],
      queueId: null,
    },
    eml: { key: 'k', sizeBytes: 1, open: () => Promise.reject(new Error('unused')) },
    settings: platformSettings(),
    settingsVersion: 'dlp-map/1;p=000000000000;t=none',
    ...overrides,
  };
}

export interface Harness {
  engine: DlpEngine;
  store: MemoryDlpStore;
  parts: MemoryParts;
  evidence: MemoryEvidence;
  extractor: InProcessExtractor;
  registry: MetricsService;
  metrics: DlpMetrics;
}

export function harness(
  data: (parts: MemoryParts) => MemoryMessage,
  options: { logger?: Logger; kek?: string | null; limits?: Partial<DlpEngineLimits> } = {},
): Harness {
  const parts = new MemoryParts();
  const store = new MemoryDlpStore(data(parts));
  const evidence = new MemoryEvidence();
  const extractor = new InProcessExtractor();
  const registry = new MetricsService({ service: 'dlp-engine-test' });
  const metrics = DlpMetrics.for(registry);
  const engine = new DlpEngine({
    store,
    parts,
    extractor,
    budget: new ByteBudget(64 * 1024 * 1024),
    evidence,
    kek: options.kek === null ? null : { current: options.kek ?? TEST_KEK },
    engineVersion: 'dlp/1;dict=00000000;data=00000000;ext=dlp-extract/1',
    limits: { ...LIMITS, ...options.limits },
    metrics,
    logger: options.logger ?? createLogger({ service: 'dlp-engine-test', level: 'silent' }),
    now: () => new Date('2026-11-07T06:00:00.000Z'),
  });
  return { engine, store, parts, evidence, extractor, registry, metrics };
}
