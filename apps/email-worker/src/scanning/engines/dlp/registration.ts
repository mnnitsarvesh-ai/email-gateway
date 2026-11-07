import { DLP_PDFJS_VERSION, dlpEngineVersion, type EvidenceKek } from '@email-gateway/dlp';
import {
  DLP_MAPPING_VERSION,
  engineCatalogEntry,
  type EngineCatalogEntry,
  resolveDlpSettings,
  settingsVersion,
} from '@email-gateway/security-contracts';
import type { WorkerConfig } from '../../../config';
import { dlpPlatformFromConfig } from '../../dlp-config';
import { S3PartReader } from '../../parts/part-reader';
import type { EngineDeps, EngineSettingsResolution, ScanEngineRegistration } from '../../registry';
import { ByteBudget } from '../attachment/byte-budget';
import { inspectLimitsFromConfig } from '../attachment/registration';
import { DlpEngine, type DlpEngineLimits, type DlpEngineOptions } from './dlp.engine';
import { DlpMetrics } from './dlp-metrics';
import { type DlpStore, PrismaDlpStore } from './dlp-store';
import { type EvidenceObjects, S3EvidenceObjects } from './evidence-objects';
import { DLP_MAX_SEGMENTS, DLP_MAX_TABLE_COLUMNS } from './extractor/extraction';
import { type DlpExtractor, DlpExtractorPool } from './extractor/pool';
import type { ChildPoolOptions } from '../attachment/inspector/pool';

/** Ledger consumer of `scan.dlp` (topology v7 `ledgerName`). */
export const DLP_CONSUMER = 'email-worker.scan.dlp';

const catalog = engineCatalogEntry('dlp') as EngineCatalogEntry;

/** D18 / S8: tenant row → effective settings (an invalid row falls back to the platform). */
export function dlpSettingsFor(
  config: Readonly<WorkerConfig>,
  row: { settings: unknown; version: number } | null,
): EngineSettingsResolution {
  const platform = dlpPlatformFromConfig(config);
  const resolved = resolveDlpSettings(platform, row?.settings ?? null);
  if (resolved.ok) {
    return {
      settings: resolved.settings,
      settingsVersion: settingsVersion(DLP_MAPPING_VERSION, platform, row ? row.version : null),
      invalidRow: false,
      violations: [],
    };
  }
  const fallback = resolveDlpSettings(platform, null);
  if (!fallback.ok) throw new Error('the platform DLP settings are invalid');
  return {
    settings: fallback.settings,
    settingsVersion: settingsVersion(DLP_MAPPING_VERSION, platform, null),
    invalidRow: true,
    violations: [...new Set(resolved.violations.map((v) => v.code))],
  };
}

/** The engine's bounds (D3, D4, D7, D16) from the validated config. */
export function dlpLimitsFromConfig(config: Readonly<WorkerConfig>): DlpEngineLimits {
  return {
    maxAttachments: config.DLP_MAX_ATTACHMENTS,
    attachmentMaxBytes: config.DLP_ATTACHMENT_MAX_BYTES,
    bodyMaxBytes: config.DLP_BODY_MAX_BYTES,
    textMaxCharsPerPart: config.DLP_TEXT_MAX_CHARS_PER_PART,
    textMaxCharsPerMessage: config.DLP_TEXT_MAX_CHARS_PER_MESSAGE,
    detectTimeoutMs: config.DLP_DETECT_TIMEOUT_MS,
    extractConcurrency: config.DLP_EXTRACTOR_POOL_SIZE,
    scanChunkChars: config.DLP_SCAN_CHUNK_CHARS,
    maxMatchesPerDetector: config.DLP_MAX_MATCHES_PER_DETECTOR,
    maxFindings: config.DLP_MAX_FINDINGS,
    customScanMaxChars: config.DLP_CUSTOM_SCAN_MAX_CHARS,
    evidenceMaxBytes: config.DLP_EVIDENCE_MAX_BYTES,
    evidenceMaxMatches: config.DLP_EVIDENCE_MAX_MATCHES,
    // The same platform archive limits as the attachment inspector (D1: DLP reaches exactly the
    // entries 4.2 reaches); CPU/RSS of the job are the extractor's own.
    walk: {
      ...inspectLimitsFromConfig(config),
      cpuSeconds: config.DLP_EXTRACT_CPU_SECONDS,
      maxRssMb: config.DLP_EXTRACT_MAX_RSS_MB,
    },
    extract: {
      maxTextChars: config.DLP_TEXT_MAX_CHARS_PER_PART,
      maxSegments: DLP_MAX_SEGMENTS,
      pdfMaxPages: config.DLP_PDF_MAX_PAGES,
      maxTableColumns: DLP_MAX_TABLE_COLUMNS,
      maxXmlBytes: config.ATTACHMENT_MAX_ENTRY_BYTES,
    },
  };
}

/** The evidence key-encryption key (D16), or null when evidence is disabled at the platform. */
export function evidenceKekFromConfig(config: Readonly<WorkerConfig>): EvidenceKek | null {
  if (!config.DLP_EVIDENCE_ENABLED) return null;
  if (!config.DLP_EVIDENCE_KEY || !/^[0-9a-fA-F]{64}$/.test(config.DLP_EVIDENCE_KEY)) {
    throw new Error('DLP_EVIDENCE_KEY is required (64 hex) where the dlp engine consumes');
  }
  return {
    current: config.DLP_EVIDENCE_KEY,
    previous: config.DLP_EVIDENCE_KEY_PREVIOUS === '' ? null : config.DLP_EVIDENCE_KEY_PREVIOUS,
  };
}

/** Overrides of the extractor pool (integration tests: tmpdir, selftest, sampler). */
export type ExtractorOverrides = Partial<Omit<ChildPoolOptions, 'logger'>>;

/** The DLP extractor pool (D4): a second instance of the generalized 4.2 child pool. */
export function createExtractorPool(
  config: Readonly<WorkerConfig>,
  deps: Pick<EngineDeps, 'logger'>,
  metrics: DlpMetrics,
  overrides: ExtractorOverrides = {},
): DlpExtractorPool {
  return new DlpExtractorPool({
    size: config.DLP_EXTRACTOR_POOL_SIZE,
    maxJobs: config.DLP_EXTRACTOR_MAX_JOBS,
    heapMb: config.DLP_EXTRACTOR_HEAP_MB,
    rlimits: config.DLP_EXTRACTOR_RLIMITS,
    tmpDir: config.ATTACHMENT_INSPECTOR_TMPDIR,
    wallTimeoutMs: config.DLP_EXTRACT_TIMEOUT_MS,
    cpuSeconds: config.DLP_EXTRACT_CPU_SECONDS,
    maxRssMb: config.DLP_EXTRACT_MAX_RSS_MB,
    selftest: config.EG_INSPECTOR_SELFTEST,
    nodeEnv: config.NODE_ENV,
    // Up to DLP_EXTRACTOR_POOL_SIZE attachments at a time per in-flight message.
    maxWaiting: Math.max(1, config.SCAN_DLP_CONCURRENCY * config.DLP_EXTRACTOR_POOL_SIZE),
    maxTextChars: config.DLP_TEXT_MAX_CHARS_PER_PART,
    logger: deps.logger,
    onKill: (reason) => metrics.kill(reason),
    onState: (state) => metrics.poolState(state),
    ...overrides,
  });
}

/** Test seams and replacements of the dlp engine's dependencies (integration tests, benchmark). */
export interface DlpEngineOverrides {
  store?: DlpStore;
  extractor?: DlpExtractor;
  extractorOptions?: ExtractorOverrides;
  evidence?: EvidenceObjects;
  parts?: DlpEngineOptions['parts'];
  now?: () => Date;
}

/** Everything the dlp engine is built from (also used by the tests and the benchmark). */
export function createDlpEngine(deps: EngineDeps, overrides: DlpEngineOverrides = {}): DlpEngine {
  const { config, logger } = deps;
  const metrics = DlpMetrics.for(deps.registry);
  const engineVersion = dlpEngineVersion();
  deps.metrics.engineVersion(catalog.name, engineVersion);
  metrics.extractorInfo.set({ extractor: 'dlp-extract/1', pdfjs: DLP_PDFJS_VERSION }, 1);
  return new DlpEngine({
    store:
      overrides.store ??
      new PrismaDlpStore(
        deps.prisma,
        {
          policies: config.DLP_POLICIES_MAX_PER_TENANT,
          rulesPerPolicy: config.DLP_RULES_MAX_PER_POLICY,
          exceptions: config.DLP_EXCEPTIONS_MAX_PER_TENANT,
          patterns: config.DLP_CUSTOM_PATTERNS_MAX_PER_TENANT,
          dictionaries: config.DLP_DICTIONARIES_MAX_PER_TENANT,
          dictionaryMaxTerms: config.DLP_DICTIONARY_MAX_TERMS,
          patternMaxLength: config.DLP_CUSTOM_PATTERN_MAX_LENGTH,
        },
        {
          ttlMs: config.DLP_TENANT_DATA_CACHE_TTL_MS,
          onInvalidTenantRow: (count) => metrics.customInvalid.inc(count),
          ...(overrides.now ? { now: overrides.now } : {}),
        },
      ),
    parts:
      overrides.parts ??
      new S3PartReader(deps.s3.client, deps.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS),
    extractor:
      overrides.extractor ??
      createExtractorPool(config, { logger }, metrics, overrides.extractorOptions ?? {}),
    budget: new ByteBudget(config.DLP_BYTE_BUDGET_BYTES, (used, limit) =>
      metrics.budget(used, limit),
    ),
    evidence:
      overrides.evidence ??
      new S3EvidenceObjects(deps.s3.client, deps.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS),
    kek: evidenceKekFromConfig(config),
    engineVersion,
    limits: dlpLimitsFromConfig(config),
    metrics,
    logger,
    ...(overrides.now ? { now: overrides.now } : {}),
  });
}

export const dlpRegistration: ScanEngineRegistration = {
  catalog,
  consumerName: DLP_CONSUMER,
  budget: (config) => ({
    concurrency: config.SCAN_DLP_CONCURRENCY,
    timeoutMs: config.SCAN_DLP_TIMEOUT_MS,
    maxAttempts: config.SCAN_DLP_MAX_ATTEMPTS,
  }),
  create: (deps) => createDlpEngine(deps),
  settingsFor: dlpSettingsFor,
};
