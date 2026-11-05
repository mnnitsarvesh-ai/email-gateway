import { ClamdClient } from '@email-gateway/clamav';
import {
  engineCatalogEntry,
  type EngineCatalogEntry,
  resolveAttachmentSettings,
  settingsVersion,
} from '@email-gateway/security-contracts';
import type { WorkerConfig } from '../../../config';
import { attachmentPlatformFromConfig } from '../../config';
import type { EngineDeps, EngineSettingsResolution, ScanEngineRegistration } from '../../registry';
import { AttachmentEngine, type ClamdScanner } from './attachment.engine';
import { AttachmentMetrics } from './attachment-metrics';
import { PrismaAttachmentStore } from './attachment-store';
import { ByteBudget } from './byte-budget';
import { ClamavVersionProvider, type ClamdVersionSource } from './clamav-versions';
import type { InspectLimits } from './content';
import { ContentCache } from './content-cache';
import { BUNDLED_RULES_DIR, bundleIdOf } from './inspector/bundle';
import { InspectorPool, type InspectorPoolOptions } from './inspector/pool';
import { S3PartReader } from './part-reader';
import { MAPPING_VERSION } from './verdict-mapper';

/** Ledger consumer of `scan.attachment` (topology v4 `ledgerName`). */
export const ATTACHMENT_CONSUMER = 'email-worker.scan.attachment';

const catalog = engineCatalogEntry('attachment') as EngineCatalogEntry;

/** The rules directory (A9): ATTACHMENT_YARA_RULES_DIR or the bundled `apps/email-worker/yara`. */
export const rulesDirOf = (config: Readonly<WorkerConfig>): string =>
  config.ATTACHMENT_YARA_RULES_DIR.length > 0
    ? config.ATTACHMENT_YARA_RULES_DIR
    : BUNDLED_RULES_DIR;

/** The platform limits the inspector applies (A4; part of the content version, A9). */
export function inspectLimitsFromConfig(config: Readonly<WorkerConfig>): InspectLimits {
  return {
    archiveMaxDepth: config.ATTACHMENT_ARCHIVE_MAX_DEPTH,
    archiveMaxEntries: config.ATTACHMENT_ARCHIVE_MAX_ENTRIES,
    maxEntryBytes: config.ATTACHMENT_MAX_ENTRY_BYTES,
    maxDecompressedBytes: config.ATTACHMENT_MAX_DECOMPRESSED_BYTES,
    maxCompressionRatio: config.ATTACHMENT_MAX_COMPRESSION_RATIO,
    maxEntryFindings: config.ATTACHMENT_MAX_ENTRY_FINDINGS,
    yaraTimeoutMs: config.ATTACHMENT_YARA_TIMEOUT_MS,
    cpuSeconds: config.ATTACHMENT_INSPECT_CPU_SECONDS,
    maxRssMb: config.ATTACHMENT_INSPECT_MAX_RSS_MB,
  };
}

/** The clamd client of the attachment engine (A7). */
export function createClamdClient(config: Readonly<WorkerConfig>): ClamdClient {
  return new ClamdClient({
    host: config.CLAMAV_HOST,
    port: config.CLAMAV_PORT,
    timeoutMs: config.CLAMAV_TIMEOUT_MS,
    maxConnections: config.CLAMAV_MAX_CONNECTIONS,
    chunkBytes: config.CLAMAV_CHUNK_BYTES,
  });
}

/** S8 / A8: tenant row → effective settings (an invalid row falls back to the platform). */
export function attachmentSettingsFor(
  config: Readonly<WorkerConfig>,
  row: { settings: unknown; version: number } | null,
): EngineSettingsResolution {
  const platform = attachmentPlatformFromConfig(config);
  const resolved = resolveAttachmentSettings(platform, row?.settings ?? null);
  if (resolved.ok) {
    return {
      settings: resolved.settings,
      settingsVersion: settingsVersion(MAPPING_VERSION, platform, row ? row.version : null),
      invalidRow: false,
      violations: [],
    };
  }
  const fallback = resolveAttachmentSettings(platform, null);
  if (!fallback.ok) throw new Error('the platform attachment settings are invalid');
  return {
    settings: fallback.settings,
    settingsVersion: settingsVersion(MAPPING_VERSION, platform, null),
    invalidRow: true,
    violations: [...new Set(resolved.violations.map((v) => v.code))],
  };
}

/** Overrides of the inspector pool (integration tests: per-run tmpdir, fake sampler). */
export type InspectorOverrides = Partial<Omit<InspectorPoolOptions, 'logger'>>;

/** Everything the attachment engine is built from (also used by tests and the benchmark). */
export function createAttachmentEngine(
  deps: EngineDeps,
  overrides: { inspector?: InspectorOverrides; clamd?: ClamdScanner & ClamdVersionSource } = {},
): AttachmentEngine {
  const { config, logger } = deps;
  const metrics = AttachmentMetrics.for(deps.registry);
  const rulesDir = rulesDirOf(config);
  const bundle = bundleIdOf(rulesDir);
  const clamd = overrides.clamd ?? createClamdClient(config);
  if (config.ATTACHMENT_CACHE_ENABLED && !deps.redis) {
    throw new Error('REDIS_URL is required when ATTACHMENT_CACHE_ENABLED is true');
  }
  if (config.ATTACHMENT_CACHE_ENABLED && !config.ATTACHMENT_CACHE_HMAC_KEY) {
    throw new Error('ATTACHMENT_CACHE_HMAC_KEY is required when ATTACHMENT_CACHE_ENABLED is true');
  }
  const cache =
    config.ATTACHMENT_CACHE_ENABLED && deps.redis && config.ATTACHMENT_CACHE_HMAC_KEY
      ? new ContentCache(
          deps.redis.client,
          {
            cleanSeconds: config.ATTACHMENT_CACHE_CLEAN_TTL_SECONDS,
            maliciousSeconds: config.ATTACHMENT_CACHE_MALICIOUS_TTL_SECONDS,
            otherSeconds: config.ATTACHMENT_CACHE_OTHER_TTL_SECONDS,
          },
          config.ATTACHMENT_CACHE_TIMEOUT_MS,
          config.ATTACHMENT_CACHE_HMAC_KEY,
        )
      : null;
  const inspector = new InspectorPool({
    size: config.ATTACHMENT_INSPECTOR_POOL_SIZE,
    maxJobs: config.ATTACHMENT_INSPECTOR_MAX_JOBS,
    heapMb: config.ATTACHMENT_INSPECTOR_HEAP_MB,
    rlimits: config.ATTACHMENT_INSPECTOR_RLIMITS,
    tmpDir: config.ATTACHMENT_INSPECTOR_TMPDIR,
    wallTimeoutMs: config.ATTACHMENT_INSPECT_TIMEOUT_MS,
    cpuSeconds: config.ATTACHMENT_INSPECT_CPU_SECONDS,
    maxRssMb: config.ATTACHMENT_INSPECT_MAX_RSS_MB,
    rulesDir,
    yaraTimeoutMs: config.ATTACHMENT_YARA_TIMEOUT_MS,
    expectedBundleId: bundle.bundleId,
    selftest: config.EG_INSPECTOR_SELFTEST,
    nodeEnv: config.NODE_ENV,
    maxWaiting: config.SCAN_ATTACHMENT_CONCURRENCY * config.ATTACHMENT_PER_MESSAGE_PARALLELISM,
    logger,
    onKill: (reason) => metrics.kill(reason),
    onState: (state) => metrics.pool(state),
    ...overrides.inspector,
  });
  return new AttachmentEngine({
    store: new PrismaAttachmentStore(deps.prisma),
    parts: new S3PartReader(deps.s3.client, deps.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS),
    clamd,
    versions: new ClamavVersionProvider(clamd, config.SCAN_ENGINE_VERSION_TTL_MS),
    inspector,
    cache,
    budget: new ByteBudget(config.ATTACHMENT_MEMORY_BUDGET_BYTES, (used, limit) =>
      metrics.budget(used, limit),
    ),
    metrics,
    logger,
    bundleId: bundle.bundleId,
    yaraXVersion: bundle.yaraX,
    limits: inspectLimitsFromConfig(config),
    maxPerMessage: config.ATTACHMENT_MAX_PER_MESSAGE,
    parallelism: config.ATTACHMENT_PER_MESSAGE_PARALLELISM,
    sandbox: {
      enabled: config.ATTACHMENT_SANDBOX_SUBMIT,
      maxPerMessage: config.ATTACHMENT_SANDBOX_MAX_PER_MESSAGE,
    },
    poolSize: config.ATTACHMENT_INSPECTOR_POOL_SIZE,
  });
}

export const attachmentRegistration: ScanEngineRegistration = {
  catalog,
  consumerName: ATTACHMENT_CONSUMER,
  budget: (config) => ({
    concurrency: config.SCAN_ATTACHMENT_CONCURRENCY,
    timeoutMs: config.SCAN_ATTACHMENT_TIMEOUT_MS,
    maxAttempts: config.SCAN_ATTACHMENT_MAX_ATTEMPTS,
  }),
  create: (deps) => createAttachmentEngine(deps),
  settingsFor: attachmentSettingsFor,
};
