import { amqpUrlListSchema } from '@email-gateway/config';
import { CLAMD_MAX_CONNECTIONS_LIMIT } from '@email-gateway/clamav';
import { HOLD_MAX_DELAY_MS, queueDefinition } from '@email-gateway/event-contracts';
import {
  ATTACHMENT_DEFAULT_DENIED_TYPES,
  ATTACHMENT_PLATFORM_DEFAULTS,
  ATTACHMENT_PLATFORM_ENV_KEYS,
  ATTACHMENT_RULE_VERDICTS,
  type AttachmentPlatformSettings,
  attachmentPlatformSettingsSchema,
  AUTH_FAILURE_VERDICTS,
  DMARC_REJECT_VERDICTS,
  type EngineName,
  engineCatalogEntry,
  parseEnabledEngines,
  PHISHING_VERDICTS,
  RSPAMD_PLATFORM_DEFAULTS,
  rspamdPlatformSettingsSchema,
  type RspamdPlatformSettings,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { urlConfigShape, validateUrlConfig } from './url-config';

export { urlPlatformFromConfig, urlProductionLike } from './url-config';

const int = z.coerce.number().int();
const positiveInt = int.min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const httpUrl = z.url({ protocol: /^https?$/ });
const score = z.coerce.number().finite();

/** Longest round deadline (S10): must stay well below LIFECYCLE_DEADLINE_SCANNING_HOURS (24). */
export const SCAN_ROUND_DEADLINE_MAX_SECONDS = 6 * 3600;

/**
 * Counted (retryable) failures after which the consumer of an engine queue dead-letters a
 * delivery (topology v3 retry policy of the queue, step 3.2 Q8). An engine's attempt budget
 * (`SCAN_<ENGINE>_MAX_ATTEMPTS`) must stay below it, so the stage finalizes the engine's result
 * before the broker gives up on the delivery (S5).
 */
export function engineQueueMaxAttempts(engine: EngineName): number {
  const entry = engineCatalogEntry(engine);
  if (!entry) return 0;
  return queueDefinition(entry.queue).retry?.maxAttempts ?? 0;
}

const ruleVerdict = z.enum(ATTACHMENT_RULE_VERDICTS);

/**
 * The attachment engine's keys (step 4.2 §5, A1, A4, A7, A8, A10, A11, A13, A14, A20;
 * `.env.example` section "Attachment scanning (step 4.2)"). Every key has the design default;
 * the platform settings (A8) are validated with `attachmentPlatformSettingsSchema` and the
 * cross-field rules in `validateAttachmentConfig`.
 */
function attachmentConfigShape() {
  return {
    // clamd over TCP (A7).
    CLAMAV_HOST: z.string().trim().min(1).default('127.0.0.1'),
    CLAMAV_PORT: int.min(1).max(65_535).default(3310),
    CLAMAV_TIMEOUT_MS: int.min(1_000).max(600_000).default(60_000),
    CLAMAV_MAX_CONNECTIONS: positiveInt.max(CLAMD_MAX_CONNECTIONS_LIMIT).default(4),
    CLAMAV_CHUNK_BYTES: int
      .min(1_024)
      .max(8 * 1024 * 1024)
      .default(65_536),

    // The engine's budgets (A12): prefetch, engine-call timeout, attempts.
    SCAN_ATTACHMENT_CONCURRENCY: positiveInt.max(64).default(4),
    SCAN_ATTACHMENT_TIMEOUT_MS: int.min(1_000).default(180_000),
    SCAN_ATTACHMENT_MAX_ATTEMPTS: positiveInt.default(6),

    // Per message and per worker (A3, A14).
    ATTACHMENT_MAX_PER_MESSAGE: positiveInt.max(1_000).default(100),
    ATTACHMENT_PER_MESSAGE_PARALLELISM: positiveInt.max(16).default(2),
    ATTACHMENT_MEMORY_BUDGET_BYTES: positiveInt.max(8 * 1024 * 1024 * 1024).default(134_217_728),

    // Platform settings (A8), validated by attachmentPlatformSettingsSchema.
    ATTACHMENT_MAX_BYTES: positiveInt.default(ATTACHMENT_PLATFORM_DEFAULTS.maxAttachmentBytes),
    ATTACHMENT_ARCHIVE_MAX_DEPTH: positiveInt.default(ATTACHMENT_PLATFORM_DEFAULTS.archiveMaxDepth),
    ATTACHMENT_ARCHIVE_MAX_ENTRIES: positiveInt.default(
      ATTACHMENT_PLATFORM_DEFAULTS.archiveMaxEntries,
    ),
    ATTACHMENT_MAX_ENTRY_BYTES: positiveInt.default(ATTACHMENT_PLATFORM_DEFAULTS.maxEntryBytes),
    ATTACHMENT_MAX_DECOMPRESSED_BYTES: positiveInt.default(
      ATTACHMENT_PLATFORM_DEFAULTS.maxDecompressedBytes,
    ),
    ATTACHMENT_MAX_COMPRESSION_RATIO: positiveInt.default(
      ATTACHMENT_PLATFORM_DEFAULTS.maxCompressionRatio,
    ),
    ATTACHMENT_MAX_ENTRY_FINDINGS: positiveInt.default(
      ATTACHMENT_PLATFORM_DEFAULTS.maxEntryFindings,
    ),
    /** FILE_TYPES ids, comma-separated; empty = the default list, `none` = no platform deny list. */
    ATTACHMENT_DENIED_TYPES: z
      .string()
      .default('')
      .transform((value): string[] => {
        const trimmed = value.trim();
        if (trimmed === '') return [...ATTACHMENT_DEFAULT_DENIED_TYPES];
        if (trimmed === 'none') return [];
        return trimmed
          .split(',')
          .map((t) => t.trim())
          .filter((t) => t.length > 0);
      }),
    ATTACHMENT_DENIED_TYPE_VERDICT: ruleVerdict.default(
      ATTACHMENT_PLATFORM_DEFAULTS.deniedTypeVerdict,
    ),
    ATTACHMENT_TYPE_MISMATCH_VERDICT: ruleVerdict.default(
      ATTACHMENT_PLATFORM_DEFAULTS.typeMismatchVerdict,
    ),
    ATTACHMENT_ENCRYPTED_VERDICT: ruleVerdict.default(
      ATTACHMENT_PLATFORM_DEFAULTS.encryptedArchiveVerdict,
    ),

    // Inspector pool (A4).
    ATTACHMENT_INSPECTOR_POOL_SIZE: positiveInt.max(16).default(2),
    ATTACHMENT_INSPECTOR_MAX_JOBS: positiveInt.max(100_000).default(500),
    ATTACHMENT_INSPECTOR_HEAP_MB: int.min(32).max(4_096).default(192),
    /** `required` (production, containers) refuses to start without prlimit on Linux. */
    ATTACHMENT_INSPECTOR_RLIMITS: z.enum(['required', 'best_effort']).default('required'),
    /** Parent of the per-child private directories; empty = os.tmpdir(). */
    ATTACHMENT_INSPECTOR_TMPDIR: z.string().trim().default(''),
    ATTACHMENT_INSPECT_TIMEOUT_MS: int.min(100).max(600_000).default(30_000),
    ATTACHMENT_INSPECT_CPU_SECONDS: positiveInt.max(600).default(10),
    ATTACHMENT_INSPECT_MAX_RSS_MB: int.min(64).max(16_384).default(384),
    ATTACHMENT_YARA_TIMEOUT_MS: int.min(100).max(600_000).default(10_000),
    /** Another bundle directory with the layout of apps/email-worker/yara; empty = the bundled one. */
    ATTACHMENT_YARA_RULES_DIR: z.string().trim().default(''),
    /**
     * Test hook (A4): spawns inspector children that accept the `selftest` op (spin CPU,
     * allocate memory). Refused when NODE_ENV=production.
     */
    EG_INSPECTOR_SELFTEST: flag.default(false),

    // Content cache (A10).
    ATTACHMENT_CACHE_ENABLED: flag.default(true),
    ATTACHMENT_CACHE_CLEAN_TTL_SECONDS: positiveInt.max(86_400).default(21_600),
    ATTACHMENT_CACHE_MALICIOUS_TTL_SECONDS: positiveInt.max(2_592_000).default(604_800),
    ATTACHMENT_CACHE_OTHER_TTL_SECONDS: positiveInt.max(86_400).default(3_600),
    ATTACHMENT_CACHE_TIMEOUT_MS: int.min(10).max(10_000).default(200),
    /**
     * Secret MAC key of the content cache values (A10): only the email-worker holds it, so a
     * client of the shared Redis cannot plant a cache entry. Required when the cache is enabled.
     */
    ATTACHMENT_CACHE_HMAC_KEY: z.string().min(32).optional(),

    // Sandbox submissions (A11).
    ATTACHMENT_SANDBOX_SUBMIT: flag.default(true),
    ATTACHMENT_SANDBOX_MAX_PER_MESSAGE: int.min(0).max(100).default(5),

    // Signature watcher and rescan jobs (A13).
    ATTACHMENT_SIGNATURE_POLL_MS: int.min(1_000).max(86_400_000).default(300_000),
    ATTACHMENT_SIGNATURE_RESCAN: z.enum(['off', 'record', 'rescan']).default('record'),
    ATTACHMENT_RESCAN_INTERVAL_MS: int.min(100).max(3_600_000).default(10_000),
    ATTACHMENT_RESCAN_BATCH_SIZE: positiveInt.max(1_000).default(50),
    ATTACHMENT_RESCAN_MAX_MESSAGES: positiveInt.max(50_000).default(5_000),
    ATTACHMENT_RESCAN_WINDOW_HOURS: positiveInt.max(168).default(24),
  };
}

/**
 * Security scan configuration (step 4.1 §5, S5, S8, S10, docs/plan/steps/09-rspamd.md;
 * `.env.example` section "Security scanning (step 4.1)"). Every key has the design default; the
 * cross-field refusals are in `validateScanConfig`.
 */
export const scanConfigShape = {
  /** Role flag (S1): the scan role of the worker. */
  SCAN_ENABLED: flag.default(true),
  /** Platform-enabled engines (S4), comma-separated, validated against ENGINE_CATALOG. */
  SCAN_ENGINES: z
    .string()
    .default('rspamd,attachment,url')
    .transform((value, ctx): EngineName[] => {
      try {
        return parseEnabledEngines(value);
      } catch (err) {
        ctx.addIssue({ code: 'custom', message: (err as Error).message });
        return z.NEVER;
      }
    }),
  /**
   * Engines whose queue consumers this replica runs (step 4.2 A1), comma-separated; empty = every
   * enabled engine. Must be a non-empty subset of SCAN_ENGINES (validated). The required engines
   * of a round still come from SCAN_ENGINES, identical on every scan replica.
   */
  SCAN_CONSUMERS: z
    .string()
    .default('')
    .transform((value, ctx): EngineName[] => {
      if (value.trim() === '') return [];
      try {
        return parseEnabledEngines(value);
      } catch (err) {
        ctx.addIssue({ code: 'custom', message: (err as Error).message });
        return z.NEVER;
      }
    }),
  /**
   * The scan role's own least-privilege RabbitMQ user `eg-scanner` (S1, S2): read `scan.spam`,
   * write `email.security` / `email.events`. Comma-separated node URLs (`_FILE` supported).
   * Required when SCAN_ENABLED.
   */
  RABBITMQ_SCANNER_URL: amqpUrlListSchema.optional(),

  // Rspamd (S9): the normal worker for /checkv2, the controller (read password) for the
  // engine version when a reply carries no Server header.
  SCAN_RSPAMD_URL: httpUrl.optional(),
  RSPAMD_CONTROLLER_URL: httpUrl.optional(),
  RSPAMD_CONTROLLER_PASSWORD: z.string().min(1).optional(),

  // The Rspamd engine's budgets (S5, S10).
  SCAN_RSPAMD_CONCURRENCY: positiveInt.max(64).default(8),
  SCAN_RSPAMD_TIMEOUT_MS: int.min(100).default(20_000),
  SCAN_RSPAMD_MAX_ATTEMPTS: positiveInt.default(6),
  SCAN_RSPAMD_MAX_BYTES: positiveInt.default(26_214_400),

  // Hold retries of the engine consumers (step 3.2 Q8: the delay keeps the prefetch slot).
  SCAN_RETRY_BASE_MS: positiveInt.default(2_000),
  SCAN_RETRY_MAX_MS: positiveInt.max(HOLD_MAX_DELAY_MS).default(60_000),

  SCAN_S3_TIMEOUT_MS: int.min(100).default(30_000),
  /** Writer transaction budget; above lock waits and writer stalls (as MIME_DB_TIMEOUT_MS, §6). */
  SCAN_DB_TIMEOUT_MS: int.min(100).default(120_000),

  // Round deadline and its sweeper (S10).
  SCAN_ROUND_DEADLINE_SECONDS: positiveInt.max(SCAN_ROUND_DEADLINE_MAX_SECONDS).default(1_800),
  SCAN_SWEEP_INTERVAL_MS: int.min(100).default(30_000),
  SCAN_SWEEP_LOOKBACK_HOURS: positiveInt.max(24 * 31).default(48),
  SCAN_SWEEP_BATCH_SIZE: positiveInt.max(1_000).default(200),

  // Circuit breaker per engine and worker (S10).
  SCAN_BREAKER_FAILURE_THRESHOLD: positiveInt.max(1_000).default(5),
  SCAN_BREAKER_FAILURE_RATIO: z.coerce.number().gt(0).max(1).default(0.5),
  SCAN_BREAKER_WINDOW: int.min(10).max(1_000).default(20),
  SCAN_BREAKER_OPEN_MS: int.min(100).default(15_000),
  SCAN_BREAKER_HALF_OPEN_PROBES: positiveInt.max(64).default(1),

  // Caches (S8, S9).
  SCAN_SETTINGS_CACHE_TTL_MS: int.min(0).max(300_000).default(30_000),
  SCAN_ENGINE_VERSION_TTL_MS: int.min(1_000).default(300_000),

  // Platform Rspamd settings (S8); validated together with rspamdPlatformSettingsSchema.
  SCAN_RSPAMD_SPAM_SCORE: score.default(RSPAMD_PLATFORM_DEFAULTS.spamScore),
  SCAN_RSPAMD_SUSPICIOUS_SCORE: score.default(RSPAMD_PLATFORM_DEFAULTS.suspiciousScore),
  SCAN_RSPAMD_SCORE_MIN: score.default(RSPAMD_PLATFORM_DEFAULTS.scoreMin),
  SCAN_RSPAMD_SCORE_MAX: score.default(RSPAMD_PLATFORM_DEFAULTS.scoreMax),
  SCAN_RSPAMD_PHISHING_VERDICT: z
    .enum(PHISHING_VERDICTS)
    .default(RSPAMD_PLATFORM_DEFAULTS.phishingVerdict),
  SCAN_RSPAMD_DMARC_REJECT_VERDICT: z
    .enum(DMARC_REJECT_VERDICTS)
    .default(RSPAMD_PLATFORM_DEFAULTS.dmarcRejectVerdict),
  SCAN_RSPAMD_AUTH_FAILURE_VERDICT: z
    .enum(AUTH_FAILURE_VERDICTS)
    .default(RSPAMD_PLATFORM_DEFAULTS.authFailureVerdict),

  ...attachmentConfigShape(),
  ...urlConfigShape(),
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- only its type is used
const scanObject = z.object(scanConfigShape);
export type ScanShapeConfig = z.infer<typeof scanObject>;

/** The platform Rspamd settings of the config (S8). */
export function rspamdPlatformFromConfig(cfg: ScanShapeConfig): RspamdPlatformSettings {
  return {
    spamScore: cfg.SCAN_RSPAMD_SPAM_SCORE,
    suspiciousScore: cfg.SCAN_RSPAMD_SUSPICIOUS_SCORE,
    scoreMin: cfg.SCAN_RSPAMD_SCORE_MIN,
    scoreMax: cfg.SCAN_RSPAMD_SCORE_MAX,
    phishingVerdict: cfg.SCAN_RSPAMD_PHISHING_VERDICT,
    dmarcRejectVerdict: cfg.SCAN_RSPAMD_DMARC_REJECT_VERDICT,
    authFailureVerdict: cfg.SCAN_RSPAMD_AUTH_FAILURE_VERDICT,
  };
}

const PLATFORM_KEYS: Record<keyof RspamdPlatformSettings, keyof ScanShapeConfig> = {
  spamScore: 'SCAN_RSPAMD_SPAM_SCORE',
  suspiciousScore: 'SCAN_RSPAMD_SUSPICIOUS_SCORE',
  scoreMin: 'SCAN_RSPAMD_SCORE_MIN',
  scoreMax: 'SCAN_RSPAMD_SCORE_MAX',
  phishingVerdict: 'SCAN_RSPAMD_PHISHING_VERDICT',
  dmarcRejectVerdict: 'SCAN_RSPAMD_DMARC_REJECT_VERDICT',
  authFailureVerdict: 'SCAN_RSPAMD_AUTH_FAILURE_VERDICT',
};

/** The budget keys of one engine (S5, S10; step 4.2 A12). */
export interface EngineBudgetKeys {
  concurrency: number;
  timeoutMs: number;
  maxAttempts: number;
}

/** `SCAN_<ENGINE>_CONCURRENCY`, `_TIMEOUT_MS`, `_MAX_ATTEMPTS` of an engine with an adapter. */
export function engineBudgetFromConfig(
  cfg: ScanShapeConfig,
  engine: EngineName,
): EngineBudgetKeys | null {
  switch (engine) {
    case 'rspamd':
      return {
        concurrency: cfg.SCAN_RSPAMD_CONCURRENCY,
        timeoutMs: cfg.SCAN_RSPAMD_TIMEOUT_MS,
        maxAttempts: cfg.SCAN_RSPAMD_MAX_ATTEMPTS,
      };
    case 'attachment':
      return {
        concurrency: cfg.SCAN_ATTACHMENT_CONCURRENCY,
        timeoutMs: cfg.SCAN_ATTACHMENT_TIMEOUT_MS,
        maxAttempts: cfg.SCAN_ATTACHMENT_MAX_ATTEMPTS,
      };
    case 'url':
      return {
        concurrency: cfg.SCAN_URL_CONCURRENCY,
        timeoutMs: cfg.SCAN_URL_TIMEOUT_MS,
        maxAttempts: cfg.SCAN_URL_MAX_ATTEMPTS,
      };
    default:
      return null;
  }
}

/** The key prefix of an engine's budget keys (`SCAN_RSPAMD`, `SCAN_ATTACHMENT`). */
const budgetPrefix = (engine: EngineName): string => `SCAN_${engine.toUpperCase()}`;

/**
 * Smallest round deadline that lets every enabled engine use its whole attempt budget (S10,
 * generalized by step 4.2 A12): the maximum over SCAN_ENGINES of
 * `maxAttempts x (timeoutMs + SCAN_RETRY_MAX_MS) / 1000`.
 */
export function minimumRoundDeadlineSeconds(cfg: ScanShapeConfig): number {
  let minimum = 0;
  for (const engine of cfg.SCAN_ENGINES) {
    const budget = engineBudgetFromConfig(cfg, engine);
    if (!budget) continue;
    minimum = Math.max(
      minimum,
      Math.ceil((budget.maxAttempts * (budget.timeoutMs + cfg.SCAN_RETRY_MAX_MS)) / 1000),
    );
  }
  return minimum;
}

/** The engines whose consumers this replica runs (A1): SCAN_CONSUMERS, or every enabled engine. */
export function consumerEngines(cfg: ScanShapeConfig): EngineName[] {
  return cfg.SCAN_CONSUMERS.length > 0 ? [...cfg.SCAN_CONSUMERS] : [...cfg.SCAN_ENGINES];
}

/** True when this replica runs the attachment engine's consumer. */
export const runsAttachmentConsumer = (cfg: ScanShapeConfig): boolean =>
  cfg.SCAN_ENABLED && consumerEngines(cfg).includes('attachment');

/** True when this replica runs the url engine's consumer (and its results consumer, U1). */
export const runsUrlConsumer = (cfg: ScanShapeConfig): boolean =>
  cfg.SCAN_ENABLED && cfg.SCAN_ENGINES.includes('url') && consumerEngines(cfg).includes('url');

/** The platform attachment settings of the config (A8). Not validated (see the schema). */
export function attachmentPlatformFromConfig(cfg: ScanShapeConfig): AttachmentPlatformSettings {
  return {
    maxAttachmentBytes: cfg.ATTACHMENT_MAX_BYTES,
    archiveMaxDepth: cfg.ATTACHMENT_ARCHIVE_MAX_DEPTH,
    archiveMaxEntries: cfg.ATTACHMENT_ARCHIVE_MAX_ENTRIES,
    maxEntryBytes: cfg.ATTACHMENT_MAX_ENTRY_BYTES,
    maxDecompressedBytes: cfg.ATTACHMENT_MAX_DECOMPRESSED_BYTES,
    maxCompressionRatio: cfg.ATTACHMENT_MAX_COMPRESSION_RATIO,
    maxEntryFindings: cfg.ATTACHMENT_MAX_ENTRY_FINDINGS,
    deniedTypes: cfg.ATTACHMENT_DENIED_TYPES as AttachmentPlatformSettings['deniedTypes'],
    deniedTypeVerdict: cfg.ATTACHMENT_DENIED_TYPE_VERDICT,
    typeMismatchVerdict: cfg.ATTACHMENT_TYPE_MISMATCH_VERDICT,
    encryptedArchiveVerdict: cfg.ATTACHMENT_ENCRYPTED_VERDICT,
  };
}

/**
 * Scaling hints that are not refusals (A20): every inspector child can only be busy when the
 * engine's message concurrency times the per-message parallelism reaches the pool size.
 */
export function attachmentScalingWarnings(cfg: ScanShapeConfig): string[] {
  const warnings: string[] = [];
  if (
    cfg.SCAN_ATTACHMENT_CONCURRENCY * cfg.ATTACHMENT_PER_MESSAGE_PARALLELISM <
    cfg.ATTACHMENT_INSPECTOR_POOL_SIZE
  ) {
    warnings.push('inspector_pool_larger_than_parallelism');
  }
  if (cfg.CLAMAV_MAX_CONNECTIONS < cfg.ATTACHMENT_INSPECTOR_POOL_SIZE) {
    warnings.push('clamav_connections_below_pool_size');
  }
  return warnings;
}

type AttachmentValidationConfig = ScanShapeConfig & {
  NODE_ENV: 'development' | 'test' | 'production';
  APP_ENV: string;
  MIME_MAX_ATTACHMENT_BYTES: number;
  MIME_MAX_BODY_BYTES: number;
};

/** The cross-field refusals of the attachment engine (A4, A8, A12, A14, A20). */
function validateAttachmentConfig(
  cfg: AttachmentValidationConfig,
  refuse: (path: string, message: string) => void,
): void {
  const production = cfg.NODE_ENV === 'production';
  if (production && cfg.ATTACHMENT_INSPECTOR_RLIMITS === 'best_effort') {
    refuse(
      'ATTACHMENT_INSPECTOR_RLIMITS',
      'best_effort is refused when NODE_ENV=production (the inspector needs prlimit)',
    );
  }
  if (production && cfg.EG_INSPECTOR_SELFTEST) {
    refuse('EG_INSPECTOR_SELFTEST', 'is refused when NODE_ENV=production (test hook)');
  }
  const platform = attachmentPlatformSettingsSchema.safeParse(attachmentPlatformFromConfig(cfg));
  if (!platform.success) {
    for (const issue of platform.error.issues) {
      const key =
        ATTACHMENT_PLATFORM_ENV_KEYS[issue.path[0] as keyof AttachmentPlatformSettings] ??
        'ATTACHMENT_MAX_BYTES';
      refuse(key, issue.message);
    }
  }
  if (cfg.ATTACHMENT_MAX_BYTES > cfg.MIME_MAX_ATTACHMENT_BYTES) {
    refuse('ATTACHMENT_MAX_BYTES', 'must not exceed MIME_MAX_ATTACHMENT_BYTES');
  }
  if (cfg.ATTACHMENT_MEMORY_BUDGET_BYTES < cfg.ATTACHMENT_MAX_BYTES) {
    refuse(
      'ATTACHMENT_MEMORY_BUDGET_BYTES',
      'must be at least ATTACHMENT_MAX_BYTES (one attachment must fit the byte budget)',
    );
  }
  const queueMax = engineQueueMaxAttempts('attachment');
  if (cfg.SCAN_ATTACHMENT_MAX_ATTEMPTS >= queueMax) {
    refuse(
      'SCAN_ATTACHMENT_MAX_ATTEMPTS',
      `must be below ${String(queueMax)}, the attempt limit of queue scan.attachment ` +
        '(the engine must finalize its result before the consumer dead-letters)',
    );
  }
  if (cfg.ATTACHMENT_INSPECT_CPU_SECONDS * 1000 > cfg.ATTACHMENT_INSPECT_TIMEOUT_MS) {
    refuse(
      'ATTACHMENT_INSPECT_CPU_SECONDS',
      'must not exceed ATTACHMENT_INSPECT_TIMEOUT_MS (the CPU limit could never fire)',
    );
  }
  if (cfg.ATTACHMENT_YARA_TIMEOUT_MS > cfg.ATTACHMENT_INSPECT_TIMEOUT_MS) {
    refuse('ATTACHMENT_YARA_TIMEOUT_MS', 'must not exceed ATTACHMENT_INSPECT_TIMEOUT_MS');
  }
  if (cfg.ATTACHMENT_INSPECT_MAX_RSS_MB <= cfg.ATTACHMENT_INSPECTOR_HEAP_MB) {
    refuse(
      'ATTACHMENT_INSPECT_MAX_RSS_MB',
      'must be above ATTACHMENT_INSPECTOR_HEAP_MB (the V8 heap cap must hit first)',
    );
  }
  const perFile = Math.max(cfg.ATTACHMENT_INSPECT_TIMEOUT_MS, cfg.CLAMAV_TIMEOUT_MS);
  if (cfg.SCAN_ATTACHMENT_TIMEOUT_MS <= perFile) {
    refuse(
      'SCAN_ATTACHMENT_TIMEOUT_MS',
      'must be above ATTACHMENT_INSPECT_TIMEOUT_MS and CLAMAV_TIMEOUT_MS (one attachment must fit an engine call)',
    );
  }
  if (cfg.SCAN_S3_TIMEOUT_MS >= cfg.SCAN_ATTACHMENT_TIMEOUT_MS) {
    refuse('SCAN_S3_TIMEOUT_MS', 'must be below SCAN_ATTACHMENT_TIMEOUT_MS');
  }
}

/** The cross-field refusals of S5, S8 and S10 (startup fails with every violated rule listed). */
export function validateScanConfig(
  cfg: AttachmentValidationConfig & {
    MIME_INGESTION_ENABLED: boolean;
    RABBITMQ_EMAIL_WORKER_URL?: string[];
  },
  ctx: z.RefinementCtx,
): void {
  const refuse = (path: string, message: string): void => {
    ctx.addIssue({ code: 'custom', path: [path], message });
  };
  if (!cfg.MIME_INGESTION_ENABLED && !cfg.SCAN_ENABLED) {
    refuse(
      'SCAN_ENABLED',
      'at least one role must be enabled (MIME_INGESTION_ENABLED or SCAN_ENABLED)',
    );
  }
  if (cfg.MIME_INGESTION_ENABLED && cfg.RABBITMQ_EMAIL_WORKER_URL === undefined) {
    refuse('RABBITMQ_EMAIL_WORKER_URL', 'is required when MIME_INGESTION_ENABLED is true');
  }

  const platform = rspamdPlatformSettingsSchema.safeParse(rspamdPlatformFromConfig(cfg));
  if (!platform.success) {
    for (const issue of platform.error.issues) {
      const key = PLATFORM_KEYS[issue.path[0] as keyof RspamdPlatformSettings];
      refuse(key ?? 'SCAN_RSPAMD_SPAM_SCORE', issue.message);
    }
  }
  if (cfg.SCAN_RETRY_MAX_MS < cfg.SCAN_RETRY_BASE_MS) {
    refuse('SCAN_RETRY_MAX_MS', 'must be at least SCAN_RETRY_BASE_MS');
  }
  const queueMax = engineQueueMaxAttempts('rspamd');
  if (cfg.SCAN_RSPAMD_MAX_ATTEMPTS >= queueMax) {
    refuse(
      'SCAN_RSPAMD_MAX_ATTEMPTS',
      `must be below ${String(queueMax)}, the attempt limit of queue scan.spam ` +
        '(the engine must finalize its result before the consumer dead-letters)',
    );
  }
  const minimum = minimumRoundDeadlineSeconds(cfg);
  if (cfg.SCAN_ROUND_DEADLINE_SECONDS < minimum) {
    const engines = cfg.SCAN_ENGINES.filter((e) => engineBudgetFromConfig(cfg, e) !== null);
    refuse(
      'SCAN_ROUND_DEADLINE_SECONDS',
      `must be at least the maximum over SCAN_ENGINES (${engines.join(', ')}) of ` +
        `${engines.map(budgetPrefix).join('|')}_MAX_ATTEMPTS x (_TIMEOUT_MS + SCAN_RETRY_MAX_MS) ` +
        `/ 1000 = ${String(minimum)} (every attempt must fit before the deadline sweeper finalizes)`,
    );
  }
  for (const engine of cfg.SCAN_CONSUMERS) {
    if (!cfg.SCAN_ENGINES.includes(engine)) {
      refuse('SCAN_CONSUMERS', `must be a subset of SCAN_ENGINES (${engine} is not enabled)`);
    }
  }
  if (cfg.SCAN_ENGINES.includes('attachment')) validateAttachmentConfig(cfg, refuse);
  if (cfg.SCAN_ENGINES.includes('url')) {
    validateUrlConfig(cfg, runsUrlConsumer(cfg), engineQueueMaxAttempts('url'), refuse);
  }
  if (!cfg.SCAN_ENABLED) return;
  if (
    consumerEngines(cfg).includes('attachment') &&
    cfg.SCAN_ENGINES.includes('attachment') &&
    cfg.ATTACHMENT_CACHE_ENABLED &&
    cfg.ATTACHMENT_CACHE_HMAC_KEY === undefined
  ) {
    refuse(
      'ATTACHMENT_CACHE_HMAC_KEY',
      'is required when the attachment engine consumes with ATTACHMENT_CACHE_ENABLED=true',
    );
  }
  if (cfg.RABBITMQ_SCANNER_URL === undefined) {
    refuse('RABBITMQ_SCANNER_URL', 'is required when SCAN_ENABLED is true');
  }
  if (
    consumerEngines(cfg).includes('rspamd') &&
    cfg.SCAN_ENGINES.includes('rspamd') &&
    cfg.SCAN_RSPAMD_URL === undefined
  ) {
    refuse('SCAN_RSPAMD_URL', 'is required when the rspamd engine is enabled');
  }
  if (cfg.RSPAMD_CONTROLLER_PASSWORD !== undefined && cfg.RSPAMD_CONTROLLER_URL === undefined) {
    refuse('RSPAMD_CONTROLLER_URL', 'is required when RSPAMD_CONTROLLER_PASSWORD is set');
  }
}
