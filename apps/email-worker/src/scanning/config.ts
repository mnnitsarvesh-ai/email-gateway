import { amqpUrlListSchema } from '@email-gateway/config';
import { HOLD_MAX_DELAY_MS, queueDefinition } from '@email-gateway/event-contracts';
import {
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
    .default('rspamd')
    .transform((value, ctx): EngineName[] => {
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
  SCAN_DB_TIMEOUT_MS: int.min(100).default(15_000),

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

/** Smallest round deadline that lets the engine use its whole attempt budget (S10). */
export function minimumRoundDeadlineSeconds(cfg: ScanShapeConfig): number {
  return Math.ceil(
    (cfg.SCAN_RSPAMD_MAX_ATTEMPTS * (cfg.SCAN_RSPAMD_TIMEOUT_MS + cfg.SCAN_RETRY_MAX_MS)) / 1000,
  );
}

/** The cross-field refusals of S5, S8 and S10 (startup fails with every violated rule listed). */
export function validateScanConfig(
  cfg: ScanShapeConfig & { MIME_INGESTION_ENABLED: boolean; RABBITMQ_EMAIL_WORKER_URL?: string[] },
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
    refuse(
      'SCAN_ROUND_DEADLINE_SECONDS',
      `must be at least SCAN_RSPAMD_MAX_ATTEMPTS x (SCAN_RSPAMD_TIMEOUT_MS + SCAN_RETRY_MAX_MS) ` +
        `/ 1000 = ${String(minimum)} (every attempt must fit before the deadline sweeper finalizes)`,
    );
  }
  if (!cfg.SCAN_ENABLED) return;
  if (cfg.RABBITMQ_SCANNER_URL === undefined) {
    refuse('RABBITMQ_SCANNER_URL', 'is required when SCAN_ENABLED is true');
  }
  if (cfg.SCAN_ENGINES.includes('rspamd') && cfg.SCAN_RSPAMD_URL === undefined) {
    refuse('SCAN_RSPAMD_URL', 'is required when the rspamd engine is enabled');
  }
  if (cfg.RSPAMD_CONTROLLER_PASSWORD !== undefined && cfg.RSPAMD_CONTROLLER_URL === undefined) {
    refuse('RSPAMD_CONTROLLER_URL', 'is required when RSPAMD_CONTROLLER_PASSWORD is set');
  }
}
