import { loadLocalModel, loadModelManifest } from '@email-gateway/bec';
import {
  BEC_AI_MODES,
  BEC_PLATFORM_DEFAULTS,
  BEC_PLATFORM_ENV_KEYS,
  type BecPlatformSettings,
  becPlatformSettingsSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * The bec engine's keys (step 4.4 §5, B4, B8–B13, B16; `.env.example` section "Phishing and BEC
 * detection (step 4.4)"), as the email-worker uses them. Every key has the design default and an
 * explicit bound; the cross-field rules are in `validateBecConfig`. The api reads the platform
 * bound keys itself.
 */

const int = z.coerce.number().int();
const positiveInt = int.min(1);
const modelVersion = z
  .string()
  .trim()
  .regex(/^[a-z][a-z0-9-]*\/\d+$/, 'must be a model version such as bec-lr/1');
const optionalModelVersion = z
  .string()
  .trim()
  .default('')
  .refine((v) => v === '' || /^[a-z][a-z0-9-]*\/\d+$/.test(v), 'must be empty or a model version');
const llmModelId = z
  .string()
  .trim()
  .regex(/^[a-z0-9][a-z0-9.-]{0,95}$/, 'must be a model id (lower-case letters, digits, . and -)');

export function becConfigShape() {
  return {
    // The engine's budgets (B4): prefetch, whole-call timeout, attempts (< queue limit 10).
    SCAN_BEC_CONCURRENCY: positiveInt.max(64).default(8),
    SCAN_BEC_TIMEOUT_MS: int.min(1_000).max(600_000).default(45_000),
    SCAN_BEC_MAX_ATTEMPTS: positiveInt.default(3),

    // Text analysis (B8).
    BEC_TEXT_MAX_BYTES: int.min(1_024).max(10_485_760).default(65_536),
    BEC_TEXT_MAX_CHARS: int.min(1_000).max(1_000_000).default(40_000),
    BEC_TEXT_TIMEOUT_MS: int.min(50).max(60_000).default(2_000),

    // Platform settings (B13), validated with becPlatformSettingsSchema.
    BEC_SUSPICIOUS_SCORE: int.default(BEC_PLATFORM_DEFAULTS.suspiciousScore),
    BEC_MALICIOUS_SCORE: int.default(BEC_PLATFORM_DEFAULTS.maliciousScore),
    BEC_AI_RAISE_CONFIDENCE: z.coerce
      .number()
      .finite()
      .default(BEC_PLATFORM_DEFAULTS.aiRaiseConfidence),
    BEC_AI_CORROBORATE_CONFIDENCE: z.coerce
      .number()
      .finite()
      .default(BEC_PLATFORM_DEFAULTS.aiCorroborateConfidence),
    BEC_AI_MALICIOUS_BAND: int.default(BEC_PLATFORM_DEFAULTS.aiMaliciousBand),
    BEC_LOCAL_MODEL_MODE: z.enum(BEC_AI_MODES).default(BEC_PLATFORM_DEFAULTS.localModelMode),
    BEC_LLM_MODE: z.enum(BEC_AI_MODES).default(BEC_PLATFORM_DEFAULTS.llmMode),
    BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY: int.default(
      BEC_PLATFORM_DEFAULTS.llmMaxCallsPerTenantPerDay,
    ),
    BEC_HISTORY_DEFAULT_RETENTION_DAYS: int.default(
      BEC_PLATFORM_DEFAULTS.historyDefaultRetentionDays,
    ),
    BEC_HISTORY_MAX_RETENTION_DAYS: int.default(BEC_PLATFORM_DEFAULTS.historyMaxRetentionDays),

    // Local model (B9, B16): versions of packages/bec/models/manifest.json.
    BEC_LOCAL_MODEL: modelVersion.default('bec-lr/1'),
    BEC_LOCAL_MODEL_SHADOW: optionalModelVersion,

    // LLM (B10).
    BEC_LLM_PROVIDER: z.enum(['anthropic', 'fake']).default('anthropic'),
    BEC_LLM_MODEL: llmModelId.default('claude-opus-5-5'),
    BEC_LLM_SHADOW_MODEL: z
      .string()
      .trim()
      .default('')
      .refine(
        (v) => v === '' || /^[a-z0-9][a-z0-9.-]{0,95}$/.test(v),
        'must be empty or a model id',
      ),
    BEC_LLM_REFUSAL_FALLBACK: z.enum(['default', 'off']).default('default'),
    /** Operator-supplied secret; never logged. Empty = no LLM calls. */
    BEC_LLM_API_KEY: z.string().min(1).optional(),
    BEC_LLM_TIMEOUT_MS: int.min(1_000).max(120_000).default(20_000),
    BEC_LLM_MAX_OUTPUT_TOKENS: int.min(256).max(32_000).default(4_096),
    BEC_LLM_MAX_EXCERPT_CHARS: int.min(200).max(10_000).default(1_500),
    BEC_LLM_MIN_SCORE: int.min(0).max(100).default(15),
    BEC_LLM_CONCURRENCY: positiveInt.max(64).default(4),
    BEC_LLM_MAX_CALLS_PER_MINUTE: positiveInt.max(100_000).default(120),
    BEC_LLM_BREAKER_THRESHOLD: positiveInt.max(1_000).default(5),
    BEC_LLM_BREAKER_RESET_MS: int.min(1_000).max(3_600_000).default(60_000),

    // Communication history (B12, ADR-0035).
    /** Secret (≥ 32 characters): only the bec-consuming worker holds it. */
    BEC_CONTEXT_HMAC_KEY: z.string().min(32).optional(),
    BEC_HISTORY_MIN_MESSAGES: positiveInt.max(1_000).default(3),
    BEC_HISTORY_MAX_RECIPIENTS: positiveInt.max(50).default(50),
    BEC_HISTORY_SWEEP_INTERVAL_MS: int.min(1_000).max(86_400_000).default(3_600_000),

    // Tenant data (B4 step 3, B11, B18).
    BEC_TENANT_DATA_CACHE_TTL_MS: int.min(0).max(300_000).default(30_000),
    BEC_SUPPRESSIONS_MAX_PER_TENANT: positiveInt.max(10_000).default(200),
    BEC_SUPPRESSION_MAX_WEIGHT: int.min(0).max(100).default(40),
    BEC_MAX_EXECUTIVES: positiveInt.max(10_000).default(500),
    BEC_MAX_VENDORS: positiveInt.max(50_000).default(2_000),
    BEC_MAX_TRUSTED_SENDERS: positiveInt.max(50_000).default(1_000),
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- only its type is used
const becObject = z.object(becConfigShape());
export type BecShapeConfig = z.infer<typeof becObject>;

/** The platform BEC settings of the config (B13). Not validated (see the schema). */
export function becPlatformFromConfig(cfg: BecShapeConfig): BecPlatformSettings {
  return {
    suspiciousScore: cfg.BEC_SUSPICIOUS_SCORE,
    maliciousScore: cfg.BEC_MALICIOUS_SCORE,
    aiRaiseConfidence: cfg.BEC_AI_RAISE_CONFIDENCE,
    aiCorroborateConfidence: cfg.BEC_AI_CORROBORATE_CONFIDENCE,
    aiMaliciousBand: cfg.BEC_AI_MALICIOUS_BAND,
    localModelMode: cfg.BEC_LOCAL_MODEL_MODE,
    llmMode: cfg.BEC_LLM_MODE,
    llmMaxCallsPerTenantPerDay: cfg.BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY,
    historyDefaultRetentionDays: cfg.BEC_HISTORY_DEFAULT_RETENTION_DAYS,
    historyMaxRetentionDays: cfg.BEC_HISTORY_MAX_RETENTION_DAYS,
  };
}

type BecValidationConfig = BecShapeConfig & {
  NODE_ENV: string;
  SCAN_S3_TIMEOUT_MS: number;
};

/**
 * The cross-field refusals of the bec engine (startup fails with every violated rule listed;
 * values, in particular the secrets, are never echoed). `consumes`: this replica runs the `bec`
 * consumer (the secrets and the local models are checked only there).
 */
export function validateBecConfig(
  cfg: BecValidationConfig,
  consumes: boolean,
  queueMaxAttempts: number,
  refuse: (path: string, message: string) => void,
): void {
  if (cfg.SCAN_BEC_MAX_ATTEMPTS >= queueMaxAttempts) {
    refuse(
      'SCAN_BEC_MAX_ATTEMPTS',
      `must be below ${String(queueMaxAttempts)}, the attempt limit of queue scan.bec ` +
        '(the engine must finalize its result before the consumer dead-letters)',
    );
  }
  for (const key of ['BEC_LLM_TIMEOUT_MS', 'BEC_TEXT_TIMEOUT_MS', 'SCAN_S3_TIMEOUT_MS'] as const) {
    if (cfg[key] >= cfg.SCAN_BEC_TIMEOUT_MS) refuse(key, 'must be below SCAN_BEC_TIMEOUT_MS');
  }
  const platform = becPlatformSettingsSchema.safeParse(becPlatformFromConfig(cfg));
  if (!platform.success) {
    for (const issue of platform.error.issues) {
      const key = BEC_PLATFORM_ENV_KEYS[issue.path[0] as keyof BecPlatformSettings];
      refuse(key ?? 'BEC_SUSPICIOUS_SCORE', issue.message);
    }
  }
  if (cfg.BEC_LLM_PROVIDER === 'fake' && cfg.NODE_ENV === 'production') {
    refuse('BEC_LLM_PROVIDER', 'fake is refused when NODE_ENV=production (test stand-in)');
  }
  if (cfg.BEC_LOCAL_MODEL_SHADOW !== '' && cfg.BEC_LOCAL_MODEL_SHADOW === cfg.BEC_LOCAL_MODEL) {
    refuse('BEC_LOCAL_MODEL_SHADOW', 'must differ from BEC_LOCAL_MODEL');
  }
  if (cfg.BEC_LLM_SHADOW_MODEL !== '' && cfg.BEC_LLM_SHADOW_MODEL === cfg.BEC_LLM_MODEL) {
    refuse('BEC_LLM_SHADOW_MODEL', 'must differ from BEC_LLM_MODEL');
  }

  if (!consumes) return;
  if (cfg.BEC_CONTEXT_HMAC_KEY === undefined) {
    refuse('BEC_CONTEXT_HMAC_KEY', 'is required (>= 32 characters) when the bec engine consumes');
  }
  if (
    cfg.BEC_LLM_MODE !== 'off' &&
    cfg.BEC_LLM_PROVIDER === 'anthropic' &&
    cfg.BEC_LLM_API_KEY === undefined
  ) {
    refuse(
      'BEC_LLM_API_KEY',
      'is required when BEC_LLM_MODE is not off with BEC_LLM_PROVIDER=anthropic',
    );
  }
  // B16: the active and shadow local models must be in the packaged manifest with the hash of
  // their file; the worker refuses to start otherwise.
  let manifest: ReturnType<typeof loadModelManifest> | null = null;
  try {
    manifest = loadModelManifest();
  } catch {
    refuse('BEC_LOCAL_MODEL', 'packages/bec/models/manifest.json is missing or invalid');
  }
  if (!manifest) return;
  for (const key of ['BEC_LOCAL_MODEL', 'BEC_LOCAL_MODEL_SHADOW'] as const) {
    const version = cfg[key];
    if (version === '') continue;
    try {
      loadLocalModel(version, manifest);
    } catch (err) {
      refuse(key, (err as Error).message);
    }
  }
}
