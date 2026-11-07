import {
  DLP_PLATFORM_ENV_KEYS,
  type DlpPlatformSettings,
  dlpPlatformSettingsSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * The dlp engine's keys (step 4.5 §5, D1, D3, D4, D9, D16, D18; `.env.example` section "Data loss
 * prevention (step 4.5)"), as the email-worker uses them. Every key has the design default and an
 * explicit bound; the cross-field rules are in `validateDlpConfig`. The api reads the bound keys
 * itself. Start-up errors name the key, never its value (the evidence key is a secret).
 */

const int = z.coerce.number().int();
const positiveInt = int.min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const HEX64 = /^[0-9a-fA-F]{64}$/;

export function dlpConfigShape() {
  return {
    // The engine's budgets (D1): prefetch, whole-message call timeout, attempts (< queue limit 10).
    SCAN_DLP_CONCURRENCY: positiveInt.max(64).default(4),
    SCAN_DLP_TIMEOUT_MS: int.min(1_000).max(600_000).default(120_000),
    SCAN_DLP_MAX_ATTEMPTS: positiveInt.default(3),

    // Extractor pool (D4): the generalized 4.2 child pool, second instance.
    DLP_EXTRACTOR_POOL_SIZE: positiveInt.max(16).default(2),
    DLP_EXTRACTOR_MAX_JOBS: positiveInt.max(100_000).default(200),
    DLP_EXTRACTOR_HEAP_MB: int.min(64).max(4_096).default(256),
    /** `required` (production, containers) refuses to start without prlimit on Linux. */
    DLP_EXTRACTOR_RLIMITS: z.enum(['required', 'best_effort']).default('required'),
    DLP_EXTRACT_TIMEOUT_MS: int.min(100).max(600_000).default(20_000),
    DLP_EXTRACT_CPU_SECONDS: positiveInt.max(600).default(10),
    DLP_EXTRACT_MAX_RSS_MB: int.min(64).max(16_384).default(512),

    // Attachment and text bounds (D4).
    DLP_MAX_ATTACHMENTS: positiveInt.max(1_000).default(50),
    DLP_ATTACHMENT_MAX_BYTES: positiveInt.max(1_073_741_824).default(26_214_400),
    DLP_BYTE_BUDGET_BYTES: positiveInt.max(8 * 1024 * 1024 * 1024).default(67_108_864),
    DLP_PDF_MAX_PAGES: positiveInt.max(10_000).default(200),
    DLP_BODY_MAX_BYTES: positiveInt.max(104_857_600).default(4_194_304),
    DLP_TEXT_MAX_CHARS_PER_PART: int.min(1_000).max(10_000_000).default(1_000_000),
    DLP_TEXT_MAX_CHARS_PER_MESSAGE: int.min(1_000).max(40_000_000).default(4_000_000),

    // Detection (D3 step 5, D7).
    DLP_DETECT_TIMEOUT_MS: int.min(50).max(600_000).default(15_000),
    DLP_SCAN_CHUNK_CHARS: int.min(4_096).max(1_048_576).default(65_536),
    DLP_MAX_MATCHES_PER_DETECTOR: positiveInt.max(100_000).default(1_000),
    DLP_MAX_FINDINGS: positiveInt.max(64).default(64),

    // Platform settings (D18), validated with dlpPlatformSettingsSchema.
    DLP_CONFIDENCE_THRESHOLD: z.coerce.number().finite().default(0.6),
    DLP_CONTEXT_WINDOW_CHARS: int.default(64),
    DLP_BULK_MIN_DISTINCT: int.default(5),
    DLP_DEFAULT_POLICY: z.enum(['alert', 'allow']).default('alert'),
    DLP_EVIDENCE_ENABLED: flag.default(true),
    DLP_EVIDENCE_DEFAULT_RETENTION_DAYS: int.default(30),
    DLP_EVIDENCE_MAX_RETENTION_DAYS: int.default(180),

    // Tenant patterns and data the worker loads (D8, D9, D21).
    DLP_CUSTOM_PATTERN_MAX_LENGTH: int.min(16).max(512).default(256),
    DLP_CUSTOM_SCAN_MAX_CHARS: int.min(1_000).max(40_000_000).default(1_000_000),
    DLP_CUSTOM_PATTERNS_MAX_PER_TENANT: positiveInt.max(1_000).default(50),
    DLP_DICTIONARIES_MAX_PER_TENANT: positiveInt.max(200).default(20),
    DLP_DICTIONARY_MAX_TERMS: positiveInt.max(10_000).default(1_000),
    DLP_POLICIES_MAX_PER_TENANT: positiveInt.max(200).default(20),
    DLP_RULES_MAX_PER_POLICY: positiveInt.max(500).default(50),
    DLP_EXCEPTIONS_MAX_PER_TENANT: positiveInt.max(10_000).default(500),
    DLP_EXCEPTION_MAX_DAYS: positiveInt.max(3_650).default(365),
    DLP_TENANT_DATA_CACHE_TTL_MS: int.min(0).max(300_000).default(30_000),

    // Evidence (D16).
    /** Secret (64 hex): only the dlp-consuming worker (seal) and the api (open) hold it. */
    DLP_EVIDENCE_KEY: z.string().trim().optional(),
    /** Secret (rotation): empty or 64 hex, different from the current key. */
    DLP_EVIDENCE_KEY_PREVIOUS: z.string().trim().default(''),
    DLP_EVIDENCE_MAX_BYTES: int.min(1_024).max(32_768).default(32_768),
    DLP_EVIDENCE_MAX_MATCHES: positiveInt.max(50).default(50),
    DLP_EVIDENCE_SWEEP_INTERVAL_MS: int.min(1_000).max(86_400_000).default(3_600_000),
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- only its type is used
const dlpObject = z.object(dlpConfigShape());
export type DlpShapeConfig = z.infer<typeof dlpObject>;

/** The platform DLP settings of the config (D18). Not validated (see the schema). */
export function dlpPlatformFromConfig(cfg: DlpShapeConfig): DlpPlatformSettings {
  return {
    confidenceThreshold: cfg.DLP_CONFIDENCE_THRESHOLD,
    defaultPolicy: cfg.DLP_DEFAULT_POLICY,
    evidenceEnabled: cfg.DLP_EVIDENCE_ENABLED,
    evidenceDefaultRetentionDays: cfg.DLP_EVIDENCE_DEFAULT_RETENTION_DAYS,
    evidenceMaxRetentionDays: cfg.DLP_EVIDENCE_MAX_RETENTION_DAYS,
    contextWindowChars: cfg.DLP_CONTEXT_WINDOW_CHARS,
    bulkMinDistinct: cfg.DLP_BULK_MIN_DISTINCT,
  };
}

type DlpValidationConfig = DlpShapeConfig & {
  NODE_ENV: string;
  SCAN_S3_TIMEOUT_MS: number;
  ATTACHMENT_MAX_BYTES: number;
};

/**
 * The cross-field refusals of the dlp engine (startup fails with every violated rule listed;
 * values, in particular the evidence keys, are never echoed). `consumes`: this replica runs the
 * `dlp` consumer (the evidence key is checked only there).
 */
export function validateDlpConfig(
  cfg: DlpValidationConfig,
  consumes: boolean,
  queueMaxAttempts: number,
  refuse: (path: string, message: string) => void,
): void {
  if (cfg.SCAN_DLP_MAX_ATTEMPTS >= queueMaxAttempts) {
    refuse(
      'SCAN_DLP_MAX_ATTEMPTS',
      `must be below ${String(queueMaxAttempts)}, the attempt limit of queue scan.dlp ` +
        '(the engine must finalize its result before the consumer dead-letters)',
    );
  }
  const platform = dlpPlatformSettingsSchema.safeParse(dlpPlatformFromConfig(cfg));
  if (!platform.success) {
    for (const issue of platform.error.issues) {
      const key = DLP_PLATFORM_ENV_KEYS[issue.path[0] as keyof DlpPlatformSettings];
      refuse(key ?? 'DLP_CONFIDENCE_THRESHOLD', issue.message);
    }
  }
  if (cfg.DLP_ATTACHMENT_MAX_BYTES > cfg.DLP_BYTE_BUDGET_BYTES) {
    refuse(
      'DLP_ATTACHMENT_MAX_BYTES',
      'must not exceed DLP_BYTE_BUDGET_BYTES (one attachment must fit the byte budget)',
    );
  }
  if (cfg.DLP_ATTACHMENT_MAX_BYTES > cfg.ATTACHMENT_MAX_BYTES) {
    refuse('DLP_ATTACHMENT_MAX_BYTES', 'must not exceed ATTACHMENT_MAX_BYTES');
  }
  if (cfg.DLP_TEXT_MAX_CHARS_PER_PART > cfg.DLP_TEXT_MAX_CHARS_PER_MESSAGE) {
    refuse('DLP_TEXT_MAX_CHARS_PER_PART', 'must not exceed DLP_TEXT_MAX_CHARS_PER_MESSAGE');
  }
  if (cfg.DLP_EXTRACT_CPU_SECONDS * 1000 > cfg.DLP_EXTRACT_TIMEOUT_MS) {
    refuse(
      'DLP_EXTRACT_CPU_SECONDS',
      'must not exceed DLP_EXTRACT_TIMEOUT_MS (the CPU limit could never fire)',
    );
  }
  if (cfg.DLP_EXTRACT_MAX_RSS_MB <= cfg.DLP_EXTRACTOR_HEAP_MB) {
    refuse(
      'DLP_EXTRACT_MAX_RSS_MB',
      'must be above DLP_EXTRACTOR_HEAP_MB (the V8 heap cap must hit first)',
    );
  }
  for (const key of [
    'DLP_EXTRACT_TIMEOUT_MS',
    'DLP_DETECT_TIMEOUT_MS',
    'SCAN_S3_TIMEOUT_MS',
  ] as const) {
    if (cfg[key] >= cfg.SCAN_DLP_TIMEOUT_MS) refuse(key, 'must be below SCAN_DLP_TIMEOUT_MS');
  }
  // One attachment extraction and the detection of the message must fit one engine call together
  // (attachments run DLP_EXTRACTOR_POOL_SIZE at a time; closer review 2026-11-08).
  if (
    cfg.DLP_EXTRACT_TIMEOUT_MS < cfg.SCAN_DLP_TIMEOUT_MS &&
    cfg.DLP_DETECT_TIMEOUT_MS < cfg.SCAN_DLP_TIMEOUT_MS &&
    cfg.DLP_EXTRACT_TIMEOUT_MS + cfg.DLP_DETECT_TIMEOUT_MS >= cfg.SCAN_DLP_TIMEOUT_MS
  ) {
    refuse(
      'DLP_DETECT_TIMEOUT_MS',
      'DLP_EXTRACT_TIMEOUT_MS + DLP_DETECT_TIMEOUT_MS must be below SCAN_DLP_TIMEOUT_MS',
    );
  }
  if (cfg.NODE_ENV === 'production' && cfg.DLP_EXTRACTOR_RLIMITS === 'best_effort') {
    refuse(
      'DLP_EXTRACTOR_RLIMITS',
      'best_effort is refused when NODE_ENV=production (the extractor needs prlimit)',
    );
  }
  const previous = cfg.DLP_EVIDENCE_KEY_PREVIOUS;
  if (previous !== '' && !HEX64.test(previous)) {
    refuse('DLP_EVIDENCE_KEY_PREVIOUS', 'must be empty or exactly 64 hex characters');
  }
  if (!consumes) return;
  const key = cfg.DLP_EVIDENCE_KEY ?? '';
  if (cfg.DLP_EVIDENCE_ENABLED && !HEX64.test(key)) {
    refuse(
      'DLP_EVIDENCE_KEY',
      'is required (exactly 64 hex characters) when the dlp engine consumes with DLP_EVIDENCE_ENABLED=true',
    );
  }
  if (previous !== '' && key !== '' && previous.toLowerCase() === key.toLowerCase()) {
    refuse('DLP_EVIDENCE_KEY_PREVIOUS', 'must differ from DLP_EVIDENCE_KEY');
  }
}
