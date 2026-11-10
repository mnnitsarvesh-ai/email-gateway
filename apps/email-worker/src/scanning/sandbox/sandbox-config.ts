import {
  parseOptionalSymmetricKey,
  parseSymmetricKey,
  SandboxKeyError,
} from '@email-gateway/sandbox';
import {
  SANDBOX_MAX_ARTIFACT_BYTES_CEILING,
  SANDBOX_MAX_ARTIFACTS_CEILING,
  SANDBOX_MAX_TOTAL_ARTIFACT_BYTES_CEILING,
  SANDBOX_PLATFORM_DEFAULTS,
  SANDBOX_PLATFORM_ENV_KEYS,
  SANDBOX_TASK_LIMIT_BOUNDS,
  type SandboxPlatformSettings,
  sandboxPlatformSettingsSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * The sandbox engine's keys as the email-worker uses them (step 4.6 §5, X13, X16, X17;
 * `.env.example` section "Sandbox (step 4.6 …)"): the platform settings shared with the api
 * (`SANDBOX_TENANT_DEFAULT_ENABLED`, `SANDBOX_FILE_TYPES`, `SANDBOX_MAX_SAMPLE_BYTES`,
 * `SANDBOX_BROWSER_ANALYSIS`), the role switch `SANDBOX_ENABLED` (code default `false`), the
 * sandbox bucket and the two symmetric keys, concurrency, deadlines, reuse windows, the task
 * limits, the sweeper and the retention. Every key has the design default and an explicit
 * bound; the cross-field rules are in `validateSandboxConfig`. Start-up errors name keys, never
 * values (the sample and result keys are secrets).
 */

const int = z.coerce.number().int();
const positiveInt = int.min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

/** The controller's clamp maxima defaults (§5 `SANDBOX_MAX_*`); the run limits stay below them. */
export const SANDBOX_CONTROLLER_MAXIMA = Object.freeze({
  SANDBOX_RUN_TIMEOUT_MS: 300_000,
  SANDBOX_RUN_MEMORY_MB: 1_024,
  SANDBOX_RUN_CPU_MILLIS: 2_000,
  SANDBOX_RUN_PIDS: 256,
  SANDBOX_RUN_SCRATCH_MB: 256,
});

/** Browser runners need at least 1 GiB and 256 pids (X6, X13 step 4). */
export const SANDBOX_BROWSER_MIN_MEMORY_MB = 1_024;
export const SANDBOX_BROWSER_MIN_PIDS = 256;

const bounded = (bounds: { min: number; max: number }) => int.min(bounds.min).max(bounds.max);

export function sandboxConfigShape() {
  return {
    // Platform settings (X17), validated with sandboxPlatformSettingsSchema.
    SANDBOX_TENANT_DEFAULT_ENABLED: flag.default(SANDBOX_PLATFORM_DEFAULTS.tenantDefaultEnabled),
    /** FILE_TYPES ids, comma-separated; empty = the default list. */
    SANDBOX_FILE_TYPES: z
      .string()
      .default('')
      .transform((value): string[] => {
        const trimmed = value.trim();
        if (trimmed === '') return [...SANDBOX_PLATFORM_DEFAULTS.fileTypes];
        return trimmed
          .split(',')
          .map((t) => t.trim())
          .filter((t) => t.length > 0);
      }),
    SANDBOX_MAX_SAMPLE_BYTES: positiveInt.default(SANDBOX_PLATFORM_DEFAULTS.maxSampleBytes),
    SANDBOX_BROWSER_ANALYSIS: flag.default(SANDBOX_PLATFORM_DEFAULTS.browserAnalysis),

    /** Role switch of the sandbox engine (X13): dispatcher, results consumer and sweeper. */
    SANDBOX_ENABLED: flag.default(false),
    /** The restricted sandbox bucket (X12); written with the worker's own S3 client. */
    SANDBOX_S3_BUCKET: z.string().trim().default(''),
    /** Secret (64 hex): wraps the data key of every staged sample (`sandbox-sample/1`). */
    SANDBOX_SAMPLE_KEY: z.string().trim().default(''),
    /** Secret (rotation): empty or 64 hex, different from the current key. */
    SANDBOX_SAMPLE_KEY_PREVIOUS: z.string().trim().default(''),
    /** Secret (64 hex): the result MAC key shared with the controller (X11). */
    SANDBOX_RESULT_KEY: z.string().trim().default(''),

    // Consumers (X13).
    SANDBOX_DISPATCH_CONCURRENCY: positiveInt.max(32).default(4),
    SANDBOX_RESULTS_CONCURRENCY: positiveInt.max(32).default(4),

    // Deadlines (X10).
    SANDBOX_TASK_DEADLINE_SECONDS: int.min(60).max(86_400).default(900),
    SANDBOX_SUBMISSION_TTL_SECONDS: int.min(300).max(604_800).default(3_600),

    // Reuse windows (X13 results step 3); 0 disables reuse for that class.
    SANDBOX_REUSE_DEFINITE_SECONDS: int.min(0).max(2_592_000).default(86_400),
    SANDBOX_REUSE_UNKNOWN_SECONDS: int.min(0).max(2_592_000).default(21_600),
    SANDBOX_REUSE_NOT_EXECUTED_SECONDS: int.min(0).max(2_592_000).default(3_600),
    /** Bumping it forces new analyses for every sample (part of the analysis key, X13 step 4). */
    SANDBOX_ANALYSIS_EPOCH: positiveInt.max(1_000_000).default(1),

    // Task limits (X2 TaskLimits; the controller clamps further to its SANDBOX_MAX_*).
    SANDBOX_RUN_TIMEOUT_MS: bounded(SANDBOX_TASK_LIMIT_BOUNDS.wallTimeoutMs).default(60_000),
    SANDBOX_RUN_MEMORY_MB: bounded(SANDBOX_TASK_LIMIT_BOUNDS.memoryMb).default(512),
    SANDBOX_RUN_CPU_MILLIS: bounded(SANDBOX_TASK_LIMIT_BOUNDS.cpuMillis).default(1_000),
    SANDBOX_RUN_PIDS: bounded(SANDBOX_TASK_LIMIT_BOUNDS.pids).default(128),
    SANDBOX_RUN_SCRATCH_MB: bounded(SANDBOX_TASK_LIMIT_BOUNDS.scratchMb).default(64),
    SANDBOX_MAX_ARTIFACTS: int.min(0).max(SANDBOX_MAX_ARTIFACTS_CEILING).default(16),
    SANDBOX_MAX_ARTIFACT_BYTES: positiveInt
      .max(SANDBOX_MAX_ARTIFACT_BYTES_CEILING)
      .default(2_097_152),
    SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: positiveInt
      .max(SANDBOX_MAX_TOTAL_ARTIFACT_BYTES_CEILING)
      .default(8_388_608),

    // Sweeper (X16).
    SANDBOX_SWEEP_INTERVAL_MS: int.min(1_000).max(86_400_000).default(60_000),
    SANDBOX_SWEEP_BATCH: positiveInt.max(5_000).default(500),

    // Retention (X12, X16).
    SANDBOX_ARTIFACT_RETENTION_DAYS: int.min(1).max(180).default(30),
    SANDBOX_ANALYSIS_RETENTION_DAYS: int.min(1).max(180).default(180),
    SANDBOX_SAMPLE_RETENTION_HOURS: int.min(1).max(48).default(24),

    /** Adds the SHA-256 of malicious analyses to malware_signatures (X13 results step 4). */
    SANDBOX_PUBLISH_HASHES: flag.default(false),
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- only its type is used
const sandboxObject = z.object(sandboxConfigShape());
export type SandboxShapeConfig = z.infer<typeof sandboxObject>;

/** The platform sandbox settings of the config (X17). Not validated (see the schema). */
export function sandboxPlatformFromConfig(cfg: SandboxShapeConfig): SandboxPlatformSettings {
  return {
    tenantDefaultEnabled: cfg.SANDBOX_TENANT_DEFAULT_ENABLED,
    fileTypes: cfg.SANDBOX_FILE_TYPES as SandboxPlatformSettings['fileTypes'],
    maxSampleBytes: cfg.SANDBOX_MAX_SAMPLE_BYTES,
    browserAnalysis: cfg.SANDBOX_BROWSER_ANALYSIS,
  };
}

/**
 * The cross-field refusals of the sandbox engine (§5): the platform settings, the retention
 * relations, the run limits below the controller maxima defaults, and — when this replica runs
 * the sandbox consumers (`runs`) — the bucket, the sample key and the result key. Values are never
 * echoed.
 */
export function validateSandboxConfig(
  cfg: SandboxShapeConfig,
  runs: boolean,
  refuse: (path: string, message: string) => void,
): void {
  const platform = sandboxPlatformSettingsSchema.safeParse(sandboxPlatformFromConfig(cfg));
  if (!platform.success) {
    for (const issue of platform.error.issues) {
      const key = SANDBOX_PLATFORM_ENV_KEYS[issue.path[0] as keyof SandboxPlatformSettings];
      refuse(key ?? 'SANDBOX_FILE_TYPES', issue.message);
    }
  }
  if (cfg.SANDBOX_ANALYSIS_RETENTION_DAYS < cfg.SANDBOX_ARTIFACT_RETENTION_DAYS) {
    refuse(
      'SANDBOX_ANALYSIS_RETENTION_DAYS',
      'must be at least SANDBOX_ARTIFACT_RETENTION_DAYS (artifact rows are deleted before their analysis)',
    );
  }
  for (const [key, max] of Object.entries(SANDBOX_CONTROLLER_MAXIMA)) {
    if (cfg[key as keyof typeof SANDBOX_CONTROLLER_MAXIMA] > max) {
      refuse(key, `must not exceed ${String(max)} (the controller's clamp maximum default)`);
    }
  }
  if (cfg.SANDBOX_MAX_ARTIFACT_BYTES > cfg.SANDBOX_MAX_TOTAL_ARTIFACT_BYTES) {
    refuse('SANDBOX_MAX_ARTIFACT_BYTES', 'must not exceed SANDBOX_MAX_TOTAL_ARTIFACT_BYTES');
  }
  if (cfg.SANDBOX_TASK_DEADLINE_SECONDS * 1000 <= cfg.SANDBOX_RUN_TIMEOUT_MS) {
    refuse(
      'SANDBOX_TASK_DEADLINE_SECONDS',
      'must be above SANDBOX_RUN_TIMEOUT_MS (a run must fit before the analysis deadline)',
    );
  }
  if (cfg.SANDBOX_SAMPLE_RETENTION_HOURS * 3600 < cfg.SANDBOX_TASK_DEADLINE_SECONDS) {
    refuse(
      'SANDBOX_SAMPLE_RETENTION_HOURS',
      'must cover SANDBOX_TASK_DEADLINE_SECONDS (the bucket lifecycle must not delete a sample before its deadline)',
    );
  }
  if (!runs) return;
  if (cfg.SANDBOX_S3_BUCKET === '') {
    refuse('SANDBOX_S3_BUCKET', 'is required when SANDBOX_ENABLED is true');
  }
  let sample: Buffer | null = null;
  try {
    sample = parseSymmetricKey('SANDBOX_SAMPLE_KEY', cfg.SANDBOX_SAMPLE_KEY);
  } catch (error) {
    if (!(error instanceof SandboxKeyError)) throw error;
    refuse(
      'SANDBOX_SAMPLE_KEY',
      'is required (exactly 64 hex characters) when SANDBOX_ENABLED is true',
    );
  }
  try {
    parseOptionalSymmetricKey(
      'SANDBOX_SAMPLE_KEY_PREVIOUS',
      cfg.SANDBOX_SAMPLE_KEY_PREVIOUS,
      sample ?? undefined,
    )?.fill(0);
  } catch (error) {
    if (!(error instanceof SandboxKeyError)) throw error;
    refuse(
      'SANDBOX_SAMPLE_KEY_PREVIOUS',
      'must be empty or exactly 64 hex characters, different from SANDBOX_SAMPLE_KEY',
    );
  }
  sample?.fill(0);
  try {
    parseSymmetricKey('SANDBOX_RESULT_KEY', cfg.SANDBOX_RESULT_KEY).fill(0);
  } catch (error) {
    if (!(error instanceof SandboxKeyError)) throw error;
    refuse(
      'SANDBOX_RESULT_KEY',
      'is required (exactly 64 hex characters) when SANDBOX_ENABLED is true',
    );
  }
  if (
    cfg.SANDBOX_SAMPLE_KEY !== '' &&
    cfg.SANDBOX_SAMPLE_KEY.toLowerCase() === cfg.SANDBOX_RESULT_KEY.toLowerCase()
  ) {
    refuse('SANDBOX_RESULT_KEY', 'must differ from SANDBOX_SAMPLE_KEY');
  }
}
