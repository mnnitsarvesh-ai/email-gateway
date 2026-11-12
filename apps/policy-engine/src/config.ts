import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import { isPlatformDefaultId, POLICY_DEFAULT_PLATFORM_ID } from '@email-gateway/policy-dsl';
import { validateQuarantinePlatformBounds } from '@email-gateway/quarantine';
import {
  DKIM_SIGNED_POLICIES,
  URL_PLATFORM_DEFAULTS,
  URL_TOKEN_EXPIRY_DAYS_CEILING,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

const int = z.coerce.number().int();
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be 64 hexadecimal characters');

/** Default writer-transaction budget of one evaluation (step 4.2 §6, P13). */
export const DEFAULT_POLICY_DB_TX_TIMEOUT_MS = 120_000;

/** The roles of one policy-engine process (step 5.3 Q28). */
export const POLICY_ENGINE_ROLE_VALUES = ['evaluate', 'quarantine'] as const;
export type PolicyEngineRole = (typeof POLICY_ENGINE_ROLE_VALUES)[number];

/**
 * Policy-engine configuration (step 5.2 §5, docs/plan/steps/16-policy-engine.md; `.env.example`
 * section "Policy engine (step 5.2 …)"). Bounds as in §5.
 */
export const policyConfigShape = {
  /** The platform default policy (`pol-default/1`), a key of `POLICY_PLATFORM_DEFAULTS`. */
  POLICY_PLATFORM_DEFAULT: z
    .string()
    .default(POLICY_DEFAULT_PLATFORM_ID)
    .refine((value) => isPlatformDefaultId(value), 'must be a key of POLICY_PLATFORM_DEFAULTS'),
  /** Prefetch of the `email.policy.evaluate` consumer (evaluations in flight per replica). */
  POLICY_EVALUATE_PREFETCH: int.min(1).max(64).default(8),
  /**
   * Budget (timeout and maxWait) of the evaluation transaction. Above innodb_lock_wait_timeout
   * and the writer stalls the engine rides through (step 4.2 §6: never expire a transaction with
   * a statement in flight). The policy copy (S3) is written inside it with half of this budget.
   */
  POLICY_DB_TX_TIMEOUT_MS: int.min(120_000).max(600_000).default(DEFAULT_POLICY_DB_TX_TIMEOUT_MS),
  /** Compiled snapshots kept per process, keyed (organization, generation) (P12). */
  POLICY_SNAPSHOT_CACHE_MAX_ENTRIES: int.min(10).max(100_000).default(1000),
  /** Larger delivered objects get no policy copy (TAG/WARN recorded, P21). */
  POLICY_COPY_MAX_MESSAGE_BYTES: int.min(1_048_576).max(52_428_800).default(26_214_400),
  /** A header block larger than this gets no policy copy (TAG/WARN recorded, P21). */
  POLICY_COPY_MAX_HEADER_BYTES: int.min(16_384).max(1_048_576).default(262_144),
};

/**
 * Step 5.3 (docs/plan/steps/17-quarantine.md §5, Q19, Q22, Q23, Q28; `.env.example` section
 * "Quarantine (step 5.3 …)"): the roles, the quarantine bounds the engine enforces, the
 * executor and sweeper budgets, the WARN banner bound and the policy URL rewrite with the
 * click-token key (sign only: the current key; the policy-engine never verifies tokens, so the
 * previous key is not accepted).
 */
export const quarantineConfigShape = {
  /** Comma list of `evaluate`, `quarantine` (Q28); Kubernetes runs one role per Deployment. */
  POLICY_ENGINE_ROLES: z
    .string()
    .default('evaluate,quarantine')
    .transform((value) => [
      ...new Set(
        value
          .split(',')
          .map((v) => v.trim())
          .filter((v) => v.length > 0),
      ),
    ])
    .pipe(z.array(z.enum(POLICY_ENGINE_ROLE_VALUES)).min(1, 'must name at least one role')),
  /** Longest hold of a quarantine entry (7–80; below the lifecycle `quarantined` deadline). */
  QUARANTINE_MAX_HOLD_DAYS: int.min(7).max(80).default(60),
  /** Longest review period (1–13; below the lifecycle `held_for_review` deadline). */
  QUARANTINE_MAX_REVIEW_DAYS: int.min(1).max(13).default(13),
  /** Read for validation only (the event-relay's lifecycle sweeper owns these deadlines). */
  LIFECYCLE_DEADLINE_QUARANTINED_HOURS: int.min(1).max(87_600).default(2160),
  LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: int.min(1).max(87_600).default(336),
  /** Prefetch of the `email.quarantine` release executor. */
  QUARANTINE_RELEASE_PREFETCH: int.min(1).max(32).default(4),
  /** Budget of one executor / sweeper writer transaction (≥ 120 s, step 4.2 §6). */
  QUARANTINE_DB_TX_TIMEOUT_MS: int.min(120_000).max(600_000).default(120_000),
  QUARANTINE_SWEEP_INTERVAL_MS: int.min(10_000).max(3_600_000).default(60_000),
  QUARANTINE_SWEEP_BATCH_SIZE: int.min(10).max(2_000).default(200),
  /** Terminal entries older than this are hard-deleted (≥ the 6-month core tier). */
  QUARANTINE_ENTRY_RETENTION_DAYS: int.min(186).max(3_650).default(186),
  QUARANTINE_DIGEST_MAX_USERS_PER_RUN: int.min(100).max(100_000).default(5_000),
  /** Q13.4 staleness bounds of the release re-validation. */
  QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS: int.min(1).max(720).default(72),
  QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS: int.min(1).max(168).default(24),
  /** Q22: encoded bytes of one candidate part of a WARN banner. */
  POLICY_BANNER_MAX_PART_BYTES: int.min(65_536).max(8_388_608).default(1_048_576),
  /** Q23: false = URL_REWRITE after the scan is recorded only (the 5.2 behaviour). */
  POLICY_URL_REWRITE_ENABLED: flag.default(true),
  /** Click-token key (sign only, ADR-0049 amends ADR-0030): required with policy rewriting. */
  URL_TOKEN_KEY_CURRENT: hex64.optional(),
  URL_TOKEN_KEY_CURRENT_ID: int.min(1).max(255).default(1),
  URL_CLICK_BASE_URL: z.url({ protocol: /^https?$/ }).default('http://localhost:3080'),
  URL_TOKEN_DEFAULT_EXPIRY_DAYS: int
    .min(1)
    .max(URL_TOKEN_EXPIRY_DAYS_CEILING)
    .default(URL_PLATFORM_DEFAULTS.rewrite.defaultExpiryDays),
  URL_TOKEN_MAX_EXPIRY_DAYS: int
    .min(1)
    .max(URL_TOKEN_EXPIRY_DAYS_CEILING)
    .default(URL_PLATFORM_DEFAULTS.rewrite.maxExpiryDays),
  URL_REWRITE_MAX_MESSAGE_BYTES: int.min(1).max(104_857_600).default(26_214_400),
  URL_REWRITE_MAX_PART_BYTES: int.min(1).max(52_428_800).default(5_242_880),
  URL_REWRITE_DKIM_SIGNED: z
    .enum(DKIM_SIGNED_POLICIES)
    .default(URL_PLATFORM_DEFAULTS.rewrite.dkimSignedPolicy),
};

/**
 * RabbitMQ (P13, P15): the policy-engine's own least-privilege role user `eg-policy-engine`
 * (read `email.policy.evaluate` and, topology v10, `email.quarantine`; write `email.policy` /
 * `email.events` for retry hops and dead letters), one URL per cluster node, comma-separated
 * (`RABBITMQ_POLICY_ENGINE_URL_FILE` for a mounted secret).
 */
export const amqpConfigShape = {
  RABBITMQ_POLICY_ENGINE_URL: amqpUrlListSchema,
};

const objectSchema = baseConfigSchema
  .extend(httpConfigSchema(3030).shape)
  .extend(databaseConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend(amqpConfigShape)
  .extend(policyConfigShape)
  .extend(quarantineConfigShape);

export const configSchema = objectSchema.superRefine((cfg, ctx) => {
  // Q19: the quarantine sweeper must expire entries before the lifecycle backstop fires.
  for (const message of validateQuarantinePlatformBounds({
    maxHoldDays: cfg.QUARANTINE_MAX_HOLD_DAYS,
    maxReviewDays: cfg.QUARANTINE_MAX_REVIEW_DAYS,
    lifecycleQuarantinedHours: cfg.LIFECYCLE_DEADLINE_QUARANTINED_HOURS,
    lifecycleHeldForReviewHours: cfg.LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS,
  })) {
    ctx.addIssue({
      code: 'custom',
      path: [
        message.startsWith('QUARANTINE_MAX_HOLD')
          ? 'QUARANTINE_MAX_HOLD_DAYS'
          : 'QUARANTINE_MAX_REVIEW_DAYS',
      ],
      message,
    });
  }
  if (cfg.URL_TOKEN_DEFAULT_EXPIRY_DAYS > cfg.URL_TOKEN_MAX_EXPIRY_DAYS) {
    ctx.addIssue({
      code: 'custom',
      path: ['URL_TOKEN_DEFAULT_EXPIRY_DAYS'],
      message: 'must not exceed URL_TOKEN_MAX_EXPIRY_DAYS',
    });
  }
  if (cfg.URL_REWRITE_MAX_PART_BYTES > cfg.URL_REWRITE_MAX_MESSAGE_BYTES) {
    ctx.addIssue({
      code: 'custom',
      path: ['URL_REWRITE_MAX_PART_BYTES'],
      message: 'must not exceed URL_REWRITE_MAX_MESSAGE_BYTES',
    });
  }
  if (cfg.POLICY_URL_REWRITE_ENABLED && cfg.URL_TOKEN_KEY_CURRENT === undefined) {
    ctx.addIssue({
      code: 'custom',
      path: ['URL_TOKEN_KEY_CURRENT'],
      message: 'is required when POLICY_URL_REWRITE_ENABLED=true (sign-only click-token key)',
    });
  }
  const click = new URL(cfg.URL_CLICK_BASE_URL);
  if (click.search !== '' || click.hash !== '' || click.username !== '') {
    ctx.addIssue({
      code: 'custom',
      path: ['URL_CLICK_BASE_URL'],
      message: 'must not carry userinfo, a query or a fragment',
    });
  }
  if ((cfg.APP_ENV === 'staging' || cfg.APP_ENV === 'production') && click.protocol !== 'https:') {
    ctx.addIssue({
      code: 'custom',
      path: ['URL_CLICK_BASE_URL'],
      message: 'must be https when APP_ENV is staging or production',
    });
  }
});

export type WorkerConfig = z.infer<typeof configSchema>;

/**
 * Only the engine's own keys (and their `<KEY>_FILE` secret indirections) reach `loadConfig`:
 * the shared `.env` holds keys of other services, and a foreign `*_FILE` key would otherwise be
 * read as a secret file of this service (same defence as the delivery-worker).
 */
function ownEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const keys = new Set(Object.keys(objectSchema.shape));
  return Object.fromEntries(
    Object.entries(env).filter(
      ([key]) => keys.has(key) || (key.endsWith('_FILE') && keys.has(key.slice(0, -5))),
    ),
  );
}

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, ownEnv(env));

/** True when this process runs `role` (Q28). */
export const hasRole = (
  config: Pick<WorkerConfig, 'POLICY_ENGINE_ROLES'>,
  role: PolicyEngineRole,
) => config.POLICY_ENGINE_ROLES.includes(role);
