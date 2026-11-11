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
import { z } from 'zod';

const int = z.coerce.number().int();

/** Default writer-transaction budget of one evaluation (step 4.2 §6, P13). */
export const DEFAULT_POLICY_DB_TX_TIMEOUT_MS = 120_000;

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
 * RabbitMQ (P13, P15): the policy-engine's own least-privilege role user `eg-policy-engine`
 * (read `email.policy.evaluate`, write `email.policy` / `email.events` for retry hops and dead
 * letters), one URL per cluster node, comma-separated (`RABBITMQ_POLICY_ENGINE_URL_FILE` for a
 * mounted secret).
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
  .extend(policyConfigShape);

export const configSchema = objectSchema;

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
