import { isIP } from 'node:net';
import { isAbsolute, normalize } from 'node:path';
import {
  amqpUrlListSchema,
  baseConfigSchema,
  ConfigValidationError,
  loadConfig,
} from '@email-gateway/config';
import {
  parseArtifactPublicKey,
  parseOptionalSymmetricKey,
  parseSymmetricKey,
  SandboxKeyError,
} from '@email-gateway/sandbox';
import {
  SANDBOX_BACKENDS,
  SANDBOX_MAX_ARTIFACT_BYTES_CEILING,
  SANDBOX_MAX_ARTIFACTS_CEILING,
  SANDBOX_MAX_SAMPLE_BYTES_CEILING,
  SANDBOX_MAX_TOTAL_ARTIFACT_BYTES_CEILING,
  SANDBOX_TASK_LIMIT_BOUNDS,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * sandbox-controller configuration (step 4.6 §5, X1, X3, X9; ADR-0039;
 * docs/security/sandbox-threat-model.md §2.0 invariant 3).
 *
 * The controller is the most exposed component of the platform: it holds nothing worth stealing.
 * `loadControllerConfig` refuses to start (naming keys, never values) when any database, Redis,
 * main-S3, MinIO root, token, auth, DLP, BEC LLM, click, data-encryption, cache, egress-proxy,
 * AI or other broker credential is present — or the artifact PRIVATE key. Its own S3 settings
 * are therefore named `SANDBOX_S3_*` (they must not match the `S3_` prefix).
 */

const int = z.coerce.number().int();
const port = int.min(1).max(65535);
const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((value) => value === 'true' || value === '1');
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);
const bounded = (bounds: { min: number; max: number }) => int.min(bounds.min).max(bounds.max);

/** Prefixes the controller refuses (X1), also as `<KEY>_FILE`. */
export const FORBIDDEN_PREFIXES = [
  'DATABASE_',
  'MYSQL_',
  'REDIS_',
  'S3_',
  'MINIO_',
  'URL_TOKEN_',
  'AUTH_',
  'DLP_',
  'BEC_LLM_',
  'CLICK_',
] as const;

/** Keys the controller refuses (X1), also as `<KEY>_FILE`. */
export const FORBIDDEN_KEYS = [
  'DATA_ENCRYPTION_KEY',
  'DATA_ENCRYPTION_KEY_PREVIOUS',
  'ATTACHMENT_CACHE_HMAC_KEY',
  'URL_CACHE_HMAC_KEY',
  'URL_EGRESS_PROXY_TOKEN',
  'ANTHROPIC_API_KEY',
  'SANDBOX_ARTIFACT_PRIVATE_KEY',
  'RABBITMQ_URL',
  'RABBITMQ_ADMIN_URL',
  'RABBITMQ_DEFAULT_USER',
  'RABBITMQ_DEFAULT_PASS',
  // Not named in X1 but the same class of secret (the root broker password and the cluster
  // cookie of the local .env): refused as well (§12 WP2).
  'RABBITMQ_PASSWORD',
  'RABBITMQ_CLUSTER_ERLANG_COOKIE',
] as const;

/** The controller's own broker credentials (the only `RABBITMQ_*_URL` / `_PASSWORD` allowed). */
const ALLOWED_BROKER_KEYS: ReadonlySet<string> = new Set([
  'RABBITMQ_SANDBOX_URL',
  'RABBITMQ_SANDBOX_PASSWORD',
]);

function isForbiddenKey(key: string): boolean {
  const base = key.endsWith('_FILE') ? key.slice(0, -'_FILE'.length) : key;
  if ((FORBIDDEN_KEYS as readonly string[]).includes(base)) return true;
  if (FORBIDDEN_PREFIXES.some((prefix) => base.startsWith(prefix))) return true;
  if (
    base.startsWith('RABBITMQ_') &&
    (base.endsWith('_URL') || base.endsWith('_PASSWORD')) &&
    !ALLOWED_BROKER_KEYS.has(base)
  ) {
    return true;
  }
  return false;
}

/**
 * Names (never values) of forbidden keys set (non-empty) in `env`, including their `<KEY>_FILE`
 * secret indirection, sorted.
 */
export function forbiddenKeysPresent(env: NodeJS.ProcessEnv): string[] {
  return Object.keys(env)
    .filter((key) => (env[key] ?? '') !== '')
    .filter(isForbiddenKey)
    .sort();
}

/**
 * Keys `scripts/dev-env.mjs` copies from `../../.env` for a host run (X1): the controller's own
 * keys only. Every key here is allowed by `forbiddenKeysPresent` (unit-tested).
 */
export const CONTROLLER_ENV_KEYS = [
  'NODE_ENV',
  'APP_ENV',
  'LOG_LEVEL',
  'SERVICE_VERSION',
  'HTTP_HOST',
  'SANDBOX_HTTP_PORT',
  'SANDBOX_BACKEND',
  'SANDBOX_ALLOW_NON_VM_EXECUTION',
  'SANDBOX_CONTROLLER_NAME',
  'RABBITMQ_SANDBOX_URL',
  'SANDBOX_S3_BUCKET',
  'SANDBOX_S3_ENDPOINT',
  'SANDBOX_S3_REGION',
  'SANDBOX_S3_FORCE_PATH_STYLE',
  'SANDBOX_S3_ACCESS_KEY_ID',
  'SANDBOX_S3_SECRET_ACCESS_KEY',
  'SANDBOX_SAMPLE_KEY',
  'SANDBOX_SAMPLE_KEY_PREVIOUS',
  'SANDBOX_RESULT_KEY',
  'SANDBOX_ARTIFACT_PUBLIC_KEY',
  'SANDBOX_CONCURRENCY',
  'SANDBOX_TASK_TIMEOUT_MS',
  'SANDBOX_MAX_RUN_TIMEOUT_MS',
  'SANDBOX_MAX_MEMORY_MB',
  'SANDBOX_MAX_CPU_MILLIS',
  'SANDBOX_MAX_PIDS',
  'SANDBOX_MAX_SCRATCH_MB',
  'SANDBOX_MAX_ARTIFACTS',
  'SANDBOX_MAX_ARTIFACT_BYTES',
  'SANDBOX_MAX_TOTAL_ARTIFACT_BYTES',
  'SANDBOX_MAX_SAMPLE_BYTES',
  'SANDBOX_SCRATCH_DIR',
  'SANDBOX_REAPER_INTERVAL_MS',
  'SANDBOX_SELF_TEST_INTERVAL_MS',
  'SANDBOX_STATIC_HEAP_MB',
  'SANDBOX_STATIC_MAX_RSS_MB',
  'SANDBOX_STATIC_CPU_SECONDS',
  'SANDBOX_STATIC_TIMEOUT_MS',
  'SANDBOX_VM_RUNTIME_CLASS',
  'SANDBOX_VM_ALLOWED_HANDLERS',
  'SANDBOX_VM_NAMESPACE',
  'SANDBOX_DOCKER_SOCKET',
  'SANDBOX_RUNNER_IMAGE',
  'SANDBOX_BROWSER_IMAGE',
  'SANDBOX_RUNNER_NETWORK',
  'SANDBOX_SINKHOLE_DNS',
  'SANDBOX_SINKHOLE_ADMIN_URL',
  'SANDBOX_SINKHOLE_ADMIN_TOKEN',
] as const;

/** Environments in which the local/CI test harness may execute samples (X3, invariant 1). */
export const TEST_ENVIRONMENTS: readonly string[] = ['local', 'ci'];

/** S3 request budget of the controller (sample GET, artifact PUT, readiness probe). */
export const SANDBOX_S3_TIMEOUT_MS = 15_000;

const K8S_NAME = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const IMAGE = /^[a-z0-9][a-z0-9._/:@-]{0,254}$/;
const DOCKER_NETWORK = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;

export const controllerConfigSchema = baseConfigSchema
  .extend({
    HTTP_HOST: z.string().default('0.0.0.0'),
    /** Health and metrics (`/health/live`, `/health/ready`, `/metrics`). */
    SANDBOX_HTTP_PORT: port.default(3092),
    SANDBOX_BACKEND: z.enum(SANDBOX_BACKENDS).default('disabled'),
    /** Opt-in of the local/CI executing harness; refused outside APP_ENV local/ci. */
    SANDBOX_ALLOW_NON_VM_EXECUTION: bool.default(false),
    /** Distinct per instance (labels its runners; Kubernetes: the pod name). */
    SANDBOX_CONTROLLER_NAME: z
      .string()
      .regex(K8S_NAME, 'must be a DNS label (lower-case letters, digits, -)')
      .default('sandbox-controller-local'),
    /** The `eg-sandbox` user: read `scan.sandbox`, publish its own result keys only. */
    RABBITMQ_SANDBOX_URL: amqpUrlListSchema,
    SANDBOX_S3_BUCKET: z
      .string()
      .regex(BUCKET, 'must be an S3 bucket name')
      .default('email-gateway-sandbox'),
    /** Empty = AWS S3 of the region. */
    SANDBOX_S3_ENDPOINT: z.url().optional(),
    SANDBOX_S3_REGION: z.string().min(1).default('ap-south-1'),
    SANDBOX_S3_FORCE_PATH_STYLE: bool.default(false),
    SANDBOX_S3_ACCESS_KEY_ID: z.string().min(3).max(128).optional(),
    SANDBOX_S3_SECRET_ACCESS_KEY: z.string().min(8).max(128).optional(),
    SANDBOX_SAMPLE_KEY: z.string().optional(),
    SANDBOX_SAMPLE_KEY_PREVIOUS: z.string().optional(),
    SANDBOX_RESULT_KEY: z.string().optional(),
    SANDBOX_ARTIFACT_PUBLIC_KEY: z.string().optional(),
    /** Tasks at a time = prefetch of the consumer (X7: 1, max 4). */
    SANDBOX_CONCURRENCY: int.min(1).max(4).default(1),
    SANDBOX_TASK_TIMEOUT_MS: int.min(30_000).max(1_800_000).default(180_000),
    /** Controller maxima the task limits are clamped to (X7). */
    SANDBOX_MAX_RUN_TIMEOUT_MS: bounded(SANDBOX_TASK_LIMIT_BOUNDS.wallTimeoutMs).default(300_000),
    SANDBOX_MAX_MEMORY_MB: bounded(SANDBOX_TASK_LIMIT_BOUNDS.memoryMb).default(1024),
    SANDBOX_MAX_CPU_MILLIS: bounded(SANDBOX_TASK_LIMIT_BOUNDS.cpuMillis).default(2000),
    SANDBOX_MAX_PIDS: bounded(SANDBOX_TASK_LIMIT_BOUNDS.pids).default(256),
    SANDBOX_MAX_SCRATCH_MB: bounded(SANDBOX_TASK_LIMIT_BOUNDS.scratchMb).default(256),
    SANDBOX_MAX_ARTIFACTS: int.min(0).max(SANDBOX_MAX_ARTIFACTS_CEILING).default(16),
    SANDBOX_MAX_ARTIFACT_BYTES: int
      .min(1)
      .max(SANDBOX_MAX_ARTIFACT_BYTES_CEILING)
      .default(2_097_152),
    SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: int
      .min(1)
      .max(SANDBOX_MAX_TOTAL_ARTIFACT_BYTES_CEILING)
      .default(8_388_608),
    SANDBOX_MAX_SAMPLE_BYTES: int.min(1).max(SANDBOX_MAX_SAMPLE_BYTES_CEILING).default(26_214_400),
    /** Per-task scratch root (0700 task directories; reaped). */
    SANDBOX_SCRATCH_DIR: z.string().default('/scratch'),
    SANDBOX_REAPER_INTERVAL_MS: int.min(1_000).max(3_600_000).default(30_000),
    SANDBOX_SELF_TEST_INTERVAL_MS: int.min(10_000).max(86_400_000).default(300_000),
    /** Static analyzer child (X4). */
    SANDBOX_STATIC_HEAP_MB: int.min(32).max(2048).default(256),
    SANDBOX_STATIC_MAX_RSS_MB: int.min(64).max(4096).default(384),
    SANDBOX_STATIC_CPU_SECONDS: int.min(1).max(600).default(20),
    SANDBOX_STATIC_TIMEOUT_MS: int.min(1_000).max(600_000).default(30_000),
    /** vm backend preflight (X9). */
    SANDBOX_VM_RUNTIME_CLASS: z.string().regex(K8S_NAME).default('gvisor'),
    SANDBOX_VM_ALLOWED_HANDLERS: list.default([
      'runsc',
      'kata',
      'kata-qemu',
      'kata-clh',
      'kata-fc',
    ]),
    SANDBOX_VM_NAMESPACE: z.string().regex(K8S_NAME).default('email-gateway-sandbox-runners'),
    /** hardened-container (local/CI only, X6; wired in wave 3). */
    SANDBOX_DOCKER_SOCKET: z.string().default('/var/run/docker.sock'),
    SANDBOX_RUNNER_IMAGE: z.string().regex(IMAGE).default('email-gateway/sandbox-runner:local'),
    SANDBOX_BROWSER_IMAGE: z
      .string()
      .regex(IMAGE)
      .default('email-gateway/url-browser-worker:local'),
    SANDBOX_RUNNER_NETWORK: z
      .string()
      .regex(DOCKER_NETWORK)
      .default('email-gateway_sandbox-detonation'),
    SANDBOX_SINKHOLE_DNS: z
      .string()
      .refine((value) => isIP(value) === 4, 'must be an IPv4 address')
      .default('172.31.253.53'),
    SANDBOX_SINKHOLE_ADMIN_URL: z.url().default('http://172.31.252.53:3094'),
    SANDBOX_SINKHOLE_ADMIN_TOKEN: z.string().min(16).optional(),
    /** Set by Kubernetes in every pod: `hardened-container` is refused there; `vm` needs it. */
    KUBERNETES_SERVICE_HOST: z.string().optional(),
    KUBERNETES_SERVICE_PORT: port.optional(),
  })
  .superRefine((c, ctx) => {
    const issue = (path: string, message: string): void =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    const testEnvironment = TEST_ENVIRONMENTS.includes(c.APP_ENV);

    // Invariant 1: execution only in the local/CI harness, outside Kubernetes, opted in.
    if (c.SANDBOX_ALLOW_NON_VM_EXECUTION && !testEnvironment) {
      issue('SANDBOX_ALLOW_NON_VM_EXECUTION', 'is refused outside APP_ENV local/ci');
    }
    if (c.SANDBOX_BACKEND === 'hardened-container') {
      if (!testEnvironment) {
        issue(
          'SANDBOX_BACKEND',
          'hardened-container (not a VM boundary) requires APP_ENV local or ci',
        );
      }
      if (c.KUBERNETES_SERVICE_HOST) {
        issue('SANDBOX_BACKEND', 'hardened-container is refused inside Kubernetes');
      }
      if (!c.SANDBOX_ALLOW_NON_VM_EXECUTION) {
        issue('SANDBOX_ALLOW_NON_VM_EXECUTION', 'must be true for hardened-container');
      }
      if (!c.SANDBOX_SINKHOLE_ADMIN_TOKEN) {
        issue('SANDBOX_SINKHOLE_ADMIN_TOKEN', 'is required for hardened-container');
      }
    }

    // Keys per backend: every backend that publishes results needs the result key; the ones
    // that read samples and write artifacts need the bucket credentials and the envelope keys.
    const publishes = c.SANDBOX_BACKEND !== 'vm';
    const analyses = c.SANDBOX_BACKEND === 'static' || c.SANDBOX_BACKEND === 'hardened-container';
    if (publishes) {
      checkSymmetric(ctx, 'SANDBOX_RESULT_KEY', c.SANDBOX_RESULT_KEY, true);
    }
    if (analyses) {
      if (!c.SANDBOX_S3_ACCESS_KEY_ID)
        issue('SANDBOX_S3_ACCESS_KEY_ID', `is required for ${c.SANDBOX_BACKEND}`);
      if (!c.SANDBOX_S3_SECRET_ACCESS_KEY) {
        issue('SANDBOX_S3_SECRET_ACCESS_KEY', `is required for ${c.SANDBOX_BACKEND}`);
      }
      const sampleKey = checkSymmetric(ctx, 'SANDBOX_SAMPLE_KEY', c.SANDBOX_SAMPLE_KEY, true);
      if (sampleKey) {
        try {
          parseOptionalSymmetricKey(
            'SANDBOX_SAMPLE_KEY_PREVIOUS',
            c.SANDBOX_SAMPLE_KEY_PREVIOUS,
            sampleKey,
          );
        } catch (error) {
          issue('SANDBOX_SAMPLE_KEY_PREVIOUS', keyMessage(error));
        }
        sampleKey.fill(0);
      }
      if (!c.SANDBOX_ARTIFACT_PUBLIC_KEY) {
        issue('SANDBOX_ARTIFACT_PUBLIC_KEY', `is required for ${c.SANDBOX_BACKEND}`);
      } else {
        try {
          parseArtifactPublicKey(c.SANDBOX_ARTIFACT_PUBLIC_KEY);
        } catch (error) {
          issue('SANDBOX_ARTIFACT_PUBLIC_KEY', keyMessage(error));
        }
      }
    }

    const scratch = c.SANDBOX_SCRATCH_DIR;
    if (
      !isAbsolute(scratch) ||
      normalize(scratch) === '/' ||
      normalize(scratch) !== scratch.replace(/\/+$/, '')
    ) {
      issue('SANDBOX_SCRATCH_DIR', 'must be a normalized absolute directory other than /');
    }
    if (c.SANDBOX_STATIC_MAX_RSS_MB <= c.SANDBOX_STATIC_HEAP_MB) {
      issue('SANDBOX_STATIC_MAX_RSS_MB', 'must be above SANDBOX_STATIC_HEAP_MB');
    }
    if (c.SANDBOX_STATIC_TIMEOUT_MS >= c.SANDBOX_TASK_TIMEOUT_MS) {
      issue('SANDBOX_STATIC_TIMEOUT_MS', 'must be below SANDBOX_TASK_TIMEOUT_MS');
    }
    if (c.SANDBOX_VM_ALLOWED_HANDLERS.length === 0) {
      issue('SANDBOX_VM_ALLOWED_HANDLERS', 'must list at least one RuntimeClass handler');
    }
    for (const handler of c.SANDBOX_VM_ALLOWED_HANDLERS) {
      if (!K8S_NAME.test(handler)) issue('SANDBOX_VM_ALLOWED_HANDLERS', 'must list DNS labels');
    }
    const sinkhole = new URL(c.SANDBOX_SINKHOLE_ADMIN_URL);
    if (sinkhole.protocol !== 'http:' || sinkhole.username || sinkhole.password) {
      issue('SANDBOX_SINKHOLE_ADMIN_URL', 'must be http://host:port without credentials');
    }
  });

function keyMessage(error: unknown): string {
  // SandboxKeyError messages name the key and the expected shape, never the value.
  return error instanceof SandboxKeyError ? error.message.replace(/^\S+ /, '') : 'is invalid';
}

function checkSymmetric(
  ctx: z.RefinementCtx,
  key: string,
  value: string | undefined,
  required: boolean,
): Buffer | null {
  if (!value) {
    if (required) ctx.addIssue({ code: 'custom', path: [key], message: 'is required' });
    return null;
  }
  try {
    return parseSymmetricKey(key, value);
  } catch (error) {
    ctx.addIssue({ code: 'custom', path: [key], message: keyMessage(error) });
    return null;
  }
}

export type ControllerConfig = z.infer<typeof controllerConfigSchema>;

/** APP_ENV of the execution rule: NODE_ENV=production without APP_ENV counts as production. */
function withAppEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  return appEnv ? { ...env, APP_ENV: appEnv } : env;
}

/**
 * Loads the controller configuration: refuses forbidden keys first (names only), then validates
 * every key with its bounds and the backend rules. Throws `ConfigValidationError`.
 */
export function loadControllerConfig(
  env: NodeJS.ProcessEnv = process.env,
): Readonly<ControllerConfig> {
  const present = forbiddenKeysPresent(env);
  if (present.length > 0) {
    throw new ConfigValidationError(
      present.map(
        (key) =>
          `${key}: must not be set for the sandbox-controller (step 4.6 X1; it holds no such credential)`,
      ),
    );
  }
  return loadConfig(controllerConfigSchema, withAppEnv(env));
}

/** `sandbox-controller/<SERVICE_VERSION>`, ≤ 64 (task_completed.v1 `controllerVersion`). */
export function controllerVersion(config: Pick<ControllerConfig, 'SERVICE_VERSION'>): string {
  const version = config.SERVICE_VERSION.replace(/[^A-Za-z0-9._+-]/g, '-');
  return `sandbox-controller/${version}`.slice(0, 64);
}
