import {
  amqpUrlListSchema,
  archiveKeysFieldsSchema,
  archiveSearchFieldsSchema,
  archiveStorageConfigSchema,
  archiveTestSeamFieldsSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  s3ConfigSchema,
  validateArchiveKeysConfig,
  validateArchiveSearchConfig,
  validateArchiveTestSeam,
} from '@email-gateway/config';
import { z } from 'zod';

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);

/** Roles of one archive-worker process (A1). */
export const ARCHIVE_WORKER_ROLES = ['capture', 'index', 'lifecycle', 'ediscovery'] as const;
export type ArchiveWorkerRole = (typeof ARCHIVE_WORKER_ROLES)[number];

const roles = list.transform((entries, ctx): ArchiveWorkerRole[] => {
  if (entries.length === 0) {
    ctx.addIssue({
      code: 'custom',
      message: 'must list at least one of capture, index, lifecycle, ediscovery',
    });
    return z.NEVER;
  }
  for (const entry of entries) {
    if (!(ARCHIVE_WORKER_ROLES as readonly string[]).includes(entry)) {
      ctx.addIssue({
        code: 'custom',
        message: 'may only list capture, index, lifecycle and ediscovery',
      });
      return z.NEVER;
    }
  }
  if (new Set(entries).size !== entries.length) {
    ctx.addIssue({ code: 'custom', message: 'lists a role twice' });
    return z.NEVER;
  }
  return entries as ArchiveWorkerRole[];
});

/** One replica target: `bucket` or `bucket@region` (same endpoint and credentials, A14). */
export interface ReplicaTarget {
  bucket: string;
  region: string | null;
}

const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION = /^[a-z]{2}(-[a-z0-9]+){1,3}$/;

const replicaTargets = list.transform((entries, ctx): ReplicaTarget[] => {
  const out: ReplicaTarget[] = [];
  for (const entry of entries) {
    const [bucket, region, extra] = entry.split('@');
    if (
      bucket === undefined ||
      !BUCKET.test(bucket) ||
      extra !== undefined ||
      (region !== undefined && !REGION.test(region))
    ) {
      ctx.addIssue({ code: 'custom', message: 'must list bucket or bucket@region entries' });
      return z.NEVER;
    }
    out.push({ bucket, region: region ?? null });
  }
  if (new Set(out.map((t) => t.bucket)).size !== out.length) {
    ctx.addIssue({ code: 'custom', message: 'lists a bucket twice' });
    return z.NEVER;
  }
  return out;
});

const sweepStart = z.enum(['now', 'oldest']);

/**
 * archive-worker configuration (step 8.1 §4.8, docs/plan/steps/23-journaling-archiving.md;
 * `.env.example` section "Journaling and compliance archiving"): the writer database, S3 (mail
 * and archive buckets), the root key (and its previous key during a rotation), OpenSearch, the
 * Object Lock mode, the `eg-archive` broker user (capture role), the roles and every worker bound
 * of §4.8, the export signing key, and the TEST-ONLY day length. Start-up errors name keys, never
 * values.
 */
export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3060).shape)
  .extend(databaseConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend(archiveKeysFieldsSchema.shape)
  .extend(archiveSearchFieldsSchema.shape)
  .extend(archiveStorageConfigSchema.shape)
  .extend(archiveTestSeamFieldsSchema.shape)
  .extend({
    /** amqp(s) URL(s) of the `eg-archive` broker user; required by the `capture` role only. */
    RABBITMQ_ARCHIVE_URL: amqpUrlListSchema.optional(),
    ARCHIVE_WORKER_ROLES: roles.default(['capture', 'index', 'lifecycle', 'ediscovery']),
    ARCHIVE_PREFETCH: int(1, 200).default(20),
    ARCHIVE_DB_TX_TIMEOUT_MS: int(15_000, 300_000).default(60_000),

    // Capture (A2–A7).
    ARCHIVE_CAPTURE_CONCURRENCY: int(1, 32).default(4),
    ARCHIVE_CAPTURE_LEASE_SECONDS: int(60, 3_600).default(600),
    ARCHIVE_CAPTURE_RETRY_BASE_MS: int(1_000, 3_600_000).default(5_000),
    ARCHIVE_CAPTURE_RETRY_MAX_MS: int(1_000, 86_400_000).default(3_600_000),
    ARCHIVE_INTENT_MAX_AGE_DAYS: int(1, 30).default(25),
    ARCHIVE_OUTCOME_WINDOW_DAYS: int(1, 30).default(7),
    ARCHIVE_SWEEP_INTERVAL_MS: int(1_000, 600_000).default(15_000),
    ARCHIVE_SWEEP_BATCH_SIZE: int(100, 5_000).default(1_000),
    ARCHIVE_SWEEP_SAFETY_LAG_SECONDS: int(30, 3_600).default(120),
    ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS: int(60, 3_600).default(300),
    ARCHIVE_JOURNAL_SWEEP_START: sweepStart.default('now'),
    ARCHIVE_POLICY_RECONCILE_START: sweepStart.default('oldest'),

    // Storage and crypto (A5, A8).
    ARCHIVE_S3_TIMEOUT_MS: int(5_000, 600_000).default(120_000),
    ARCHIVE_S3_PART_SIZE_BYTES: int(5 * 1_048_576, 64 * 1_048_576).default(8 * 1_048_576),
    ARCHIVE_CHUNK_BYTES: int(16_384, 1_048_576).default(65_536),
    ARCHIVE_PREVIEW_PART_MAX_BYTES: int(65_536, 4 * 1_048_576).default(1_048_576),
    ARCHIVE_SETTINGS_CACHE_TTL_MS: int(1_000, 600_000).default(30_000),
    ARCHIVE_KEY_CACHE_TTL_MS: int(1_000, 3_600_000).default(60_000),

    // Index (A15, A16).
    ARCHIVE_INDEX_BATCH_SIZE: int(1, 5_000).default(500),
    ARCHIVE_INDEX_INTERVAL_MS: int(100, 600_000).default(2_000),
    ARCHIVE_INDEX_SHARDS: int(1, 64).default(1),
    ARCHIVE_INDEX_REPLICAS: int(0, 16).default(0),
    ARCHIVE_RECONCILE_INTERVAL_MS: int(10_000, 86_400_000).default(600_000),
    ARCHIVE_RECONCILE_RECENT_DAYS: int(1, 31).default(3),

    // Lifecycle (A13–A15).
    ARCHIVE_LIFECYCLE_INTERVAL_MS: int(1_000, 86_400_000).default(60_000),
    ARCHIVE_LIFECYCLE_BATCH_SIZE: int(1, 5_000).default(200),
    ARCHIVE_HOLD_EXTENSION_DAYS: int(1, 3_650).default(30),
    ARCHIVE_REVIEW_EXTENSION_DAYS: int(1, 3_650).default(30),
    ARCHIVE_DISPOSAL_MAX_ATTEMPTS: int(1, 1_000).default(20),
    ARCHIVE_GOVERNANCE_BYPASS_ORPHANS: flag.default(true),
    ARCHIVE_REPLICA_TARGETS: replicaTargets.default([]),

    // eDiscovery (A18).
    ARCHIVE_EXPORT_SIGNING_KEY: z.string().min(1).max(4_096).optional(),
    ARCHIVE_EXPORT_SIGNING_KEY_ID: z
      .string()
      .regex(/^[a-z][a-z0-9]{0,15}$/, 'must match ^[a-z][a-z0-9]{0,15}$')
      .default('es1'),
    ARCHIVE_EXPORT_MAX_ITEMS: int(1, 1_000_000).default(10_000),
    ARCHIVE_EXPORT_MAX_BYTES: int(1_048_576, 1_099_511_627_776).default(2_147_483_648),
    ARCHIVE_EXPORT_TTL_HOURS: int(1, 8_760).default(168),
    ARCHIVE_EXPORT_CONCURRENCY: int(1, 8).default(1),
    ARCHIVE_CASE_SEARCH_MAX_HITS: int(1, 10_000_000).default(100_000),
    ARCHIVE_CASE_SEARCH_DEADLINE_MS: int(1_000, 86_400_000).default(600_000),
  })
  .superRefine((cfg, ctx) => {
    validateArchiveKeysConfig(cfg, ctx);
    validateArchiveSearchConfig(cfg, ctx);
    validateArchiveTestSeam(cfg, ctx);
    const issue = (path: string, message: string): void =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    const has = (role: ArchiveWorkerRole) => cfg.ARCHIVE_WORKER_ROLES.includes(role);
    if (has('capture') && cfg.RABBITMQ_ARCHIVE_URL === undefined) {
      issue('RABBITMQ_ARCHIVE_URL', 'is required by the capture role');
    }
    if ((has('index') || has('ediscovery')) && cfg.ARCHIVE_SEARCH_URL === undefined) {
      issue('ARCHIVE_SEARCH_URL', 'is required by the index and ediscovery roles');
    }
    if (has('ediscovery') && cfg.ARCHIVE_EXPORT_SIGNING_KEY === undefined) {
      issue('ARCHIVE_EXPORT_SIGNING_KEY', 'is required by the ediscovery role');
    }
    if (cfg.ARCHIVE_CAPTURE_RETRY_BASE_MS > cfg.ARCHIVE_CAPTURE_RETRY_MAX_MS) {
      issue('ARCHIVE_CAPTURE_RETRY_BASE_MS', 'must not exceed ARCHIVE_CAPTURE_RETRY_MAX_MS');
    }
    if (cfg.ARCHIVE_REPLICA_TARGETS.some((t) => t.bucket === cfg.S3_BUCKET_ARCHIVE)) {
      issue('ARCHIVE_REPLICA_TARGETS', 'must not list the archive bucket itself');
    }
  });

export type WorkerConfig = z.infer<typeof configSchema>;

/** Validates the environment once; refuses to start on any invalid or forbidden key. */
export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> {
  // APP_ENV defaults to `local` in the shared base schema; with NODE_ENV=production and no APP_ENV
  // the worker assumes production, so the test seam is never enabled by omission.
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  return loadConfig(configSchema, appEnv ? { ...env, APP_ENV: appEnv } : env);
}

/** True when this process runs `role` (Compose: every role; Kubernetes: two Deployments). */
export function hasRole(
  cfg: Pick<WorkerConfig, 'ARCHIVE_WORKER_ROLES'>,
  role: ArchiveWorkerRole,
): boolean {
  return cfg.ARCHIVE_WORKER_ROLES.includes(role);
}

/** The retention day length in seconds (`ARCHIVE_TEST_DAY_SECONDS` in local/ci only). */
export function daySeconds(cfg: Pick<WorkerConfig, 'ARCHIVE_TEST_DAY_SECONDS'>): number {
  return cfg.ARCHIVE_TEST_DAY_SECONDS ?? 86_400;
}
