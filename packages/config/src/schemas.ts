import { z } from 'zod';

const port = z.coerce.number().int().min(1).max(65535);
const bool = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

export const baseConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  APP_ENV: z.enum(['local', 'ci', 'staging', 'production']).default('local'),
  DEPLOYMENT_MODE: z.enum(['saas', 'dedicated']).default('saas'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  SERVICE_VERSION: z.string().default('0.0.0-dev'),
  OTEL_EXPORTER_OTLP_ENDPOINT: z.url().optional(),
});

/** HTTP listener config; each service passes its own default port (overridable via HTTP_PORT). */
export const httpConfigSchema = (defaultPort: number) =>
  z.object({
    HTTP_PORT: port.default(defaultPort),
    HTTP_HOST: z.string().default('0.0.0.0'),
  });

export const databaseConfigSchema = z.object({
  DATABASE_URL: z.string().startsWith('mysql://', 'DATABASE_URL must be a mysql:// URL'),
});

/**
 * Optional read replica, composed only by control-plane services (api). Data-plane services
 * never read from a replica (ADR-0014): replica lag must not affect a mail decision.
 * Without DATABASE_READ_URL, reads go to the writer.
 */
export const databaseReadConfigSchema = z.object({
  DATABASE_READ_URL: z
    .string()
    .startsWith('mysql://', 'DATABASE_READ_URL must be a mysql:// URL')
    .optional(),
  /** Above this replication lag, reads fall back to the writer. */
  DATABASE_READ_MAX_LAG_SECONDS: z.coerce.number().int().min(0).default(10),
  /** How often the replica's lag and thread state are probed. */
  DATABASE_READ_LAG_CHECK_INTERVAL_MS: z.coerce.number().int().min(1000).max(60000).default(5000),
});

/**
 * A comma-separated list of `amqp://` or `amqps://` URLs (one per cluster node, tried in rotation
 * by the AMQP client, step 3.2 Q6), trimmed, transformed to `string[]`. Each entry needs a host.
 * Issues name the entry's position only: URLs carry credentials, so a value is never echoed.
 */
export const amqpUrlListSchema = z.string().transform((value, ctx): string[] => {
  const entries = value.split(',').map((entry) => entry.trim());
  if (entries.length === 1 && entries[0] === '') {
    ctx.addIssue({ code: 'custom', message: 'must list at least one amqp(s):// URL' });
    return z.NEVER;
  }
  entries.forEach((entry, index) => {
    const position = `entry ${index + 1}`;
    if (entry === '') {
      ctx.addIssue({ code: 'custom', message: `${position} is empty` });
      return;
    }
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      ctx.addIssue({ code: 'custom', message: `${position} is not a valid URL` });
      return;
    }
    if (url.protocol !== 'amqp:' && url.protocol !== 'amqps:') {
      ctx.addIssue({ code: 'custom', message: `${position} must be an amqp(s):// URL` });
    } else if (url.hostname === '') {
      ctx.addIssue({ code: 'custom', message: `${position} has no host` });
    }
  });
  return entries;
});

export const redisConfigSchema = z.object({
  REDIS_URL: z.string().regex(/^rediss?:\/\//, 'REDIS_URL must be a redis(s):// URL'),
});

export const s3ConfigSchema = z.object({
  S3_REGION: z.string().min(1),
  /** Set only for S3-compatible stores such as MinIO; leave unset on AWS. */
  S3_ENDPOINT: z.url().optional(),
  S3_FORCE_PATH_STYLE: bool.default(false),
  S3_BUCKET_MAIL: z.string().min(3),
  S3_BUCKET_ARCHIVE: z.string().min(3),
  /** Optional: on AWS the default credential chain (IRSA, instance profile) is used instead. */
  S3_ACCESS_KEY_ID: z.string().optional(),
  S3_SECRET_ACCESS_KEY: z.string().optional(),
});

export type BaseConfig = z.infer<typeof baseConfigSchema>;
export type HttpConfig = z.infer<ReturnType<typeof httpConfigSchema>>;
export type DatabaseConfig = z.infer<typeof databaseConfigSchema>;
export type DatabaseReadConfig = z.infer<typeof databaseReadConfigSchema>;
export type RedisConfig = z.infer<typeof redisConfigSchema>;
export type S3Config = z.infer<typeof s3ConfigSchema>;

const EMAIL = z.email();
const NAMED_ADDRESS = /^(?<name>[^<>\r\n]*?)\s*<(?<address>[^<>\s]+)>$/;

/** True for `user@example.com` or `Display Name <user@example.com>` (no CR/LF anywhere). */
export function isSenderAddress(value: string): boolean {
  if (/[\r\n]/.test(value)) return false;
  const named = NAMED_ADDRESS.exec(value.trim());
  const address = named?.groups?.address ?? value.trim();
  return EMAIL.safeParse(address).success;
}

/**
 * Transactional-email relay (password reset, verification, invitations; later the notification
 * service). Without NOTIFY_SMTP_HOST no relay is configured and callers fall back to logging.
 * `APP_ENV` is part of the schema because plaintext SMTP is accepted only in local and CI.
 */
export const notifySmtpFieldsSchema = z.object({
  APP_ENV: baseConfigSchema.shape.APP_ENV,
  NOTIFY_SMTP_HOST: z.string().min(1).max(253).optional(),
  NOTIFY_SMTP_PORT: port.default(587),
  /** `tls`: implicit TLS (465). `starttls`: upgrade required (587). `none`: plaintext, local/CI only. */
  NOTIFY_SMTP_SECURE: z.enum(['tls', 'starttls', 'none']).default('starttls'),
  NOTIFY_SMTP_USER: z.string().min(1).optional(),
  NOTIFY_SMTP_PASSWORD: z.string().min(1).optional(),
  /**
   * PEM file of extra certificates to trust for the relay, e.g. a pinned self-signed relay
   * certificate. Verification stays on: only these (and the system CAs) are accepted.
   * Deliberately not named *_FILE, which is the secret-indirection convention.
   */
  NOTIFY_SMTP_CA_PATH: z.string().min(1).optional(),
  /** `no-reply@example.com` or `Example <no-reply@example.com>`. Required when HOST is set. */
  NOTIFY_SMTP_FROM: z
    .string()
    .refine(isSenderAddress, 'must be an email address or "Name <email>"')
    .optional(),
});

export type NotifySmtpConfig = z.infer<typeof notifySmtpFieldsSchema>;

/**
 * Cross-field rules of the relay config. Exported so a service that composes the fields into a
 * larger schema (`.extend(notifySmtpFieldsSchema.shape)`) can apply them with `.superRefine`.
 */
export function validateNotifySmtpConfig(cfg: NotifySmtpConfig, ctx: z.RefinementCtx): void {
  if (cfg.NOTIFY_SMTP_HOST && !cfg.NOTIFY_SMTP_FROM) {
    ctx.addIssue({
      code: 'custom',
      path: ['NOTIFY_SMTP_FROM'],
      message: 'is required when NOTIFY_SMTP_HOST is set',
    });
  }
  if (Boolean(cfg.NOTIFY_SMTP_USER) !== Boolean(cfg.NOTIFY_SMTP_PASSWORD)) {
    ctx.addIssue({
      code: 'custom',
      path: [cfg.NOTIFY_SMTP_USER ? 'NOTIFY_SMTP_PASSWORD' : 'NOTIFY_SMTP_USER'],
      message: 'NOTIFY_SMTP_USER and NOTIFY_SMTP_PASSWORD must be set together',
    });
  }
  if (cfg.NOTIFY_SMTP_SECURE === 'none' && cfg.APP_ENV !== 'local' && cfg.APP_ENV !== 'ci') {
    ctx.addIssue({
      code: 'custom',
      path: ['NOTIFY_SMTP_SECURE'],
      message: 'none (plaintext SMTP) is allowed only when APP_ENV is local or ci',
    });
  }
}

export const notifySmtpConfigSchema = notifySmtpFieldsSchema.superRefine(validateNotifySmtpConfig);

// ---------------------------------------------------------------------------------------------
// Journaling and compliance archiving (step 8.1, docs/plan/steps/23-journaling-archiving.md §4.8)
// ---------------------------------------------------------------------------------------------

const ARCHIVE_KEY_HEX = /^[0-9a-fA-F]{64}$/;
const ARCHIVE_KEY_ID = /^[a-z][a-z0-9]{0,15}$/;

/**
 * The archive root key (A8, ADR-0065): `ARCHIVE_ROOT_KEY` (32 bytes, 64 hex) with its id, and the
 * previous key and id during a root rotation (set together). Held by the api and the
 * archive-worker only. Messages name keys, never values.
 */
export const archiveKeysFieldsSchema = z.object({
  ARCHIVE_ROOT_KEY: z.string().regex(ARCHIVE_KEY_HEX, 'must be 32 bytes (64 hex characters)'),
  ARCHIVE_ROOT_KEY_ID: z
    .string()
    .regex(ARCHIVE_KEY_ID, 'must match ^[a-z][a-z0-9]{0,15}$')
    .default('r1'),
  ARCHIVE_ROOT_KEY_PREVIOUS: z
    .string()
    .regex(ARCHIVE_KEY_HEX, 'must be 32 bytes (64 hex characters)')
    .optional(),
  ARCHIVE_ROOT_KEY_PREVIOUS_ID: z
    .string()
    .regex(ARCHIVE_KEY_ID, 'must match ^[a-z][a-z0-9]{0,15}$')
    .optional(),
});
export type ArchiveKeysConfig = z.infer<typeof archiveKeysFieldsSchema>;

/** Cross-field rules of the root keys; exported for services that compose the fields. */
export function validateArchiveKeysConfig(cfg: ArchiveKeysConfig, ctx: z.RefinementCtx): void {
  const prevKey = cfg.ARCHIVE_ROOT_KEY_PREVIOUS;
  const prevId = cfg.ARCHIVE_ROOT_KEY_PREVIOUS_ID;
  if (Boolean(prevKey) !== Boolean(prevId)) {
    ctx.addIssue({
      code: 'custom',
      path: [prevKey ? 'ARCHIVE_ROOT_KEY_PREVIOUS_ID' : 'ARCHIVE_ROOT_KEY_PREVIOUS'],
      message: 'ARCHIVE_ROOT_KEY_PREVIOUS and ARCHIVE_ROOT_KEY_PREVIOUS_ID must be set together',
    });
    return;
  }
  if (prevKey && prevKey.toLowerCase() === cfg.ARCHIVE_ROOT_KEY.toLowerCase()) {
    ctx.addIssue({
      code: 'custom',
      path: ['ARCHIVE_ROOT_KEY_PREVIOUS'],
      message: 'must differ from ARCHIVE_ROOT_KEY',
    });
  }
  if (prevId && prevId === cfg.ARCHIVE_ROOT_KEY_ID) {
    ctx.addIssue({
      code: 'custom',
      path: ['ARCHIVE_ROOT_KEY_PREVIOUS_ID'],
      message: 'must differ from ARCHIVE_ROOT_KEY_ID',
    });
  }
}

export const archiveKeysConfigSchema =
  archiveKeysFieldsSchema.superRefine(validateArchiveKeysConfig);

/**
 * The archive search index (A16, ADR-0068). `ARCHIVE_SEARCH_URL` is optional (the api answers
 * `503 archive_search_unavailable` without it; the worker roles `index`/`ediscovery` require it).
 */
export const archiveSearchFieldsSchema = z.object({
  ARCHIVE_SEARCH_URL: z
    .url({ protocol: /^https?$/, message: 'must be an http(s) URL' })
    .refine((value) => {
      try {
        const url = new URL(value);
        return url.username === '' && url.password === '';
      } catch {
        return false;
      }
    }, 'must not embed credentials (use ARCHIVE_SEARCH_USERNAME and ARCHIVE_SEARCH_PASSWORD)')
    .optional(),
  ARCHIVE_SEARCH_USERNAME: z.string().min(1).max(256).optional(),
  ARCHIVE_SEARCH_PASSWORD: z.string().min(1).max(1024).optional(),
  ARCHIVE_SEARCH_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(10000),
  ARCHIVE_SEARCH_INDEX_PREFIX: z
    .string()
    .regex(/^[a-z][a-z0-9-]{2,40}$/, 'must match ^[a-z][a-z0-9-]{2,40}$')
    .default('eg-archive'),
});
export type ArchiveSearchConfig = z.infer<typeof archiveSearchFieldsSchema>;

export function validateArchiveSearchConfig(cfg: ArchiveSearchConfig, ctx: z.RefinementCtx): void {
  if (Boolean(cfg.ARCHIVE_SEARCH_USERNAME) !== Boolean(cfg.ARCHIVE_SEARCH_PASSWORD)) {
    ctx.addIssue({
      code: 'custom',
      path: [cfg.ARCHIVE_SEARCH_USERNAME ? 'ARCHIVE_SEARCH_PASSWORD' : 'ARCHIVE_SEARCH_USERNAME'],
      message: 'ARCHIVE_SEARCH_USERNAME and ARCHIVE_SEARCH_PASSWORD must be set together',
    });
  }
}

export const archiveSearchConfigSchema = archiveSearchFieldsSchema.superRefine(
  validateArchiveSearchConfig,
);

/** Archive storage (A10, A11): Object Lock probing and the platform retention cap. */
export const archiveStorageConfigSchema = z.object({
  /** `auto`: probe the bucket's Object Lock configuration at start; `disabled`: never use it. */
  ARCHIVE_OBJECT_LOCK: z.enum(['auto', 'disabled']).default('auto'),
  ARCHIVE_MAX_RETENTION_DAYS: z.coerce.number().int().min(1).max(36500).default(3650),
});
export type ArchiveStorageConfig = z.infer<typeof archiveStorageConfigSchema>;

/**
 * Test seam (A11): `ARCHIVE_TEST_DAY_SECONDS` replaces the length of a retention day so stack
 * tests can expire records in seconds. Refused unless `APP_ENV` is `local` or `ci`.
 */
export const archiveTestSeamFieldsSchema = z.object({
  APP_ENV: baseConfigSchema.shape.APP_ENV,
  ARCHIVE_TEST_DAY_SECONDS: z.coerce.number().int().min(1).max(86400).optional(),
});
export type ArchiveTestSeamConfig = z.infer<typeof archiveTestSeamFieldsSchema>;

export function validateArchiveTestSeam(cfg: ArchiveTestSeamConfig, ctx: z.RefinementCtx): void {
  if (
    cfg.ARCHIVE_TEST_DAY_SECONDS !== undefined &&
    cfg.APP_ENV !== 'local' &&
    cfg.APP_ENV !== 'ci'
  ) {
    ctx.addIssue({
      code: 'custom',
      path: ['ARCHIVE_TEST_DAY_SECONDS'],
      message: 'is allowed only when APP_ENV is local or ci',
    });
  }
}

export const archiveTestSeamSchema =
  archiveTestSeamFieldsSchema.superRefine(validateArchiveTestSeam);
