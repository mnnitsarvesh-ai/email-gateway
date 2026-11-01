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

export const rabbitmqConfigSchema = z.object({
  RABBITMQ_URL: z.string().regex(/^amqps?:\/\//, 'RABBITMQ_URL must be an amqp(s):// URL'),
  RABBITMQ_PREFETCH: z.coerce.number().int().min(1).max(1000).default(20),
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
export type RabbitmqConfig = z.infer<typeof rabbitmqConfigSchema>;
export type RedisConfig = z.infer<typeof redisConfigSchema>;
export type S3Config = z.infer<typeof s3ConfigSchema>;
