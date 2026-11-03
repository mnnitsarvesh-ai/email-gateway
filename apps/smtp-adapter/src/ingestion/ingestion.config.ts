import { z } from 'zod';

const port = (fallback: number) => z.coerce.number().int().min(1).max(65535).default(fallback);

/** S3 multipart uploads need parts of at least 5 MiB (except the last). */
export const MIN_S3_PART_SIZE_BYTES = 5 * 1024 * 1024;

/**
 * Configuration of durable LMTP ingestion (step 2.2 D7, D8, D14; `.env.example` section
 * "SMTP gateway"). The app merges this raw shape into its config schema.
 */
export const ingestionConfigShape = {
  LMTP_INBOUND_PORT: port(10050),
  LMTP_OUTBOUND_PORT: port(10051),
  LMTP_MAX_CLIENTS: z.coerce.number().int().min(1).max(1000).default(20),
  /** Above Postfix's 50 MiB `message_size_limit`: a guard, never the effective limit. */
  INGEST_MAX_MESSAGE_BYTES: z.coerce.number().int().min(1024).default(53_477_376),
  INGEST_S3_PART_SIZE_BYTES: z.coerce
    .number()
    .int()
    .min(MIN_S3_PART_SIZE_BYTES)
    .default(MIN_S3_PART_SIZE_BYTES),
  INGEST_S3_QUEUE_SIZE: z.coerce.number().int().min(1).max(16).default(2),
  INGEST_S3_TIMEOUT_MS: z.coerce.number().int().min(1000).default(120_000),
  INGEST_DB_TIMEOUT_MS: z.coerce.number().int().min(1000).default(15_000),
  INGEST_HEADER_MAX_BYTES: z.coerce.number().int().min(1024).max(1_048_576).default(65_536),
  /** HMAC key of the X-Gateway-Trace header (D14). Never logged. */
  GATEWAY_TRACE_SECRET: z.string().min(32),
  GATEWAY_TRACE_ID: z
    .string()
    .regex(/^[A-Za-z0-9._-]{1,64}$/)
    .default('gw-local'),
  SMTP_LOOP_MAX_PASSES: z.coerce.number().int().min(1).default(1),
};

export type IngestionConfig = z.infer<z.ZodObject<typeof ingestionConfigShape>>;
