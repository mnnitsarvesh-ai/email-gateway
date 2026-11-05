import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import { HOLD_MAX_DELAY_MS, queueDefinition } from '@email-gateway/event-contracts';
import { MAX_PART_PATH_CHARS } from '@email-gateway/mime-parser';
import { z } from 'zod';
import { scanConfigShape, validateScanConfig } from './scanning/config';

const int = z.coerce.number().int();
const positiveInt = int.min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

/** S3 multipart uploads need parts of at least 5 MiB (except the last). */
export const MIN_S3_PART_SIZE_BYTES = 5 * 1024 * 1024;

/** The queue the stage consumes (step 3.2 Q13): `mail.message.received.v1`, work policy. */
export const MIME_QUEUE = 'email.received';

/**
 * Counted (retryable) failures after which the consumer dead-letters a delivery of
 * `email.received` (topology v1 retry policy, step 3.2 Q8). MIME_MAX_ATTEMPTS must stay below
 * it, so the stage's own poison guard (3.1 M3.4) finalizes `max_attempts_exceeded` first and a
 * received message always ends with a parse row instead of a dead letter.
 */
export const MIME_QUEUE_MAX_ATTEMPTS: number = queueDefinition(MIME_QUEUE).retry?.maxAttempts ?? 0;

/** `email_attachments.part_path` is VARCHAR(128) (migration `mime_ingestion`). */
export const PART_PATH_COLUMN_CHARS = MAX_PART_PATH_CHARS;

/**
 * Longest `part_path` a parse within these limits can record: `0`, then one `.<n>` segment per
 * level of MIME_MAX_DEPTH, where a child number is below MIME_MAX_PARTS.
 */
export function worstCasePartPathChars(maxDepth: number, maxParts: number): number {
  return 1 + maxDepth * (1 + String(Math.max(1, maxParts - 1)).length);
}

/**
 * MIME ingestion configuration (step 3.1 §5, docs/plan/steps/06-mime-ingestion.md; `.env.example`
 * section "MIME ingestion (step 3.1)"). Every key has the design default; the cross-field
 * refusals of M5 are in `validateMimeConfig`.
 */
export const mimeConfigShape = {
  /** Role flag (M1): scanning-only replicas of later steps switch the parse stage off. */
  MIME_INGESTION_ENABLED: flag.default(true),
  /**
   * Events handled at the same time by one replica: the prefetch of its `email.received`
   * consumer (step 3.2 Q13, Q16), so also the bound on unacknowledged deliveries per replica.
   */
  MIME_CONCURRENCY: positiveInt.max(64).default(4),

  // Retry backoff of the queue consumer (step 3.2 Q8 `hold`: a held delivery keeps its prefetch
  // slot for the delay, so the maximum is capped at 60 s).
  MIME_RETRY_BASE_MS: positiveInt.default(1000),
  MIME_RETRY_MAX_MS: positiveInt.max(HOLD_MAX_DELAY_MS).default(60_000),
  /** Poison-message guard (M3.4, M12); below the queue's attempt limit (step 3.2 Q13). */
  MIME_MAX_ATTEMPTS: positiveInt.max(1000).default(5),

  // Budgets of one attempt.
  /**
   * Writer transaction budget (timeout and maxWait). Above innodb_lock_wait_timeout (50 s) and
   * the writer stalls the worker rides through: on Prisma 6.19.3 an expired interactive
   * transaction returns its connection to the pool with the reply unread, and later queries on
   * it read other queries' results (step 4.2 §6, §13).
   */
  MIME_DB_TIMEOUT_MS: int.min(100).default(120_000),
  /** Longest single wait on S3 (a request, a body chunk, a part upload); below the parse budget. */
  MIME_S3_TIMEOUT_MS: int.min(100).default(30_000),
  MIME_S3_PART_SIZE_BYTES: int.min(MIN_S3_PART_SIZE_BYTES).default(MIN_S3_PART_SIZE_BYTES),
  MIME_S3_QUEUE_SIZE: positiveInt.max(16).default(2),
  MIME_MEMORY_BUDGET_BYTES: positiveInt.default(268_435_456),

  // Parser limits (M5) and storage caps (M7, M9).
  MIME_MAX_MESSAGE_BYTES: positiveInt.default(53_477_376),
  MIME_MAX_DEPTH: int.default(10),
  MIME_MAX_PARTS: int.default(250),
  MIME_MAX_HEADERS: positiveInt.default(1000),
  MIME_MAX_HEADER_LINE_BYTES: positiveInt.default(32_768),
  MIME_MAX_HEADER_BLOCK_BYTES: positiveInt.default(262_144),
  MIME_MAX_ATTACHMENTS: positiveInt.default(100),
  MIME_MAX_ATTACHMENT_BYTES: positiveInt.default(26_214_400),
  MIME_MAX_BODY_BYTES: positiveInt.default(10_485_760),
  MIME_MAX_DECODED_RATIO: z.coerce.number().finite().default(1.1),
  MIME_MAX_TOTAL_DECODED_BYTES: positiveInt.default(104_857_600),
  MIME_PARSE_TIMEOUT_MS: int.min(100).default(120_000),
  MIME_MAX_STORED_HEADERS: int.default(200),
  MIME_FILENAME_MAX_CHARS: int.default(200),

  // Archive inspection thresholds (M10).
  MIME_ARCHIVE_MAX_ENTRIES: positiveInt.default(1000),
  MIME_ARCHIVE_MAX_RATIO: z.coerce.number().finite().positive().default(100),
  MIME_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES: positiveInt.default(1_073_741_824),
  MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES: positiveInt.default(8_388_608),
};

type MimeShapeConfig = {
  [K in keyof typeof mimeConfigShape]: z.infer<(typeof mimeConfigShape)[K]>;
};

/**
 * Worst-case parse buffers of one replica (design M5, step 3.2 Q13): its queue consumer runs at
 * most MIME_CONCURRENCY (= prefetch) parses, and each parse holds one part upload (part size x
 * (queue + 1)) and at most one zip central directory.
 */
export function parseMemoryBytes(cfg: MimeShapeConfig): number {
  const perParse =
    cfg.MIME_S3_PART_SIZE_BYTES * (cfg.MIME_S3_QUEUE_SIZE + 1) +
    cfg.MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES;
  return cfg.MIME_CONCURRENCY * perParse;
}

/** The cross-field refusals of design M5 (startup fails with every violated rule listed). */
export function validateMimeConfig(cfg: MimeShapeConfig, ctx: z.RefinementCtx): void {
  const refuse = (path: keyof MimeShapeConfig, message: string): void => {
    ctx.addIssue({ code: 'custom', path: [path], message });
  };
  if (cfg.MIME_MAX_ATTACHMENT_BYTES > cfg.MIME_MAX_MESSAGE_BYTES) {
    refuse('MIME_MAX_ATTACHMENT_BYTES', 'must not exceed MIME_MAX_MESSAGE_BYTES');
  }
  if (cfg.MIME_MAX_BODY_BYTES > cfg.MIME_MAX_MESSAGE_BYTES) {
    refuse('MIME_MAX_BODY_BYTES', 'must not exceed MIME_MAX_MESSAGE_BYTES');
  }
  if (cfg.MIME_MAX_HEADER_LINE_BYTES > cfg.MIME_MAX_HEADER_BLOCK_BYTES) {
    refuse('MIME_MAX_HEADER_LINE_BYTES', 'must not exceed MIME_MAX_HEADER_BLOCK_BYTES');
  }
  if (cfg.MIME_MAX_DECODED_RATIO < 1) {
    refuse('MIME_MAX_DECODED_RATIO', 'must be at least 1 (decoding never shrinks below 0.75)');
  }
  if (cfg.MIME_MAX_DEPTH < 1 || cfg.MIME_MAX_DEPTH > 50) {
    refuse('MIME_MAX_DEPTH', 'must be between 1 and 50');
  }
  if (cfg.MIME_MAX_PARTS < 2 || cfg.MIME_MAX_PARTS > 1000) {
    refuse('MIME_MAX_PARTS', 'must be between 2 and 1000');
  }
  const pathChars = worstCasePartPathChars(cfg.MIME_MAX_DEPTH, cfg.MIME_MAX_PARTS);
  if (pathChars > PART_PATH_COLUMN_CHARS) {
    refuse(
      'MIME_MAX_DEPTH',
      `with MIME_MAX_PARTS=${String(cfg.MIME_MAX_PARTS)} a part_path can reach ${String(pathChars)} characters ` +
        `(email_attachments.part_path holds ${String(PART_PATH_COLUMN_CHARS)}); lower MIME_MAX_DEPTH or MIME_MAX_PARTS`,
    );
  }
  if (cfg.MIME_MAX_ATTACHMENTS > cfg.MIME_MAX_PARTS) {
    refuse('MIME_MAX_ATTACHMENTS', 'must not exceed MIME_MAX_PARTS');
  }
  if (cfg.MIME_MAX_STORED_HEADERS < 1 || cfg.MIME_MAX_STORED_HEADERS > 500) {
    refuse('MIME_MAX_STORED_HEADERS', 'must be between 1 and 500');
  }
  if (cfg.MIME_FILENAME_MAX_CHARS < 16 || cfg.MIME_FILENAME_MAX_CHARS > 240) {
    refuse('MIME_FILENAME_MAX_CHARS', 'must be between 16 and 240');
  }
  if (cfg.MIME_RETRY_MAX_MS < cfg.MIME_RETRY_BASE_MS) {
    refuse('MIME_RETRY_MAX_MS', 'must be at least MIME_RETRY_BASE_MS');
  }
  if (cfg.MIME_MAX_ATTEMPTS >= MIME_QUEUE_MAX_ATTEMPTS) {
    refuse(
      'MIME_MAX_ATTEMPTS',
      `must be below ${String(MIME_QUEUE_MAX_ATTEMPTS)}, the attempt limit of queue ${MIME_QUEUE} ` +
        '(the parse poison guard must finalize before the consumer dead-letters)',
    );
  }
  if (cfg.MIME_S3_TIMEOUT_MS >= cfg.MIME_PARSE_TIMEOUT_MS) {
    // A stalled S3 call must fail as an infrastructure retry before the parse budget runs out.
    refuse('MIME_S3_TIMEOUT_MS', 'must be below MIME_PARSE_TIMEOUT_MS');
  }
  if (parseMemoryBytes(cfg) > cfg.MIME_MEMORY_BUDGET_BYTES) {
    refuse(
      'MIME_MEMORY_BUDGET_BYTES',
      'MIME_CONCURRENCY x (MIME_S3_PART_SIZE_BYTES x (MIME_S3_QUEUE_SIZE + 1) + ' +
        'MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES) exceeds the budget',
    );
  }
}

/**
 * RabbitMQ (step 3.2 Q10): the email-worker's own least-privilege role user on the topology
 * vhost (read `email.received`, write `email.ingestion` / `email.events`), one URL per cluster
 * node, comma-separated (`RABBITMQ_EMAIL_WORKER_URL_FILE` for a mounted secret). Required when
 * MIME_INGESTION_ENABLED (a scan-only replica, step 4.1 S1, connects as `eg-scanner` only).
 */
export const amqpConfigShape = {
  RABBITMQ_EMAIL_WORKER_URL: amqpUrlListSchema.optional(),
};

const objectSchema = baseConfigSchema
  .extend(httpConfigSchema(3020).shape)
  .extend(databaseConfigSchema.shape)
  .extend(amqpConfigShape)
  .extend(redisConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend(mimeConfigShape)
  .extend(scanConfigShape);

export const configSchema = objectSchema.superRefine((cfg, ctx) => {
  validateMimeConfig(cfg, ctx);
  validateScanConfig(cfg, ctx);
});

export type WorkerConfig = z.infer<typeof configSchema>;

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);
