import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import {
  MAX_DATABASE_SOCKET_TIMEOUT_SECONDS,
  transactionOutlastsSocket,
} from '@email-gateway/database';
import { z } from 'zod';

const port = z.coerce.number().int().min(1).max(65535);
const positiveInt = z.coerce.number().int().min(1);
const nonNegativeInt = z.coerce.number().int().min(0);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

const HOST_NAME =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

const hostName = z
  .string()
  .transform((value) => value.trim().toLowerCase().replace(/\.$/, ''))
  .refine((v) => HOST_NAME.test(v) && v.length <= 253, 'must be a host name');

/**
 * Default writer-transaction budget of every data-plane interactive transaction of this worker
 * (`DELIVERY_DB_TX_TIMEOUT_MS`, step 4.2 §6.2, §12 WP4). Longer than MySQL's default
 * `innodb_lock_wait_timeout` (50 s) and than the writer stalls the worker rides through, so the
 * client never expires a transaction while one of its statements is in flight (with the Prisma
 * 6.19 library engine that leaves the reply unread on a pooled connection: wrong reads).
 */
export const DEFAULT_DELIVERY_DB_TX_TIMEOUT_MS = 120_000;
/** Lower bound of `DELIVERY_DB_TX_TIMEOUT_MS` (above `innodb_lock_wait_timeout` 50 s). */
export const MIN_DELIVERY_DB_TX_TIMEOUT_MS = 60_000;

/**
 * Delivery-worker configuration (step 2.3 §5; `.env.example` section "Mail routing and delivery
 * (step 2.3)"). Every key is validated here; the cross-field rules are in `validateWorkerConfig`.
 */
export const deliveryConfigShape = {
  // Reinjection into postfix-outbound (R8).
  DELIVERY_REINJECT_HOST: z.string().min(1).max(253).default('postfix-outbound'),
  DELIVERY_REINJECT_INBOUND_PORT: port.default(10026),
  DELIVERY_REINJECT_OUTBOUND_PORT: port.default(10027),
  /** Organization-neutral EHLO name (invariant 9). */
  DELIVERY_REINJECT_HELO: hostName.default('delivery.gateway.local'),
  DELIVERY_REINJECT_CONCURRENCY: positiveInt.max(256).default(8),
  /** ≤ postfix-outbound `smtpd_recipient_limit` (100). */
  DELIVERY_BATCH_MAX_RECIPIENTS: positiveInt.max(100).default(100),
  DELIVERY_REINJECT_COMMAND_TIMEOUT_MS: z.coerce.number().int().min(100).default(60_000),
  DELIVERY_REINJECT_DATA_TIMEOUT_MS: z.coerce.number().int().min(100).default(600_000),
  DELIVERY_REINJECT_LEASE_SECONDS: positiveInt.max(86_400).default(900),
  DELIVERY_REINJECT_RETRY_BASE_SECONDS: positiveInt.default(30),
  DELIVERY_REINJECT_RETRY_MAX_SECONDS: positiveInt.default(900),
  DELIVERY_REINJECT_MAX_AGE_SECONDS: positiveInt.default(432_000),
  /**
   * Attempts after which a reinjection whose message context stays unreadable (`context_missing`)
   * fails with its active deliveries (`message_missing`, step 4.2 §6.2 item 3).
   */
  DELIVERY_REINJECT_MAX_ATTEMPTS: positiveInt.max(1000).default(10),

  // Writer client (step 4.2 §6.2 F2).
  /** `socket_timeout` of the writer client; 0 = none (default; see `client-url.ts`). */
  DATABASE_SOCKET_TIMEOUT_SECONDS: nonNegativeInt
    .max(MAX_DATABASE_SOCKET_TIMEOUT_SECONDS)
    .default(0),
  /** Budget of every data-plane interactive transaction (planner, recorder, claims, results). */
  DELIVERY_DB_TX_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(MIN_DELIVERY_DB_TX_TIMEOUT_MS)
    .max(900_000)
    .default(DEFAULT_DELIVERY_DB_TX_TIMEOUT_MS),

  // Approvals from RabbitMQ (step 3.2 Q13): prefetch of the `email.delivery.pending` consumer
  // (= approvals planned at the same time by one replica).
  DELIVERY_APPROVAL_PREFETCH: positiveInt.max(64).default(4),

  // Scheduler (R8) and the dev pass-through's outbox poller (R6; since step 3.2 the poller
  // serves only the development pass-through, the planner consumes from RabbitMQ).
  DELIVERY_POLL_INTERVAL_MS: z.coerce.number().int().min(10).default(1000),
  DELIVERY_OUTBOX_POLL_INTERVAL_MS: z.coerce.number().int().min(10).default(1000),
  DELIVERY_OUTBOX_SAFETY_LAG_MS: nonNegativeInt.default(120_000),
  DELIVERY_OUTBOX_BATCH_SIZE: positiveInt.max(5000).default(500),

  // Roles of this process.
  DELIVERY_APPROVALS_ENABLED: flag.default(true),
  DELIVERY_REINJECTION_ENABLED: flag.default(true),
  DELIVERY_STATUS_LOG_ENABLED: flag.default(true),
  /** DEVELOPMENT ONLY (R5): refused unless APP_ENV is local or ci. */
  DELIVERY_DEV_PASSTHROUGH_ENABLED: flag.default(false),

  // Postfix delivery log (R9) and reconciler (R12).
  DELIVERY_STATUS_LOG_PATH: z.string().min(1).default('/var/log/postfix-outbound/maillog'),
  /** Unique per postfix-outbound host; part of the cursor name and of the GET_LOCK name (≤ 64). */
  DELIVERY_STATUS_LOG_SOURCE_ID: z
    .string()
    .regex(/^[A-Za-z0-9._-]{1,48}$/, 'must be 1-48 characters of [A-Za-z0-9._-]')
    .default('out.gateway.local'),
  DELIVERY_STATUS_LOG_POLL_MS: z.coerce.number().int().min(10).default(500),
  DELIVERY_STATUS_UNMATCHED_RETRY_SECONDS: nonNegativeInt.default(60),
  DELIVERY_STATUS_STALE_AFTER_SECONDS: positiveInt.default(518_400),
  DELIVERY_RECONCILE_INTERVAL_MS: z.coerce.number().int().min(100).default(30_000),
  /**
   * A recipient of a queued reinjection with no delivery-log line this long after qmgr took the
   * queue file (and the log past that time) was not accepted at RCPT: it is re-planned.
   */
  DELIVERY_RECONCILE_UNCONFIRMED_SECONDS: positiveInt.default(3600),

  // Outbound rate limits per UTC minute (R11); 0 = hold.
  DELIVERY_RATE_TENANT_RCPT_PER_MINUTE: nonNegativeInt.default(600),
  DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE: nonNegativeInt.default(300),
  DELIVERY_RATE_DESTINATION_DOMAIN_RCPT_PER_MINUTE: nonNegativeInt.default(6000),

  // Hop enforcement at reinjection (R10).
  ROUTING_MAX_RECEIVED_HEADERS: positiveInt.max(1000).default(25),
  ROUTING_MAX_GATEWAY_PASSES: positiveInt.max(100).default(4),

  // Shared with the smtp-adapter (step 2.2 D14).
  /** HMAC key of the X-Gateway-Trace header. Never logged. */
  GATEWAY_TRACE_SECRET: z.string().min(32),
  GATEWAY_TRACE_ID: z
    .string()
    .regex(/^[A-Za-z0-9._-]{1,64}$/)
    .default('gw-local'),
  POSTFIX_OUTBOUND_MYHOSTNAME: hostName.default('out.gateway.local'),
  /** Header block read cap before connecting (R8 step 2). */
  INGEST_HEADER_MAX_BYTES: z.coerce.number().int().min(1024).max(1_048_576).default(65_536),
};

/** The text of the startup refusal (also asserted by the tests). */
export const DEV_PASSTHROUGH_REFUSAL =
  'true is allowed only when APP_ENV is local or ci: the dev pass-through delivers scanned mail without policy';

/** Cross-field rules. */
export function validateWorkerConfig(
  cfg: {
    APP_ENV: string;
    DELIVERY_DEV_PASSTHROUGH_ENABLED: boolean;
    DELIVERY_APPROVALS_ENABLED: boolean;
    DELIVERY_REINJECT_RETRY_BASE_SECONDS: number;
    DELIVERY_REINJECT_RETRY_MAX_SECONDS: number;
    DELIVERY_REINJECT_INBOUND_PORT: number;
    DELIVERY_REINJECT_OUTBOUND_PORT: number;
    DATABASE_SOCKET_TIMEOUT_SECONDS: number;
    DELIVERY_DB_TX_TIMEOUT_MS: number;
  },
  ctx: z.RefinementCtx,
): void {
  if (
    !transactionOutlastsSocket(cfg.DELIVERY_DB_TX_TIMEOUT_MS, cfg.DATABASE_SOCKET_TIMEOUT_SECONDS)
  ) {
    ctx.addIssue({
      code: 'custom',
      path: ['DELIVERY_DB_TX_TIMEOUT_MS'],
      message:
        'must be longer than DATABASE_SOCKET_TIMEOUT_SECONDS: a transaction must never expire ' +
        'while one of its statements is in flight (step 4.2 §6.2)',
    });
  }
  if (cfg.DELIVERY_DEV_PASSTHROUGH_ENABLED && cfg.APP_ENV !== 'local' && cfg.APP_ENV !== 'ci') {
    ctx.addIssue({
      code: 'custom',
      path: ['DELIVERY_DEV_PASSTHROUGH_ENABLED'],
      message: DEV_PASSTHROUGH_REFUSAL,
    });
  }
  if (cfg.DELIVERY_DEV_PASSTHROUGH_ENABLED && !cfg.DELIVERY_APPROVALS_ENABLED) {
    ctx.addIssue({
      code: 'custom',
      path: ['DELIVERY_DEV_PASSTHROUGH_ENABLED'],
      message: 'requires DELIVERY_APPROVALS_ENABLED=true (it writes approvals for the planner)',
    });
  }
  if (cfg.DELIVERY_REINJECT_RETRY_MAX_SECONDS < cfg.DELIVERY_REINJECT_RETRY_BASE_SECONDS) {
    ctx.addIssue({
      code: 'custom',
      path: ['DELIVERY_REINJECT_RETRY_MAX_SECONDS'],
      message: 'must be at least DELIVERY_REINJECT_RETRY_BASE_SECONDS',
    });
  }
  if (cfg.DELIVERY_REINJECT_INBOUND_PORT === cfg.DELIVERY_REINJECT_OUTBOUND_PORT) {
    ctx.addIssue({
      code: 'custom',
      path: ['DELIVERY_REINJECT_OUTBOUND_PORT'],
      message:
        'must differ from DELIVERY_REINJECT_INBOUND_PORT (10026 and 10027 apply different policies)',
    });
  }
}

/**
 * RabbitMQ (step 3.2 Q10): the delivery-worker's own least-privilege role user on the topology
 * vhost (read `email.delivery.pending`, write `email.delivery` / `email.events` for delay and
 * dead-letter copies), one URL per cluster node, comma-separated
 * (`RABBITMQ_DELIVERY_WORKER_URL_FILE` for a mounted secret).
 */
export const amqpConfigShape = {
  RABBITMQ_DELIVERY_WORKER_URL: amqpUrlListSchema,
};

const objectSchema = baseConfigSchema
  .extend(httpConfigSchema(3040).shape)
  .extend(databaseConfigSchema.shape)
  .extend(amqpConfigShape)
  .extend(redisConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend(deliveryConfigShape);

export const configSchema = objectSchema.superRefine(validateWorkerConfig);

export type WorkerConfig = z.infer<typeof configSchema>;

/**
 * Only the worker's own keys (and their `<KEY>_FILE` secret indirections) are handed to
 * `loadConfig`: the shared `.env` holds keys of other services, and a foreign `*_FILE` key would
 * otherwise be read as a secret file of this service (same defence as the smtp-adapter).
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

// --- Injection tokens ---------------------------------------------------------------------------

/** The validated `WorkerConfig`. */
export const WORKER_CONFIG = Symbol('WORKER_CONFIG');
/** Root pino logger of the worker (components derive `.child({ component })`). */
export const WORKER_LOGGER = Symbol('WORKER_LOGGER');
