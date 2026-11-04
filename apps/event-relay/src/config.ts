import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
} from '@email-gateway/config';
import { isQueueName, queueDefinition, type QueueName } from '@email-gateway/event-contracts';
import type { MessageState } from '@email-gateway/message-lifecycle';
import { z } from 'zod';

const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);

/** The reconciler re-check needs every writer transaction long finished (Q12). */
export const MIN_UNCONSUMED_AFTER_SECONDS = 300;
/** Below the 7-day `message_outbox` retention (Q12, §6). */
export const MAX_LOOKBACK_HOURS = 144;

/**
 * `RECONCILE_QUEUES`: comma-separated queue names. Each must be a `work` queue of topology v1
 * whose consumer leaves `message_idempotency` rows (`consumer.kind = 'ledger'`). Messages name
 * the position in the list, never the value.
 */
export const reconcileQueuesSchema = z.string().transform((value, ctx): QueueName[] => {
  const entries = value.split(',').map((entry) => entry.trim());
  const queues: QueueName[] = [];
  entries.forEach((entry, index) => {
    const position = `entry ${index + 1}`;
    if (!isQueueName(entry)) {
      ctx.addIssue({ code: 'custom', message: `${position} is not a queue of topology v1` });
      return;
    }
    const queue = queueDefinition(entry);
    if (queue.role !== 'work' || queue.consumer.kind !== 'ledger') {
      ctx.addIssue({
        code: 'custom',
        message: `${position} must be a work queue with a ledger consumer`,
      });
      return;
    }
    if (queues.includes(entry)) {
      ctx.addIssue({ code: 'custom', message: `${position} is listed twice` });
      return;
    }
    queues.push(entry);
  });
  return queues;
});

/** Postfix `maximal_queue_lifetime` (5 d): a delivery deadline must exceed it (step 3.3 L13). */
export const POSTFIX_QUEUE_LIFETIME_HOURS = 120;
/** Longest per-state deadline: 400 days (the longest lookback). */
export const MAX_DEADLINE_HOURS = 9600;

/** `LIFECYCLE_DEADLINE_<STATE>_HOURS` of every expirable state (step 3.3 §5, L13). */
export const LIFECYCLE_DEADLINE_KEYS = {
  persisted: 'LIFECYCLE_DEADLINE_PERSISTED_HOURS',
  scanning: 'LIFECYCLE_DEADLINE_SCANNING_HOURS',
  scanned: 'LIFECYCLE_DEADLINE_SCANNED_HOURS',
  scan_failed: 'LIFECYCLE_DEADLINE_SCAN_FAILED_HOURS',
  policy_evaluated: 'LIFECYCLE_DEADLINE_POLICY_EVALUATED_HOURS',
  approved: 'LIFECYCLE_DEADLINE_APPROVED_HOURS',
  quarantined: 'LIFECYCLE_DEADLINE_QUARANTINED_HOURS',
  held_for_review: 'LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS',
  delivery_pending: 'LIFECYCLE_DEADLINE_DELIVERY_PENDING_HOURS',
  delivery_retry: 'LIFECYCLE_DEADLINE_DELIVERY_RETRY_HOURS',
} as const satisfies Partial<Record<MessageState, string>>;

export type ExpirableDeadlineState = keyof typeof LIFECYCLE_DEADLINE_KEYS;
type DeadlineKey = (typeof LIFECYCLE_DEADLINE_KEYS)[ExpirableDeadlineState];

const deadline = (hours: number) => int(0, MAX_DEADLINE_HOURS).default(hours);

/**
 * Message lifecycle roles of event-relay (step 3.3 §5, L13 expiry sweeper, L14 lifecycle check;
 * `.env.example` section "Message lifecycle (step 3.3)"). Deadlines in hours, 0 = never expire
 * the state.
 */
export const lifecycleConfigShape = {
  LIFECYCLE_EXPIRY_ENABLED: flag.default(true),
  LIFECYCLE_EXPIRY_INTERVAL_MS: int(1000, 3_600_000).default(60_000),
  LIFECYCLE_EXPIRY_SHARDS: int(1, 64).default(4),
  LIFECYCLE_EXPIRY_MAX_HELD_SHARDS: int(1, 64).default(4),
  LIFECYCLE_EXPIRY_BATCH_SIZE: int(1, 5000).default(200),
  LIFECYCLE_EXPIRY_LOOKBACK_DAYS: int(1, 400).default(186),
  LIFECYCLE_TX_TIMEOUT_MS: int(1000, 60_000).default(5000),
  LIFECYCLE_DEADLINE_PERSISTED_HOURS: deadline(72),
  LIFECYCLE_DEADLINE_SCANNING_HOURS: deadline(24),
  LIFECYCLE_DEADLINE_SCANNED_HOURS: deadline(24),
  LIFECYCLE_DEADLINE_SCAN_FAILED_HOURS: deadline(72),
  LIFECYCLE_DEADLINE_POLICY_EVALUATED_HOURS: deadline(24),
  LIFECYCLE_DEADLINE_APPROVED_HOURS: deadline(24),
  LIFECYCLE_DEADLINE_QUARANTINED_HOURS: deadline(2160),
  LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: deadline(336),
  LIFECYCLE_DEADLINE_DELIVERY_PENDING_HOURS: deadline(168),
  LIFECYCLE_DEADLINE_DELIVERY_RETRY_HOURS: deadline(168),
  LIFECYCLE_CHECK_ENABLED: flag.default(true),
  LIFECYCLE_CHECK_INTERVAL_MS: int(1000, 3_600_000).default(60_000),
  LIFECYCLE_CHECK_AFTER_SECONDS: int(300, 86_400).default(900),
  LIFECYCLE_CHECK_BATCH_SIZE: int(1, 5000).default(500),
  LIFECYCLE_CHECK_LOOKBACK_HOURS: int(1, 4464).default(192),
};

/** Cross-field rules of the lifecycle keys (step 3.3 §5). Errors name keys, never values. */
export function validateLifecycleConfig(
  cfg: Record<DeadlineKey, number> & {
    LIFECYCLE_EXPIRY_SHARDS: number;
    LIFECYCLE_EXPIRY_MAX_HELD_SHARDS: number;
    LIFECYCLE_EXPIRY_LOOKBACK_DAYS: number;
    LIFECYCLE_CHECK_AFTER_SECONDS: number;
    LIFECYCLE_CHECK_LOOKBACK_HOURS: number;
  },
  ctx: z.RefinementCtx,
): void {
  // The check reads states changed between LOOKBACK and AFTER ago: an empty window checks nothing.
  if (cfg.LIFECYCLE_CHECK_LOOKBACK_HOURS * 3600 <= cfg.LIFECYCLE_CHECK_AFTER_SECONDS) {
    ctx.addIssue({
      code: 'custom',
      path: ['LIFECYCLE_CHECK_LOOKBACK_HOURS'],
      message: 'must exceed LIFECYCLE_CHECK_AFTER_SECONDS (in hours)',
    });
  }
  if (cfg.LIFECYCLE_EXPIRY_MAX_HELD_SHARDS > cfg.LIFECYCLE_EXPIRY_SHARDS) {
    ctx.addIssue({
      code: 'custom',
      path: ['LIFECYCLE_EXPIRY_MAX_HELD_SHARDS'],
      message: 'must be at most LIFECYCLE_EXPIRY_SHARDS',
    });
  }
  for (const key of [
    LIFECYCLE_DEADLINE_KEYS.delivery_pending,
    LIFECYCLE_DEADLINE_KEYS.delivery_retry,
  ]) {
    const hours = cfg[key];
    if (hours > 0 && hours <= POSTFIX_QUEUE_LIFETIME_HOURS) {
      ctx.addIssue({
        code: 'custom',
        path: [key],
        message: `must be 0 or above ${POSTFIX_QUEUE_LIFETIME_HOURS} (Postfix maximal_queue_lifetime)`,
      });
    }
  }
  for (const key of Object.values(LIFECYCLE_DEADLINE_KEYS)) {
    if (cfg[key] > cfg.LIFECYCLE_EXPIRY_LOOKBACK_DAYS * 24) {
      ctx.addIssue({
        code: 'custom',
        path: [key],
        message: 'must not exceed LIFECYCLE_EXPIRY_LOOKBACK_DAYS (in hours)',
      });
    }
  }
}

/**
 * event-relay configuration (step 3.2 §6, `.env.example` section "Event relay (step 3.2)"; step
 * 3.3 §5, section "Message lifecycle (step 3.3)"). Bounds per key here, cross-field rules in
 * `validateRelayConfig` and `validateLifecycleConfig`. Errors name keys, never values.
 */
export const relayConfigShape = {
  /** Comma-separated amqp(s) URLs of the publish-only user `eg-relay` (cluster nodes). */
  RABBITMQ_RELAY_URL: amqpUrlListSchema,

  // Roles.
  RELAY_ENABLED: flag.default(true),
  RECONCILE_ENABLED: flag.default(true),

  // Relay (Q11).
  RELAY_SHARDS: int(1, 64).default(4),
  RELAY_MAX_HELD_SHARDS: int(1, 64).default(4),
  RELAY_BATCH_SIZE: int(1, 1000).default(200),
  RELAY_SCAN_LIMIT: int(1, 10_000).default(1000),
  RELAY_POLL_INTERVAL_MS: int(50, 60_000).default(250),
  RELAY_CONFIRM_TIMEOUT_MS: int(1000, 120_000).default(15_000),
  RELAY_BROKER_BACKOFF_BASE_MS: int(10, 600_000).default(500),
  RELAY_BROKER_BACKOFF_MAX_MS: int(10, 600_000).default(30_000),
  RELAY_ROW_BACKOFF_BASE_MS: int(10, 86_400_000).default(1000),
  RELAY_ROW_BACKOFF_MAX_MS: int(10, 86_400_000).default(300_000),
  RELAY_MAX_ATTEMPTS: int(1, 100).default(10),
  RELAY_MAX_MESSAGE_BYTES: int(4096, 262_144).default(131_072),

  // Reconciler (Q12).
  RECONCILE_INTERVAL_MS: int(1000, 3_600_000).default(60_000),
  RECONCILE_UNCONSUMED_AFTER_SECONDS: int(MIN_UNCONSUMED_AFTER_SECONDS, 518_400).default(900),
  /** 0 = detect only (every unconsumed row is reported as exhausted). */
  RECONCILE_MAX_REDRIVES: int(0, 20).default(3),
  RECONCILE_LOOKBACK_HOURS: int(1, MAX_LOOKBACK_HOURS).default(72),
  RECONCILE_BATCH_SIZE: int(1, 10_000).default(1000),
  RECONCILE_QUEUES: reconcileQueuesSchema.default(['email.received', 'email.delivery.pending']),
  RECONCILE_START_POSITION: z.enum(['oldest', 'latest']).default('oldest'),

  // Message lifecycle (step 3.3).
  ...lifecycleConfigShape,
};

/** Cross-field rules. */
export function validateRelayConfig(
  cfg: {
    RELAY_BATCH_SIZE: number;
    RELAY_SCAN_LIMIT: number;
    RELAY_BROKER_BACKOFF_BASE_MS: number;
    RELAY_BROKER_BACKOFF_MAX_MS: number;
    RELAY_ROW_BACKOFF_BASE_MS: number;
    RELAY_ROW_BACKOFF_MAX_MS: number;
    RECONCILE_UNCONSUMED_AFTER_SECONDS: number;
    RECONCILE_LOOKBACK_HOURS: number;
    RECONCILE_QUEUES: readonly string[];
    RECONCILE_ENABLED: boolean;
  },
  ctx: z.RefinementCtx,
): void {
  if (cfg.RELAY_SCAN_LIMIT < cfg.RELAY_BATCH_SIZE) {
    ctx.addIssue({
      code: 'custom',
      path: ['RELAY_SCAN_LIMIT'],
      message: 'must be at least RELAY_BATCH_SIZE',
    });
  }
  if (cfg.RELAY_BROKER_BACKOFF_MAX_MS < cfg.RELAY_BROKER_BACKOFF_BASE_MS) {
    ctx.addIssue({
      code: 'custom',
      path: ['RELAY_BROKER_BACKOFF_MAX_MS'],
      message: 'must be at least RELAY_BROKER_BACKOFF_BASE_MS',
    });
  }
  if (cfg.RELAY_ROW_BACKOFF_MAX_MS < cfg.RELAY_ROW_BACKOFF_BASE_MS) {
    ctx.addIssue({
      code: 'custom',
      path: ['RELAY_ROW_BACKOFF_MAX_MS'],
      message: 'must be at least RELAY_ROW_BACKOFF_BASE_MS',
    });
  }
  if (cfg.RECONCILE_UNCONSUMED_AFTER_SECONDS >= cfg.RECONCILE_LOOKBACK_HOURS * 3600) {
    ctx.addIssue({
      code: 'custom',
      path: ['RECONCILE_UNCONSUMED_AFTER_SECONDS'],
      message: 'must be below RECONCILE_LOOKBACK_HOURS (no row would ever be due)',
    });
  }
  if (cfg.RECONCILE_ENABLED && cfg.RECONCILE_QUEUES.length === 0) {
    ctx.addIssue({
      code: 'custom',
      path: ['RECONCILE_QUEUES'],
      message: 'must list at least one queue while RECONCILE_ENABLED=true',
    });
  }
}

const objectSchema = baseConfigSchema
  .extend(httpConfigSchema(3070).shape)
  .extend(databaseConfigSchema.shape)
  .extend(relayConfigShape);

export const configSchema = objectSchema.superRefine((cfg, ctx) => {
  validateRelayConfig(cfg, ctx);
  validateLifecycleConfig(cfg, ctx);
});

export type RelayConfig = z.infer<typeof configSchema>;

/**
 * Only the relay's own keys (and their `<KEY>_FILE` secret indirections) are handed to
 * `loadConfig`: the shared `.env` holds keys of other services, and a foreign `*_FILE` key would
 * otherwise be read as a secret file of this service (same defence as the workers).
 */
function ownEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const keys = new Set(Object.keys(objectSchema.shape));
  return Object.fromEntries(
    Object.entries(env).filter(
      ([key]) => keys.has(key) || (key.endsWith('_FILE') && keys.has(key.slice(0, -5))),
    ),
  );
}

export const loadRelayConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<RelayConfig> =>
  loadConfig(configSchema, ownEnv(env));
