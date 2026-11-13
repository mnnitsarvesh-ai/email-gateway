/**
 * Echo-checked reads and writes of the webhook-worker (step 6.2 §2.0 invariant 2, 6.1 D15): the
 * `read` label of `webhook_inconsistent_reads_total` (bounded enum, never a tenant id).
 */
export const WEBHOOK_READS = [
  'organization',
  'subscriptions',
  'notification_settings',
  'message',
  'message_identity',
  'recipients',
  'domain',
  'scan',
  'execution_log',
  'quarantine_entries',
  'release_logs',
  'sandbox_submission',
  'deliveries',
  'delivery_cas',
  'claim',
  'event',
  'replay',
  'alert_window',
] as const;
export type WebhookRead = (typeof WEBHOOK_READS)[number];

/**
 * A writer read returned rows that do not belong to the request (the Prisma wrong-read defect,
 * step 4.2 §6), or a required row is missing. Retryable: the transaction rolls back and the
 * source event is redelivered (fanout) or the delivery is left for the next tick (delivery role).
 * Carries the read name and a fixed check name only (no data).
 */
export class InconsistentReadError extends Error {
  override readonly name = 'InconsistentReadError';

  constructor(
    readonly read: WebhookRead,
    readonly check: string,
  ) {
    super(`inconsistent webhook ${read} read: ${check}`);
  }
}

/** Reports a failed echo check (metric) before throwing. */
export type InconsistencySink = (read: WebhookRead) => void;

/** Throws `InconsistentReadError` after counting it. */
export function wrongRead(sink: InconsistencySink, read: WebhookRead, check: string): never {
  sink(read);
  throw new InconsistentReadError(read, check);
}

/** Dead-letter code of a source event whose public payload fails the payload guard (W4). */
export const WEBHOOK_PAYLOAD_UNSAFE = 'webhook_payload_unsafe';
/** Dead-letter code of a source event whose public payload fails its strict schema. */
export const WEBHOOK_PAYLOAD_INVALID = 'webhook_payload_invalid';

/** Canonical decimal string of an id from a raw query (bigint, number or string). */
export const idOf = (value: bigint | number | string): bigint => BigInt(value);
