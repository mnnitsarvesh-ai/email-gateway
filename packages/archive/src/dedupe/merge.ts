import type { IngestSource, MessageDirection } from '../vocabulary';

/**
 * The merge decision of cross-source dedupe (step 8.6 D7, ADR-0088), pure. The caller found a
 * candidate record (same organization, `message_id_hash` and `header_fingerprint`, live, inside
 * the window) under the row lock of the key, and computed the incoming copy's body hash.
 *
 * Order:
 * 1. **scope**: merging needs at least one intake copy. An incoming gateway copy merges only into
 *    a record that has no gateway copy yet (`scope_gateway_gateway` otherwise: forwarding loops
 *    and resends through the gateway keep one record per message, as in 8.1);
 * 2. **inactive / outside window** (when the caller passes the facts): `record_inactive`,
 *    `outside_window`;
 * 2a. **copy consistency** (review fix: a header match alone is forgeable, every header input of
 *    the key is known to any recipient of the message). When the caller passes the facts:
 *    - `direction_mismatch`: the copy's `email_messages.direction` differs from the record's.
 *      Both are computed from trusted inputs (the gateway's listener path; the provider-proven
 *      journal envelope, D3), so an external recipient who resends an organization user's
 *      outbound or internal message through the gateway's inbound path never merges into it;
 *    - `order_mismatch`: an **inbound** gateway copy and a record whose copies are of the other
 *      source only, where the gateway copy was received more than `MERGE_ORDER_SKEW_MS` after
 *      the intake copy. Inbound mail passes the gateway before the mailbox provider journals it,
 *      so a later gateway copy is a resend (forged or not), never the same delivery;
 * 3. **merged copies**: a record holds at most `maxMergedCopies` merged copies
 *    (`ARCHIVE_MAX_MERGED_COPIES`, 8) → `merged_limit`;
 * 4. **same body** (the incoming body hash equals one of the record's stored bodies) → merge
 *    without content;
 * 5. **different body**: fewer than `maxContentVariants` stored variants
 *    (`ARCHIVE_MAX_CONTENT_VARIANTS`, 4; the primary EML is not a variant) → merge with a content
 *    variant, else `variant_limit`.
 *
 * Every `separate` outcome captures the copy as a record of its own (8.1 path).
 */

export interface MergeCandidate {
  /** `email_archives.direction` (the record's primary copy). */
  direction?: MessageDirection;
  /** `email_archives.received_at` (the record's primary copy). */
  receivedAt?: Date;
  /** `email_archives.source_gateway`. */
  hasGateway: boolean;
  /** `email_archives.source_journal_intake`. */
  hasIntake: boolean;
  /** Body hashes of the record's stored contents (primary and variants; dedupe rows). */
  bodySha256s: readonly string[];
  /** Stored content variants (excluding the primary EML). */
  contentVariants: number;
  /** `objects.merged` entries (`merged_count`). */
  mergedCopies: number;
  /** `email_archives.status` (only `active` records take merges). */
  status?: string;
  /** `archive_dedupe_keys.created_at` of the matched row. */
  keyCreatedAt?: Date;
}

export interface MergeIncoming {
  source: IngestSource;
  bodySha256: string;
  /** The copy's `email_messages.direction` (checked against the record's when both are known). */
  direction?: MessageDirection;
  /** The copy's `email_messages.received_at`. */
  receivedAt?: Date;
}

/**
 * Clock tolerance of the inbound order rule: the gateway and the intake listener stamp
 * `received_at` on different hosts.
 */
export const MERGE_ORDER_SKEW_MS = 300_000;

export interface MergeLimits {
  maxContentVariants: number;
  maxMergedCopies: number;
  /** `ARCHIVE_DEDUPE_WINDOW_HOURS` (checked with `now` and `keyCreatedAt` when given). */
  windowHours?: number;
}

export type MergeSeparateReason =
  | 'scope_gateway_gateway'
  | 'record_inactive'
  | 'outside_window'
  | 'direction_mismatch'
  | 'order_mismatch'
  | 'merged_limit'
  | 'variant_limit';

export type MergeDecision =
  | { action: 'merge'; content: 'none' }
  | { action: 'merge'; content: 'variant' }
  | { action: 'separate'; reason: MergeSeparateReason };

export interface DecideMergeInput {
  candidate: MergeCandidate;
  incoming: MergeIncoming;
  limits: MergeLimits;
  now?: Date;
}

/** Whether two copies are in the dedupe scope (at least one intake copy, D7). */
export function inMergeScope(
  candidate: Pick<MergeCandidate, 'hasGateway'>,
  incoming: IngestSource,
) {
  return incoming === 'journal_intake' || !candidate.hasGateway;
}

export function decideMerge(input: DecideMergeInput): MergeDecision {
  const { candidate, incoming, limits } = input;
  if (!inMergeScope(candidate, incoming.source)) {
    return { action: 'separate', reason: 'scope_gateway_gateway' };
  }
  if (candidate.status !== undefined && candidate.status !== 'active') {
    return { action: 'separate', reason: 'record_inactive' };
  }
  if (
    limits.windowHours !== undefined &&
    input.now !== undefined &&
    candidate.keyCreatedAt !== undefined &&
    input.now.getTime() - candidate.keyCreatedAt.getTime() > limits.windowHours * 3_600_000
  ) {
    return { action: 'separate', reason: 'outside_window' };
  }
  if (
    candidate.direction !== undefined &&
    incoming.direction !== undefined &&
    candidate.direction !== incoming.direction
  ) {
    return { action: 'separate', reason: 'direction_mismatch' };
  }
  if (violatesInboundOrder(candidate, incoming)) {
    return { action: 'separate', reason: 'order_mismatch' };
  }
  if (candidate.mergedCopies >= limits.maxMergedCopies) {
    return { action: 'separate', reason: 'merged_limit' };
  }
  const body = incoming.bodySha256.toLowerCase();
  if (candidate.bodySha256s.some((b) => b.toLowerCase() === body)) {
    return { action: 'merge', content: 'none' };
  }
  if (candidate.contentVariants >= limits.maxContentVariants) {
    return { action: 'separate', reason: 'variant_limit' };
  }
  return { action: 'merge', content: 'variant' };
}

/**
 * The inbound order rule (see `decideMerge`): only between a record of one source and a copy of
 * the other; the gateway copy must not be received later than the intake copy (± skew).
 */
function violatesInboundOrder(candidate: MergeCandidate, incoming: MergeIncoming): boolean {
  if (candidate.receivedAt === undefined || incoming.receivedAt === undefined) return false;
  const direction = incoming.direction ?? candidate.direction;
  if (direction !== 'inbound') return false;
  let gatewayAt: number;
  let intakeAt: number;
  if (incoming.source === 'gateway' && !candidate.hasGateway && candidate.hasIntake) {
    gatewayAt = incoming.receivedAt.getTime();
    intakeAt = candidate.receivedAt.getTime();
  } else if (incoming.source === 'journal_intake' && candidate.hasGateway && !candidate.hasIntake) {
    gatewayAt = candidate.receivedAt.getTime();
    intakeAt = incoming.receivedAt.getTime();
  } else {
    return false;
  }
  return gatewayAt > intakeAt + MERGE_ORDER_SKEW_MS;
}
