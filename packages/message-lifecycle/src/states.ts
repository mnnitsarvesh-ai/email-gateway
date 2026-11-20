import {
  ACTOR_ROLES,
  MESSAGE_STATES,
  type ActorRoleValue,
  type MessageStateValue,
} from '@email-gateway/event-contracts';

/**
 * The sixteen lifecycle states (step 3.3 L2, ADR-0025; `journaled` appended by step 8.6,
 * ADR-0087) and the actor roles (L3). The lists are
 * defined once in `@email-gateway/event-contracts` (events carry them) and re-exported here;
 * `states.test.ts` asserts that they equal the Prisma `MessageStatus` enum. `archived` and the
 * role `archive` are reserved since step 8.1 retired edge E25 (docs/plan/steps/
 * 23-journaling-archiving.md A25, ADR-0064): the append-only enum keeps the value, but no edge
 * produces it and the archive-worker never changes `email_messages.status`. `journaled` (step 8.6,
 * docs/plan/steps/27-journal-intake-and-archive-split.md D4) is the final state of a journal
 * intake message (`email_messages.ingest_source = journal_intake`): never expirable, never a
 * source of the rescan (E19), the partial release (E28) or the manual quarantine (E29), and
 * reachable only by a journal intake message (the transition service asserts it).
 */
export { ACTOR_ROLES, MESSAGE_STATES };

export type MessageState = MessageStateValue;
export type ActorRole = ActorRoleValue;

/**
 * Rank of each state (L2): a request whose target ranks at or below the current state and has no
 * edge is a late event (`stale/overtaken`, L4 step 5). Equal ranks are not ordered.
 */
export const STATE_RANK: Readonly<Record<MessageState, number>> = {
  received: 0,
  persisted: 1,
  scanning: 2,
  scanned: 3,
  scan_failed: 3,
  policy_evaluated: 4,
  approved: 5,
  quarantined: 5,
  held_for_review: 5,
  rejected: 8,
  delivery_pending: 6,
  delivery_retry: 6,
  delivered: 7,
  archived: 9,
  expired: 8,
  // Step 8.6: after every scan state (E30-E32 lead into it), like the other final states.
  journaled: 8,
};

/**
 * No automatic processing leaves these states (L2). `archived` is reserved (E25 retired, 8.1);
 * `journaled` (step 8.6) is final and no edge leaves it.
 */
export const FINAL_STATES: readonly MessageState[] = [
  'delivered',
  'rejected',
  'archived',
  'expired',
  'journaled',
];

/** States with a deadline: the sweeper (L13) moves them to `expired` (edge E26). */
export const EXPIRABLE_STATES: readonly MessageState[] = [
  'persisted',
  'scanning',
  'scanned',
  'scan_failed',
  'policy_evaluated',
  'approved',
  'quarantined',
  'held_for_review',
  'delivery_pending',
  'delivery_retry',
];

const STATE_SET: ReadonlySet<string> = new Set(MESSAGE_STATES);
const ROLE_SET: ReadonlySet<string> = new Set(ACTOR_ROLES);

export const isMessageState = (value: unknown): value is MessageState =>
  typeof value === 'string' && STATE_SET.has(value);

export const isActorRole = (value: unknown): value is ActorRole =>
  typeof value === 'string' && ROLE_SET.has(value);

export const isFinalState = (state: MessageState): boolean => FINAL_STATES.includes(state);
