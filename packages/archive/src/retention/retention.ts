import { archiveRetentionCriteriaSchema } from '../documents/criteria';
import type { NumericId } from '../ids';
import type {
  ArchiveCategory,
  MessageDirection,
  ObjectLockMode,
  RetentionExpiryAction,
} from '../vocabulary';
import { type LegalHoldFacts, legalHoldMatches, type LegalHoldRow } from '../holds/matcher';

/**
 * Retention selection and the expiry decision (A11, A13, ADR-0067). Pure: time is a parameter;
 * `daySeconds` is the day length (86 400, or `ARCHIVE_TEST_DAY_SECONDS` in local/ci tests).
 */

export const SECONDS_PER_DAY = 86_400;

export interface RetentionPolicyCandidate {
  /** Internal id (`archive_retention_policies.id`): the tie-breaker after `priority`. */
  id: NumericId;
  priority: number;
  /** `archive-retention/1` (unparsable criteria never match). */
  criteria: unknown;
  retentionDays: number;
  onExpiry: RetentionExpiryAction;
  /** Soft-deleted policies are never selected. */
  deletedAt?: Date | null;
}

/** Facts of a record (at capture) that retention criteria test. */
export interface RetentionRecordFacts {
  /** The message direction plus every recipient direction (NULL = unknown, ignored; 8.6 D3). */
  directions: readonly (MessageDirection | null)[];
  category: ArchiveCategory;
  sources: { journal: boolean; policy: boolean };
  policyRuleRef: string | null;
  /** Public ids of verified domains of an org-side party. */
  partyDomainIds: readonly string[];
  /** Public ids of departments with an org-side party as member. */
  departmentIds: readonly string[];
}

/** Whether `archive-retention/1` criteria match the record (every present criterion). */
export function retentionCriteriaMatch(criteria: unknown, facts: RetentionRecordFacts): boolean {
  const parsed = archiveRetentionCriteriaSchema.safeParse(criteria ?? {});
  if (!parsed.success) return false;
  const c = parsed.data;
  const any = <T>(wanted: readonly T[] | undefined, have: readonly T[]) =>
    wanted === undefined || wanted.some((w) => have.includes(w));
  const sources = [
    ...(facts.sources.journal ? (['journal'] as const) : []),
    ...(facts.sources.policy ? (['policy'] as const) : []),
  ];
  return (
    any(
      c.directions,
      facts.directions.filter((d): d is MessageDirection => d !== null),
    ) &&
    any(c.categories, [facts.category]) &&
    any(c.sources, sources) &&
    any(c.policyRuleRefs, facts.policyRuleRef === null ? [] : [facts.policyRuleRef]) &&
    any(c.domainIds, facts.partyDomainIds) &&
    any(c.departmentIds, facts.departmentIds)
  );
}

function idOrder(a: NumericId, b: NumericId): number {
  const x = BigInt(a);
  const y = BigInt(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

export type RetentionSelection<P extends RetentionPolicyCandidate> = {
  policy: P;
  matchedBy: 'criteria' | 'default';
} | null;

/**
 * Selection at capture (A11): live policies by `priority` ascending then id; the first whose
 * criteria match wins; else the default policy (`archive_settings.default_retention_policy_id`)
 * when it is live; null when neither exists (the capture then fails: settings require a default).
 */
export function selectRetentionPolicy<P extends RetentionPolicyCandidate>(
  policies: readonly P[],
  facts: RetentionRecordFacts,
  defaultPolicyId: NumericId | null,
): RetentionSelection<P> {
  const live = policies
    .filter((p) => !p.deletedAt)
    .slice()
    .sort((a, b) => a.priority - b.priority || idOrder(a.id, b.id));
  const hit = live.find((p) => retentionCriteriaMatch(p.criteria, facts));
  if (hit) return { policy: hit, matchedBy: 'criteria' };
  if (defaultPolicyId === null) return null;
  const fallback = live.find((p) => idOrder(p.id, defaultPolicyId) === 0);
  return fallback ? { policy: fallback, matchedBy: 'default' } : null;
}

/** `received_at + days` (UTC; the day length is `daySeconds`). */
export function computeRetainUntil(
  receivedAt: Date,
  days: number,
  daySeconds: number = SECONDS_PER_DAY,
): Date {
  if (!Number.isInteger(days) || days < 0)
    throw new RangeError('retention days must be an integer');
  if (!Number.isInteger(daySeconds) || daySeconds < 1 || daySeconds > SECONDS_PER_DAY) {
    throw new RangeError('day length must be 1 … 86 400 seconds');
  }
  return new Date(receivedAt.getTime() + days * daySeconds * 1000);
}

/** The policy as it is now (null = deleted or unknown). */
export interface CurrentRetentionPolicy {
  retentionDays: number;
  onExpiry: RetentionExpiryAction;
  /** False once soft-deleted. */
  live: boolean;
}

/**
 * Lazy, extend-only recomputation (A11): max(stored, `received_at` + the policy's current days
 * when the policy is live). Shortening a policy never shortens a record.
 */
export function effectiveRetainUntil(input: {
  storedRetainUntil: Date;
  receivedAt: Date;
  policy: CurrentRetentionPolicy | null;
  daySeconds?: number;
}): Date {
  const stored = input.storedRetainUntil.getTime();
  if (!input.policy?.live) return new Date(stored);
  const current = computeRetainUntil(
    input.receivedAt,
    input.policy.retentionDays,
    input.daySeconds,
  ).getTime();
  return new Date(Math.max(stored, current));
}

export type ExpiryOutcome = 'policy_extended' | 'held' | 'review' | 'disposed';

export interface ExpiryRecordFacts {
  receivedAt: Date;
  retainUntil: Date;
  expiryAction: RetentionExpiryAction;
  lockMode: ObjectLockMode;
  lockUntil: Date | null;
  status: 'active' | 'expiry_review';
}

export interface ExpiryDecisionInput {
  now: Date;
  /** `expiry` = the lifecycle pass; `manual_dispose` = `POST …/dispose` (re-runs rules 1–2). */
  mode: 'expiry' | 'manual_dispose';
  record: ExpiryRecordFacts;
  policy: CurrentRetentionPolicy | null;
  /** Active holds of the organization (`status = active`) with their criteria version. */
  holds: readonly LegalHoldRow[];
  /** Facts the hold criteria test (writer, at decision time). */
  holdFacts: LegalHoldFacts;
  holdExtensionDays: number;
  reviewExtensionDays: number;
  daySeconds?: number;
}

export interface ExpiryDecision {
  outcome: ExpiryOutcome;
  /** New `retain_until` (never earlier than the stored one). */
  retainUntil: Date;
  /**
   * Object Lock target: extend every object version to this date **before** updating the row
   * (null = no lock change: unlocked record, or the lock already reaches it).
   */
  lockUntil: Date | null;
  /** `held`: set `legal_hold = 1`. */
  legalHold: boolean;
  /** `held`: the first matching hold. */
  holdId: string | null;
  /** `review`: the record goes to `expiry_review`. */
  status: 'active' | 'expiry_review' | 'disposing';
}

/**
 * The expiry decision (A13), rules in order: 1. effective retention beyond now →
 * `policy_extended`; 2. a matching active hold → `held` (extended by `ARCHIVE_HOLD_EXTENSION_DAYS`);
 * 3. `expiry_action = review` (the live policy's current value, else the stored one) → `review`
 * (locked records extended by `ARCHIVE_REVIEW_EXTENSION_DAYS`); 4. otherwise `disposed`. A
 * manual disposal skips rule 3. Retention and locks only ever grow.
 */
export function decideExpiry(input: ExpiryDecisionInput): ExpiryDecision {
  const now = input.now.getTime();
  const rec = input.record;
  const dayMs = (input.daySeconds ?? SECONDS_PER_DAY) * 1000;
  const stored = rec.retainUntil.getTime();
  const locked = rec.lockMode !== 'none';
  const lockTarget = (until: number): Date | null =>
    locked && (rec.lockUntil === null || rec.lockUntil.getTime() < until) ? new Date(until) : null;
  // An object lock still running also keeps the record (its objects cannot be deleted yet).
  const effective = Math.max(
    effectiveRetainUntil({
      storedRetainUntil: rec.retainUntil,
      receivedAt: rec.receivedAt,
      policy: input.policy,
      daySeconds: input.daySeconds,
    }).getTime(),
    locked && rec.lockUntil !== null ? rec.lockUntil.getTime() : 0,
  );
  if (effective > now) {
    return {
      outcome: 'policy_extended',
      retainUntil: new Date(Math.max(stored, effective)),
      lockUntil: lockTarget(effective),
      legalHold: false,
      holdId: null,
      status: rec.status,
    };
  }
  const hold = input.holds.find((h) => legalHoldMatches(h.criteria, input.holdFacts, h));
  if (hold) {
    const until = Math.max(stored, now + input.holdExtensionDays * dayMs);
    return {
      outcome: 'held',
      retainUntil: new Date(until),
      lockUntil: lockTarget(until),
      legalHold: true,
      holdId: hold.id,
      status: rec.status,
    };
  }
  const action = input.policy?.live ? input.policy.onExpiry : rec.expiryAction;
  if (input.mode === 'expiry' && action === 'review') {
    const until = locked ? Math.max(stored, now + input.reviewExtensionDays * dayMs) : stored;
    return {
      outcome: 'review',
      retainUntil: new Date(until),
      lockUntil: lockTarget(until),
      legalHold: false,
      holdId: null,
      status: 'expiry_review',
    };
  }
  return {
    outcome: 'disposed',
    retainUntil: new Date(stored),
    lockUntil: null,
    legalHold: false,
    holdId: null,
    status: 'disposing',
  };
}
