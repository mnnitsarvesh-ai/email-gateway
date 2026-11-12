import { z } from 'zod';
import type {
  MessageState,
  QuarantineDirection,
  QuarantineState,
  RecipientState,
} from './vocabulary';

/**
 * Delete subject to retention and legal hold (step 5.3 Q17). `decideObjectDisposal` is evaluated
 * on writer facts by the delete route (logical delete allowed or refused) and again by the
 * sweeper at purge time (purge now or keep). Step 8.1 owns legal-hold and retention criteria;
 * 5.3 reads them conservatively: a legal hold whose criteria it cannot parse matches everything,
 * and the archive retention is the maximum of the organization's policies (criteria ignored).
 */

/** The strict criteria subset 5.3 understands (anything else: match everything). */
export const legalHoldCriteriaSchema = z.strictObject({
  custodians: z.array(z.string().min(1).max(320)).max(10_000).optional(),
  from: z.union([z.iso.date(), z.iso.datetime({ offset: true })]).optional(),
  to: z.union([z.iso.date(), z.iso.datetime({ offset: true })]).optional(),
});
export type LegalHoldCriteria = z.infer<typeof legalHoldCriteriaSchema>;

export interface DisposalMessageFacts {
  receivedAt: Date;
  direction: QuarantineDirection;
  /** Envelope sender and header From (lower-cased by the check). */
  senderAddresses: readonly string[];
  recipientAddresses: readonly string[];
}

/** One active `archive_legal_holds` row (`status = active`) of the organization. */
export interface LegalHoldFacts {
  id: string;
  criteria: unknown;
}

export interface ObjectDisposalInput {
  now: Date;
  message: DisposalMessageFacts & { state?: MessageState };
  legalHolds: readonly LegalHoldFacts[];
  /** `archive_settings` (null = no row). */
  archive: { enabled: boolean; scope: 'all' | 'inbound' | 'outbound' | 'internal' } | null;
  /** `retention_days` of the organization's `archive_retention_policies`. */
  retentionPolicyDays: readonly number[];
  /** `email_archives` rows of the message. */
  emailArchives: ReadonlyArray<{ retainUntil: Date | null; legalHold: boolean }>;
  /** An evaluation of the message requested ARCHIVE. */
  archiveRequested: boolean;
  /** Every entry of the message, **after** the action being decided (the deleted one as `deleted`). */
  entries: ReadonlyArray<{ state: QuarantineState }>;
  /** `email_recipients.status` of every recipient of the message. */
  recipientStatuses: readonly RecipientState[];
}

export type DisposalRetainReason = 'legal_hold' | 'retention' | 'archive_pending' | 'shared';

export interface ObjectDisposal {
  /** The logical delete of an entry (`409` when refused). */
  deleteAllowed: boolean;
  refusal: {
    code: 'quarantine_legal_hold' | 'quarantine_retention_active';
    retainUntil: Date | null;
    legalHoldId: string | null;
  } | null;
  /** What happens to the stored objects now. */
  purge: 'now' | 'retained';
  retainedReason: DisposalRetainReason | null;
  /** When a retained purge should be re-evaluated (null = no known date). */
  purgeAfter: Date | null;
}

const DAY_MS = 86_400_000;

function bound(value: string, end: boolean): number {
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const start = Date.parse(`${value}T00:00:00.000Z`);
    return end ? start + DAY_MS - 1 : start;
  }
  return Date.parse(value);
}

/**
 * Whether one legal hold covers the message: no custodians or a sender/recipient is a custodian,
 * and `received_at` within `[from, to]` (date-only bounds are whole UTC days). Criteria that are
 * not the strict subset match everything (fail-safe).
 */
export function legalHoldMatches(criteria: unknown, message: DisposalMessageFacts): boolean {
  if (criteria === null || criteria === undefined) return true;
  const parsed = legalHoldCriteriaSchema.safeParse(criteria);
  if (!parsed.success) return true;
  const c = parsed.data;
  const t = message.receivedAt.getTime();
  if (c.from !== undefined) {
    const from = bound(c.from, false);
    if (!Number.isFinite(from)) return true;
    if (t < from) return false;
  }
  if (c.to !== undefined) {
    const to = bound(c.to, true);
    if (!Number.isFinite(to)) return true;
    if (t > to) return false;
  }
  if (c.custodians !== undefined && c.custodians.length > 0) {
    const custodians = new Set(c.custodians.map((x) => x.trim().toLowerCase()));
    const parties = [...message.senderAddresses, ...message.recipientAddresses].map((x) =>
      x.trim().toLowerCase(),
    );
    if (!parties.some((p) => custodians.has(p))) return false;
  }
  return true;
}

const LIVE_RECIPIENT: readonly RecipientState[] = ['pending', 'deferred', 'delivered'];
const NON_TERMINAL: readonly QuarantineState[] = ['held', 'pending_approval', 'releasing'];

/** Q17 rules 1–4, in order. */
export function decideObjectDisposal(input: ObjectDisposalInput): ObjectDisposal {
  const now = input.now.getTime();
  // 1. Legal hold.
  const hold = input.legalHolds.find((h) => legalHoldMatches(h.criteria, input.message));
  if (hold) {
    return {
      deleteAllowed: false,
      refusal: { code: 'quarantine_legal_hold', retainUntil: null, legalHoldId: hold.id },
      purge: 'retained',
      retainedReason: 'legal_hold',
      purgeAfter: null,
    };
  }
  // 2. Retention: archive policies covering the direction, or the message's archive rows.
  let retainUntil: number | null = null;
  let indefinite = false;
  const a = input.archive;
  const days = input.retentionPolicyDays.filter((d) => Number.isFinite(d) && d > 0);
  if (a?.enabled && (a.scope === 'all' || a.scope === input.message.direction) && days.length > 0) {
    retainUntil = input.message.receivedAt.getTime() + Math.max(...days) * DAY_MS;
  }
  for (const row of input.emailArchives) {
    if (row.legalHold) indefinite = true;
    if (row.retainUntil !== null) {
      retainUntil = Math.max(retainUntil ?? 0, row.retainUntil.getTime());
    }
  }
  if (indefinite || (retainUntil !== null && retainUntil > now)) {
    return {
      deleteAllowed: false,
      refusal: {
        code: 'quarantine_retention_active',
        retainUntil: indefinite || retainUntil === null ? null : new Date(retainUntil),
        legalHoldId: null,
      },
      purge: 'retained',
      retainedReason: 'retention',
      purgeAfter: indefinite || retainUntil === null ? null : new Date(retainUntil),
    };
  }
  // 3. Archive pending: ARCHIVE requested and not archived yet (8.1 lifts the deferral).
  if (input.archiveRequested && input.emailArchives.length === 0) {
    return {
      deleteAllowed: true,
      refusal: null,
      purge: 'retained',
      retainedReason: 'archive_pending',
      purgeAfter: null,
    };
  }
  // 4. Shared object: every entry terminal and not released, no live recipient.
  const shared =
    input.entries.some((e) => NON_TERMINAL.includes(e.state) || e.state === 'released') ||
    input.recipientStatuses.some((s) => LIVE_RECIPIENT.includes(s));
  if (shared) {
    return {
      deleteAllowed: true,
      refusal: null,
      purge: 'retained',
      retainedReason: 'shared',
      purgeAfter: null,
    };
  }
  return {
    deleteAllowed: true,
    refusal: null,
    purge: 'now',
    retainedReason: null,
    purgeAfter: null,
  };
}
