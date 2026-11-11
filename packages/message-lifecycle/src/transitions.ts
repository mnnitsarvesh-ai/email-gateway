import { EXPIRABLE_STATES, type ActorRole, type MessageState } from './states';

/**
 * Reason codes of the transition table (L3) plus the history-only codes no edge lists, so
 * `decideTransition` never accepts them: `lifecycle_backfill` (only the step 3.3 migration writes
 * it) and `dev_passthrough` (the retired E4/E27, step 5.2; rows written before stay readable).
 * Codes match `/^[a-z0-9_]{1,64}$/`.
 */
export const LIFECYCLE_REASON_CODES = [
  'smtp_accepted',
  'committed',
  'scan_started',
  'dev_passthrough',
  'parse_failed_fail_safe',
  'scan_complete',
  'scan_error',
  'scan_timeout',
  'eml_unavailable',
  'policy_decided',
  'scan_failed_fail_safe',
  'policy_deliver',
  'policy_tag',
  'policy_quarantine',
  'policy_hold',
  'policy_discard',
  'policy_reject',
  'quarantine_release',
  'review_release',
  'review_quarantined',
  'quarantine_deleted',
  'review_rejected',
  'admin_rescan',
  'signature_rescan',
  'delivery_planned',
  'delivery_deferred',
  'delivery_requeued',
  'delivery_complete',
  'delivery_partial',
  'delivery_failed',
  'archived',
  'deadline_exceeded',
  'lifecycle_backfill',
] as const;

export type LifecycleReasonCode = (typeof LIFECYCLE_REASON_CODES)[number];

const REASON_SET: ReadonlySet<string> = new Set(LIFECYCLE_REASON_CODES);

export const isLifecycleReasonCode = (value: unknown): value is LifecycleReasonCode =>
  typeof value === 'string' && REASON_SET.has(value);

/** One edge of the transition table (L3). */
export interface TransitionEdge {
  /** 'E1' … stable, used in tests and docs. */
  id: string;
  /** Source states; `null` = creation. */
  from: readonly (MessageState | null)[];
  to: MessageState;
  roles: readonly ActorRole[];
  reasons: readonly LifecycleReasonCode[];
  /**
   * Optional role/reason pairing (step 4.2 A13): when present, each listed reason may be used
   * only by the roles given for it (every reason of the edge is listed). Absent = any listed
   * role with any listed reason.
   */
  reasonRoles?: Readonly<Partial<Record<LifecycleReasonCode, readonly ActorRole[]>>>;
  /** Re-entry edge: lifecycle_round + 1 (rescan, release). Allowed even when from = to. */
  newRound?: true;
  /** Step that builds the producer; '3.3' = this step. */
  producedBy: string;
}

/**
 * The transition table (step 3.3 L3, edges E1–E26; step 4.1 S15 adds E27 and retires E4; step
 * 4.2 A13 gives E19 the scanner role with the reason signature_rescan; step 5.2 retires E27 and
 * gives E5, E8–E13 their producer, the policy-engine, ADR-0044), as data. Every allowed change of `email_messages.status` is one of these edges; everything else is
 * stale or invalid (L4). Retired ids are never reused.
 * At most one edge exists per `(from, to)` pair (`transitions.test.ts`).
 */
export const TRANSITIONS: readonly TransitionEdge[] = [
  {
    id: 'E1',
    from: [null],
    to: 'received',
    roles: ['ingestion'],
    reasons: ['smtp_accepted'],
    producedBy: '3.3',
  },
  {
    id: 'E2',
    from: ['received'],
    to: 'persisted',
    roles: ['ingestion'],
    reasons: ['committed'],
    producedBy: '3.3',
  },
  {
    id: 'E3',
    from: ['persisted'],
    to: 'scanning',
    roles: ['scanner'],
    reasons: ['scan_started'],
    producedBy: '4.1',
  },
  // E4 (`persisted → approved`, dev pass-through before scanning, step 3.3) is retired by step
  // 4.1 (S15): the pass-through approves after the scan (E27). The id is never reused.
  {
    id: 'E5',
    from: ['persisted'],
    to: 'policy_evaluated',
    roles: ['policy'],
    reasons: ['parse_failed_fail_safe'],
    producedBy: '5.2',
  },
  {
    id: 'E6',
    from: ['scanning'],
    to: 'scanned',
    roles: ['scanner'],
    reasons: ['scan_complete'],
    producedBy: '4.x',
  },
  {
    id: 'E7',
    from: ['scanning'],
    to: 'scan_failed',
    roles: ['scanner'],
    reasons: ['scan_error', 'scan_timeout', 'eml_unavailable'],
    producedBy: '4.x',
  },
  {
    id: 'E8',
    from: ['scanned'],
    to: 'policy_evaluated',
    roles: ['policy'],
    reasons: ['policy_decided'],
    producedBy: '5.2',
  },
  {
    id: 'E9',
    from: ['scan_failed'],
    to: 'policy_evaluated',
    roles: ['policy'],
    reasons: ['scan_failed_fail_safe'],
    producedBy: '5.2',
  },
  {
    id: 'E10',
    from: ['policy_evaluated'],
    to: 'approved',
    roles: ['policy'],
    reasons: ['policy_deliver', 'policy_tag'],
    producedBy: '5.2',
  },
  {
    id: 'E11',
    from: ['policy_evaluated'],
    to: 'quarantined',
    roles: ['policy'],
    reasons: ['policy_quarantine'],
    producedBy: '5.2',
  },
  {
    id: 'E12',
    from: ['policy_evaluated'],
    to: 'held_for_review',
    roles: ['policy'],
    reasons: ['policy_hold'],
    producedBy: '5.2',
  },
  {
    id: 'E13',
    from: ['policy_evaluated'],
    to: 'rejected',
    roles: ['policy'],
    reasons: ['policy_discard', 'policy_reject'],
    producedBy: '5.2',
  },
  {
    id: 'E14',
    from: ['quarantined'],
    to: 'approved',
    roles: ['operator', 'quarantine'],
    reasons: ['quarantine_release'],
    newRound: true,
    producedBy: '3.3',
  },
  {
    id: 'E15',
    from: ['held_for_review'],
    to: 'approved',
    roles: ['operator', 'quarantine'],
    reasons: ['review_release'],
    newRound: true,
    producedBy: '3.3',
  },
  {
    id: 'E16',
    from: ['held_for_review'],
    to: 'quarantined',
    roles: ['quarantine'],
    reasons: ['review_quarantined'],
    producedBy: '5.3',
  },
  {
    id: 'E17',
    from: ['quarantined'],
    to: 'rejected',
    roles: ['quarantine'],
    reasons: ['quarantine_deleted'],
    producedBy: '5.3',
  },
  {
    id: 'E18',
    from: ['held_for_review'],
    to: 'rejected',
    roles: ['quarantine'],
    reasons: ['review_rejected'],
    producedBy: '5.3',
  },
  {
    id: 'E19',
    from: [
      'scanning',
      'scanned',
      'scan_failed',
      'policy_evaluated',
      'quarantined',
      'held_for_review',
      'expired',
    ],
    to: 'scanning',
    // Step 4.2 A13 (ADR-0028 amends ADR-0025): the email-worker's rescan job runner re-scans
    // after signature updates as `scanner`; an operator rescan stays `admin_rescan`.
    roles: ['operator', 'scanner'],
    reasons: ['admin_rescan', 'signature_rescan'],
    reasonRoles: { admin_rescan: ['operator'], signature_rescan: ['scanner'] },
    newRound: true,
    producedBy: '3.3',
  },
  {
    id: 'E20',
    from: ['approved'],
    to: 'delivery_pending',
    roles: ['delivery'],
    reasons: ['delivery_planned'],
    producedBy: '3.3',
  },
  {
    id: 'E21',
    from: ['delivery_pending'],
    to: 'delivery_retry',
    roles: ['delivery', 'recovery'],
    reasons: ['delivery_deferred'],
    producedBy: '3.3',
  },
  {
    id: 'E22',
    from: ['delivery_retry'],
    to: 'delivery_pending',
    roles: ['delivery', 'recovery'],
    reasons: ['delivery_requeued'],
    producedBy: '3.3',
  },
  {
    id: 'E23',
    from: ['delivery_pending', 'delivery_retry'],
    to: 'delivered',
    roles: ['delivery', 'recovery'],
    reasons: ['delivery_complete', 'delivery_partial'],
    producedBy: '3.3',
  },
  {
    id: 'E24',
    from: ['delivery_pending', 'delivery_retry'],
    to: 'rejected',
    roles: ['delivery', 'recovery'],
    reasons: ['delivery_failed'],
    producedBy: '3.3',
  },
  {
    id: 'E25',
    from: ['delivered', 'rejected'],
    to: 'archived',
    roles: ['archive'],
    reasons: ['archived'],
    producedBy: '8.1',
  },
  {
    id: 'E26',
    from: EXPIRABLE_STATES,
    to: 'expired',
    roles: ['sweeper'],
    reasons: ['deadline_exceeded'],
    producedBy: '3.3',
  },
  // E27 (`scanned → approved`, the development pass-through after the scan, step 4.1 S15) is
  // retired by step 5.2 (ADR-0044): delivery is approved only by the policy engine (E8 → E10) and
  // the operator release (E14/E15). The id is never reused; `dev_passthrough` stays a valid actor
  // role and reason code for the history rows written before, but no edge accepts it.
];

/** The edge from `from` to `to` in `table`, if any (at most one exists per pair). */
export function findEdge(
  from: MessageState | null,
  to: MessageState,
  table: readonly TransitionEdge[] = TRANSITIONS,
): TransitionEdge | undefined {
  return table.find((edge) => edge.to === to && edge.from.includes(from));
}
