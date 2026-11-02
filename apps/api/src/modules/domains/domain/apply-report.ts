import type {
  DkimAlgorithm,
  DkimKeyStatus,
  DnsCheckOutcome,
  DnsRecordPurpose,
  DnsRecordStatus,
  DomainStatus,
  DomainVerificationStatus,
} from '@email-gateway/database';
import type { MxAnswer } from '../../../dns/dns-resolver';
import { DomainAuditAction, DomainStatusReason } from '../domains.constants';
import type { DomainCheckReport, RecordCheckResult } from '../engine/types';
import { allRecordsValid } from './readiness';
import { type Jitter, nextCheckAt, type ScheduleConfig } from './schedule';
import {
  CHECKED_STATUSES,
  type DomainLifecycleEvent,
  nextStatus,
  OWNED_STATUSES,
} from './state-machine';

/** What `planReportApplication` needs to know about the stored domain (locked row). */
export interface StoredDomainState {
  domain: { id: bigint; status: DomainStatus; checkFailures: number };
  /** The current (newest) verification row. */
  verification: {
    id: bigint;
    status: DomainVerificationStatus;
    attempts: number;
    expiresAt: Date;
  } | null;
  records: ReadonlyArray<{
    id: bigint;
    recordKey: string;
    purpose: DnsRecordPurpose;
    status: DnsRecordStatus;
    evidence: unknown;
  }>;
  dkimKeys: ReadonlyArray<{
    id: bigint;
    selector: string;
    algorithm: DkimAlgorithm;
    status: DkimKeyStatus;
  }>;
}

/** Ownership step of a check of a pending domain (D3, D4). */
export type OwnershipIntent = 'claim' | 'expire' | null;

export interface RecordUpdate {
  id: bigint;
  recordKey: string;
  data: {
    status?: DnsRecordStatus;
    statusChangedAt?: Date;
    observedValue?: string | null;
    expectedValue?: string;
    lastOutcome: DnsCheckOutcome;
    lastCheckedAt: Date;
    lastError: string | null;
    evidence: Record<string, unknown>;
  };
}

export interface VerificationUpdate {
  id: bigint;
  data: {
    attempts: number;
    lastCheckedAt: Date;
    lastOutcome: DnsCheckOutcome | null;
    lastError: string | null;
    evidence: Record<string, unknown> | null;
    nextCheckAt: Date | null;
    status?: DomainVerificationStatus;
    verifiedAt?: Date;
  };
}

export interface DomainUpdate {
  lastCheckedAt: Date;
  checkFailures: number;
  nextCheckAt: Date | null;
  status?: DomainStatus;
  statusReason?: string | null;
  statusChangedAt?: Date;
  verifiedAt?: Date;
}

/** A lifecycle transition of the checked domain: one audit row and one event (D15). */
export interface PlannedTransition {
  event: DomainLifecycleEvent;
  from: DomainStatus;
  to: DomainStatus;
  reason: string | null;
  auditAction: DomainAuditAction;
}

export interface PlannedKeyChange {
  keyId: bigint;
  selector: string;
  algorithm: DkimAlgorithm;
  to: 'active' | 'rotating';
  /** `rotating` only: end of the overlap. */
  retireAfter?: Date;
}

/** `domain.dkim_key_activated` audit of one activated key. */
export interface PlannedKeyActivation {
  selector: string;
  algorithm: DkimAlgorithm;
  previousSelector: string | null;
}

export type CheckOutcomeSummary = 'verified' | 'failed' | 'indeterminate' | 'checked';

export interface ApplyPlan {
  records: RecordUpdate[];
  verification: VerificationUpdate | null;
  domain: DomainUpdate;
  transition: PlannedTransition | null;
  keyChanges: PlannedKeyChange[];
  keyActivations: PlannedKeyActivation[];
  /** The ownership TXT of an owned domain went from valid to missing/invalid (audit only). */
  ownershipRecordMissing: { outcome: DnsCheckOutcome } | null;
  /** Observed MX hosts to store; null when the primary MX result was indeterminate. */
  mxObservations: MxAnswer[] | null;
  outcome: CheckOutcomeSummary;
}

export interface ApplyContext {
  now: Date;
  /** Result of the ownership step when `ownershipIntent` returned `claim`. */
  ownership?: 'won' | 'lost';
  schedule: ScheduleConfig;
  overlapDays: number;
  jitter?: Jitter;
}

const MAX_ERROR_LENGTH = 512;
const DAY_MS = 86_400_000;

function verificationResult(report: DomainCheckReport): RecordCheckResult | undefined {
  return report.records.find((r) => r.recordKey === 'verification');
}

/**
 * The ownership step of a check (D3, D4): a pending domain whose ownership TXT was found
 * (definitive `valid`) claims the name; otherwise, once the verification has expired, the
 * claim fails (time-based: an indeterminate result at expiry does not extend it). Owned
 * domains never change status because of DNS.
 */
export function ownershipIntent(
  state: StoredDomainState,
  report: DomainCheckReport,
  now: Date,
): OwnershipIntent {
  if (state.domain.status !== 'pending_verification') return null;
  if (verificationResult(report)?.outcome === 'valid') return 'claim';
  if (state.verification && now.getTime() >= state.verification.expiresAt.getTime()) {
    return 'expire';
  }
  return null;
}

/** False when the report must not be applied: the domain left the checked statuses. */
export function reportApplies(status: DomainStatus): boolean {
  return CHECKED_STATUSES.has(status);
}

/** `<reason>: <detail>` of an indeterminate result, from the engine's evidence. */
export function indeterminateError(evidence: Record<string, unknown>): string {
  const query = evidence.query as { reason?: unknown; detail?: unknown } | undefined;
  const reason = typeof query?.reason === 'string' ? query.reason : 'other';
  const detail = typeof query?.detail === 'string' ? query.detail : 'no definitive DNS answer';
  return `${reason}: ${detail}`.slice(0, MAX_ERROR_LENGTH);
}

/** Warnings stored in a record's evidence (D10). */
export function warningsOf(evidence: unknown): string[] {
  if (evidence === null || typeof evidence !== 'object') return [];
  const warnings = (evidence as { warnings?: unknown }).warnings;
  return Array.isArray(warnings) ? warnings.filter((w): w is string => typeof w === 'string') : [];
}

function evidenceFor(
  result: RecordCheckResult,
  report: DomainCheckReport,
  warnings: string[],
): Record<string, unknown> {
  const evidence: Record<string, unknown> = { ...result.evidence, warnings };
  // The status view reads these back (§4): per-upstream MX outcomes and the DMARC next step.
  if (result.recordKey.startsWith('mx:')) evidence.propagationOutcomes = report.mx.propagation;
  if (result.recordKey === 'dmarc') {
    evidence.stage = report.dmarc.stage;
    evidence.partial = report.dmarc.partial;
    evidence.nextStep = report.dmarc.nextStep;
  }
  return evidence;
}

function transitionFor(
  from: DomainStatus,
  event: DomainLifecycleEvent,
  reason: string | null,
  auditAction: DomainAuditAction,
): PlannedTransition {
  return { event, from, to: nextStatus(from, event), reason, auditAction };
}

/**
 * Plans the persistence of one check report (D10) against the locked, stored state:
 *
 * - definitive record outcomes set `status` (and `status_changed_at` when it changes), the
 *   observed value, the current recommendation (`expected_value`), the outcome, evidence and
 *   warnings; **indeterminate** outcomes only record the attempt (`last_outcome`,
 *   `last_checked_at`, `last_error`, evidence) and never change a status;
 * - the lifecycle transition that follows (ownership won/lost, expiry);
 * - DKIM key activation (pending key with a valid record on an owned domain → active; the
 *   previous active key of that algorithm → rotating until the overlap ends, D9);
 * - the verification row, the domain's check counters and its next check (D11).
 *
 * Pure: the caller performs the writes, audits and events in one transaction.
 */
export function planReportApplication(
  state: StoredDomainState,
  report: DomainCheckReport,
  context: ApplyContext,
): ApplyPlan {
  const { now } = context;
  const intent = ownershipIntent(state, report, now);
  if (intent === 'claim' && context.ownership === undefined) {
    throw new Error('planReportApplication: the ownership step must run before planning a claim');
  }

  // Records.
  const results = new Map(report.records.map((r) => [r.recordKey, r]));
  const effective = new Map<string, DnsRecordStatus>();
  const records: RecordUpdate[] = [];
  let ownershipRecordMissing: ApplyPlan['ownershipRecordMissing'] = null;
  for (const row of state.records) {
    const result = results.get(row.recordKey);
    if (!result) {
      effective.set(row.recordKey, row.status);
      continue;
    }
    if (result.outcome === 'indeterminate') {
      effective.set(row.recordKey, row.status);
      records.push({
        id: row.id,
        recordKey: row.recordKey,
        data: {
          lastOutcome: 'indeterminate',
          lastCheckedAt: now,
          lastError: indeterminateError(result.evidence),
          evidence: evidenceFor(result, report, warningsOf(row.evidence)),
        },
      });
      continue;
    }
    const status: DnsRecordStatus = result.outcome;
    effective.set(row.recordKey, status);
    if (row.recordKey === 'verification' && row.status === 'valid' && status !== 'valid') {
      ownershipRecordMissing = { outcome: result.outcome };
    }
    records.push({
      id: row.id,
      recordKey: row.recordKey,
      data: {
        status,
        ...(status !== row.status && { statusChangedAt: now }),
        observedValue: result.observedValue,
        expectedValue: result.expectedValue,
        lastOutcome: result.outcome,
        lastCheckedAt: now,
        lastError: null,
        evidence: evidenceFor(result, report, result.warnings),
      },
    });
  }

  // Lifecycle.
  const from = state.domain.status;
  let transition: PlannedTransition | null = null;
  if (intent === 'claim') {
    transition =
      context.ownership === 'won'
        ? transitionFor(from, 'ownership_verified', null, DomainAuditAction.Verified)
        : transitionFor(
            from,
            'claim_superseded',
            DomainStatusReason.ClaimedByAnotherOrganization,
            DomainAuditAction.ClaimSuperseded,
          );
  } else if (intent === 'expire') {
    transition = transitionFor(
      from,
      'verification_expired',
      DomainStatusReason.VerificationExpired,
      DomainAuditAction.VerificationExpired,
    );
  }
  const status = transition?.to ?? from;
  if (!OWNED_STATUSES.has(status)) ownershipRecordMissing = null;

  // DKIM key activation (D9): only once the domain is owned.
  const keyChanges: PlannedKeyChange[] = [];
  const keyActivations: PlannedKeyActivation[] = [];
  if (OWNED_STATUSES.has(status)) {
    const keys = [...state.dkimKeys]
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .map((key) => ({ ...key }));
    const retireAfter = new Date(now.getTime() + context.overlapDays * DAY_MS);
    for (const key of keys) {
      if (key.status !== 'pending' || effective.get(`dkim:${key.selector}`) !== 'valid') continue;
      let previousSelector: string | null = null;
      for (const other of keys) {
        if (other !== key && other.algorithm === key.algorithm && other.status === 'active') {
          other.status = 'rotating';
          previousSelector = other.selector;
          keyChanges.push({
            keyId: other.id,
            selector: other.selector,
            algorithm: other.algorithm,
            to: 'rotating',
            retireAfter,
          });
        }
      }
      key.status = 'active';
      keyChanges.push({
        keyId: key.id,
        selector: key.selector,
        algorithm: key.algorithm,
        to: 'active',
      });
      keyActivations.push({ selector: key.selector, algorithm: key.algorithm, previousSelector });
    }
  }

  // Counters and schedule.
  const checkFailures = report.indeterminate ? state.domain.checkFailures + 1 : 0;
  const attempts = (state.verification?.attempts ?? 0) + 1;
  const next = nextCheckAt(
    {
      status,
      checkFailures,
      attempts,
      allRecordsValid: allRecordsValid([...effective.values()]),
      verificationExpiresAt: state.verification?.expiresAt ?? null,
      now,
    },
    context.schedule,
    context.jitter,
  );

  const domain: DomainUpdate = { lastCheckedAt: now, checkFailures, nextCheckAt: next };
  if (transition) {
    domain.status = transition.to;
    domain.statusReason = transition.reason;
    domain.statusChangedAt = now;
    if (transition.to === 'verified') domain.verifiedAt = now;
  }

  let verification: VerificationUpdate | null = null;
  if (state.verification) {
    const result = verificationResult(report);
    verification = {
      id: state.verification.id,
      data: {
        attempts,
        lastCheckedAt: now,
        lastOutcome: result?.outcome ?? null,
        lastError: result?.outcome === 'indeterminate' ? indeterminateError(result.evidence) : null,
        evidence: result ? { ...result.evidence } : null,
        nextCheckAt: next,
      },
    };
    if (transition?.event === 'ownership_verified') {
      verification.data.status = 'verified';
      verification.data.verifiedAt = now;
    } else if (transition?.event === 'claim_superseded') {
      verification.data.status = 'failed';
    } else if (transition?.event === 'verification_expired') {
      verification.data.status = 'expired';
    }
  }

  let outcome: CheckOutcomeSummary = report.indeterminate ? 'indeterminate' : 'checked';
  if (transition?.to === 'verified') outcome = 'verified';
  else if (transition?.to === 'failed') outcome = 'failed';

  return {
    records,
    verification,
    domain,
    transition,
    keyChanges,
    keyActivations,
    ownershipRecordMissing,
    mxObservations: report.mx.observed,
    outcome,
  };
}
