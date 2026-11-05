import type { HandleOutcome } from '@email-gateway/common';
import type { MessageState } from '@email-gateway/message-lifecycle';
import type { AuthResults, EngineOutcome } from '@email-gateway/security-contracts';
import type { RoundAggregate } from './aggregate';
import type { MessageDirectionValue } from './engine';
import type { EngineSettingsSource } from './settings-resolver';
import type { SkipReason } from './scan-metrics';

/** The writer row of a message, as the scan stage needs it (S5 step 2, S9 envelope). */
export interface ScanMessageRecord {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  direction: MessageDirectionValue;
  emlObjectKey: string;
  sizeBytes: number;
  clientIp: string | null;
  clientHelo: string | null;
  clientName: string | null;
  envelopeFrom: string;
  mtaQueueId: string | null;
  /** Envelope recipients by `rcpt_seq`. */
  recipients: string[];
}

export type ScanKindValue = 'initial' | 'rescan';
export type ScanTrigger = 'parsed' | 'rescan';

/** One `email_scans` row (a round, S3). */
export interface ScanRound {
  scanId: bigint;
  receivedAt: Date;
  messageId: bigint;
  organizationId: bigint;
  round: number;
  scanKind: ScanKindValue;
  requiredEngines: string[];
  startedAt: Date;
  deadlineAt: Date;
}

export interface OpenRoundInput {
  message: ScanMessageRecord;
  round: number;
  scanKind: ScanKindValue;
  trigger: ScanTrigger;
  engine: string;
  eventId: string;
  correlationId: string;
  /** Snapshot for `email_scans.required_engines` (S4). */
  requiredEngines: string[];
  deadlineSeconds: number;
  now: Date;
}

export type OpenRoundResult =
  | {
      kind: 'open';
      round: ScanRound;
      /** This engine already has its final row in the round (go to the completion re-check). */
      finalExists: boolean;
      /** Non-final attempt rows of this engine in the round. */
      attempts: number;
      /** E3 was applied by this delivery. */
      opened: boolean;
    }
  | { kind: 'skip'; reason: SkipReason };

/** A non-final attempt row (S5 step 5, first branch). */
export interface AttemptInput {
  round: ScanRound;
  engine: string;
  attempt: number;
  outcome: 'timeout' | 'error';
  errorCode: string;
  reasonCode: string;
  durationMs: number;
  engineVersion: string | null;
  settingsVersion: string | null;
  completedAt: Date;
}

/** The final row of one engine (S5 step 5, second branch). */
export interface FinalRowInput {
  engine: string;
  attempt: number;
  outcome: EngineOutcome;
  errorCode: string | null;
  engineVersion: string | null;
  score: number | null;
  requiredScore: number | null;
  action: string | null;
  reasonCodes: string[];
  /** `{ signals[], auth?, rcptTruncated? }`: bounded, never content. */
  evidence: Record<string, unknown> | null;
  durationMs: number;
  settingsVersion: string | null;
  /** The `email_auth_results` row of an engine that reports authentication (Rspamd). */
  auth: AuthResults | null;
}

export interface CompletionContext {
  /** The triggering event (causation of the transition), null for the sweeper. */
  causationEventId: string | null;
  correlationId: string;
  now: Date;
}

export type CompletionResult =
  | { kind: 'not_complete' }
  | { kind: 'already_completed' }
  | {
      kind: 'completed';
      aggregate: RoundAggregate;
      round: ScanRound;
      /** applied → `scanned.v1` written; stale/invalid/not_found → superseded, no event. */
      transition: 'applied' | 'duplicate' | 'stale' | 'invalid' | 'not_found';
      scannedEventId: string | null;
    };

export interface FinalizeInput {
  consumer: string;
  eventId: string;
  round: ScanRound;
  /** Null: this engine's final already exists (completion re-check only). */
  final: FinalRowInput | null;
  completion: CompletionContext;
}

export type FinalizeResult =
  { kind: 'duplicate' } | { kind: 'handled'; inserted: boolean; completion: CompletionResult };

/** A running round past its deadline (S10). */
export interface SweepCandidate {
  scanId: bigint;
  receivedAt: Date;
  messageId: bigint;
  organizationId: bigint;
}

export interface SweepResult {
  /** Required engines that received a `deadline_exceeded` final row. */
  finalized: string[];
  completion: CompletionResult;
}

/** The writer side of the scan stage (a fake in unit tests, `ScanRepository` in production). */
export interface ScanStore extends EngineSettingsSource {
  isProcessed(consumer: string, eventId: string): Promise<boolean>;
  /** The ledger row alone (a delivery without effect). */
  recordNoop(consumer: string, eventId: string): Promise<HandleOutcome>;
  loadMessage(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<ScanMessageRecord | null>;
  openRound(input: OpenRoundInput): Promise<OpenRoundResult>;
  recordAttempt(input: AttemptInput): Promise<void>;
  finalize(input: FinalizeInput): Promise<FinalizeResult>;
  /** `organizationIds` restricts the pass (integration tests on the shared writer). */
  sweepCandidates(
    now: Date,
    lookbackHours: number,
    limit: number,
    organizationIds?: readonly bigint[],
  ): Promise<SweepCandidate[]>;
  sweepRound(candidate: SweepCandidate, now: Date): Promise<SweepResult>;
}

export type OpenDecision =
  | { action: 'open_e3' }
  | { action: 'open' }
  | { action: 'check_final' }
  | { action: 'skip'; reason: SkipReason };

/**
 * Whether a delivery may open (or join) its round (S5 step 3), from the message's lifecycle
 * under its row lock. Pure.
 */
export function decideOpen(
  current: { state: MessageState; round: number },
  round: number,
  trigger: ScanTrigger,
): OpenDecision {
  if (current.round > round) return { action: 'skip', reason: 'older_round' };
  if (current.round < round) return { action: 'skip', reason: `lifecycle_${current.state}` };
  if (current.state === 'persisted' && round === 0 && trigger === 'parsed') {
    return { action: 'open_e3' };
  }
  if (current.state === 'scanning') return { action: 'open' };
  if (current.state === 'scanned' || current.state === 'scan_failed') {
    return { action: 'check_final' };
  }
  return { action: 'skip', reason: `lifecycle_${current.state}` };
}
