import type { HandleOutcome } from '@email-gateway/common';
import type { MessageState } from '@email-gateway/message-lifecycle';
import {
  type AuthResults,
  engineCatalogEntry,
  type EngineOutcome,
} from '@email-gateway/security-contracts';
import type { RoundAggregate } from './aggregate';
import type { EngineChildRows, MessageDirectionValue } from './engine';
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
/**
 * What triggered a delivery: `parsed` / `rescan` open (or join) a round as stage-1 engines;
 * `stage` (step 4.4 B2, `mail.message.scan_stage_ready.v1`) runs a stage-2 engine in a round that
 * stage-1 engines opened.
 */
export type ScanTrigger = 'parsed' | 'rescan' | 'stage';

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
  /**
   * `email_scans.risk_profile_version_id` (step 5.1 R13): the organization's active risk profile
   * version when the round opened; null = the platform default. Completion scores with it.
   */
  riskProfileVersionId: bigint | null;
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
  /**
   * Trigger `stage` only (B2): the `email_scans.id` the stage event names. The round is never
   * created for a stage trigger; it must exist with this id.
   */
  scanId?: bigint;
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
  /**
   * Engine-specific child rows (step 4.2 A12: `attachment_scan_results`, `sandbox_submissions`
   * with their outbox rows), written after the final row in the same transaction, only when the
   * final row was inserted.
   */
  childRows?: EngineChildRows;
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
  | { kind: 'duplicate' }
  | {
      kind: 'handled';
      inserted: boolean;
      completion: CompletionResult;
      /**
       * Stage-2 engines whose `scan_stage_ready.v1` outbox row this transaction wrote (B2):
       * at most one per engine and round, written by the transaction that inserted the last
       * dependency final.
       */
      stageTriggers: string[];
    };

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
  // Only a parse result opens round 0 (E3). A stage trigger (B2) never opens a round: stage-1
  // engines opened it, so a `persisted` message has no round to run a stage-2 engine in.
  if (current.state === 'persisted' && round === 0 && trigger === 'parsed') {
    return { action: 'open_e3' };
  }
  if (current.state === 'scanning') return { action: 'open' };
  if (current.state === 'scanned' || current.state === 'scan_failed') {
    return { action: 'check_final' };
  }
  return { action: 'skip', reason: `lifecycle_${current.state}` };
}

/** A dependency final as `stageTriggersFor` needs it. */
export interface StageFinal {
  engine: string;
  outcome: string;
}

/** One `mail.message.scan_stage_ready.v1` to write (B2). */
export interface StageTrigger {
  engine: string;
  dependencies: Array<{ engine: string; outcome: string }>;
}

/**
 * The stage-2 engines a completion check must trigger (step 4.4 B2), pure and generic over the
 * catalog (it never names an engine): every engine `E` of the round's required set that declares
 * `dependsOn`, has no final row yet, and whose dependencies **within the required set** all have
 * final rows — but only when the final inserted by this transaction (`insertedEngine`) is one of
 * those dependencies. Finals of one round are serialized by the message row lock and read after
 * it, so exactly one transaction (the one inserting the last dependency final) gets a trigger.
 * `insertedEngine` is null for a completion re-check and for the deadline sweeper (never a
 * trigger). Dependencies outside the required set are ignored (the engine records them as
 * `not_in_round`); an engine none of whose dependencies is required is never triggered (the
 * configuration refuses that set-up).
 */
export function stageTriggersFor(
  requiredEngines: readonly string[],
  finals: readonly StageFinal[],
  insertedEngine: string | null,
): StageTrigger[] {
  if (insertedEngine === null) return [];
  const triggers: StageTrigger[] = [];
  for (const engine of requiredEngines) {
    const entry = engineCatalogEntry(engine);
    const deps = (entry?.dependsOn ?? []).filter((d) => requiredEngines.includes(d));
    if (deps.length === 0 || !deps.includes(insertedEngine as never)) continue;
    if (finals.some((f) => f.engine === engine)) continue;
    const dependencyFinals = deps.map((d) => finals.find((f) => f.engine === d));
    if (dependencyFinals.some((f) => f === undefined)) continue;
    triggers.push({
      engine,
      dependencies: dependencyFinals.map((f) => ({ engine: f!.engine, outcome: f!.outcome })),
    });
  }
  return triggers;
}
