import type { HandleOutcome } from '@email-gateway/common';
import type { MessageDirection, MessageParseStatus } from '@email-gateway/database';
import type { MimeLimitName, ParseFailureReason } from '@email-gateway/event-contracts';
import type { MessageIngestSourceValue } from '@email-gateway/message-lifecycle';
import type { MimeParseResult, MimeParseStats } from '@email-gateway/mime-parser';

/** The writer row of the message being parsed (the only source of ids, keys and the tenant). */
export interface MessageRecord {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  direction: MessageDirection;
  emlObjectKey: string;
  emlSha256: string;
  sizeBytes: number;
  /**
   * `email_messages.ingest_source` (step 8.6 D4, step API-1 D8); absent = `gateway`. A copy
   * (`journal_intake`, `mailbox_api`) never gets `parse_failed.v1`, and `parsed.v1` only when its
   * scan was requested (always for `mailbox_api`).
   */
  ingestSource?: MessageIngestSourceValue;
}

export interface ParseRowState {
  status: MessageParseStatus;
  attempts: number;
}

export type FinalParseStatus = Exclude<MessageParseStatus, 'parsing'>;

/** What the finalize transaction records (design M3.9). */
export interface FinalOutcome {
  status: FinalParseStatus;
  failureReason: ParseFailureReason | null;
  limitsExceeded: MimeLimitName[];
  defects: string[];
  /**
   * The parse whose headers, attachments, bodies, structure and subject are recorded; null when
   * nothing of the content is recorded (pre-checks, eml_missing, integrity_mismatch, max attempts).
   */
  result: MimeParseResult | null;
  /** Counters of the read (kept for an integrity mismatch too); null when nothing was read. */
  stats: MimeParseStats | null;
}

export interface FinalizeInput {
  consumer: string;
  /** The `mail.message.received.v1` envelope being handled. */
  event: { eventId: string; correlationId: string };
  message: MessageRecord;
  attempts: number;
  parserVersion: string;
  outcome: FinalOutcome;
  completedAt: Date;
  durationMs: number;
}

/**
 * What the parse commit did for a copy (step 8.6 D4, step API-1 D8): `scan_requested` wrote
 * `parsed.v1` (the scan stage runs and ends the message with E31/E32); `journaled` applied E30
 * (`intake_unscanned` or `intake_parse_failed`; for a copy whose scan was requested and whose
 * parse failed, also the `mail.message.copy_scanned.v1` row with `outcome = parse_failed`, never
 * `parse_failed.v1`); `transition_skipped` wrote no outbox row and found the message no longer
 * `persisted` (E30 stale or invalid).
 */
export type IntakeGateResult = 'scan_requested' | 'journaled' | 'transition_skipped';

export interface FinalizeResult {
  outcome: HandleOutcome;
  /** The new outbox event id (`handled` with an outbox row only). */
  outboxEventId?: string;
  /** Copies only (`journal_intake`, `mailbox_api`; step 8.6 D4, step API-1 D8). */
  intake?: IntakeGateResult;
  /** The `mail.message.copy_scanned.v1` outbox event id (a copy's parse failure, API-1 D8). */
  copyScannedEventId?: string;
}

export type MarkParsingResult = { kind: 'parsing'; attempts: number } | { kind: 'final' };

/** Writer-side persistence of the MIME ingestion stage (a fake implements it in unit tests). */
export interface MimeStore {
  /** True when the consumer's ledger already holds the event (M3.1). */
  isProcessed(consumer: string, eventId: string): Promise<boolean>;
  /** Records the event in the ledger with no other effect. */
  recordNoop(consumer: string, eventId: string): Promise<HandleOutcome>;
  /** The message of the envelope's organization, or null (M3.2). */
  loadMessage(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<MessageRecord | null>;
  loadParse(message: MessageRecord): Promise<ParseRowState | null>;
  /** none → parsing (attempts 1) or parsing → parsing (attempts + 1) (M3.4). */
  markParsing(
    message: MessageRecord,
    start: { eventId: string; parserVersion: string; startedAt: Date },
  ): Promise<MarkParsingResult>;
  /** Gives back the attempt of an infrastructure failure (best effort, M3.10). */
  decrementAttempts(message: MessageRecord): Promise<void>;
  /** The final transaction (M3.9); `duplicate` when another worker finalized first. */
  finalize(input: FinalizeInput): Promise<FinalizeResult>;
}
