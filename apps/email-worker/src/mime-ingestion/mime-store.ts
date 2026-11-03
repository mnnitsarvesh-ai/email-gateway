import type { HandleOutcome } from '@email-gateway/common';
import type { MessageDirection, MessageParseStatus } from '@email-gateway/database';
import type { MimeLimitName, ParseFailureReason } from '@email-gateway/event-contracts';
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

export interface FinalizeResult {
  outcome: HandleOutcome;
  /** The new outbox event id (`handled` only). */
  outboxEventId?: string;
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
