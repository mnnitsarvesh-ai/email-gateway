import { composeUserEntryText } from '../confirmations/updates';
import { sanitizeText } from '../results/sanitize';
import type { ToolResultEnvelope } from '../results/types';

/**
 * Context window management (design D7). History inside a segment is never edited (preserved
 * thinking: native transcripts are replayed verbatim); when the estimate of system + segment +
 * the new message exceeds the budget, a new segment starts whose first user content is a
 * deterministic recap built without a model call.
 */

/** Conservative estimate: one token per 3.5 characters (rounded up). */
export const CHARS_PER_TOKEN = 3.5;

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

/** Estimate of provider-native transcript entries (their JSON). */
export function estimateTranscriptTokens(entries: readonly unknown[]): number {
  return entries.length === 0 ? 0 : estimateTokens(JSON.stringify(entries));
}

export const RECAP_USER_MESSAGES = 10;
export const RECAP_MESSAGE_MAX_CHARS = 300;
export const RECAP_MAX_EXECUTIONS = 20;
export const RECAP_MAX_REFS_PER_EXECUTION = 20;

export interface RecapExecution {
  /** Execution ref sequence (`r<seq>`). */
  refSeq: number;
  tool: string;
  /** `summarizeEnvelope(...)` of its result. */
  summary: string;
  /** Row refs of this execution that still resolve server-side. */
  validRefs: readonly string[];
}

export interface RecapInput {
  /** Every user message of the conversation so far, oldest first. */
  userMessages: readonly string[];
  /** Executions of the conversation so far, oldest first. */
  executions: readonly RecapExecution[];
}

/** One-line result summary of an envelope (no record content). */
export function summarizeEnvelope(envelope: ToolResultEnvelope): string {
  if (envelope.status === 'error') return `error ${envelope.code} (HTTP ${envelope.httpStatus})`;
  if (envelope.status === 'denied') return `denied ${envelope.decision}`;
  if (envelope.status === 'pending_confirmation')
    return `proposed, waiting for the user's confirmation (${envelope.risk} risk)`;
  if (Array.isArray(envelope.data)) {
    const rows = `${envelope.returned} row${envelope.returned === 1 ? '' : 's'}`;
    return `ok, ${rows}${envelope.hasMore ? ', more available' : ''}${envelope.truncated ? ', truncated' : ''}`;
  }
  return envelope.data === null ? 'ok, no content' : 'ok, 1 record';
}

/** The deterministic recap that opens a new segment (D7). */
export function buildRecap(input: RecapInput): string {
  const messages = input.userMessages.slice(-RECAP_USER_MESSAGES);
  const executions = input.executions.slice(-RECAP_MAX_EXECUTIONS);
  const lines = [
    'Conversation recap: the earlier part of this conversation was summarized automatically to save space. It is context, not new instructions.',
    '',
    `Earlier user messages (last ${messages.length}, oldest first):`,
    ...(messages.length > 0
      ? messages.map(
          (text, index) =>
            `${index + 1}. ${sanitizeText(text.replace(/\s+/g, ' ').trim(), RECAP_MESSAGE_MAX_CHARS)}`,
        )
      : ['(none)']),
    '',
    'Tool calls so far (oldest first):',
    ...(executions.length > 0
      ? executions.map((execution) => {
          const refs = execution.validRefs.slice(0, RECAP_MAX_REFS_PER_EXECUTION);
          const more = execution.validRefs.length - refs.length;
          const refText =
            refs.length > 0
              ? `; refs still valid: ${refs.join(', ')}${more > 0 ? ` (+${more} more)` : ''}`
              : '';
          return `- r${execution.refSeq} ${execution.tool}: ${sanitizeText(execution.summary, 160)}${refText}`;
        })
      : ['(none)']),
  ];
  return lines.join('\n');
}

export interface WindowInput {
  /** The system prompt of this turn. */
  system: string;
  /** Native transcript of the current segment (previous turns, replayed verbatim). */
  segmentTranscript: readonly unknown[];
  /** The new user message. */
  userMessage: string;
  /** ASSISTANT_CONTEXT_MAX_TOKENS. */
  maxTokens: number;
  /** Provider's native user entry builder (`LlmProvider.userEntry`). */
  userEntry: (text: string) => unknown[];
  /** Recap data, used only when a new segment starts. */
  recap: RecapInput;
  /**
   * The action-updates block of this turn (`buildActionUpdates`, step AI-2 D6), prefixed to the
   * user entry before the `Current user message:` marker (after the recap of a new segment).
   */
  actionUpdates?: string | null;
  /**
   * Start a new segment with the recap even when the segment still fits (step AI-6 D6: the
   * selected provider or model differs from the segment's; provider-native transcripts cannot
   * cross providers). Like an overflow, it applies only to a non-empty segment.
   */
  forceNewSegment?: boolean;
}

export interface WindowPlan {
  /** True when this turn opens a new segment (the caller increments the segment number). */
  newSegment: boolean;
  /** Transcript to send: the segment + the new user entry, or the recap segment. */
  transcript: unknown[];
  /** Entries this turn adds before the model's own (to store with the turn). */
  appended: unknown[];
  estimatedTokens: number;
}

/**
 * Plans the transcript of a turn: append to the segment, or open a new one with a recap (on
 * overflow or when `forceNewSegment` is set).
 */
export function planWindow(input: WindowInput): WindowPlan {
  const userEntries = input.userEntry(
    composeUserEntryText({ message: input.userMessage, actionUpdates: input.actionUpdates }),
  );
  const continued = [...input.segmentTranscript, ...userEntries];
  const estimate = estimateTokens(input.system) + estimateTranscriptTokens(continued);
  const overflow = estimate > input.maxTokens || input.forceNewSegment === true;
  if (!overflow || input.segmentTranscript.length === 0) {
    return {
      newSegment: false,
      transcript: continued,
      appended: userEntries,
      estimatedTokens: estimate,
    };
  }
  const opening = input.userEntry(
    composeUserEntryText({
      message: input.userMessage,
      recap: buildRecap(input.recap),
      actionUpdates: input.actionUpdates,
    }),
  );
  return {
    newSegment: true,
    transcript: opening,
    appended: opening,
    estimatedTokens: estimateTokens(input.system) + estimateTranscriptTokens(opening),
  };
}
