import type {
  AssistantCard,
  ConfirmationSummary,
  ConfirmationView,
} from '@email-gateway/assistant';
import type {
  ConversationView,
  ExecutionView,
  MessageView,
  TurnView,
} from '../dto/assistant.schemas';
import type { ConfirmationWithRefs } from '../repositories/confirmations.repository';
import type {
  ConversationRow,
  MessageRow,
  TurnRow,
} from '../repositories/conversations.repository';
import type { ExecutionWithRefs } from '../repositories/executions.repository';
import { refusalMessageOf } from './denials';
import { toolTitleOf } from './tool-catalog';

/** Row → response view mappers of the assistant routes (public ids only, ISO instants). */

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

export function conversationView(row: ConversationRow): ConversationView {
  return {
    id: row.publicId,
    title: row.title,
    status: row.status === 'archived' ? 'archived' : 'active',
    turnCount: row.turnCount,
    lastTurnAt: iso(row.lastTurnAt),
    purgeAfter: iso(row.purgeAfter),
    contentPurged: row.contentPurgedAt !== null,
    underPlatformOverride: row.platformOverrideId !== null,
    rowVersion: row.rowVersion,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function turnView(row: TurnRow, conversationPublicId: string): TurnView {
  return {
    id: row.publicId,
    conversationId: conversationPublicId,
    seq: row.seq,
    status: row.status,
    errorCode: row.errorCode,
    provider: row.provider,
    model: row.model,
    responseModel: row.responseModel,
    rounds: row.rounds,
    toolCalls: row.toolCalls,
    usage: {
      inputTokens: row.inputTokens,
      outputTokens: row.outputTokens,
      cacheReadTokens: row.cacheReadTokens,
      cacheWriteTokens: row.cacheWriteTokens,
    },
    latencyMs: row.latencyMs,
    startedAt: row.startedAt.toISOString(),
    finishedAt: iso(row.finishedAt),
  };
}

export function messageView(row: MessageRow, turnPublicId: string): MessageView {
  return {
    id: row.publicId,
    turnId: turnPublicId,
    seq: row.seq,
    role: row.role,
    content: row.content,
    createdAt: row.createdAt.toISOString(),
  };
}

function cardOf(value: unknown): AssistantCard | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as AssistantCard)
    : null;
}

function summaryOf(value: unknown): ConfirmationSummary | null {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (value as { version?: unknown }).version === 'assistant-confirmation/1'
    ? (value as ConfirmationSummary)
    : null;
}

/**
 * A confirmation as the routes return it (step AI-2 §4.2): never the token or its hash; a
 * `pending` row past `expires_at` shows as `expired` (the sweeper moves it later).
 * `reauthFresh` = the viewing session re-authenticated within the window (high risk only).
 */
export function confirmationView(
  row: ConfirmationWithRefs,
  now: Date,
  reauthFresh: boolean,
): ConfirmationView {
  const status =
    row.status === 'pending' && row.expiresAt.getTime() <= now.getTime() ? 'expired' : row.status;
  const decided = row.status === 'executed' || row.status === 'failed';
  return {
    id: row.publicId,
    executionId: row.executionPublicId,
    resultExecutionId: row.resultExecutionPublicId,
    conversationId: row.conversationPublicId,
    tool: row.toolName,
    operationId: row.operationId,
    risk: row.risk,
    requiresReauth: row.requiresReauth,
    reauthFresh: row.requiresReauth && reauthFresh,
    status,
    summary: summaryOf(row.summary),
    actionDigest: row.actionDigest,
    expiresAt: row.expiresAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
    decidedAt: iso(row.decidedAt),
    executedAt: iso(row.executedAt),
    result: decided ? { httpStatus: row.resultHttpStatus, error: row.errorCode } : null,
  };
}

export function executionView(
  row: ExecutionWithRefs,
  confirmation: ConfirmationView | null = null,
): ExecutionView {
  return {
    id: row.publicId,
    conversationId: row.conversationPublicId,
    turnId: row.turnPublicId,
    parentExecutionId: row.parentPublicId,
    seq: row.seq,
    ref: `r${row.seq}`,
    tool: row.toolName,
    title: toolTitleOf(row.toolName),
    operationId: row.operationId,
    access: row.access,
    risk: row.risk,
    decision: row.decision,
    status: row.status,
    httpStatus: row.httpStatus,
    errorCode: row.errorCode,
    message: refusalMessageOf(row.decision, row.operationId),
    hasMore: row.nextCursor !== null,
    card: cardOf(row.resultCard),
    latencyMs: row.latencyMs,
    createdAt: row.createdAt.toISOString(),
    confirmation,
  };
}

/** Execution views with the confirmations of their proposals (by execution id). */
export function executionViews(
  rows: readonly ExecutionWithRefs[],
  confirmations: ReadonlyMap<bigint, ConfirmationView>,
): ExecutionView[] {
  return rows.map((row) => executionView(row, confirmations.get(row.id) ?? null));
}
