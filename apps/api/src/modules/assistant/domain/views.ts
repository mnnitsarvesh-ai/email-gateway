import type { AssistantCard } from '@email-gateway/assistant';
import type {
  ConversationView,
  ExecutionView,
  MessageView,
  TurnView,
} from '../dto/assistant.schemas';
import type {
  ConversationRow,
  MessageRow,
  TurnRow,
} from '../repositories/conversations.repository';
import type { ExecutionWithRefs } from '../repositories/executions.repository';

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

export function executionView(row: ExecutionWithRefs): ExecutionView {
  return {
    id: row.publicId,
    conversationId: row.conversationPublicId,
    turnId: row.turnPublicId,
    parentExecutionId: row.parentPublicId,
    seq: row.seq,
    ref: `r${row.seq}`,
    tool: row.toolName,
    operationId: row.operationId,
    access: row.access,
    risk: row.risk,
    decision: row.decision,
    status: row.status,
    httpStatus: row.httpStatus,
    errorCode: row.errorCode,
    hasMore: row.nextCursor !== null,
    card: cardOf(row.resultCard),
    latencyMs: row.latencyMs,
    createdAt: row.createdAt.toISOString(),
  };
}
