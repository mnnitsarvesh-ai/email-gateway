import { findTool } from '@email-gateway/assistant';
import type {
  AuditConfirmationView,
  AuditConversationHeader,
  AuditExecutionView,
  AuditReportView,
  AuditTurnView,
  FeedbackView,
  InsightsUserView,
  UsageFigures,
} from '../dto/insights.schemas';
import type {
  AuditConfirmationRow,
  AuditConversationRow,
  AuditDeliveryRow,
  AuditExecutionRow,
  AuditFeedbackRow,
  AuditReportRow,
  AuditTurnRow,
  ConversationAggregates,
} from '../repositories/audit.repository';
import type { FeedbackRow } from '../repositories/feedback.repository';
import type { IdentityRow } from '../repositories/identity.repository';
import type { UsageSums } from '../repositories/user-usage.repository';

/**
 * Row → view mappers of the insights routes (step AI-6 D1, D2, D4). Every admin and audit view is
 * built field by field from an explicit allow-list (I24): a repository row that carries more
 * (a title, message text, a transcript, a card, an object key or a recipient address) never
 * reaches the response, because nothing here copies a row as a whole.
 */

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());
const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const CODE = /^[a-z0-9_]{1,64}$/;
const SECTION = /^[a-z_]{1,40}$/;

/** The user of a row: name and address only for members of the scope's organization. */
export function identityOf(
  userId: bigint,
  users: ReadonlyMap<bigint, IdentityRow>,
  organizationId: bigint,
): InsightsUserView {
  const user = users.get(userId);
  if (!user) return { id: 'unknown', displayName: null, email: null };
  const member = user.organizationId === organizationId;
  return {
    id: user.publicId,
    displayName: member ? user.displayName : null,
    email: member ? user.email : null,
  };
}

/** Usage sums → figures; the estimated cost is null when no summed row had a price. */
export function usageFigures(sums: UsageSums): UsageFigures {
  const totalTokens =
    sums.inputTokens + sums.outputTokens + sums.cacheReadTokens + sums.cacheWriteTokens;
  return {
    turns: sums.turns,
    inputTokens: sums.inputTokens,
    outputTokens: sums.outputTokens,
    cacheReadTokens: sums.cacheReadTokens,
    cacheWriteTokens: sums.cacheWriteTokens,
    totalTokens,
    estimatedCostMicros: sums.pricedRows > 0 ? sums.costMicros : null,
  };
}

/** The owner's feedback view (the comment included: it is the owner's own text). */
export function feedbackView(row: FeedbackRow, messagePublicId: string): FeedbackView {
  return {
    messageId: messagePublicId,
    rating: row.rating,
    reason: row.reason,
    comment: row.comment,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const CONFIRMATION_STATUSES = [
  'pending',
  'executing',
  'executed',
  'failed',
  'expired',
  'cancelled',
] as const;

/** The audit header of a conversation (no title). */
export function conversationHeader(
  row: AuditConversationRow,
  aggregates: ConversationAggregates,
  users: ReadonlyMap<bigint, IdentityRow>,
): AuditConversationHeader {
  const tokens = aggregates.tokens.get(row.id);
  const executions = aggregates.executions.get(row.id);
  const confirmations = aggregates.confirmations.get(row.id);
  const feedback = aggregates.feedback.get(row.id);
  const byStatus = Object.fromEntries(
    CONFIRMATION_STATUSES.map((status) => [status, confirmations?.get(status) ?? 0]),
  ) as Record<(typeof CONFIRMATION_STATUSES)[number], number>;
  return {
    id: row.publicId,
    user: identityOf(row.userId, users, row.organizationId),
    status: row.status,
    createdAt: row.createdAt.toISOString(),
    lastTurnAt: iso(row.lastTurnAt),
    turnCount: row.turnCount,
    segmentCount: row.segment,
    contentPurged: row.contentPurgedAt !== null,
    underPlatformOverride: row.platformOverrideId !== null,
    totals: {
      tokens: tokens?.tokens ?? 0,
      estimatedCostMicros: tokens && tokens.pricedTurns > 0 ? tokens.costMicros : null,
      toolCalls: executions?.total ?? 0,
      deniedCalls: executions?.denied ?? 0,
      confirmations: byStatus,
      reports: aggregates.reports.get(row.id) ?? 0,
      feedback: { up: feedback?.up ?? 0, down: feedback?.down ?? 0 },
    },
  };
}

export function auditTurnView(row: AuditTurnRow): AuditTurnView {
  return {
    seq: row.seq,
    status: row.status,
    provider: row.provider,
    model: row.model,
    responseModel: row.responseModel,
    keySource: row.keySource,
    dataSharing: row.dataSharing,
    fallbackFrom: row.fallbackFrom,
    promptVersion: row.promptVersion,
    registryVersion: row.registryVersion,
    rounds: row.rounds,
    toolCalls: row.toolCalls,
    tokens: {
      input: row.inputTokens,
      output: row.outputTokens,
      cacheRead: row.cacheReadTokens,
      cacheWrite: row.cacheWriteTokens,
    },
    costMicros: row.costMicros === null ? null : Number(row.costMicros),
    latencyMs: row.latencyMs,
    errorCode: row.errorCode,
    startedAt: row.startedAt.toISOString(),
    finishedAt: iso(row.finishedAt),
  };
}

/** The registry module of a tool name (null for an unknown or retired tool). */
export function moduleOfTool(toolName: string): string | null {
  return findTool(toolName)?.module ?? null;
}

export function auditExecutionView(row: AuditExecutionRow): AuditExecutionView {
  return {
    id: row.publicId,
    seq: row.seq,
    turnSeq: row.turnSeq,
    tool: row.toolName,
    module: moduleOfTool(row.toolName),
    operationId: row.operationId,
    method: row.httpMethod,
    access: row.access,
    risk: row.risk,
    decision: row.decision,
    status: row.status,
    httpStatus: row.httpStatus,
    errorCode: row.errorCode,
    // Exactly as stored: the executor already dropped credential keys and masked values.
    paramsRedacted: row.paramsRedacted ?? null,
    resourceRef: row.resourceRef,
    latencyMs: row.latencyMs,
    correlationId: row.correlationId,
    createdAt: row.createdAt.toISOString(),
  };
}

export function auditConfirmationView(row: AuditConfirmationRow): AuditConfirmationView {
  return {
    id: row.publicId,
    operationId: row.operationId,
    risk: row.risk,
    requiresReauth: row.requiresReauth,
    status: row.status,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    decidedAt: iso(row.decidedAt),
    resultHttpStatus: row.resultHttpStatus,
    errorCode: row.errorCode,
  };
}

/** The stored `sections` JSON → section names and omissions (never its organization label). */
export function reportSectionsOf(value: unknown): {
  sections: string[];
  omitted: Array<{ section: string; reason: string; code: string | null }>;
} {
  const v = isRecord(value) ? value : {};
  const sections = (Array.isArray(v.included) ? v.included : []).filter(
    (s): s is string => typeof s === 'string' && SECTION.test(s),
  );
  const omitted = (Array.isArray(v.omitted) ? v.omitted : []).flatMap((o) =>
    isRecord(o) &&
    typeof o.section === 'string' &&
    SECTION.test(o.section) &&
    typeof o.reason === 'string' &&
    SECTION.test(o.reason)
      ? [
          {
            section: o.section,
            reason: o.reason,
            code: typeof o.code === 'string' && CODE.test(o.code) ? o.code : null,
          },
        ]
      : [],
  );
  return { sections, omitted };
}

const RECIPIENT_KINDS = ['self', 'member', 'domain'] as const;
const DELIVERY_STATUSES = ['queued', 'sent', 'failed'] as const;
const DOMAIN = /^[a-z0-9.-]{1,253}$/;

export function auditReportView(
  row: AuditReportRow,
  deliveries: readonly AuditDeliveryRow[],
): AuditReportView {
  const { sections, omitted } = reportSectionsOf(row.sections);
  return {
    id: row.publicId,
    status: row.status,
    period: {
      from: row.periodFrom.toISOString(),
      to: row.periodTo.toISOString(),
      granularity: row.granularity,
    },
    sections,
    omitted,
    sizeBytes: row.sizeBytes,
    errorCode: row.errorCode,
    createdAt: row.createdAt.toISOString(),
    async: row.job !== null,
    jobStatus: row.job?.status ?? null,
    deliveries: deliveries.flatMap((d) =>
      (RECIPIENT_KINDS as readonly string[]).includes(d.recipientKind) &&
      (DELIVERY_STATUSES as readonly string[]).includes(d.status)
        ? [
            {
              recipientKind: d.recipientKind as (typeof RECIPIENT_KINDS)[number],
              // Only a bare domain: anything else (a malformed stored value) is withheld.
              recipientDomain:
                d.recipientDomain !== null && DOMAIN.test(d.recipientDomain)
                  ? d.recipientDomain
                  : null,
              status: d.status as (typeof DELIVERY_STATUSES)[number],
              errorCode: d.errorCode,
              requestedAt: d.requestedAt.toISOString(),
              sentAt: iso(d.sentAt),
            },
          ]
        : [],
    ),
  };
}

export function auditFeedbackView(row: AuditFeedbackRow): {
  messageId: string;
  rating: 'up' | 'down';
  reason: FeedbackView['reason'];
} {
  return {
    messageId: row.messagePublicId,
    rating: row.rating,
    reason: row.reason as FeedbackView['reason'],
  };
}
