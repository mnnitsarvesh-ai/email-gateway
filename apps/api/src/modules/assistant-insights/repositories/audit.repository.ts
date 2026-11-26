import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  type AiChatConversationStatus,
  type AiChatToolAccess,
  type AiChatToolDecision,
  type AiChatToolRisk,
  type AiChatToolStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import { AUDIT_INDEXES } from '../insights.constants';

/**
 * The metadata-only conversation audit view (step AI-6 D4, I24) on the read replica. Every select
 * is an explicit allow-list: conversation titles, message text, provider transcripts, result
 * cards/refs/cursors, confirmation requests/summaries, report object keys, figures and HTML, and
 * delivery addresses are never selected (the delivery's recipient domain is computed by MySQL,
 * the address never leaves the database). Organization from the scope only; override
 * conversations of the organization are included. Every row is echo-checked.
 */

export const auditConversationSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  platformOverrideId: true,
  status: true,
  turnCount: true,
  segment: true,
  lastTurnAt: true,
  contentPurgedAt: true,
  createdAt: true,
} satisfies Prisma.AiChatConversationSelect;
export type AuditConversationRow = Prisma.AiChatConversationGetPayload<{
  select: typeof auditConversationSelect;
}>;

export const auditTurnSelect = {
  id: true,
  organizationId: true,
  conversationId: true,
  seq: true,
  status: true,
  provider: true,
  model: true,
  responseModel: true,
  keySource: true,
  dataSharing: true,
  fallbackFrom: true,
  promptVersion: true,
  registryVersion: true,
  rounds: true,
  toolCalls: true,
  inputTokens: true,
  outputTokens: true,
  cacheReadTokens: true,
  cacheWriteTokens: true,
  costMicros: true,
  latencyMs: true,
  errorCode: true,
  startedAt: true,
  finishedAt: true,
} satisfies Prisma.AiChatTurnSelect;
export type AuditTurnRow = Prisma.AiChatTurnGetPayload<{ select: typeof auditTurnSelect }>;

export const auditExecutionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  conversationId: true,
  turnId: true,
  seq: true,
  toolName: true,
  operationId: true,
  httpMethod: true,
  access: true,
  risk: true,
  decision: true,
  status: true,
  httpStatus: true,
  errorCode: true,
  correlationId: true,
  paramsRedacted: true,
  resourceRef: true,
  latencyMs: true,
  createdAt: true,
} satisfies Prisma.AiChatToolExecutionSelect;
export type AuditExecutionRow = Prisma.AiChatToolExecutionGetPayload<{
  select: typeof auditExecutionSelect;
}> & { turnSeq: number | null; conversationPublicId: string };

export const auditConfirmationSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  operationId: true,
  risk: true,
  requiresReauth: true,
  status: true,
  createdAt: true,
  expiresAt: true,
  decidedAt: true,
  resultHttpStatus: true,
  errorCode: true,
} satisfies Prisma.AiChatActionConfirmationSelect;
export type AuditConfirmationRow = Prisma.AiChatActionConfirmationGetPayload<{
  select: typeof auditConfirmationSelect;
}>;

export const auditReportSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  status: true,
  periodFrom: true,
  periodTo: true,
  granularity: true,
  /** `{ included, omitted, atoRange, label }`: the view keeps the section names and omissions. */
  sections: true,
  sizeBytes: true,
  errorCode: true,
  createdAt: true,
  job: { select: { status: true } },
} satisfies Prisma.AiChatReportSelect;
export type AuditReportRow = Prisma.AiChatReportGetPayload<{ select: typeof auditReportSelect }>;

export interface AuditDeliveryRow {
  organizationId: bigint;
  reportId: bigint;
  recipientKind: string;
  recipientDomain: string | null;
  status: string;
  errorCode: string | null;
  requestedAt: Date;
  sentAt: Date | null;
}

export interface AuditFeedbackRow {
  organizationId: bigint;
  messagePublicId: string;
  rating: 'up' | 'down';
  reason: string | null;
}

/** Aggregates of a page of conversations (the header totals). */
export interface ConversationAggregates {
  tokens: Map<bigint, { tokens: number; costMicros: number; pricedTurns: number }>;
  executions: Map<bigint, { total: number; denied: number }>;
  confirmations: Map<bigint, Map<string, number>>;
  reports: Map<bigint, number>;
  feedback: Map<bigint, { up: number; down: number }>;
}

export interface AuditConversationFilter {
  userId?: bigint;
  statuses?: AiChatConversationStatus[];
  window: { from: Date; to: Date } | null;
  after?: { lastTurnAt: Date; id: bigint };
  take: number;
}

export interface AuditExecutionFilter {
  from: Date;
  to: Date;
  userId?: bigint;
  conversationId?: bigint;
  toolNames?: string[];
  decisions?: AiChatToolDecision[];
  statuses?: AiChatToolStatus[];
  risks?: AiChatToolRisk[];
  access?: AiChatToolAccess;
  correlationId?: string;
  after?: { createdAt: Date; id: bigint };
  take: number;
}

const num = (value: unknown): number => Number(typeof value === 'bigint' ? value : String(value));

@Injectable()
export class AuditRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db(): PrismaReadService['client'] {
    return this.reader.client;
  }

  // ---- conversations ---------------------------------------------------------------------------

  /**
   * One page of the organization's conversations, newest `last_turn_at` first. Without a user
   * filter the statement names `(organization_id, last_turn_at, id)` (step AI-6 WP1: otherwise
   * the optimizer prefers the owner index plus a filesort of the organization); with a user the
   * owner index serves it. Step 1 reads the keyset ids, step 2 the allow-listed columns.
   */
  async conversationPage(
    scope: TenantScope,
    filter: AuditConversationFilter,
  ): Promise<AuditConversationRow[]> {
    const org = scope.organizationId;
    const index =
      filter.userId === undefined
        ? Prisma.raw(`FORCE INDEX (${AUDIT_INDEXES.conversationsByActivity})`)
        : Prisma.empty;
    const conditions: Prisma.Sql[] = [
      Prisma.sql`organization_id = ${org}`,
      Prisma.sql`last_turn_at IS NOT NULL`,
    ];
    if (filter.userId !== undefined) conditions.push(Prisma.sql`user_id = ${filter.userId}`);
    if (filter.statuses !== undefined && filter.statuses.length > 0) {
      conditions.push(Prisma.sql`status IN (${Prisma.join(filter.statuses)})`);
    }
    if (filter.window) {
      conditions.push(
        Prisma.sql`last_turn_at >= ${filter.window.from} AND last_turn_at < ${filter.window.to}`,
      );
    }
    if (filter.after) {
      conditions.push(Prisma.sql`(last_turn_at < ${filter.after.lastTurnAt}
        OR (last_turn_at = ${filter.after.lastTurnAt} AND id < ${filter.after.id}))`);
    }
    const keys = await this.db.$queryRaw<Array<{ id: unknown; organizationId: unknown }>>(
      Prisma.sql`SELECT id, organization_id AS organizationId FROM ai_chat_conversations ${index}
        WHERE ${Prisma.join(conditions, ' AND ')}
        ORDER BY last_turn_at DESC, id DESC
        LIMIT ${filter.take}`,
    );
    const ids = keys.map((k) => {
      if (BigInt(String(k.organizationId)) !== org) {
        throw new InconsistentReadError('assistant.audit_conversations');
      }
      return BigInt(String(k.id));
    });
    if (ids.length === 0) return [];
    const rows = await this.db.aiChatConversation.findMany({
      where: tenantWhere(scope, { id: { in: ids } }),
      select: auditConversationSelect,
    });
    assertEcho('assistant.audit_conversations', rows, {
      organizationId: org,
      ...(filter.userId !== undefined && { userId: filter.userId }),
    });
    const byId = new Map(rows.map((r) => [r.id, r]));
    // Keep the keyset order; a row that vanished between the two reads is skipped.
    return ids.flatMap((id) => {
      const row = byId.get(id);
      return row ? [row] : [];
    });
  }

  /** A conversation of the organization by public id (any status: metadata stays audit-visible). */
  async findConversation(
    scope: TenantScope,
    publicId: string,
  ): Promise<AuditConversationRow | null> {
    const row = await this.db.aiChatConversation.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: auditConversationSelect,
    });
    if (row)
      assertEcho('assistant.audit_conversation', [row], { organizationId: scope.organizationId });
    return row;
  }

  /** Header totals of the given conversations (tokens, cost, calls, confirmations, reports, ratings). */
  async aggregates(
    scope: TenantScope,
    conversationIds: readonly bigint[],
  ): Promise<ConversationAggregates> {
    const out: ConversationAggregates = {
      tokens: new Map(),
      executions: new Map(),
      confirmations: new Map(),
      reports: new Map(),
      feedback: new Map(),
    };
    const ids = [...new Set(conversationIds)];
    if (ids.length === 0) return out;
    const where = tenantWhere(scope, { conversationId: { in: ids } });
    const [turns, executions, confirmations, reports, feedback] = await Promise.all([
      this.db.aiChatTurn.groupBy({
        by: ['conversationId'],
        where,
        _sum: {
          inputTokens: true,
          outputTokens: true,
          cacheReadTokens: true,
          cacheWriteTokens: true,
          costMicros: true,
        },
        _count: { costMicros: true },
      }),
      this.db.aiChatToolExecution.groupBy({
        by: ['conversationId', 'decision'],
        where,
        _count: { _all: true },
      }),
      this.db.aiChatActionConfirmation.groupBy({
        by: ['conversationId', 'status'],
        where,
        _count: { _all: true },
      }),
      this.db.aiChatReport.groupBy({ by: ['conversationId'], where, _count: { _all: true } }),
      this.db.aiChatFeedback.groupBy({
        by: ['conversationId', 'rating'],
        where,
        _count: { _all: true },
      }),
    ]);
    const known = new Set(ids);
    const check = (id: bigint): bigint => {
      if (!known.has(id)) throw new InconsistentReadError('assistant.audit_aggregates');
      return id;
    };
    for (const t of turns) {
      out.tokens.set(check(t.conversationId), {
        tokens:
          num(t._sum.inputTokens ?? 0) +
          num(t._sum.outputTokens ?? 0) +
          num(t._sum.cacheReadTokens ?? 0) +
          num(t._sum.cacheWriteTokens ?? 0),
        costMicros: num(t._sum.costMicros ?? 0),
        pricedTurns: t._count.costMicros,
      });
    }
    for (const e of executions) {
      const entry = out.executions.get(check(e.conversationId)) ?? { total: 0, denied: 0 };
      entry.total += e._count._all;
      if (e.decision !== 'allowed') entry.denied += e._count._all;
      out.executions.set(e.conversationId, entry);
    }
    for (const c of confirmations) {
      const entry = out.confirmations.get(check(c.conversationId)) ?? new Map<string, number>();
      entry.set(c.status, (entry.get(c.status) ?? 0) + c._count._all);
      out.confirmations.set(c.conversationId, entry);
    }
    for (const r of reports) out.reports.set(check(r.conversationId), r._count._all);
    for (const f of feedback) {
      const entry = out.feedback.get(check(f.conversationId)) ?? { up: 0, down: 0 };
      entry[f.rating] += f._count._all;
      out.feedback.set(f.conversationId, entry);
    }
    return out;
  }

  // ---- detail ----------------------------------------------------------------------------------

  async turns(scope: TenantScope, conversationId: bigint, take: number): Promise<AuditTurnRow[]> {
    const rows = await this.db.aiChatTurn.findMany({
      where: tenantWhere(scope, { conversationId }),
      orderBy: { seq: 'asc' },
      take,
      select: auditTurnSelect,
    });
    assertEcho('assistant.audit_turns', rows, {
      organizationId: scope.organizationId,
      conversationId,
    });
    return rows;
  }

  async executionsOf(
    scope: TenantScope,
    conversationId: bigint,
    conversationPublicId: string,
    take: number,
  ): Promise<AuditExecutionRow[]> {
    const rows = await this.db.aiChatToolExecution.findMany({
      where: tenantWhere(scope, { conversationId }),
      orderBy: { seq: 'asc' },
      take,
      select: { ...auditExecutionSelect, turn: { select: { seq: true } } },
    });
    assertEcho('assistant.audit_executions', rows, {
      organizationId: scope.organizationId,
      conversationId,
    });
    return rows.map(({ turn, ...row }) => ({
      ...row,
      turnSeq: turn?.seq ?? null,
      conversationPublicId,
    }));
  }

  async confirmations(
    scope: TenantScope,
    conversationId: bigint,
    take: number,
  ): Promise<AuditConfirmationRow[]> {
    const rows = await this.db.aiChatActionConfirmation.findMany({
      where: tenantWhere(scope, { conversationId }),
      orderBy: { id: 'asc' },
      take,
      select: auditConfirmationSelect,
    });
    assertEcho('assistant.audit_confirmations', rows, { organizationId: scope.organizationId });
    return rows;
  }

  async reports(
    scope: TenantScope,
    conversationId: bigint,
    take: number,
  ): Promise<AuditReportRow[]> {
    const rows = await this.db.aiChatReport.findMany({
      where: tenantWhere(scope, { conversationId }),
      orderBy: { id: 'asc' },
      take,
      select: auditReportSelect,
    });
    assertEcho('assistant.audit_reports', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /**
   * Deliveries of the given reports, oldest first. The recipient is reduced to its domain by
   * MySQL (`SUBSTRING_INDEX(recipient_address, '@', -1)`; null after the content purge): the
   * address column is never returned.
   */
  async deliveries(scope: TenantScope, reportIds: readonly bigint[]): Promise<AuditDeliveryRow[]> {
    const ids = [...new Set(reportIds)];
    if (ids.length === 0) return [];
    const raw = await this.db.$queryRaw<
      Array<
        Omit<AuditDeliveryRow, 'organizationId' | 'reportId'> & {
          organizationId: unknown;
          reportId: unknown;
        }
      >
    >(Prisma.sql`SELECT organization_id AS organizationId, report_id AS reportId,
        CAST(recipient_kind AS CHAR) AS recipientKind,
        LOWER(SUBSTRING_INDEX(recipient_address, '@', -1)) AS recipientDomain,
        CAST(status AS CHAR) AS status, error_code AS errorCode,
        requested_at AS requestedAt, sent_at AS sentAt
      FROM ai_chat_report_deliveries
      WHERE organization_id = ${scope.organizationId} AND report_id IN (${Prisma.join(ids)})
      ORDER BY requested_at ASC, id ASC`);
    const rows = raw.map((r): AuditDeliveryRow => ({
      ...r,
      organizationId: BigInt(String(r.organizationId)),
      reportId: BigInt(String(r.reportId)),
    }));
    assertEcho('assistant.audit_deliveries', rows, {
      organizationId: scope.organizationId,
      reportId: ids,
    });
    return rows;
  }

  async feedbackOf(
    scope: TenantScope,
    conversationId: bigint,
    take: number,
  ): Promise<AuditFeedbackRow[]> {
    const rows = await this.db.aiChatFeedback.findMany({
      where: tenantWhere(scope, { conversationId }),
      orderBy: { id: 'asc' },
      take,
      select: {
        organizationId: true,
        rating: true,
        reason: true,
        message: { select: { publicId: true } },
      },
    });
    assertEcho('assistant.audit_feedback', rows, { organizationId: scope.organizationId });
    return rows.map((r) => ({
      organizationId: r.organizationId,
      messagePublicId: r.message.publicId,
      rating: r.rating,
      reason: r.reason,
    }));
  }

  // ---- execution search ------------------------------------------------------------------------

  /** A conversation id of the organization (the `conversationId` filter); null when unknown. */
  async conversationIdOf(scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await this.db.aiChatConversation.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true },
    });
    return row?.id ?? null;
  }

  /**
   * One page of the organization's executions in `[from, to)`, newest first. The statement names
   * the index that serves its filters (step AI-6 WP1: the window-only search needs
   * `(organization_id, created_at)` named). Step 1 reads the keyset ids, step 2 the allow-list.
   */
  async executionPage(
    scope: TenantScope,
    filter: AuditExecutionFilter,
  ): Promise<AuditExecutionRow[]> {
    const org = scope.organizationId;
    if (filter.toolNames !== undefined && filter.toolNames.length === 0) return [];
    const index =
      filter.conversationId !== undefined
        ? Prisma.empty
        : filter.userId !== undefined
          ? Prisma.raw(`FORCE INDEX (${AUDIT_INDEXES.executionsByUser})`)
          : filter.toolNames !== undefined && filter.toolNames.length === 1
            ? Prisma.raw(`FORCE INDEX (${AUDIT_INDEXES.executionsByTool})`)
            : Prisma.raw(`FORCE INDEX (${AUDIT_INDEXES.executionsByTime})`);
    const conditions: Prisma.Sql[] = [
      Prisma.sql`organization_id = ${org}`,
      Prisma.sql`created_at >= ${filter.from} AND created_at < ${filter.to}`,
    ];
    if (filter.userId !== undefined) conditions.push(Prisma.sql`user_id = ${filter.userId}`);
    if (filter.conversationId !== undefined) {
      conditions.push(Prisma.sql`conversation_id = ${filter.conversationId}`);
    }
    if (filter.toolNames !== undefined) {
      conditions.push(Prisma.sql`tool_name IN (${Prisma.join(filter.toolNames)})`);
    }
    if (filter.decisions?.length) {
      conditions.push(Prisma.sql`decision IN (${Prisma.join(filter.decisions)})`);
    }
    if (filter.statuses?.length) {
      conditions.push(Prisma.sql`status IN (${Prisma.join(filter.statuses)})`);
    }
    if (filter.risks?.length) conditions.push(Prisma.sql`risk IN (${Prisma.join(filter.risks)})`);
    if (filter.access !== undefined) conditions.push(Prisma.sql`access = ${filter.access}`);
    if (filter.correlationId !== undefined) {
      conditions.push(Prisma.sql`correlation_id = ${filter.correlationId}`);
    }
    if (filter.after) {
      conditions.push(Prisma.sql`(created_at < ${filter.after.createdAt}
        OR (created_at = ${filter.after.createdAt} AND id < ${filter.after.id}))`);
    }
    const keys = await this.db.$queryRaw<Array<{ id: unknown; organizationId: unknown }>>(
      Prisma.sql`SELECT id, organization_id AS organizationId FROM ai_chat_tool_executions ${index}
        WHERE ${Prisma.join(conditions, ' AND ')}
        ORDER BY created_at DESC, id DESC
        LIMIT ${filter.take}`,
    );
    const ids = keys.map((k) => {
      if (BigInt(String(k.organizationId)) !== org) {
        throw new InconsistentReadError('assistant.audit_execution_search');
      }
      return BigInt(String(k.id));
    });
    if (ids.length === 0) return [];
    const rows = await this.db.aiChatToolExecution.findMany({
      where: tenantWhere(scope, { id: { in: ids } }),
      select: {
        ...auditExecutionSelect,
        turn: { select: { seq: true } },
        conversation: { select: { publicId: true } },
      },
    });
    assertEcho('assistant.audit_execution_search', rows, {
      organizationId: org,
      ...(filter.userId !== undefined && { userId: filter.userId }),
      ...(filter.conversationId !== undefined && { conversationId: filter.conversationId }),
    });
    for (const row of rows) {
      if (row.createdAt < filter.from || row.createdAt >= filter.to) {
        throw new InconsistentReadError('assistant.audit_execution_search');
      }
    }
    const byId = new Map(
      rows.map(({ turn, conversation, ...row }) => [
        row.id,
        { ...row, turnSeq: turn?.seq ?? null, conversationPublicId: conversation.publicId },
      ]),
    );
    return ids.flatMap((id) => {
      const row = byId.get(id);
      return row ? [row] : [];
    });
  }
}
