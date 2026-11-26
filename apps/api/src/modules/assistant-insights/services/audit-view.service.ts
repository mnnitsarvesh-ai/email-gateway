import { Injectable } from '@nestjs/common';
import { ALL_TOOLS } from '@email-gateway/assistant';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { rangeWindow } from '../../../http/listing/range';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  instantKey,
  listBinding,
} from '../../messages/domain/v1-list';
import {
  auditConfirmationView,
  auditExecutionView,
  auditFeedbackView,
  auditReportView,
  auditTurnView,
  conversationHeader,
  identityOf,
} from '../domain/views';
import { resolveInstantWindow, resolveOptionalWindow } from '../domain/window';
import type {
  AuditConversationDetail,
  AuditConversationPage,
  AuditConversationsQuery,
  AuditExecutionPage,
  AuditExecutionsQuery,
} from '../dto/insights.schemas';
import {
  AUDIT_DETAIL_MAX_ROWS,
  CURSOR_RESOURCES,
  INSIGHTS_AUDIT,
  INSIGHTS_AUDIT_RESOURCE,
} from '../insights.constants';
import { assistantAdminConversationNotFound } from '../insights.errors';
import {
  type AuditConversationRow,
  type AuditExecutionRow,
  AuditRepository,
} from '../repositories/audit.repository';
import { IdentityRepository } from '../repositories/identity.repository';

/** Tool names of a registry module (the `module` filter); empty for an unknown module. */
export function toolNamesOfModule(module: string): string[] {
  return ALL_TOOLS.filter((tool) => tool.module === module).map((tool) => tool.name);
}

/** The window-bearing filters of a query, for the cursor's filter hash. */
const windowFilters = (query: { from?: Date; to?: Date }) => ({
  ...(query.from !== undefined && { from: { values: [query.from] } }),
  ...(query.to !== undefined && { to: { values: [query.to] } }),
});

/**
 * The metadata-only conversation audit view (step AI-6 D4, I24; `audit:read`): the organization's
 * conversations (incl. those held under a platform override, flagged), one conversation's turns,
 * tool executions, confirmations, reports with their deliveries (recipient domain only) and
 * ratings, and the execution search. Never a title, message, transcript, card, report object or
 * HTML, recipient address or feedback comment: every view is built from allow-listed columns.
 * Reading one conversation is audited `assistant.audit_viewed`. No content search across users
 * (A6-2). Replica reads; v1 cursors.
 */
@Injectable()
export class AssistantAuditViewService {
  constructor(
    private readonly repository: AuditRepository,
    private readonly identities: IdentityRepository,
    private readonly codec: CursorCodec,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  async conversations(
    principal: UserPrincipal,
    scope: TenantScope,
    query: AuditConversationsQuery,
  ): Promise<AuditConversationPage> {
    const binding = listBinding({
      resource: CURSOR_RESOURCES.conversations,
      principal,
      filters: { ...query.filters, ...windowFilters(query) },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const window = resolveOptionalWindow(query, this.now(), decoded?.window);
    const userPublicId = query.filters.userId?.values?.[0];
    let userId: bigint | undefined;
    if (userPublicId !== undefined) {
      const resolved = await this.identities.idOfFilter(scope, userPublicId);
      if (resolved === null) return { data: [], nextCursor: null };
      userId = resolved;
    }
    const fetched = await this.repository.conversationPage(scope, {
      ...(userId !== undefined && { userId }),
      ...(query.filters.status?.values !== undefined && { statuses: query.filters.status.values }),
      window,
      ...(decoded && {
        after: { lastTurnAt: instantKey(decoded.keys[0]), id: decimalKey(decoded.keys[1]) },
      }),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row: AuditConversationRow) => [row.lastTurnAt!.toISOString(), row.id.toString()],
    });
    const rows = fetched.slice(0, decision.rows);
    const [aggregates, users] = await Promise.all([
      this.repository.aggregates(
        scope,
        rows.map((r) => r.id),
      ),
      this.identities.byIds(rows.map((r) => r.userId)),
    ]);
    return {
      data: rows.map((row) => conversationHeader(row, aggregates, users)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(
              this.codec,
              binding,
              decision.next,
              window ? rangeWindow(window) : undefined,
            ),
    };
  }

  async conversation(
    principal: UserPrincipal,
    scope: TenantScope,
    conversationPublicId: string,
    sourceIp: string | null,
  ): Promise<AuditConversationDetail> {
    const row = await this.repository.findConversation(scope, conversationPublicId);
    if (!row) throw assistantAdminConversationNotFound();
    const take = AUDIT_DETAIL_MAX_ROWS + 1;
    const [aggregates, users, turns, executions, confirmations, reports, feedback] =
      await Promise.all([
        this.repository.aggregates(scope, [row.id]),
        this.identities.byIds([row.userId]),
        this.repository.turns(scope, row.id, take),
        this.repository.executionsOf(scope, row.id, row.publicId, take),
        this.repository.confirmations(scope, row.id, take),
        this.repository.reports(scope, row.id, take),
        this.repository.feedbackOf(scope, row.id, take),
      ]);
    const cut = <T>(list: readonly T[]): T[] => list.slice(0, AUDIT_DETAIL_MAX_ROWS);
    const shownReports = cut(reports);
    const deliveries = await this.repository.deliveries(
      scope,
      shownReports.map((r) => r.id),
    );
    const truncated = [turns, executions, confirmations, reports, feedback].some(
      (list) => list.length > AUDIT_DETAIL_MAX_ROWS,
    );
    await this.audit.record({
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action: INSIGHTS_AUDIT.auditViewed,
      resourceType: INSIGHTS_AUDIT_RESOURCE.conversation,
      resourceId: row.publicId,
      sourceIp,
      metadata: {
        turns: Math.min(turns.length, AUDIT_DETAIL_MAX_ROWS),
        executions: Math.min(executions.length, AUDIT_DETAIL_MAX_ROWS),
        underPlatformOverride: row.platformOverrideId !== null,
      },
    });
    return {
      ...conversationHeader(row, aggregates, users),
      turns: cut(turns).map(auditTurnView),
      executions: cut(executions).map(auditExecutionView),
      confirmations: cut(confirmations).map(auditConfirmationView),
      reports: shownReports.map((report) =>
        auditReportView(
          report,
          deliveries.filter((d) => d.reportId === report.id),
        ),
      ),
      feedback: cut(feedback).map(auditFeedbackView),
      truncated,
    };
  }

  async executions(
    principal: UserPrincipal,
    scope: TenantScope,
    query: AuditExecutionsQuery,
  ): Promise<AuditExecutionPage> {
    const binding = listBinding({
      resource: CURSOR_RESOURCES.executions,
      principal,
      filters: { ...query.filters, ...windowFilters(query) },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveInstantWindow(query, this.now(), decoded?.window);
    const empty: AuditExecutionPage = { data: [], nextCursor: null };
    const f = query.filters;
    let userId: bigint | undefined;
    if (f.userId?.values?.[0] !== undefined) {
      const resolved = await this.identities.idOfFilter(scope, f.userId.values[0]);
      if (resolved === null) return empty;
      userId = resolved;
    }
    let conversationId: bigint | undefined;
    if (f.conversationId?.values?.[0] !== undefined) {
      const resolved = await this.repository.conversationIdOf(scope, f.conversationId.values[0]);
      if (resolved === null) return empty;
      conversationId = resolved;
    }
    let toolNames: string[] | undefined;
    const tool = f.tool?.values?.[0];
    const module = f.module?.values?.[0];
    if (module !== undefined) {
      toolNames = toolNamesOfModule(module);
      if (tool !== undefined) toolNames = toolNames.filter((name) => name === tool);
      if (toolNames.length === 0) return empty;
    } else if (tool !== undefined) {
      toolNames = [tool];
    }
    const fetched = await this.repository.executionPage(scope, {
      from: range.from,
      to: range.to,
      ...(userId !== undefined && { userId }),
      ...(conversationId !== undefined && { conversationId }),
      ...(toolNames !== undefined && { toolNames }),
      ...(f.decision?.values !== undefined && { decisions: f.decision.values }),
      ...(f.status?.values !== undefined && { statuses: f.status.values }),
      ...(f.risk?.values !== undefined && { risks: f.risk.values }),
      ...(f.access?.values?.[0] !== undefined && { access: f.access.values[0] }),
      ...(f.correlationId?.values?.[0] !== undefined && {
        correlationId: f.correlationId.values[0],
      }),
      ...(decoded && {
        after: { createdAt: instantKey(decoded.keys[0]), id: decimalKey(decoded.keys[1]) },
      }),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row: AuditExecutionRow) => [row.createdAt.toISOString(), row.id.toString()],
    });
    const rows = fetched.slice(0, decision.rows);
    const users = await this.identities.byIds(rows.map((r) => r.userId));
    return {
      data: rows.map((row) => ({
        ...auditExecutionView(row),
        conversationId: row.conversationPublicId,
        user: identityOf(row.userId, users, scope.organizationId),
      })),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, decision.next, rangeWindow(range)),
    };
  }
}
