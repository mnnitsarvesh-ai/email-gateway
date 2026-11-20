import { Inject, Injectable } from '@nestjs/common';
import { REGISTRY_VERSION } from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  instantKey,
  intKey,
  listBinding,
} from '../../messages/domain/v1-list';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  CONVERSATIONS_CURSOR_RESOURCE,
  MESSAGES_CURSOR_RESOURCE,
} from '../assistant.constants';
import { assistantConversationLimit, assistantConversationNotFound } from '../assistant.errors';
import { availableTools } from '../domain/tool-catalog';
import { conversationView, executionView, messageView } from '../domain/views';
import type {
  ConversationListQuery,
  ConversationPage,
  ConversationView,
  CreateConversationBody,
  ExecutionView,
  MessageListItem,
  MessageListQuery,
  MessagePage,
  ToolsView,
  UpdateConversationBody,
} from '../dto/assistant.schemas';
import { AssistantSettingsRepository } from '../repositories/assistant-settings.repository';
import {
  type ConversationRow,
  ConversationsRepository,
  type Owner,
} from '../repositories/conversations.repository';
import {
  type ExecutionWithRefs,
  ExecutionsRepository,
} from '../repositories/executions.repository';
import { AssistantAvailabilityService } from './assistant-availability.service';

const DAY_MS = 86_400_000;

/** The caller as the owner of conversations: organization from the scope, the user's own rows. */
export const ownerOf = (principal: UserPrincipal, scope: TenantScope): Owner => ({
  scope,
  userId: principal.userId,
});

/**
 * Conversations, their messages and the tool catalogue of the caller (design §4.1, D12, Q9,
 * Q11). Conversations are private to their user (also from admins: another user's or another
 * organization's ids answer `404`); under a platform override they live in the override's target
 * organization with the override id. Deleting is a soft delete with an immediate content purge,
 * audited `assistant.conversation_deleted`.
 */
@Injectable()
export class ConversationService {
  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly conversations: ConversationsRepository,
    private readonly executions: ExecutionsRepository,
    private readonly settings: AssistantSettingsRepository,
    private readonly availability: AssistantAvailabilityService,
    private readonly codec: CursorCodec,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** `GET /assistant/tools`: the caller's enabled tools after the permission pre-filter. */
  tools(principal: UserPrincipal): ToolsView {
    return {
      registryVersion: REGISTRY_VERSION,
      tools: availableTools(principal).map((tool) => ({
        name: tool.name,
        module: tool.module,
        title: tool.display.title ?? tool.summary,
        access: tool.access,
        risk: tool.risk,
      })),
    };
  }

  /** The tenant's content retention in days (settings, else the platform default). */
  async retentionDays(scope: TenantScope): Promise<number> {
    const row = await this.settings.get(scope);
    return row?.retentionDays ?? this.config.ASSISTANT_RETENTION_DEFAULT_DAYS;
  }

  async list(
    principal: UserPrincipal,
    scope: TenantScope,
    query: ConversationListQuery,
  ): Promise<ConversationPage> {
    const binding = listBinding({
      resource: CONVERSATIONS_CURSOR_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const fetched = await this.conversations.list(ownerOf(principal, scope), {
      statuses: query.filters.status?.values ?? ['active', 'archived'],
      ...(query.filters.q?.values?.[0] !== undefined && {
        titleContains: query.filters.q.values[0],
      }),
      ...(decoded && {
        after: { lastTurnAt: instantKey(decoded.keys[0]), id: decimalKey(decoded.keys[1]) },
      }),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row: ConversationRow) => [row.lastTurnAt!.toISOString(), row.id.toString()],
    });
    return {
      data: fetched.slice(0, decision.rows).map(conversationView),
      nextCursor:
        decision.next === null ? null : encodeListCursor(this.codec, binding, decision.next),
    };
  }

  async create(
    principal: UserPrincipal,
    scope: TenantScope,
    body: CreateConversationBody,
  ): Promise<ConversationView> {
    const now = this.now();
    await this.availability.assertAvailable(scope, now, false);
    const owner = ownerOf(principal, scope);
    const limit = this.config.ASSISTANT_MAX_CONVERSATIONS_PER_USER;
    if ((await this.conversations.countLive(owner)) >= limit) {
      throw assistantConversationLimit(limit);
    }
    const retention = await this.retentionDays(scope);
    const row = await this.conversations.create(owner, {
      publicId: uuidv7(),
      title: body.title ?? null,
      platformOverrideId: principal.override?.id ?? null,
      now,
      purgeAfter: new Date(now.getTime() + retention * DAY_MS),
    });
    return conversationView(row);
  }

  /** The caller's own conversation or `404 assistant_conversation_not_found`. */
  async load(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
  ): Promise<ConversationRow> {
    const row = await this.conversations.findOwned(ownerOf(principal, scope), publicId);
    if (!row) throw assistantConversationNotFound();
    return row;
  }

  async get(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
  ): Promise<ConversationView> {
    return conversationView(await this.load(principal, scope, publicId));
  }

  async update(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    body: UpdateConversationBody,
  ): Promise<ConversationView> {
    const row = await this.load(principal, scope, publicId);
    await this.conversations.update(ownerOf(principal, scope), row.id, {
      ...(body.title !== undefined && { title: body.title }),
      ...(body.status !== undefined && { status: body.status }),
    });
    return this.get(principal, scope, publicId);
  }

  /** Soft delete + immediate content purge, audited (D12). */
  async remove(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    sourceIp: string | null,
  ): Promise<void> {
    const owner = ownerOf(principal, scope);
    const row = await this.load(principal, scope, publicId);
    const now = this.now();
    await this.runner.run(async (tx) => {
      if (!(await this.conversations.deleteAndPurge(owner, row.id, now, tx))) {
        throw assistantConversationNotFound();
      }
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: ASSISTANT_AUDIT.conversationDeleted,
          resourceType: AUDIT_RESOURCE.conversation,
          resourceId: row.publicId,
          sourceIp,
          metadata: { turnCount: row.turnCount, contentPurged: true },
        },
        tx,
      );
    });
  }

  /** Oldest → newest pages of messages with their turn's executions and cards (v1 cursor). */
  async messages(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    query: MessageListQuery,
  ): Promise<MessagePage> {
    const owner = ownerOf(principal, scope);
    const conversation = await this.load(principal, scope, publicId);
    const binding = listBinding({
      resource: MESSAGES_CURSOR_RESOURCE,
      principal,
      filters: { conversation: { values: [conversation.publicId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const afterSeq = decoded ? intKey(decoded.keys[0], 2_000_000_000) : undefined;
    const fetched = await this.conversations.listMessages(
      owner,
      conversation.id,
      afterSeq,
      query.limit + 1,
    );
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row) => [String(row.seq)],
    });
    const page = fetched.slice(0, decision.rows);
    const turnIds = [...new Set(page.map((m) => m.turnId))];
    const executions = await this.executions.forTurns(owner, conversation.id, turnIds, 'replica');
    const byTurn = groupByTurn(executions);
    const hasAssistant = new Set(page.filter((m) => m.role === 'assistant').map((m) => m.turnId));
    const data: MessageListItem[] = page.map((m) => {
      const carries = m.role === 'assistant' || !hasAssistant.has(m.turnId);
      // A user message carries the executions only when its answer is not on this page and
      // the turn has no assistant message (failed or running turns).
      const shown =
        carries &&
        (m.role === 'assistant' || m.turn.status === 'failed' || m.turn.status === 'running')
          ? (byTurn.get(m.turnId) ?? [])
          : [];
      return {
        ...messageView(m, m.turn.publicId),
        turn: { id: m.turn.publicId, status: m.turn.status, errorCode: m.turn.errorCode },
        executions: shown,
      };
    });
    return {
      data,
      nextCursor:
        decision.next === null ? null : encodeListCursor(this.codec, binding, decision.next),
    };
  }
}

/**
 * Executions per turn: a "more" page (no turn) belongs to the turn of its first ancestor that
 * has one.
 */
export function groupByTurn(rows: readonly ExecutionWithRefs[]): Map<bigint, ExecutionView[]> {
  const byId = new Map(rows.map((r) => [r.id, r]));
  const turnOf = (row: ExecutionWithRefs): bigint | null => {
    let current: ExecutionWithRefs | undefined = row;
    for (let depth = 0; current && depth < 1000; depth += 1) {
      if (current.turnId !== null) return current.turnId;
      current =
        current.parentExecutionId === null ? undefined : byId.get(current.parentExecutionId);
    }
    return null;
  };
  const out = new Map<bigint, ExecutionView[]>();
  for (const row of rows) {
    const turn = turnOf(row);
    if (turn === null) continue;
    const list = out.get(turn) ?? [];
    list.push(executionView(row));
    out.set(turn, list);
  }
  return out;
}
