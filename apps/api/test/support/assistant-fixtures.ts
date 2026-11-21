/**
 * In-memory doubles of the step AI-1 assistant repositories (settings, conversations with turns
 * and messages, tool executions, daily usage), a fake loopback dispatcher that records every
 * request and answers from per-path handlers, and principal builders. Used by the api unit tests
 * (src/modules/assistant/**) and the e2e suite (test/assistant.e2e.test.ts). Synthetic data only;
 * nothing here reaches MySQL, Redis, an LLM or the network, and nothing is used by production
 * code.
 */
/* eslint-disable @typescript-eslint/no-this-alias -- the doubles close over the world's state */
import { randomUUID } from 'node:crypto';
import type { TestingModuleBuilder } from '@nestjs/testing';
import type { AuditEntry } from '../../src/audit/audit.service';
import { AuditService } from '../../src/audit/audit.service';
import type { UserPrincipal } from '../../src/auth-contracts/principal';
import { systemScope, type TenantScope } from '../../src/auth-contracts/tenant-scope';
import { TransactionRunner } from '../../src/database/transaction-runner';
import {
  type ReauthenticationResult,
  ReauthenticationService,
} from '../../src/modules/auth/services/reauthentication.service';
import { AssistantSettingsRepository } from '../../src/modules/assistant/repositories/assistant-settings.repository';
import {
  type ConfirmationCreate,
  type ConfirmationFinish,
  type ConfirmationRow,
  ConfirmationsRepository,
  type ConfirmationWithRefs,
  type StaleExecutingCutoff,
  type SweptConfirmation,
  type UnreportedConfirmation,
} from '../../src/modules/assistant/repositories/confirmations.repository';

/** The repository's stale-`executing` predicate (outcome-unknown sweep). */
function staleExecuting(k: ConfirmationRow, cutoff: StaleExecutingCutoff): boolean {
  if (k.status !== 'executing') return false;
  if (k.executionStartedAt === null) {
    return k.decidedAt !== null && k.decidedAt < cutoff.decidedBefore;
  }
  return k.executionStartedAt < cutoff.startedBefore;
}
import type {
  SettingsRow,
  SettingsWrite,
} from '../../src/modules/assistant/repositories/assistant-settings.repository';
import {
  assistantMessageSeq,
  type ConversationListFilter,
  type ConversationRow,
  ConversationsRepository,
  type MessageRow,
  type Owner,
  type TurnFinish,
  type TurnRow,
  type TurnStart,
  userMessageSeq,
} from '../../src/modules/assistant/repositories/conversations.repository';
import {
  type ExecutionCreate,
  type ExecutionRow,
  ExecutionsRepository,
  type ExecutionWithRefs,
} from '../../src/modules/assistant/repositories/executions.repository';
import {
  budgetTokens,
  type UsageDayRow,
  type UsageDelta,
  UsageRepository,
} from '../../src/modules/assistant/repositories/usage.repository';
import {
  type LoopbackCall,
  LoopbackDispatcher,
  type LoopbackResult,
} from '../../src/modules/assistant/services/loopback-client';
import { OrganizationFeaturesService } from '../../src/tenancy/organization-features.service';

const clone = <T>(value: T): T => structuredClone(value);
const later = (a: Date | null, b: Date | null): number => (b?.getTime() ?? 0) - (a?.getTime() ?? 0);

export type StoredConversation = ConversationRow;
export type StoredTurn = TurnRow & {
  providerTranscript: string | null;
  promptVersion: string;
  registryVersion: string;
};
export type StoredExecution = ExecutionRow;
export type StoredConfirmation = ConfirmationRow;

/** A synthetic customer user (never a real account). */
export function testUser(overrides: Partial<UserPrincipal> = {}): UserPrincipal {
  return {
    kind: 'user',
    userId: 501n,
    userPublicId: '0193b000-0000-7000-8000-000000000501',
    organizationId: 7001n,
    organizationPublicId: '0193b000-0000-7000-8000-000000007001',
    organizationKind: 'customer',
    sessionId: '0193b000-0000-7000-8000-0000000000aa',
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(['assistant:use', 'assistant:configure', 'policy:read']),
    ...overrides,
  };
}

/** The stored state of every assistant table, with doubles of the four repositories. */
export class AssistantWorld {
  settings = new Map<bigint, SettingsRow & { updatedByUserId: bigint | null }>();
  conversations: StoredConversation[] = [];
  turns: StoredTurn[] = [];
  messages: MessageRow[] = [];
  executions: StoredExecution[] = [];
  confirmations: StoredConfirmation[] = [];
  usage: Array<UsageDayRow & { organizationId: bigint }> = [];
  /** Feature `ai_assistant` per organization. */
  features = new Map<bigint, boolean>();
  users = new Map<bigint, string>();
  /** Calls in order, e.g. `startTurn`, `execution`, `finishTurn` (persistence order tests). */
  readonly log: string[] = [];
  private nextId = 1000n;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  reset(): void {
    this.settings.clear();
    this.conversations = [];
    this.turns = [];
    this.messages = [];
    this.executions = [];
    this.confirmations = [];
    this.usage = [];
    this.features.clear();
    this.users.clear();
    this.log.length = 0;
  }

  /** Feature on and settings enabled with the acknowledgement. */
  enable(organizationId: bigint, overrides: Partial<SettingsRow> = {}): void {
    this.features.set(organizationId, true);
    this.settings.set(organizationId, {
      organizationId,
      enabled: true,
      externalProcessingAckAt: new Date('2026-11-01T00:00:00.000Z'),
      externalProcessingAckByUserId: 501n,
      dailyTokenBudget: null,
      retentionDays: 30,
      dataSharing: 'metadata',
      rowVersion: 1,
      updatedAt: new Date('2026-11-01T00:00:00.000Z'),
      updatedByUserId: 501n,
      ...overrides,
    });
  }

  private owns(owner: Owner, row: { organizationId: bigint; userId: bigint }): boolean {
    return row.organizationId === owner.scope.organizationId && row.userId === owner.userId;
  }

  private live = (c: StoredConversation): boolean => c.status !== 'deleted';

  // ---- settings ------------------------------------------------------------------------------

  settingsDouble(): AssistantSettingsRepository {
    const world = this;
    const fields = (data: SettingsWrite) => ({
      enabled: data.enabled,
      externalProcessingAckAt: data.externalProcessingAckAt,
      externalProcessingAckByUserId: data.externalProcessingAckByUserId,
      dailyTokenBudget: data.dailyTokenBudget,
      retentionDays: data.retentionDays,
      updatedByUserId: data.updatedByUserId,
    });
    return {
      get: (scope: TenantScope) => {
        const row = world.settings.get(scope.organizationId);
        if (!row) return Promise.resolve(null);
        const { updatedByUserId: _ignored, ...view } = row;
        return Promise.resolve(clone(view));
      },
      create: (scope: TenantScope, data: SettingsWrite) => {
        if (world.settings.has(scope.organizationId)) return Promise.resolve(false);
        world.settings.set(scope.organizationId, {
          organizationId: scope.organizationId,
          ...fields(data),
          dataSharing: 'metadata',
          rowVersion: 1,
          updatedAt: new Date(),
        });
        return Promise.resolve(true);
      },
      update: (scope: TenantScope, expected: number, data: SettingsWrite) => {
        const row = world.settings.get(scope.organizationId);
        if (!row || row.rowVersion !== expected) return Promise.resolve(false);
        Object.assign(row, fields(data), { rowVersion: row.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(true);
      },
      userPublicId: (id: bigint) => Promise.resolve(world.users.get(id) ?? null),
    } as unknown as AssistantSettingsRepository;
  }

  featuresDouble(): OrganizationFeaturesService {
    const world = this;
    const enabled = (organizationId: bigint) => world.features.get(organizationId) === true;
    return {
      isEnabled: (organizationId: bigint) => Promise.resolve(enabled(organizationId)),
      isEffectivelyEnabled: (organizationId: bigint) => Promise.resolve(enabled(organizationId)),
      effective: (organizationId: bigint, keys: readonly string[]) =>
        Promise.resolve(Object.fromEntries(keys.map((k) => [k, enabled(organizationId)]))),
    } as unknown as OrganizationFeaturesService;
  }

  // ---- conversations, turns, messages --------------------------------------------------------

  addConversation(owner: Owner, overrides: Partial<StoredConversation> = {}): StoredConversation {
    const now = new Date();
    const row: StoredConversation = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId: owner.scope.organizationId,
      userId: owner.userId,
      platformOverrideId: null,
      title: null,
      status: 'active',
      turnCount: 0,
      segment: 1,
      lastTurnAt: now,
      purgeAfter: new Date(now.getTime() + 30 * 86_400_000),
      contentPurgedAt: null,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      ...overrides,
    };
    this.conversations.push(row);
    return row;
  }

  conversationsDouble(): ConversationsRepository {
    const world = this;
    const findConversation = (owner: Owner, id: bigint) =>
      world.conversations.find((c) => c.id === id && world.owns(owner, c) && world.live(c));
    const purge = (organizationId: bigint, ids: readonly bigint[], now: Date) => {
      for (const m of world.messages)
        if (m.organizationId === organizationId && ids.includes(m.conversationId)) m.content = null;
      for (const t of world.turns)
        if (t.organizationId === organizationId && ids.includes(t.conversationId))
          t.providerTranscript = null;
      for (const e of world.executions)
        if (e.organizationId === organizationId && ids.includes(e.conversationId)) {
          e.resultCard = null;
          e.resultRefs = null;
          e.nextCursor = null;
        }
      for (const k of world.confirmations)
        if (k.organizationId === organizationId && ids.includes(k.conversationId)) {
          k.request = null;
          k.preconditions = null;
          k.summary = null;
        }
      for (const c of world.conversations)
        if (c.organizationId === organizationId && ids.includes(c.id)) {
          c.title = null;
          c.contentPurgedAt = now;
        }
    };
    const turnRow = (t: StoredTurn): TurnRow => {
      const { providerTranscript: _a, promptVersion: _b, registryVersion: _c, ...row } = t;
      return clone(row);
    };
    return {
      create: (
        owner: Owner,
        data: {
          publicId: string;
          title: string | null;
          platformOverrideId: string | null;
          now: Date;
          purgeAfter: Date;
        },
      ) => {
        const row = world.addConversation(owner, {
          publicId: data.publicId,
          title: data.title,
          platformOverrideId: data.platformOverrideId,
          lastTurnAt: data.now,
          purgeAfter: data.purgeAfter,
          createdAt: data.now,
          updatedAt: data.now,
        });
        return Promise.resolve(clone(row));
      },
      countLive: (owner: Owner) =>
        Promise.resolve(
          world.conversations.filter((c) => world.owns(owner, c) && world.live(c)).length,
        ),
      findOwned: (owner: Owner, publicId: string) => {
        const row = world.conversations.find(
          (c) => c.publicId === publicId && world.owns(owner, c) && world.live(c),
        );
        return Promise.resolve(row ? clone(row) : null);
      },
      list: (owner: Owner, filter: ConversationListFilter) => {
        const rows = world.conversations
          .filter((c) => world.owns(owner, c) && filter.statuses.includes(c.status))
          .filter(
            (c) =>
              filter.titleContains === undefined ||
              (c.title ?? '').toLowerCase().includes(filter.titleContains.toLowerCase()),
          )
          .filter((c) => {
            if (!filter.after) return true;
            const at = c.lastTurnAt!.getTime();
            const cut = filter.after.lastTurnAt.getTime();
            return at < cut || (at === cut && c.id < filter.after.id);
          })
          .sort((a, b) => later(a.lastTurnAt, b.lastTurnAt) || (b.id > a.id ? 1 : -1))
          .slice(0, filter.take);
        return Promise.resolve(rows.map(clone));
      },
      update: (
        owner: Owner,
        id: bigint,
        data: { title?: string; status?: 'active' | 'archived' },
      ) => {
        const row = findConversation(owner, id);
        if (row)
          Object.assign(row, data, { rowVersion: row.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve();
      },
      deleteAndPurge: (owner: Owner, id: bigint, now: Date) => {
        const row = findConversation(owner, id);
        if (!row) return Promise.resolve(false);
        row.status = 'deleted';
        purge(owner.scope.organizationId, [id], now);
        return Promise.resolve(true);
      },
      purgeContent: (organizationId: bigint, ids: readonly bigint[], now: Date) => {
        purge(organizationId, ids, now);
        return Promise.resolve();
      },
      lockDueForContentPurge: (organizationId: bigint, ids: readonly bigint[], now: Date) =>
        Promise.resolve(
          world.conversations
            .filter(
              (c) =>
                c.organizationId === organizationId &&
                ids.includes(c.id) &&
                c.purgeAfter !== null &&
                c.purgeAfter <= now &&
                c.contentPurgedAt === null,
            )
            .map((c) => c.id),
        ),
      shortenRetention: (organizationId: bigint, retentionDays: number) => {
        let changed = 0;
        for (const c of world.conversations) {
          if (c.organizationId !== organizationId || c.contentPurgedAt !== null) continue;
          const target = new Date(
            (c.lastTurnAt ?? c.createdAt).getTime() + retentionDays * 86_400_000,
          );
          if (c.purgeAfter === null || c.purgeAfter > target) {
            c.purgeAfter = target;
            changed += 1;
          }
        }
        return Promise.resolve(changed);
      },
      findTurnByClientId: (
        conversationId: bigint,
        organizationId: bigint,
        clientTurnId: string,
      ) => {
        const t = world.turns.find(
          (x) =>
            x.conversationId === conversationId &&
            x.organizationId === organizationId &&
            x.clientTurnId === clientTurnId,
        );
        return Promise.resolve(t ? turnRow(t) : null);
      },
      findOwnedTurn: (owner: Owner, publicId: string) => {
        const t = world.turns.find((x) => x.publicId === publicId && world.owns(owner, x));
        const c = t && world.conversations.find((x) => x.id === t.conversationId && world.live(x));
        return Promise.resolve(t && c ? { ...turnRow(t), conversationPublicId: c.publicId } : null);
      },
      startTurn: (owner: Owner, conversation: { id: bigint }, data: TurnStart) => {
        world.log.push('startTurn');
        const c = findConversation(owner, conversation.id);
        if (!c || c.turnCount !== data.seq - 1) return Promise.resolve(null);
        if (
          world.turns.some(
            (t) =>
              t.conversationId === c.id &&
              (t.clientTurnId === data.clientTurnId || t.seq === data.seq),
          )
        ) {
          return Promise.resolve(null);
        }
        c.turnCount = data.seq;
        c.status = 'active';
        c.purgeAfter = data.purgeAfter;
        c.contentPurgedAt = null;
        const turn: StoredTurn = {
          id: world.id(),
          publicId: data.publicId,
          conversationId: c.id,
          organizationId: owner.scope.organizationId,
          userId: owner.userId,
          seq: data.seq,
          segment: data.segment,
          clientTurnId: data.clientTurnId,
          status: 'running',
          provider: data.provider,
          model: data.model,
          responseModel: null,
          rounds: 0,
          toolCalls: 0,
          inputTokens: 0,
          outputTokens: 0,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          costMicros: null,
          latencyMs: null,
          errorCode: null,
          correlationId: data.correlationId,
          startedAt: data.startedAt,
          finishedAt: null,
          providerTranscript: null,
          promptVersion: data.promptVersion,
          registryVersion: data.registryVersion,
        };
        world.turns.push(turn);
        world.messages.push({
          id: world.id(),
          publicId: data.userMessagePublicId,
          conversationId: c.id,
          turnId: turn.id,
          organizationId: owner.scope.organizationId,
          seq: userMessageSeq(data.seq),
          role: 'user',
          content: data.userMessage,
          createdAt: data.startedAt,
        });
        return Promise.resolve(turnRow(turn));
      },
      finishTurn: (
        owner: Owner,
        turn: { id: bigint; seq: number; conversationId: bigint },
        data: TurnFinish,
        conversation: { purgeAfter: Date; lastTurnAt: Date; title: string | null },
      ) => {
        world.log.push('finishTurn');
        const t = world.turns.find((x) => x.id === turn.id && world.owns(owner, x));
        if (!t || t.status !== 'running') return Promise.resolve(false);
        Object.assign(t, {
          status: data.status,
          segment: data.segment,
          responseModel: data.responseModel,
          rounds: data.rounds,
          toolCalls: data.toolCalls,
          inputTokens: data.inputTokens,
          outputTokens: data.outputTokens,
          cacheReadTokens: data.cacheReadTokens,
          cacheWriteTokens: data.cacheWriteTokens,
          costMicros: data.costMicros,
          latencyMs: data.latencyMs,
          errorCode: data.errorCode,
          providerTranscript: data.providerTranscript,
          finishedAt: data.finishedAt,
        });
        if (data.assistantMessage) {
          world.messages.push({
            id: world.id(),
            publicId: data.assistantMessage.publicId,
            conversationId: t.conversationId,
            turnId: t.id,
            organizationId: t.organizationId,
            seq: assistantMessageSeq(t.seq),
            role: 'assistant',
            content: data.assistantMessage.content,
            createdAt: data.finishedAt,
          });
        }
        const c = world.conversations.find((x) => x.id === t.conversationId);
        if (c && c.status !== 'deleted') {
          c.lastTurnAt = conversation.lastTurnAt;
          c.purgeAfter = conversation.purgeAfter;
          c.contentPurgedAt = null;
          c.segment = data.conversationSegment;
          if (c.title === null && conversation.title !== null) c.title = conversation.title;
        }
        return Promise.resolve(true);
      },
      findTurn: (owner: Owner, id: bigint) => {
        const t = world.turns.find((x) => x.id === id && world.owns(owner, x));
        return Promise.resolve(t ? turnRow(t) : null);
      },
      segmentTranscripts: (owner: Owner, conversationId: bigint, segment: number) =>
        Promise.resolve(
          world.turns
            .filter(
              (t) =>
                world.owns(owner, t) &&
                t.conversationId === conversationId &&
                t.segment === segment &&
                t.status === 'completed',
            )
            .sort((a, b) => a.seq - b.seq)
            .map((t) => ({ seq: t.seq, providerTranscript: t.providerTranscript })),
        ),
      recentUserMessages: (owner: Owner, conversationId: bigint, take: number) =>
        Promise.resolve(
          world.messages
            .filter(
              (m) =>
                m.organizationId === owner.scope.organizationId &&
                m.conversationId === conversationId &&
                m.role === 'user' &&
                m.content !== null,
            )
            .sort((a, b) => a.seq - b.seq)
            .slice(-take)
            .map((m) => m.content ?? ''),
        ),
      listMessages: (
        owner: Owner,
        conversationId: bigint,
        afterSeq: number | undefined,
        take: number,
      ) =>
        Promise.resolve(
          world.messages
            .filter(
              (m) =>
                m.organizationId === owner.scope.organizationId &&
                m.conversationId === conversationId &&
                (afterSeq === undefined || m.seq > afterSeq),
            )
            .sort((a, b) => a.seq - b.seq)
            .slice(0, take)
            .map((m) => {
              const t = world.turns.find((x) => x.id === m.turnId)!;
              return {
                ...clone(m),
                turn: {
                  id: t.id,
                  publicId: t.publicId,
                  status: t.status,
                  errorCode: t.errorCode,
                  seq: t.seq,
                },
              };
            }),
        ),
      turnMessages: (owner: Owner, turnId: bigint) =>
        Promise.resolve(
          world.messages
            .filter((m) => m.organizationId === owner.scope.organizationId && m.turnId === turnId)
            .sort((a, b) => a.seq - b.seq)
            .map(clone),
        ),
      dueForContentPurge: (now: Date, take: number) =>
        Promise.resolve(
          world.conversations
            .filter(
              (c) => c.purgeAfter !== null && c.purgeAfter <= now && c.contentPurgedAt === null,
            )
            .slice(0, take)
            .map((c) => ({ id: c.id, organizationId: c.organizationId })),
        ),
      staleRunningTurns: (before: Date, take: number) =>
        Promise.resolve(
          world.turns
            .filter((t) => t.status === 'running' && t.startedAt < before)
            .slice(0, take)
            .map((t) => ({
              id: t.id,
              publicId: t.publicId,
              organizationId: t.organizationId,
              conversationPublicId: world.conversations.find((c) => c.id === t.conversationId)!
                .publicId,
            })),
        ),
      abandonTurn: (id: bigint, code: string, now: Date) => {
        const t = world.turns.find((x) => x.id === id && x.status === 'running');
        if (!t) return Promise.resolve(false);
        Object.assign(t, { status: 'failed', errorCode: code, finishedAt: now });
        return Promise.resolve(true);
      },
      deleteMessagesBefore: (before: Date, batch: number) =>
        Promise.resolve(
          world.deleteWhere('messages', (m: MessageRow) => m.createdAt < before, batch),
        ),
      deleteTurnsBefore: (before: Date, batch: number) =>
        Promise.resolve(
          world.deleteWhere(
            'turns',
            (t: StoredTurn) =>
              t.startedAt < before &&
              t.status !== 'running' &&
              !world.messages.some((m) => m.turnId === t.id) &&
              !world.executions.some((e) => e.turnId === t.id),
            batch,
          ),
        ),
      deleteConversationsBefore: (before: Date, batch: number) =>
        Promise.resolve(
          world.deleteWhere(
            'conversations',
            (c: StoredConversation) =>
              (c.lastTurnAt ?? c.createdAt) < before &&
              !world.turns.some((t) => t.conversationId === c.id) &&
              !world.executions.some((e) => e.conversationId === c.id),
            batch,
          ),
        ),
    } as unknown as ConversationsRepository;
  }

  /** Deletes at most `batch` rows of a table matching `predicate`; returns how many. */
  deleteWhere<K extends 'messages' | 'turns' | 'conversations' | 'executions' | 'usage'>(
    table: K,
    predicate: (row: never) => boolean,
    batch: number,
  ): number {
    const rows = this[table] as unknown[];
    let deleted = 0;
    const kept = rows.filter((row) => {
      if (deleted < batch && predicate(row as never)) {
        deleted += 1;
        return false;
      }
      return true;
    });
    (this as unknown as Record<string, unknown[]>)[table] = kept;
    return deleted;
  }

  // ---- executions ----------------------------------------------------------------------------

  withRefs(row: StoredExecution): ExecutionWithRefs {
    return {
      ...clone(row),
      conversationPublicId: this.conversations.find((c) => c.id === row.conversationId)!.publicId,
      turnPublicId:
        row.turnId === null
          ? null
          : (this.turns.find((t) => t.id === row.turnId)?.publicId ?? null),
      parentPublicId:
        row.parentExecutionId === null
          ? null
          : (this.executions.find((e) => e.id === row.parentExecutionId)?.publicId ?? null),
    };
  }

  executionsDouble(): ExecutionsRepository {
    const world = this;
    return {
      nextSeq: (owner: Owner, conversationId: bigint) =>
        Promise.resolve(
          world.executions
            .filter(
              (e) =>
                e.organizationId === owner.scope.organizationId &&
                e.conversationId === conversationId,
            )
            .reduce((max, e) => Math.max(max, e.seq), 0) + 1,
        ),
      create: (owner: Owner, data: ExecutionCreate) => {
        world.log.push(`execution:${data.decision}`);
        if (
          world.executions.some(
            (e) => e.conversationId === data.conversationId && e.seq === data.seq,
          )
        ) {
          throw new Error('duplicate (conversation_id, seq)');
        }
        const id = world.id();
        world.executions.push({
          id,
          ...clone({
            ...data,
            paramsRedacted: data.paramsRedacted ?? null,
            resultCard: data.resultCard ?? null,
            resultRefs: data.resultRefs ?? null,
          }),
          organizationId: owner.scope.organizationId,
          userId: owner.userId,
        } as StoredExecution);
        return Promise.resolve(id);
      },
      refsOf: (owner: Owner, conversationId: bigint, seq: number) =>
        Promise.resolve(
          world.executions.find(
            (e) => world.owns(owner, e) && e.conversationId === conversationId && e.seq === seq,
          )?.resultRefs ?? null,
        ),
      findOwned: (owner: Owner, publicId: string) => {
        const row = world.executions.find((e) => e.publicId === publicId && world.owns(owner, e));
        const c =
          row && world.conversations.find((x) => x.id === row.conversationId && world.live(x));
        return Promise.resolve(row && c ? world.withRefs(row) : null);
      },
      forTurns: (owner: Owner, conversationId: bigint, turnIds: readonly bigint[]) =>
        Promise.resolve(
          world.executions
            .filter(
              (e) =>
                world.owns(owner, e) &&
                e.conversationId === conversationId &&
                (e.turnId === null || turnIds.includes(e.turnId)),
            )
            .sort((a, b) => a.seq - b.seq)
            .map((e) => world.withRefs(e)),
        ),
      recapRows: (owner: Owner, conversationId: bigint, take: number) =>
        Promise.resolve(
          world.executions
            .filter((e) => world.owns(owner, e) && e.conversationId === conversationId)
            .sort((a, b) => a.seq - b.seq)
            .slice(-take)
            .map(clone),
        ),
      publicIdOf: (owner: Owner, id: bigint) =>
        Promise.resolve(
          world.executions.find((e) => e.id === id && world.owns(owner, e))?.publicId ?? null,
        ),
      deleteBefore: (before: Date, batch: number) => {
        const deleted = world.deleteWhere(
          'executions',
          (e: StoredExecution) => e.createdAt < before,
          batch,
        );
        // FK cascade: a confirmation goes with its proposal execution.
        world.confirmations = world.confirmations.filter((k) =>
          world.executions.some((e) => e.id === k.executionId),
        );
        return Promise.resolve(deleted);
      },
    } as unknown as ExecutionsRepository;
  }

  // ---- confirmations (step AI-2) -------------------------------------------------------------

  confirmationWithRefs(row: StoredConfirmation): ConfirmationWithRefs {
    const execution = this.executions.find((e) => e.id === row.executionId)!;
    return {
      ...clone(row),
      conversationPublicId: this.conversations.find((c) => c.id === row.conversationId)!.publicId,
      executionPublicId: execution.publicId,
      executionSeq: execution.seq,
      resultExecutionPublicId:
        row.resultExecutionId === null
          ? null
          : (this.executions.find((e) => e.id === row.resultExecutionId)?.publicId ?? null),
    };
  }

  private swept(row: StoredConfirmation): SweptConfirmation {
    const refs = this.confirmationWithRefs(row);
    return {
      id: row.id,
      publicId: row.publicId,
      organizationId: row.organizationId,
      conversationPublicId: refs.conversationPublicId,
      executionPublicId: refs.executionPublicId,
      toolName: row.toolName,
      operationId: row.operationId,
      risk: row.risk,
      requiresReauth: row.requiresReauth,
      createdAt: row.createdAt,
    };
  }

  confirmationsDouble(): ConfirmationsRepository {
    const world = this;
    const owned = (owner: Owner, id: bigint) =>
      world.confirmations.find((k) => k.id === id && world.owns(owner, k));
    const move = (
      row: StoredConfirmation | undefined,
      when: (k: StoredConfirmation) => boolean,
      data: Partial<StoredConfirmation>,
    ): number => {
      if (!row || !when(row)) return 0;
      Object.assign(row, data, { updatedAt: new Date() });
      return 1;
    };
    return {
      create: (owner: Owner, data: ConfirmationCreate) => {
        world.log.push('confirmation');
        if (world.confirmations.some((k) => k.executionId === data.executionId)) {
          throw new Error('duplicate (execution_id)');
        }
        const id = world.id();
        world.confirmations.push({
          id,
          ...clone(data),
          organizationId: owner.scope.organizationId,
          userId: owner.userId,
          resultExecutionId: null,
          status: 'pending',
          failedAttempts: 0,
          reauthUsed: false,
          decidedAt: null,
          executionStartedAt: null,
          executedAt: null,
          reportedAt: null,
          resultHttpStatus: null,
          errorCode: null,
          updatedAt: data.createdAt,
        } as StoredConfirmation);
        return Promise.resolve(id);
      },
      findOwned: (owner: Owner, overrideId: string | null, publicId: string) => {
        const row = world.confirmations.find(
          (k) =>
            k.publicId === publicId &&
            world.owns(owner, k) &&
            k.platformOverrideId === overrideId &&
            world.conversations.some((c) => c.id === k.conversationId && world.live(c)),
        );
        return Promise.resolve(row ? world.confirmationWithRefs(row) : null);
      },
      reload: (owner: Owner, id: bigint) => {
        const row = owned(owner, id);
        return Promise.resolve(row ? world.confirmationWithRefs(row) : null);
      },
      forExecutions: (owner: Owner, executionIds: readonly bigint[]) =>
        Promise.resolve(
          world.confirmations
            .filter((k) => world.owns(owner, k) && executionIds.includes(k.executionId))
            .map((k) => world.confirmationWithRefs(k)),
        ),
      countLivePending: (owner: Owner, conversationId: bigint, now: Date) =>
        Promise.resolve(
          world.confirmations.filter(
            (k) =>
              k.organizationId === owner.scope.organizationId &&
              k.conversationId === conversationId &&
              k.status === 'pending' &&
              k.expiresAt > now,
          ).length,
        ),
      beginExecuting: (owner: Owner, id: bigint, now: Date, reauthUsed: boolean) =>
        Promise.resolve(
          move(owned(owner, id), (k) => k.status === 'pending' && k.expiresAt > now, {
            status: 'executing',
            decidedAt: now,
            ...(reauthUsed && { reauthUsed: true }),
          }),
        ),
      claimExecution: (owner: Owner, id: bigint, now: Date) =>
        Promise.resolve(
          move(owned(owner, id), (k) => k.status === 'executing' && k.executionStartedAt === null, {
            executionStartedAt: now,
          }),
        ),
      reconcileOutcomeUnknown: (owner: Owner, id: bigint, code: string, data: ConfirmationFinish) =>
        Promise.resolve(
          move(
            owned(owner, id),
            (k) =>
              k.status === 'failed' &&
              k.errorCode === code &&
              k.resultExecutionId === null &&
              k.executionStartedAt !== null,
            {
              status: data.status,
              resultExecutionId: data.resultExecutionId,
              resultHttpStatus: data.resultHttpStatus,
              errorCode: data.errorCode,
              executedAt: data.executedAt,
              reportedAt: null,
            },
          ),
        ),
      finish: (owner: Owner, id: bigint, data: ConfirmationFinish) =>
        Promise.resolve(
          move(owned(owner, id), (k) => k.status === 'executing', {
            status: data.status,
            resultExecutionId: data.resultExecutionId,
            resultHttpStatus: data.resultHttpStatus,
            errorCode: data.errorCode,
            executedAt: data.executedAt,
          }),
        ),
      fail: (owner: Owner, id: bigint, errorCode: string, now: Date) =>
        Promise.resolve(
          move(owned(owner, id), (k) => k.status === 'pending' || k.status === 'executing', {
            status: 'failed',
            errorCode,
            decidedAt: now,
          }),
        ),
      cancel: (
        owner: Owner,
        id: bigint,
        now: Date,
        _tx: unknown,
        errorCode: string | null = null,
      ) =>
        Promise.resolve(
          move(owned(owner, id), (k) => k.status === 'pending', {
            status: 'cancelled',
            decidedAt: now,
            errorCode,
          }),
        ),
      expire: (owner: Owner, id: bigint, now: Date) =>
        Promise.resolve(
          move(owned(owner, id), (k) => k.status === 'pending' && k.expiresAt <= now, {
            status: 'expired',
            decidedAt: now,
          }),
        ),
      incrementFailedAttempts: (owner: Owner, id: bigint) => {
        const row = owned(owner, id);
        if (!row || row.status !== 'pending') return Promise.resolve(0);
        row.failedAttempts += 1;
        return Promise.resolve(row.failedAttempts);
      },
      unreported: (owner: Owner, conversationId: bigint, take: number) => {
        const rows = world.confirmations
          .filter(
            (k) =>
              world.owns(owner, k) &&
              k.conversationId === conversationId &&
              ['executed', 'failed', 'cancelled', 'expired'].includes(k.status) &&
              k.reportedAt === null,
          )
          .sort(
            (a, b) =>
              (a.decidedAt?.getTime() ?? 0) - (b.decidedAt?.getTime() ?? 0) ||
              (a.id < b.id ? -1 : 1),
          )
          .slice(0, take);
        return Promise.resolve(
          rows.map((k): UnreportedConfirmation => {
            const result =
              k.resultExecutionId === null
                ? undefined
                : world.executions.find((e) => e.id === k.resultExecutionId);
            const refs = result?.resultRefs as Record<string, unknown> | null | undefined;
            return {
              id: k.id,
              toolName: k.toolName,
              status: k.status,
              callSeq: world.executions.find((e) => e.id === k.executionId)!.seq,
              resultHttpStatus: k.resultHttpStatus,
              errorCode: k.errorCode,
              resultSeq: result?.seq ?? null,
              resultRowRef: result !== undefined && refs != null && `r${result.seq}.1` in refs,
            };
          }),
        );
      },
      markReported: (owner: Owner, ids: readonly bigint[], now: Date) => {
        world.log.push('markReported');
        for (const k of world.confirmations)
          if (world.owns(owner, k) && ids.includes(k.id) && k.reportedAt === null)
            k.reportedAt = now;
        return Promise.resolve();
      },
      cancelPendingOfConversation: (organizationId: bigint, conversationId: bigint, now: Date) => {
        const rows = world.confirmations.filter(
          (k) =>
            k.organizationId === organizationId &&
            k.conversationId === conversationId &&
            k.status === 'pending',
        );
        for (const k of rows) Object.assign(k, { status: 'cancelled', decidedAt: now });
        return Promise.resolve(rows.map((k) => world.swept(k)));
      },
      dueToExpire: (now: Date, take: number) =>
        Promise.resolve(
          world.confirmations
            .filter((k) => k.status === 'pending' && k.expiresAt <= now)
            .slice(0, take)
            .map((k) => world.swept(k)),
        ),
      expireById: (id: bigint, now: Date) =>
        Promise.resolve(
          move(
            world.confirmations.find((k) => k.id === id),
            (k) => k.status === 'pending' && k.expiresAt <= now,
            { status: 'expired', decidedAt: now },
          ) === 1,
        ),
      staleExecuting: (cutoff: StaleExecutingCutoff, take: number) =>
        Promise.resolve(
          world.confirmations
            .filter((k) => staleExecuting(k, cutoff))
            .slice(0, take)
            .map((k) => world.swept(k)),
        ),
      failStaleById: (id: bigint, cutoff: StaleExecutingCutoff, errorCode: string) =>
        Promise.resolve(
          move(
            world.confirmations.find((k) => k.id === id),
            (k) => staleExecuting(k, cutoff),
            { status: 'failed', errorCode },
          ) === 1,
        ),
    } as unknown as ConfirmationsRepository;
  }

  // ---- usage ---------------------------------------------------------------------------------

  usageDouble(): UsageRepository {
    const world = this;
    const dayOf = (d: Date) => d.toISOString().slice(0, 10);
    return {
      add: (scope: TenantScope, delta: UsageDelta) => {
        world.log.push('usage');
        const key = dayOf(delta.day);
        let row = world.usage.find(
          (u) =>
            u.organizationId === scope.organizationId &&
            dayOf(u.day) === key &&
            u.provider === delta.provider &&
            u.model === delta.model,
        );
        if (!row) {
          row = {
            organizationId: scope.organizationId,
            day: new Date(`${key}T00:00:00.000Z`),
            provider: delta.provider,
            model: delta.model,
            turns: 0,
            inputTokens: 0n,
            outputTokens: 0n,
            cacheReadTokens: 0n,
            cacheWriteTokens: 0n,
            costMicros: 0n,
          };
          world.usage.push(row);
        }
        row.turns += 1;
        row.inputTokens += BigInt(delta.inputTokens);
        row.outputTokens += BigInt(delta.outputTokens);
        row.cacheReadTokens += BigInt(delta.cacheReadTokens);
        row.cacheWriteTokens += BigInt(delta.cacheWriteTokens);
        row.costMicros += BigInt(delta.costMicros);
        return Promise.resolve();
      },
      tenantDayTokens: (organizationId: bigint, day: Date) =>
        Promise.resolve(
          world.usage
            .filter((u) => u.organizationId === organizationId && dayOf(u.day) === dayOf(day))
            .reduce((sum, u) => sum + budgetTokens(u), 0),
        ),
      platformDayTokens: (day: Date) =>
        Promise.resolve(
          world.usage
            .filter((u) => dayOf(u.day) === dayOf(day))
            .reduce((sum, u) => sum + budgetTokens(u), 0),
        ),
      range: (scope: TenantScope, from: Date, to: Date) =>
        Promise.resolve(
          world.usage
            .filter(
              (u) => u.organizationId === scope.organizationId && u.day >= from && u.day <= to,
            )
            .map(({ organizationId: _o, ...row }) => clone(row)),
        ),
      deleteBefore: (before: Date, batch: number) =>
        Promise.resolve(
          world.deleteWhere('usage', (u: UsageDayRow) => dayOf(u.day) < dayOf(before), batch),
        ),
    } as unknown as UsageRepository;
  }
}

/** An AuditService that records entries in memory (scrub applied like the real one's input). */
export class RecordingAssistantAudit extends AuditService {
  readonly entries: AuditEntry[] = [];
  constructor() {
    super({} as never);
  }
  override record(entry: AuditEntry): Promise<void> {
    this.entries.push(structuredClone(entry));
    return Promise.resolve();
  }
}

/** The synthetic password the fake re-authentication accepts (never a real credential). */
export const REAUTH_PASSWORD = 'it-reauth-password';
/** The synthetic TOTP code the fake re-authentication accepts. */
export const REAUTH_TOTP = '123456';

/**
 * A ReauthenticationService double: `REAUTH_PASSWORD` (+ `REAUTH_TOTP` when `mfa`) succeeds;
 * `next` forces one result. Records the calls' outcomes only (never the inputs).
 */
export class FakeReauthentication extends ReauthenticationService {
  mfaEnrolled = true;
  next: ReauthenticationResult | null = null;
  readonly outcomes: ReauthenticationResult[] = [];
  constructor() {
    super({} as never, {} as never, {} as never, {} as never);
  }
  override verify(
    _principal: UserPrincipal,
    input: { password: string; totpCode?: string },
  ): Promise<ReauthenticationResult> {
    let result: ReauthenticationResult;
    if (this.next) {
      result = this.next;
      this.next = null;
    } else if (input.password !== REAUTH_PASSWORD) result = { ok: false, reason: 'password' };
    else if (this.mfaEnrolled && input.totpCode === undefined) {
      result = { ok: false, reason: 'totp_required' };
    } else if (this.mfaEnrolled && input.totpCode !== REAUTH_TOTP)
      result = { ok: false, reason: 'totp' };
    else result = { ok: true };
    this.outcomes.push(result);
    return Promise.resolve(result);
  }
}

/** A TransactionRunner that runs the function with a dummy client (in-memory doubles only). */
export const immediateAssistantRunner = {
  run: <T>(fn: (tx: never) => Promise<T>): Promise<T> => fn({} as never),
} as unknown as TransactionRunner;

export type LoopbackHandler = (call: LoopbackCall) => LoopbackResult | Promise<LoopbackResult>;

/**
 * A fake loopback dispatcher: records every call (method, path, headers it would carry) and
 * answers from handlers keyed by `METHOD path-without-query`; unknown paths answer 404.
 */
export class FakeLoopback extends LoopbackDispatcher {
  readonly calls: LoopbackCall[] = [];
  readonly handlers = new Map<string, LoopbackHandler>();

  constructor() {
    super();
    this.reset();
  }

  reset(): void {
    this.calls.length = 0;
    this.handlers.clear();
    this.on('GET /api/v1/auth/me', () => ({
      kind: 'response',
      status: 200,
      body: {
        user: {
          id: randomUUID(),
          email: 'it-user@example.test',
          displayName: 'IT User',
          status: 'active',
        },
        organization: {
          id: randomUUID(),
          slug: 'it-org',
          name: 'IT Org',
          kind: 'customer',
          serviceProfile: 'gateway',
        },
        roles: ['organization_admin'],
        permissions: [],
      },
    }));
  }

  on(key: string, handler: LoopbackHandler): this {
    this.handlers.set(key, handler);
    return this;
  }

  /** Tool calls only (not the context read of `/auth/me`). */
  get toolCalls(): LoopbackCall[] {
    return this.calls.filter((c) => c.executionId !== null);
  }

  send(call: LoopbackCall): Promise<LoopbackResult> {
    this.calls.push({ ...call });
    if (call.signal.aborted) return Promise.resolve({ kind: 'aborted' });
    const path = call.path.split('?')[0]!;
    const handler = this.handlers.get(`${call.method} ${path}`);
    if (!handler) {
      return Promise.resolve({
        kind: 'response',
        status: 404,
        body: { statusCode: 404, error: 'Not Found', code: 'not_found', message: 'Not found' },
      });
    }
    return Promise.resolve(handler(call));
  }
}

/** A synthetic page of policies as `GET /api/v1/policies` answers it. */
export function policyPage(count: number, nextCursor: string | null = null): LoopbackResult {
  return {
    kind: 'response',
    status: 200,
    body: {
      data: Array.from({ length: count }, (_, i) => ({
        id: `0193c000-0000-7000-8000-${String(i + 1).padStart(12, '0')}`,
        name: `IT policy ${i + 1}`,
        status: 'active',
        direction: 'inbound',
      })),
      nextCursor,
    },
  };
}

export const scopeOf = (organizationId: bigint): TenantScope => systemScope(organizationId);

/** Overrides the assistant repositories, features, audit and runner for the e2e suite. */
export function overrideAssistant(
  builder: TestingModuleBuilder,
  world: AssistantWorld,
  audit: RecordingAssistantAudit,
  loopback: FakeLoopback,
  reauth: ReauthenticationService = new FakeReauthentication(),
): TestingModuleBuilder {
  return builder
    .overrideProvider(ReauthenticationService)
    .useValue(reauth)
    .overrideProvider(AssistantSettingsRepository)
    .useValue(world.settingsDouble())
    .overrideProvider(ConversationsRepository)
    .useValue(world.conversationsDouble())
    .overrideProvider(ExecutionsRepository)
    .useValue(world.executionsDouble())
    .overrideProvider(ConfirmationsRepository)
    .useValue(world.confirmationsDouble())
    .overrideProvider(UsageRepository)
    .useValue(world.usageDouble())
    .overrideProvider(OrganizationFeaturesService)
    .useValue(world.featuresDouble())
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(TransactionRunner)
    .useValue(immediateAssistantRunner)
    .overrideProvider(LoopbackDispatcher)
    .useValue(loopback);
}
