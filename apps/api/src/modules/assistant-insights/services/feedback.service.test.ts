import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { InsightsMetrics } from '../insights-metrics';
import type {
  FeedbackRepository,
  FeedbackRow,
  FeedbackWrite,
  OwnedMessage,
} from '../repositories/feedback.repository';
import type { SearchOwner } from '../repositories/search.repository';
import { AssistantFeedbackService, commentOf } from './feedback.service';

const ORG = 7001n;
const user: UserPrincipal = {
  kind: 'user',
  userId: 501n,
  userPublicId: '0193b000-0000-7000-8000-000000000501',
  organizationId: ORG,
  organizationPublicId: '0193b000-0000-7000-8000-000000007001',
  organizationKind: 'customer',
  sessionId: '0193b000-0000-7000-8000-0000000000aa',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['assistant:use']),
};
const scope = systemScope(ORG);

interface StoredMessage extends OwnedMessage {
  ownerUserId: bigint;
  deleted: boolean;
  /** The conversation's content was purged. */
  purged?: boolean;
}

/** An in-memory double of the feedback repository with the owner rules of the real queries. */
function harness() {
  const messages: StoredMessage[] = [];
  const feedback: FeedbackRow[] = [];
  let nextId = 1n;
  const repo = {
    findOwnedMessage: vi.fn((owner: SearchOwner, publicId: string) =>
      Promise.resolve(
        messages.find(
          (m) =>
            m.publicId === publicId &&
            m.organizationId === owner.scope.organizationId &&
            m.ownerUserId === owner.userId &&
            !m.deleted,
        ) ?? null,
      ),
    ),
    lockContentPurged: vi.fn((organizationId: bigint, conversationId: bigint) =>
      Promise.resolve(
        messages.some(
          (m) =>
            m.organizationId === organizationId &&
            m.conversationId === conversationId &&
            m.purged === true,
        ),
      ),
    ),
    findByMessage: vi.fn((s: TenantScope, messageId: bigint) =>
      Promise.resolve(
        feedback.find((f) => f.messageId === messageId && f.organizationId === s.organizationId) ??
          null,
      ),
    ),
    upsert: vi.fn((s: TenantScope, data: FeedbackWrite) => {
      const now = new Date('2026-11-26T10:00:00.000Z');
      const existing = feedback.find((f) => f.messageId === data.messageId);
      if (existing) {
        Object.assign(existing, {
          rating: data.rating,
          reason: data.reason,
          comment: data.comment,
          updatedAt: now,
        });
        return Promise.resolve(existing);
      }
      const row: FeedbackRow = {
        id: nextId++,
        publicId: data.publicId,
        organizationId: s.organizationId,
        userId: data.userId,
        conversationId: data.conversationId,
        turnId: data.turnId,
        messageId: data.messageId,
        rating: data.rating,
        reason: data.reason,
        comment: data.comment,
        createdAt: now,
        updatedAt: now,
      };
      feedback.push(row);
      return Promise.resolve(row);
    }),
    remove: vi.fn((s: TenantScope, id: bigint) => {
      const at = feedback.findIndex((f) => f.id === id && f.organizationId === s.organizationId);
      if (at < 0) return Promise.resolve(false);
      feedback.splice(at, 1);
      return Promise.resolve(true);
    }),
  };
  const audit = {
    record: vi.fn((_entry: unknown, _tx?: unknown) => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: user.userPublicId })),
  };
  const runner = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({ tx: true })) };
  const metrics = { feedback: { inc: vi.fn() } };
  const service = new AssistantFeedbackService(
    repo as unknown as FeedbackRepository,
    runner as unknown as TransactionRunner,
    audit as unknown as AuditService,
    metrics as unknown as InsightsMetrics,
  );
  const add = (m: Partial<StoredMessage> & { publicId: string }): StoredMessage => {
    const row: StoredMessage = {
      id: nextId++,
      organizationId: ORG,
      conversationId: 10n,
      conversationPublicId: 'c-10',
      turnId: 20n,
      role: 'assistant',
      turnStatus: 'completed',
      ownerUserId: user.userId,
      deleted: false,
      ...m,
    };
    messages.push(row);
    return row;
  };
  return { service, repo, audit, runner, metrics, add, feedback };
}

describe('AssistantFeedbackService (D2)', () => {
  it('records a rating of an answer of a completed turn, then replaces it', async () => {
    const h = harness();
    h.add({ publicId: 'm-1' });
    const view = await h.service.set(
      user,
      scope,
      'm-1',
      { rating: 'down', reason: 'incomplete', comment: '  Missed\u202E one \u0007 ' },
      '198.51.100.7',
    );
    expect(view).toMatchObject({
      messageId: 'm-1',
      rating: 'down',
      reason: 'incomplete',
      comment: 'Missed one',
    });
    expect(h.runner.run).toHaveBeenCalledTimes(1);
    const updated = await h.service.set(user, scope, 'm-1', { rating: 'up' }, null);
    expect(updated).toMatchObject({ rating: 'up', reason: null, comment: null });
    expect(h.feedback).toHaveLength(1);
    expect(h.metrics.feedback.inc).toHaveBeenNthCalledWith(1, { rating: 'down' });
    expect(h.metrics.feedback.inc).toHaveBeenNthCalledWith(2, { rating: 'up' });
  });

  it('audits rating and reason with the ids, never the comment', async () => {
    const h = harness();
    h.add({ publicId: 'm-1' });
    await h.service.set(
      user,
      scope,
      'm-1',
      { rating: 'down', reason: 'unsafe', comment: 'private remark' },
      '198.51.100.7',
    );
    const [entry, tx] = h.audit.record.mock.calls[0] as unknown as [
      Record<string, unknown>,
      unknown,
    ];
    expect(entry).toMatchObject({
      organizationId: ORG,
      action: 'assistant.feedback_recorded',
      resourceType: 'assistant_feedback',
      sourceIp: '198.51.100.7',
      metadata: { messageId: 'm-1', conversationId: 'c-10', rating: 'down', reason: 'unsafe' },
    });
    expect(JSON.stringify(entry.metadata)).not.toContain('private remark');
    // The audit row is written in the same transaction as the rating.
    expect(tx).toEqual({ tx: true });
  });

  it('answers 404 for another user, a deleted conversation or a user message', async () => {
    const h = harness();
    h.add({ publicId: 'm-other', ownerUserId: 999n });
    h.add({ publicId: 'm-deleted', deleted: true });
    h.add({ publicId: 'm-user', role: 'user' });
    h.add({ publicId: 'm-org', organizationId: 8002n });
    for (const id of ['m-other', 'm-deleted', 'm-user', 'm-org', 'm-unknown']) {
      await expect(h.service.set(user, scope, id, { rating: 'up' }, null)).rejects.toMatchObject({
        code: 'assistant_message_not_found',
        status: 404,
      });
    }
    expect(h.repo.upsert).not.toHaveBeenCalled();
    expect(h.audit.record).not.toHaveBeenCalled();
  });

  it('answers 409 for an answer whose turn did not complete', async () => {
    const h = harness();
    for (const turnStatus of ['failed', 'cancelled', 'running'] as const) {
      h.add({ publicId: `m-${turnStatus}`, turnStatus });
      await expect(
        h.service.set(user, scope, `m-${turnStatus}`, { rating: 'up' }, null),
      ).rejects.toMatchObject({ code: 'assistant_feedback_not_allowed', status: 409 });
    }
    expect(h.repo.upsert).not.toHaveBeenCalled();
  });

  it('removes a rating (audited) and answers 404 when there is none', async () => {
    const h = harness();
    h.add({ publicId: 'm-1' });
    await h.service.set(user, scope, 'm-1', { rating: 'up', reason: 'other' }, null);
    await h.service.remove(user, scope, 'm-1', '198.51.100.7');
    expect(h.feedback).toHaveLength(0);
    expect(h.audit.record).toHaveBeenLastCalledWith(
      expect.objectContaining({
        action: 'assistant.feedback_removed',
        metadata: { messageId: 'm-1', conversationId: 'c-10', rating: 'up', reason: 'other' },
      }),
      expect.anything(),
    );
    await expect(h.service.remove(user, scope, 'm-1', null)).rejects.toMatchObject({
      code: 'assistant_message_not_found',
    });
    h.add({ publicId: 'm-other', ownerUserId: 999n });
    await expect(h.service.remove(user, scope, 'm-other', null)).rejects.toMatchObject({
      code: 'assistant_message_not_found',
    });
  });
});

describe('commentOf', () => {
  it('sanitizes like user text, keeps lines, caps at 500 and treats blank as none', () => {
    expect(commentOf(undefined)).toBeNull();
    expect(commentOf(' \u200B \n ')).toBeNull();
    expect(commentOf('line one\nline\u202E two')).toBe('line one\nline two');
    expect(Array.from(commentOf('é'.repeat(600))!)).toHaveLength(500);
  });

  it('answers 409 for an answer of a conversation whose content was purged (the comment would survive the purge)', async () => {
    const h = harness();
    h.add({ publicId: 'm-purged', conversationId: 77n, purged: true });
    await expect(
      h.service.set(user, scope, 'm-purged', { rating: 'down', comment: 'kept forever?' }, null),
    ).rejects.toMatchObject({
      code: 'assistant_feedback_not_allowed',
      status: 409,
      message: 'Answers of a conversation whose content was purged cannot be rated',
    });
    expect(h.repo.lockContentPurged).toHaveBeenCalledWith(ORG, 77n, { tx: true });
    expect(h.repo.upsert).not.toHaveBeenCalled();
    expect(h.audit.record).not.toHaveBeenCalled();
  });
});
