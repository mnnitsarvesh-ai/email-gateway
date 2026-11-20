import { describe, expect, it } from 'vitest';
import { policyPage } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import { assistantKeys } from '../assistant.constants';
import { ownerOf } from './conversation.service';

const ORG = 7001n;
const DAY = 86_400_000;

async function seeded() {
  const h = createAssistantHarness();
  h.world.enable(ORG);
  h.loopback.on('GET /api/v1/policies', () => policyPage(1));
  const owner = ownerOf(h.user, h.scope);
  const conversation = h.world.addConversation(owner);
  await h.ask(conversation.publicId, '/tool policy_management_list {}');
  return { h, owner, conversation };
}

describe('AssistantRetentionService (D7, D12)', () => {
  it('purges content at purge_after in batches and keeps the metadata', async () => {
    const { h, owner } = await seeded();
    for (let i = 0; i < 5; i += 1) {
      h.world.addConversation(owner, { title: `old ${i}`, purgeAfter: new Date(Date.now() - DAY) });
    }
    const now = new Date();
    expect(await h.retention.purgeContent(now, 2)).toBe(5);
    const purged = h.world.conversations.filter((c) => c.contentPurgedAt !== null);
    expect(purged).toHaveLength(5);
    expect(purged.every((c) => c.title === null)).toBe(true);
    // The fresh conversation keeps its content.
    const fresh = h.world.conversations[0]!;
    expect(fresh.contentPurgedAt).toBeNull();
    expect(h.world.messages.every((m) => m.content !== null)).toBe(true);

    // Past its own purge date, the fresh one loses message texts, transcripts and cards too.
    fresh.purgeAfter = new Date(now.getTime() - 1);
    expect(await h.retention.purgeContent(now)).toBe(1);
    expect(h.world.messages.every((m) => m.content === null)).toBe(true);
    expect(h.world.turns.every((t) => t.providerTranscript === null)).toBe(true);
    expect(h.world.executions.every((e) => e.resultCard === null && e.nextCursor === null)).toBe(
      true,
    );
    expect(h.world.executions[0]!.decision).toBe('allowed');
  });

  it('a conversation used again after its purge gets a new window and is purged again', async () => {
    const { h, conversation } = await seeded();
    const stored = h.world.conversations.find((c) => c.publicId === conversation.publicId)!;
    stored.purgeAfter = new Date(Date.now() - DAY);
    expect(await h.retention.purgeContent(new Date())).toBe(1);
    expect(stored.contentPurgedAt).not.toBeNull();

    // A new turn: fresh content, purge date moved forward, due for purging again.
    await h.ask(conversation.publicId, 'hello again');
    expect(stored.contentPurgedAt).toBeNull();
    const moved = h.world.conversations.find((c) => c.id === stored.id)?.purgeAfter;
    expect(moved?.getTime()).toBeGreaterThan(Date.now() + 29 * DAY);
    const fresh = h.world.messages.filter((m) => m.content !== null);
    expect(fresh.length).toBeGreaterThan(0);
    expect(await h.retention.purgeContent(new Date())).toBe(0);

    // Past the tenant's retention (default 30 days) the new content is purged too.
    expect(await h.retention.purgeContent(new Date(Date.now() + 31 * DAY))).toBe(1);
    expect(h.world.messages.every((m) => m.content === null)).toBe(true);
    expect(h.world.turns.every((t) => t.providerTranscript === null)).toBe(true);
  });

  it('skips a candidate that a turn moved out of its purge window meanwhile (locked re-check)', async () => {
    const { h, conversation } = await seeded();
    const stored = h.world.conversations.find((c) => c.publicId === conversation.publicId)!;
    stored.purgeAfter = new Date(Date.now() - DAY);
    const due = h.conversationsRepo.dueForContentPurge.bind(h.conversationsRepo);
    // The candidate list is read; then a turn starts before the purge transaction locks the row.
    h.conversationsRepo.dueForContentPurge = async (now, take) => {
      const rows = await due(now, take);
      stored.purgeAfter = new Date(Date.now() + 30 * DAY);
      return rows;
    };
    expect(await h.retention.purgeContent(new Date())).toBe(0);
    expect(stored.contentPurgedAt).toBeNull();
    expect(h.world.messages.every((m) => m.content !== null)).toBe(true);
  });

  it('hard-deletes rows older than ASSISTANT_EXECUTION_RETENTION_DAYS', async () => {
    const { h } = await seeded();
    const future = new Date(Date.now() + 401 * DAY);
    const result = await h.retention.runOnce(future);
    expect(result).toMatchObject({
      executions: 1,
      messages: 2,
      turns: 1,
      conversations: 1,
      usage: 1,
    });
    expect(h.world.conversations).toHaveLength(0);
    expect(h.world.turns).toHaveLength(0);
  });

  it('marks stale running turns failed (assistant_turn_abandoned) and releases only their lock', async () => {
    const { h, owner } = await seeded();
    const c = h.world.addConversation(owner);
    const prepared = await h.engine.prepare(
      h.user,
      h.scope,
      c.publicId,
      { clientTurnId: '0193d000-0000-7000-8000-0000000000ff', message: 'crash' },
      { authorization: 'Bearer it', clientIp: null },
    );
    expect(prepared.kind).toBe('run');
    const running = h.world.turns.find((t) => t.status === 'running')!;
    // Simulate the crash: the slot is gone with the process, the lock stays in Redis.
    expect(await h.kv.get(assistantKeys.turnLock(c.publicId))).toBe(running.publicId);
    const later = new Date(Date.now() + 90_000 + 61_000);
    expect(await h.retention.sweepStaleTurns(later)).toBe(1);
    expect(running).toMatchObject({ status: 'failed', errorCode: 'assistant_turn_abandoned' });
    expect(await h.kv.get(assistantKeys.turnLock(c.publicId))).toBeNull();
    // A lock held by a newer turn is left alone.
    await h.kv.set(assistantKeys.turnLock(c.publicId), 'another-turn', 60);
    running.status = 'running';
    await h.retention.sweepStaleTurns(later);
    expect(await h.kv.get(assistantKeys.turnLock(c.publicId))).toBe('another-turn');
    if (prepared.kind === 'run') await prepared.release();
  });

  it('runs on one replica at a time (as:jobs:lock) and only with background jobs enabled', async () => {
    const { h } = await seeded();
    await h.kv.set(assistantKeys.jobsLock, 'other', 60);
    expect(await h.retention.runOnce()).toBeNull();
    const off = createAssistantHarness({ ASSISTANT_BACKGROUND_JOBS_ENABLED: 'false' });
    off.retention.onApplicationBootstrap();
    expect(off.retention.scheduled).toBe(false);
    h.retention.onApplicationBootstrap();
    expect(h.retention.scheduled).toBe(true);
    await h.retention.onModuleDestroy();
    expect(h.retention.scheduled).toBe(false);
  });
});
