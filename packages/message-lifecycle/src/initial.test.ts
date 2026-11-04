import { describe, expect, it, vi } from 'vitest';
import type { Prisma } from '@email-gateway/database';
import { decideTransition } from './decide';
import { initialLifecycle, writeInitialHistory } from './initial';
import { transitionKeyHash } from './keys';
import type { MessageState } from './states';

/** §9 item 5: the creation rows are edges E1 and E2. */

const at = new Date('2026-11-04T10:00:00.000Z');
const input = {
  messageId: 12_345n,
  receivedAt: at,
  organizationId: 7n,
  causationEventId: '0190f0a0-0000-7000-8000-000000000001',
  correlationId: 'lmtp:4jKFxV5fmHz12JnW',
  service: 'smtp-adapter',
  at,
};

describe('initialLifecycle (L5.2)', () => {
  it('creates the row persisted, version 1, round 0, reason committed', () => {
    expect(initialLifecycle(input).messageFields).toEqual({
      status: 'persisted',
      version: 1,
      lifecycleRound: 0,
      statusReason: 'committed',
      statusChangedAt: at,
    });
  });

  it('writes E1 and E2 rows that decideTransition accepts in order', () => {
    const { historyRows } = initialLifecycle(input);
    expect(historyRows).toHaveLength(2);
    let current: { state: MessageState | null; version: number; round: number } = {
      state: null,
      version: -1,
      round: 0,
    };
    historyRows.forEach((row, index) => {
      expect(row).toMatchObject({
        receivedAt: at,
        messageId: 12_345n,
        organizationId: 7n,
        version: index,
        lifecycleRound: 0,
        actorRole: 'ingestion',
        actorService: 'smtp-adapter',
        actorType: 'system',
        actorId: null,
        eventId: input.causationEventId,
        correlationId: input.correlationId,
        stateEventId: null,
        occurredAt: at,
        changedAt: at,
      });
      expect(row.fromStatus ?? null).toBe(current.state);
      const decision = decideTransition(current, {
        to: row.toStatus,
        reason: row.reasonCode as 'smtp_accepted' | 'committed',
        actor: { role: 'ingestion' },
      });
      expect(decision.result).toBe('apply');
      expect(decision.result === 'apply' && decision.edge.id).toBe(index === 0 ? 'E1' : 'E2');
      current = { state: row.toStatus, version: index, round: 0 };
    });
    expect(historyRows.map((r) => [r.toStatus, r.reasonCode])).toEqual([
      ['received', 'smtp_accepted'],
      ['persisted', 'committed'],
    ]);
    expect(historyRows.map((r) => r.transitionKey)).toEqual([
      transitionKeyHash('ingest:12345:received'),
      transitionKeyHash('ingest:12345:persisted'),
    ]);
  });

  it('writeInitialHistory issues one createMany with both rows', async () => {
    const createMany = vi.fn().mockResolvedValue({ count: 2 });
    const tx = { emailMessageStatusHistory: { createMany } } as unknown as Prisma.TransactionClient;
    const init = initialLifecycle(input);
    await writeInitialHistory(tx, init);
    expect(createMany).toHaveBeenCalledTimes(1);
    expect(createMany).toHaveBeenCalledWith({ data: init.historyRows });
  });
});
