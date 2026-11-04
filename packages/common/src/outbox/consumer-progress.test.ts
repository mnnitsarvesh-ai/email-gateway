import { describe, expect, it } from 'vitest';
import { PrismaConsumerProgress } from './consumer-progress';

function capture() {
  const calls: { sql: string; values: unknown[] }[] = [];
  const prisma = {
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      calls.push({ sql: strings.join('?'), values });
      return Promise.resolve(1);
    },
  };
  return { calls, prisma: prisma as never };
}

describe('PrismaConsumerProgress', () => {
  it('upserts one row per (consumer, event_id) in one statement', async () => {
    const { calls, prisma } = capture();
    await new PrismaConsumerProgress(prisma).record({
      consumer: 'delivery-worker.planner',
      eventId: '01936b2e-7c4f-7a3b-9c1d-000000000001',
      state: 'dead_lettered',
      reason: 'max_attempts_exceeded',
      attempt: 10,
      transientRetries: 2,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.sql).toMatch(/INSERT INTO message_consumer_progress/);
    expect(calls[0]?.sql).toMatch(/ON DUPLICATE KEY UPDATE/);
    expect(calls[0]?.values).toEqual([
      'delivery-worker.planner',
      '01936b2e-7c4f-7a3b-9c1d-000000000001',
      'dead_lettered',
      'max_attempts_exceeded',
      10,
      2,
    ]);
  });

  it('stores only well-formed reason codes and non-negative counters', async () => {
    const { calls, prisma } = capture();
    await new PrismaConsumerProgress(prisma).record({
      consumer: 'c',
      eventId: 'e',
      state: 'retrying',
      reason: 'Some Text With Spaces',
      attempt: -1,
      transientRetries: 1.7,
    });
    expect(calls[0]?.values.slice(3)).toEqual([null, 0, 1]);
  });
});
