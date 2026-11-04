import { BadRequestException } from '@nestjs/common';
import type { RecipientStatus } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import { encodeHistoryCursor } from '../domain/lifecycle-operations';
import type {
  LifecycleHistoryRow,
  LifecycleMessageRow,
  MessageLifecycleReadRepository,
  ParseRow,
} from '../repositories/message-lifecycle-read.repository';
import { MessageLifecycleReadService } from './message-lifecycle-read.service';

const scope = systemScope(5n);
const receivedAt = new Date('2026-11-04T08:00:00.000Z');

const message: LifecycleMessageRow = {
  id: 42n,
  publicId: '0195f3c1-7a2b-7c3d-8e4f-000000000042',
  receivedAt,
  direction: 'inbound',
  status: 'delivered',
  statusReason: 'delivery_partial',
  version: 5,
  lifecycleRound: 0,
  statusChangedAt: new Date('2026-11-04T08:05:00.000Z'),
};

const row = (
  version: number,
  overrides: Partial<LifecycleHistoryRow> = {},
): LifecycleHistoryRow => ({
  id: BigInt(100 + version),
  version,
  fromStatus: version === 0 ? null : 'persisted',
  toStatus: version === 0 ? 'received' : 'approved',
  reasonCode: 'dev_passthrough',
  lifecycleRound: 0,
  actorRole: 'dev_passthrough',
  actorType: 'system',
  actorService: 'delivery-worker',
  actorId: null,
  eventId: null,
  correlationId: null,
  occurredAt: null,
  changedAt: new Date(receivedAt.getTime() + version * 1000),
  ...overrides,
});

function fakeRepository(options: {
  message?: LifecycleMessageRow | null;
  parse?: ParseRow | null;
  counts?: Array<[RecipientStatus, number]>;
  maxDeliverySeq?: number | null;
  history?: LifecycleHistoryRow[];
}) {
  const calls: Array<{ take: number; afterVersion?: number }> = [];
  const repository = {
    findMessage: (s: { organizationId: bigint }, publicId: string) =>
      Promise.resolve(
        options.message === null || s.organizationId !== 5n
          ? null
          : publicId === message.publicId
            ? (options.message ?? message)
            : null,
      ),
    parseOf: () => Promise.resolve(options.parse ?? null),
    recipientCounts: () => Promise.resolve(new Map(options.counts ?? [])),
    maxDeliverySeq: () => Promise.resolve(options.maxDeliverySeq ?? null),
    history: (_s: unknown, _m: unknown, page: { take: number; afterVersion?: number }) => {
      calls.push(page);
      const rows = (options.history ?? [])
        .filter((r) => page.afterVersion === undefined || r.version > page.afterVersion)
        .sort((a, b) => a.version - b.version);
      return Promise.resolve(rows.slice(0, page.take));
    },
  } as unknown as MessageLifecycleReadRepository;
  return { repository, calls };
}

describe('MessageLifecycleReadService.lifecycle (L12)', () => {
  it('returns the state, counts, parse stage, delivery sequence and allowed actions', async () => {
    const { repository } = fakeRepository({
      parse: { status: 'parsed', completedAt: new Date('2026-11-04T08:00:02.000Z') },
      counts: [
        ['delivered', 2],
        ['bounced', 1],
        ['pending', 0],
      ],
      maxDeliverySeq: 0,
    });
    const view = await new MessageLifecycleReadService(repository).lifecycle(
      scope,
      message.publicId,
    );
    expect(view).toEqual({
      messageId: message.publicId,
      receivedAt: receivedAt.toISOString(),
      direction: 'inbound',
      state: 'delivered',
      statusReason: 'delivery_partial',
      version: 5,
      lifecycleRound: 0,
      statusChangedAt: '2026-11-04T08:05:00.000Z',
      parse: { status: 'parsed', completedAt: '2026-11-04T08:00:02.000Z' },
      recipients: { total: 3, byStatus: { bounced: 1, delivered: 2 } },
      deliverySeq: 0,
      actions: { rescan: false, release: false },
    });
    expect(JSON.stringify(view)).not.toContain('"42"');
  });

  it('shows the actions of a quarantined message and nulls before parse and planning', async () => {
    const { repository } = fakeRepository({
      message: { ...message, status: 'quarantined', statusReason: null },
      counts: [['quarantined', 1]],
    });
    const view = await new MessageLifecycleReadService(repository).lifecycle(
      scope,
      message.publicId,
    );
    expect(view).toMatchObject({
      state: 'quarantined',
      parse: null,
      deliverySeq: null,
      recipients: { total: 1, byStatus: { quarantined: 1 } },
      actions: { rescan: true, release: true },
    });
  });

  it('404 message_not_found for an unknown or foreign message', async () => {
    const { repository } = fakeRepository({});
    const service = new MessageLifecycleReadService(repository);
    for (const call of [
      service.lifecycle(scope, '0195f3c1-7a2b-7c3d-8e4f-000000000999'),
      service.lifecycle(systemScope(6n), message.publicId),
      service.history(systemScope(6n), message.publicId, { limit: 10 }),
    ]) {
      const error = await call.catch((e: unknown) => e);
      expect(error).toBeInstanceOf(CodedHttpException);
      expect((error as CodedHttpException).code).toBe('message_not_found');
      expect((error as CodedHttpException).getStatus()).toBe(404);
    }
  });
});

describe('MessageLifecycleReadService.history (L12)', () => {
  const history = [
    row(1, {
      fromStatus: 'received',
      toStatus: 'persisted',
      actorRole: 'legacy',
      actorService: 'legacy',
      reasonCode: null,
    }),
    row(0, {
      actorRole: 'legacy',
      actorService: 'legacy',
      reasonCode: 'lifecycle_backfill',
      id: 900n,
    }),
    row(2, {
      actorRole: 'operator',
      actorType: 'user',
      actorService: 'api',
      actorId: 'u-1',
      lifecycleRound: 1,
      correlationId: 'api:c',
      eventId: '0195f3c1-7a2b-7c3d-8e4f-0000000000ee',
      occurredAt: new Date('2026-11-04T08:10:00.000Z'),
    }),
  ];

  it('pages oldest first by version with a cursor; legacy rows as recorded', async () => {
    const { repository, calls } = fakeRepository({ history });
    const service = new MessageLifecycleReadService(repository);
    const first = await service.history(scope, message.publicId, { limit: 2 });
    expect(first.data.map((e) => e.version)).toEqual([0, 1]);
    expect(first.data[0]).toEqual({
      version: 0,
      fromState: null,
      toState: 'received',
      reasonCode: 'lifecycle_backfill',
      lifecycleRound: 0,
      actor: { role: 'legacy', type: 'system', service: 'legacy', id: null },
      causationEventId: null,
      correlationId: null,
      occurredAt: null,
      changedAt: receivedAt.toISOString(),
    });
    expect(first.nextCursor).toBe(encodeHistoryCursor(1));
    expect(calls[0]).toEqual({ take: 3 });

    const second = await service.history(scope, message.publicId, {
      limit: 2,
      cursor: first.nextCursor!,
    });
    expect(calls[1]).toEqual({ take: 3, afterVersion: 1 });
    expect(second.nextCursor).toBeNull();
    expect(second.data).toEqual([
      {
        version: 2,
        fromState: 'persisted',
        toState: 'approved',
        reasonCode: 'dev_passthrough',
        lifecycleRound: 1,
        actor: { role: 'operator', type: 'user', service: 'api', id: 'u-1' },
        causationEventId: '0195f3c1-7a2b-7c3d-8e4f-0000000000ee',
        correlationId: 'api:c',
        occurredAt: '2026-11-04T08:10:00.000Z',
        changedAt: new Date(receivedAt.getTime() + 2000).toISOString(),
      },
    ]);
  });

  it('refuses an invalid cursor (400) before reading', async () => {
    const { repository, calls } = fakeRepository({ history });
    await expect(
      new MessageLifecycleReadService(repository).history(scope, message.publicId, {
        limit: 2,
        cursor: 'bogus',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(calls).toEqual([]);
  });
});
