import { HttpException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { encodeScanCursor } from '../domain/message-scans';
import type {
  LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../repositories/message-lifecycle-read.repository';
import type {
  MessageScansReadRepository,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';
import { MessageScansReadService } from './message-scans-read.service';

const scope = systemScope(3n);
const message: LifecycleMessageRow = {
  id: 10n,
  publicId: '0190f0f0-0000-7000-8000-000000000010',
  receivedAt: new Date('2026-11-05T08:00:00Z'),
  direction: 'inbound',
  status: 'scanned',
  statusReason: null,
  version: 6,
  lifecycleRound: 2,
  statusChangedAt: new Date('2026-11-05T08:00:00Z'),
};
const round = (id: bigint, lifecycleRound: number): ScanRoundRow => ({
  id,
  lifecycleRound,
  scanKind: lifecycleRound === 0 ? 'initial' : 'rescan',
  status: 'completed',
  scanVerdict: 'clean',
  reasonCodes: [],
  requiredEngines: ['rspamd'],
  startedAt: null,
  completedAt: null,
  deadlineAt: null,
});

function setup(rows: ScanRoundRow[], found = true) {
  const lifecycle = { findMessage: vi.fn(() => Promise.resolve(found ? message : null)) };
  const scans = {
    rounds: vi.fn(() => Promise.resolve(rows)),
    engineResults: vi.fn(() => Promise.resolve([])),
    authResults: vi.fn(() => Promise.resolve([])),
  };
  const service = new MessageScansReadService(
    lifecycle as unknown as MessageLifecycleReadRepository,
    scans as unknown as MessageScansReadRepository,
  );
  return { service, lifecycle, scans };
}

describe('MessageScansReadService (step 4.1 S16)', () => {
  it('pages newest round first with a round cursor, reading only the page’s scans', async () => {
    const { service, scans } = setup([round(30n, 2), round(20n, 1), round(10n, 0)]);
    const page = await service.list(scope, message.publicId, { limit: 2 });
    expect(page.messageId).toBe(message.publicId);
    expect(page.data.map((r) => r.round)).toEqual([2, 1]);
    expect(page.nextCursor).toBe(encodeScanCursor(1));
    expect(scans.rounds).toHaveBeenCalledWith(scope, message, { take: 3 });
    expect(scans.engineResults).toHaveBeenCalledWith(scope, message, [30n, 20n]);
    expect(scans.authResults).toHaveBeenCalledWith(scope, message, [30n, 20n]);

    const next = setup([round(10n, 0)]);
    const last = await next.service.list(scope, message.publicId, {
      limit: 2,
      cursor: encodeScanCursor(1),
    });
    expect(next.scans.rounds).toHaveBeenCalledWith(scope, message, { take: 3, beforeRound: 1 });
    expect(last.nextCursor).toBeNull();
  });

  it('is 404 message_not_found for an unknown or foreign message (looked up in the scope)', async () => {
    const { service, lifecycle, scans } = setup([], false);
    const error: unknown = await service
      .list(scope, message.publicId, { limit: 10 })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpException);
    expect((error as HttpException).getStatus()).toBe(404);
    expect(lifecycle.findMessage).toHaveBeenCalledWith(scope, message.publicId);
    expect(scans.rounds).not.toHaveBeenCalled();
  });
});
